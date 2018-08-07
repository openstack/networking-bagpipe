# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

# Copyright 2014 Orange
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re

import collections
from distutils import version  # pylint: disable=no-name-in-module
import netaddr
from oslo_config import cfg
from oslo_config import types
from oslo_log import log as logging

from neutron.common import utils as n_utils

from networking_bagpipe.bagpipe_bgp.common import config
from networking_bagpipe.bagpipe_bgp.common import dataplane_utils
from networking_bagpipe.bagpipe_bgp.common import exceptions as exc
from networking_bagpipe.bagpipe_bgp.common import log_decorator
from networking_bagpipe.bagpipe_bgp.common import looking_glass as lg
from networking_bagpipe.bagpipe_bgp.common import net_utils
from networking_bagpipe.bagpipe_bgp import constants as consts
from networking_bagpipe.bagpipe_bgp.engine import exa
from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers as dp_drivers
from networking_bagpipe.bagpipe_bgp.vpn import identifier_allocators
from networking_bagpipe.bagpipe_bgp.vpn import vpn_instance

from neutron.agent.common import ovs_lib
from neutron.plugins.ml2.drivers.openvswitch.agent.common import \
    constants as ovs_const

# man ovs-ofctl /32768
DEFAULT_OVS_FLOW_PRIORITY = 0x8000

# we want to avoid having our flows having a lowest priority than
# the default
DEFAULT_RULE_PRIORITY = DEFAULT_OVS_FLOW_PRIORITY + 0x1000

# priorities for IP match flows
# highest priority MAX_PREFIX_PRIORITY for MAX_PREFIX_LENGTH prefix
# (MAX_PREFIX_PRIORITY - MAX_PREFIX_LENGTH) for a zero length prefix
MAX_PREFIX_PRIORITY = DEFAULT_RULE_PRIORITY
MAX_PREFIX_LENGTH = 0x80  # 128

# fallback flows get a priority even lower
# (we round it for better readability of flow dumps)
FALLBACK_PRIORITY = MAX_PREFIX_PRIORITY - MAX_PREFIX_LENGTH - 0x80

NO_MPLS_PHY_INTERFACE = -1

VXLAN_TUNNEL = "vxlan"

OVS_DUMP_FLOW_FILTER = "| grep -v NXST_FLOW | perl -pe '"               \
    "s/ *cookie=[^,]+, duration=[^,]+, table=[^,]+, //;" \
    "s/ *n_bytes=[^,]+, //; "                            \
    "s/ *(hard|idle)_age=[^,]+, //g; "                   \
    "s/n_packets=([0-9]),/packets=$1    /; "             \
    "s/n_packets=([0-9]{2}),/packets=$1   /; "           \
    "s/n_packets=([0-9]{3}),/packets=$1  /; "            \
    "s/n_packets=([0-9]+),/packets=$1 /; "               \
    "'"

GATEWAY_MAC = "00:00:5e:00:43:64"

ARP_RESPONDER_ACTIONS = ('move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],'
                         'mod_dl_src:%(mac)s,'
                         'load:0x2->NXM_OF_ARP_OP[],'
                         'move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],'
                         'push:NXM_OF_ARP_TPA[],'
                         'move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],'
                         'load:%(mac)#x->NXM_NX_ARP_SHA[],'
                         'pop:NXM_OF_ARP_SPA[],'
                         '%(vlan_action)soutput:%(in_port)d')

VRF_REGISTER = 0


def _match_from_prefix(prefix):
    # A zero-length prefix is a default route, no nw_dst is needed/possible
    # in this case
    prefix_length = netaddr.IPNetwork(prefix).prefixlen
    return {'nw_dst': prefix} if prefix_length != 0 else {}


def _priority_from_prefix(prefix):
    # FIXME: use a priority depending on the prefix len
    #        to compensate the fact that "OpenFlow  leaves  behavior
    #        undefined when two or more flows with the same priority
    #        can match a single packet.  Some users expect ``sensible''
    #        behavior, such as more specific flows taking precedence
    #        over less specific flows, but OpenFlow does not specify
    #        this and Open vSwitch does not implement it.  Users should
    #        therefore  take  care  to  use  priorities  to ensure the
    #        behavior that they expect.
    prefix_length = netaddr.IPNetwork(prefix).prefixlen
    # to implement a longest-match lookup we give longest prefixes
    # the higher priority
    priority = MAX_PREFIX_PRIORITY - (MAX_PREFIX_LENGTH - prefix_length)
    return priority


class MPLSOVSVRFDataplane(dp_drivers.VPNInstanceDataplane):

    def __init__(self, *args, **kwargs):
        super(MPLSOVSVRFDataplane, self).__init__(*args, **kwargs)

        # Initialize dict where we store info on OVS ports (port numbers and
        # bound IP address)
        self._ovs_port_info = dict()

        self.bridge = self.driver.bridge

        self.nh_group_mgr = NextHopGroupManagerProxy(
            self.driver.nh_group_mgr,
            self.instance_id,
            self.driver.vrf_table,
            self._vrf_match(),
            self._cookie
        )

        self.fallback = None
        self.ovs_vlan = None

    @log_decorator.log_info
    def cleanup(self):
        if self._ovs_port_info:
            self.log.warning("OVS port numbers list for local ports plugged in"
                             " VRF is not empty, clearing...")
            self._ovs_port_info.clear()

        # Remove all flows for this instance
        for table in self.driver.all_tables.values():
            self.bridge.delete_flows(table=table,
                                     cookie=self._cookie(add=False))

        # Remove all groups for this instance
        self.nh_group_mgr.clear_objects()

    @log_decorator.log
    def _extract_mac_address(self, output):
        """Extract MAC address from command output"""

        return re.search(r"([0-9A-F]{2}[:-]){5}([0-9A-F]{2})", output,
                         re.IGNORECASE).group()

    def _find_remote_mac_address(self, remote_ip):
        """Find MAC address for a remote IP address"""

        # PING remote IP address
        (_, exit_code) = self._run_command("fping -r4 -t100 -q -I %s %s" %
                                           (self.bridge.br_name, remote_ip),
                                           raise_on_error=False,
                                           acceptable_return_codes=[-1])
        if exit_code != 0:
            self.log.info("can't ping %s via %s, proceeding anyways",
                          remote_ip, self.bridge.br_name)
            # we proceed even if the ping failed, since the ping was
            # just a way to trigger an ARP resolution which may have
            # succeeded even if the ping failed

        # Look in ARP cache to find remote MAC address
        (output, _) = self._run_command("ip neigh show to %s dev %s" %
                                        (remote_ip, self.bridge.br_name))

        if (not output or
                "FAILED" in output[0] or
                "INCOMPLETE" in output[0]):
            raise exc.RemotePEMACAddressNotFound(remote_ip)

        try:
            return self._extract_mac_address(output[0])
        except Exception:
            raise exc.RemotePEMACAddressNotFound(remote_ip)

    def _mtu_fixup(self, localport):
        # This is a hack, proper MTUs should actually be configured in the
        # hybrid vif driver
        # TODO(tmorin): obsolete

        mtu = self.config["ovsbr_interfaces_mtu"]
        if not mtu:
            self.log.debug("No ovsbr_interfaces_mtu specified in config file,"
                           " not trying to fixup MTU")
            return

        try:
            itf = localport['ovs']['port_name']
        except KeyError:
            self.log.warning("No OVS port name provided, cannot fix MTU")
            return

        self.log.info("Will adjust %s if with MTU %s "
                      "(ovsbr_interfaces_mtu specified in config)", itf, mtu)

        (_, exit_code) = self._run_command("ip link show %s" % itf,
                                           raise_on_error=False,
                                           acceptable_return_codes=[0, 1])

        if exit_code != 0:
            self.log.warning("No %s if, not trying to fix MTU", itf)
        else:
            self._run_command("ip link set %s mtu %s" % (itf, mtu),
                              run_as_root=True)

    def _get_ovs_port_specifics(self, localport):
        # Returns a tuple of:
        # - OVS port number for traffic to/from VMs
        # - OVS port name
        try:
            port_name = ""
            if ('ovs' in localport and localport['ovs']['plugged']):
                try:
                    port = localport['ovs']['port_number']
                except KeyError:
                    self.log.info("No OVS port number provided, trying to use"
                                  " a port name")
                    port = self.driver.find_ovs_port(
                        localport['ovs']['port_name'])
            else:
                try:
                    try:
                        port_name = localport['ovs']['port_name']
                    except KeyError as e:
                        port_name = localport['linuxif']
                except Exception:
                    raise Exception("Trying to find which port to plug, but no"
                                    " portname was provided")

                try:
                    port = self.driver.find_ovs_port(port_name)
                except Exception:
                    port = self.bridge.add_port(port_name)
                self.log.debug("Corresponding port number: %s", port)
        except KeyError as e:
            self.log.error("Incomplete port specification: %s", e)
            raise Exception("Incomplete port specification: %s" % e)

        return (port, port_name)

    def _vlan_match(self):
        return {'dl_vlan': self.ovs_vlan} if self.ovs_vlan else {}

    def get_push_vlan_action(self):
        return ("push_vlan:0x8100,mod_vlan_vid:%d" % self.ovs_vlan
                if self.ovs_vlan else "")

    def get_strip_vlan_action(self):
        return "strip_vlan" if self.ovs_vlan else ""

    @log_decorator.log_info
    def update_fallback(self, fallback=None):
        if fallback:
            self.fallback = fallback

        if not self.fallback:
            return

        for param in ('src_mac', 'dst_mac', 'ovs_port_number'):
            if not self.fallback.get(param):
                self.log.error("fallback specified without '%s'", param)
                return

        # use priority -1 so that the route only hits when the packet
        # does not matches any VRF route
        self.bridge.add_flow_extended(
            flow_matches=[dict(table=self.driver.vrf_table,
                               cookie=self._cookie(add=True),
                               priority=FALLBACK_PRIORITY),
                          self._vrf_match()],
            actions=[self.get_push_vlan_action(),
                     'mod_dl_src:%s' % self.fallback.get('src_mac'),
                     'mod_dl_dst:%s' % self.fallback.get('dst_mac'),
                     'output:%d' % self.fallback.get('ovs_port_number')])

    @log_decorator.log_info
    def setup_arp_responder(self, ovs_port):
        if not self.driver.config.arp_responder:
            return

        self.bridge.add_flow_extended(
            flow_matches=[dict(table=self.driver.vrf_table,
                               cookie=self._cookie(add=True),
                               priority=DEFAULT_RULE_PRIORITY,
                               proto='arp',
                               dl_dst='ff:ff:ff:ff:ff:ff',
                               arp_op='0x1'),
                          self._vrf_match(),
                          # Respond to all IP addresses if proxy ARP is
                          # enabled, otherwise only for gateway
                          {'arp_tpa': self.gateway_ip}
                          if not self.driver.config.proxy_arp else {}],
            actions=[ARP_RESPONDER_ACTIONS % {
                'mac': netaddr.EUI(GATEWAY_MAC, dialect=netaddr.mac_unix),
                'vlan_action': self.get_push_vlan_action(),
                'in_port': ovs_port
            }])

    @log_decorator.log_info
    def remove_arp_responder(self):
        self.bridge.delete_flows_extended(
            flow_matches=[dict(table=self.driver.vrf_table,
                               cookie=self._cookie(add=False),
                               proto='arp'),
                          self._vrf_match()])

    def _check_vlan_use(self, localport):
        # checks that if a vlan_action is used, it is the same
        # for all interfaces plugged into the VRF
        # on first plug we update
        try:
            ovs_vlan = int(localport['ovs']['vlan'])
        except KeyError:
            return

        if self.ovs_vlan is None:
            self.ovs_vlan = ovs_vlan
        else:
            # on a subsequent plug, we check
            if self.ovs_vlan != ovs_vlan:
                self.log.error("different VLAN for different interfaces: "
                               "%s vs %s", self.ovs_vlan,
                               ovs_vlan)
                raise Exception("can't specify a different VLAN for different"
                                " interfaces")

    @log_decorator.log
    def vif_plugged(self, mac_address, ip_address, localport, label,
                    direction):

        (ovs_port, ovs_port_name) = self._get_ovs_port_specifics(localport)

        self._check_vlan_use(localport)

        # need to update fallback, in case it was called before the
        # first vifPlugged call could define the push_vlan action
        self.update_fallback()

        # This is a hack used with previous versions of Openstack
        #  proper MTUs should actually be configured in the hybrid vif driver
        # Please consider this obsolete until it gets clean'd up
        self._mtu_fixup(localport)

        if vpn_instance.forward_from_port(direction):
            # Map traffic from plugged port to VRF

            # Note that we first reset the in_port so that OVS will allow the
            # packet to eventually go back to this port after a VRF lookup
            # (the case where that happens is where in port is a patch-port on
            # which different VLANs are used to reach different networks):
            # patch port vlan X -- VRFX --- VRF Y -- patch-port vlan Y
            #
            # ( see http://docs.openvswitch.org/en/latest/faq/openflow/
            # "Q: I added a flow to send packets out the ingress port..." )
            for proto in ('ip', 'arp'):
                self.bridge.add_flow_extended(
                    flow_matches=[dict(table=self.driver.input_table,
                                       cookie=self._cookie(add=True),
                                       priority=DEFAULT_RULE_PRIORITY,
                                       proto=proto,
                                       in_port=ovs_port),
                                  self._vlan_match()],
                    actions=[self.get_strip_vlan_action(),
                             'load:0->NXM_OF_IN_PORT[],',
                             'set_field:%d->reg%d,' % (self.instance_id,
                                                       VRF_REGISTER),
                             'resubmit(,%d)' % self.driver.vrf_table])

        # Map ARP responder if necessary
        if not self._ovs_port_info:
            self.setup_arp_responder(ovs_port)

        if vpn_instance.forward_to_port(direction):
            # Map incoming MPLS traffic going to the VM port
            incoming_actions = [self.get_push_vlan_action(),
                                "mod_dl_src:%s,mod_dl_dst:%s" % (GATEWAY_MAC,
                                                                 mac_address),
                                "output:%s" % ovs_port]

            self.bridge.add_flow_extended(
                flow_matches=[dict(table=self.driver.encap_in_table,
                                   cookie=self._cookie(add=True),
                                   priority=DEFAULT_RULE_PRIORITY,
                                   proto="mpls",
                                   mpls_label=label,
                                   mpls_bos=1)],
                actions=["pop_mpls:0x0800"] + incoming_actions)

            # additional incoming traffic rule for VXLAN
            if self.driver.vxlan_encap:
                self.bridge.add_flow_extended(
                    flow_matches=[
                        dict(table=self.driver.encap_in_table,
                             cookie=self._cookie(add=True),
                             priority=DEFAULT_RULE_PRIORITY,
                             in_port=self.driver.vxlan_tunnel_port_number,
                             tun_id=label)],
                    actions=incoming_actions)

        # Add OVS port number in list for local port plugged in VRF
        # FIXME: check check check, is linuxif the right key??
        self.log.debug("Adding OVS port %s with port %s for address "
                       "%s, to the list of ports plugged in VRF",
                       localport['linuxif'], ovs_port, ip_address)
        self._ovs_port_info[localport['linuxif']] = {
            "ovs_port": ovs_port,
            "ovs_port_name": ovs_port_name,
        }

    @log_decorator.log
    def vif_unplugged(self, mac_address, ip_address, localport, label,
                      direction, last_endpoint=True):

        ovs_port = self._ovs_port_info[localport['linuxif']]['ovs_port']
        ovs_port_name = self._ovs_port_info[
            localport['linuxif']]['ovs_port_name']

        if vpn_instance.forward_to_port(direction):
            # Unmap incoming MPLS traffic going to the VM port
            self.bridge.delete_flows(table=self.driver.encap_in_table,
                                     cookie=self._cookie(add=False),
                                     proto="mpls",
                                     mpls_label=label,
                                     mpls_bos=1)

            # Unmap incoming VXLAN traffic...
            if self.driver.vxlan_encap:
                self.bridge.delete_flows(
                    table=self.driver.encap_in_table,
                    cookie=self._cookie(add=False),
                    in_port=self.driver.vxlan_tunnel_port_number,
                    tun_id=label)

        if last_endpoint:
            if vpn_instance.forward_from_port(direction):
                # Unmap all traffic from plugged port
                self.bridge.delete_flows_extended(
                    flow_matches=[dict(table=self.driver.input_table,
                                       cookie=self._cookie(add=False),
                                       in_port=ovs_port),
                                  self._vlan_match()])

            # Unmap ARP responder
            self.remove_arp_responder()

            # Run port unplug action if necessary (OVS port delete)
            if ovs_port_name:
                self.bridge.delete_port(ovs_port_name)

            # Remove OVS port number from list for local port plugged in VRF
            del self._ovs_port_info[localport['linuxif']]

    def _get_label_action(self, label, encaps):
        if (self.driver.vxlan_encap and
                exa.Encapsulation(exa.Encapsulation.Type.VXLAN) in encaps):
            return "set_field:%d->tunnel_id" % label
        else:
            return "push_mpls:0x8847,set_mpls_label:%d" % label

    def _get_output_action(self, remote_pe, encaps):
        # Check if prefix is from a local VRF
        if self.driver.get_local_address() == remote_pe:
            self.log.debug("Local route, using a resubmit action")
            # For local traffic, we have to use a resubmit action
            if (self.driver.vxlan_encap and
                    exa.Encapsulation(exa.Encapsulation.Type.VXLAN) in encaps):
                return ("resubmit(%d,%d)" %
                        (self.driver.vxlan_tunnel_port_number,
                         self.driver.encap_in_table))
            else:
                return "resubmit(%d,%d)" % (self.driver.mpls_in_port(),
                                            self.driver.encap_in_table)
        else:
            if (self.driver.vxlan_encap and
                    exa.Encapsulation(exa.Encapsulation.Type.VXLAN) in encaps):
                self.log.debug("Will use a VXLAN encap for this destination")
                return "set_field:%s->tun_dst,output:%s" % (
                    remote_pe, self.driver.vxlan_tunnel_port_number)
            elif self.driver.use_gre:
                self.log.debug("Using MPLS/GRE encap")
                return "set_field:%s->tun_dst,output:%s" % (
                    remote_pe, self.driver.gre_tunnel_port_number)
            else:
                self.log.debug("Using bare MPLS encap")
                # Find remote router MAC address
                try:
                    remote_pe_mac_address = self._find_remote_mac_address(
                        remote_pe)
                    self.log.debug("MAC address found for remote router "
                                   "%(remote_pe)s: %(remote_pe_mac_address)s",
                                   locals())
                except exc.RemotePEMACAddressNotFound as e:
                    self.log.error("An error occured during setupDataplaneFor"
                                   "RemoteEndpoint: %s", e)
                    raise

                # Map traffic to remote IP address as MPLS on ethX to remote
                # router MAC address
                return "mod_dl_src:%s,mod_dl_dst:%s,output:%s" % (
                    self.driver.mpls_if_mac_address, remote_pe_mac_address,
                    self.driver.ovs_mpls_if_port_number)

    def _cookie(self, add=False):
        mask = ""
        if not add:
            mask = "/-1"
        return "%d%s" % (self.instance_id, mask)

    def _vrf_match(self):
        return {'reg%d' % VRF_REGISTER: self.instance_id}

    @log_decorator.log_info
    def setup_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                            nlri, encaps,
                                            lb_consistent_hash_order=0):
        nexthop = NextHop(label, remote_pe, encaps, lb_consistent_hash_order)

        if self.nh_group_mgr.is_object_user(prefix, nexthop):
            self.log.debug("Dataplane already in place for %s, %s, skipping",
                           prefix, nexthop)
            return

        dec_ttl = (netaddr.IPNetwork(prefix) not in netaddr.IPNetwork(
                   "%s/%s" % (self.gateway_ip, self.network_plen)))
        label_action = self._get_label_action(nexthop.label,
                                              nexthop.encaps)
        output_action = self._get_output_action(nexthop.remote_pe,
                                                nexthop.encaps)
        self.nh_group_mgr.new_nexthop(prefix, nexthop,
                                      actions=["dec_ttl" if dec_ttl else "",
                                               label_action,
                                               output_action])

    @log_decorator.log_info
    def remove_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                             nlri, encaps,
                                             lb_consistent_hash_order=0):

        nexthop = NextHop(label, remote_pe, encaps, lb_consistent_hash_order)

        if self.nh_group_mgr.is_object_user(prefix, nexthop):
            self.nh_group_mgr.del_nexthop(prefix, nexthop)
        else:
            self.log.debug("remove_dataplane_for_remote_endpoint called, "
                           "for %s and %s, but we don't know about this "
                           "prefix and next-hop", prefix, nexthop.__dict__)

    def _get_port_range_from_classifier(self, classifier_port):
        if classifier_port:
            if type(classifier_port) == tuple:
                port_min, port_max = classifier_port
            else:
                port_min = port_max = classifier_port

        return port_min, port_max

    def _create_port_range_flow_matches(self, classifier_match, classifier):
        flow_matches = []
        src_port_match = '{:s}_src'.format(classifier.protocol)

        if classifier.source_port:
            if type(classifier.source_port) == tuple:
                src_port_min, src_port_max = classifier.source_port
            else:
                src_port_min = src_port_max = classifier.source_port

        dst_port_match = '{:s}_dst'.format(classifier.protocol)

        if classifier.destination_port:
            if type(classifier.destination_port) == tuple:
                dst_port_min, dst_port_max = classifier.destination_port
            else:
                dst_port_min = dst_port_max = classifier.destination_port

        dst_port_range = []
        if dst_port_min and dst_port_max:
            dst_port_range = n_utils.port_rule_masking(dst_port_min,
                                                       dst_port_max)
        src_port_range = []
        if src_port_min and src_port_max:
            src_port_range = n_utils.port_rule_masking(src_port_min,
                                                       src_port_max)
            for port in src_port_range:
                flow_match = classifier_match.copy()
                flow_match[src_port_match] = port
                if dst_port_range:
                    for port in dst_port_range:
                        dst_flow = flow_match.copy()
                        dst_flow[dst_port_match] = port
                        flow_matches.append(dst_flow)
                else:
                    flow_matches.append(flow_match)
        else:
            for port in dst_port_range:
                flow_match = classifier_match.copy()
                flow_match[dst_port_match] = port
                flow_matches.append(flow_match)

        return flow_matches

    def _create_classifier_flow_matches(self, classifier):
        classifier_match = dict(proto=classifier.protocol)

        if classifier.source_pfx:
            classifier_match.update({'nw_src': classifier.source_pfx})

        if classifier.destination_pfx:
            classifier_match.update({'nw_dst': classifier.destination_pfx})

        return self._create_port_range_flow_matches(classifier_match,
                                                    classifier)

    @log_decorator.log_info
    def add_dataplane_for_traffic_classifier(self, classifier,
                                             redirect_to_instance_id):
        classifier_matches = self._create_classifier_flow_matches(classifier)

        # Add traffic redirection to redirection VRF for classifier matches
        for classifier_match in classifier_matches:
            self.bridge.add_flow_extended(
                flow_matches=[dict(table=self.driver.vrf_table,
                                   cookie=self._cookie(add=True),
                                   priority=DEFAULT_RULE_PRIORITY),
                              self._vrf_match(),
                              classifier_match],
                actions=['set_field:%d->reg%d' % (redirect_to_instance_id,
                                                  VRF_REGISTER),
                         'resubmit(,%d)' % self.driver.vrf_table])

    @log_decorator.log_info
    def remove_dataplane_for_traffic_classifier(self, classifier):
        classifier_matches = self._create_classifier_flow_matches(classifier)

        # Remove traffic redirection to redirection VRF for classifier matches
        for classifier_match in classifier_matches:
            self.bridge.delete_flows_extended(
                flow_matches=[dict(table=self.driver.vrf_table,
                                   cookie=self._cookie(add=False)),
                              self._vrf_match(),
                              classifier_match])

    def get_lg_map(self):
        return {
            "flows": (lg.SUBTREE, self.get_lg_ovs_flows)
        }

    def get_lg_ovs_flows(self, path_prefix):
        return self.driver.get_lg_ovs_flows(
            path_prefix, 'cookie=%s' % self._cookie(add=False))


class OVSGroupAllocator(identifier_allocators.IDAllocator):

    MAX = 2**32-1


class OVSBucketAllocator(identifier_allocators.IDAllocator):

    # Values greater than 0xFFFFFF00 are reserved
    MAX = 2**32-2**8-1


class NextHop(object):

    def __init__(self, label, remote_pe, encaps, lb_consistent_hash_order):
        self.label = label
        self.remote_pe = str(remote_pe)
        self.encaps = frozenset(encaps)
        self.lb_consistent_hash_order = lb_consistent_hash_order

    def __eq__(self, other):
        return ((self.label, self.remote_pe, self.encaps) ==
                (other.label, other.remote_pe, other.encaps))

    def __hash__(self):
        return hash((self.label,
                     self.remote_pe,
                     self.encaps))

    def __repr__(self):
        return "NextHop(%s,%s,%s,%s)" % (self.label,
                                         self.remote_pe,
                                         self.encaps,
                                         self.lb_consistent_hash_order)


class NextHopGroupManager(dataplane_utils.ObjectLifecycleManager):

    def __init__(self, bridge, hash_method, hash_method_param, hash_fields):
        super(NextHopGroupManager, self).__init__()

        self.bridge = bridge
        self.hash_method = hash_method
        self.hash_method_param = hash_method_param
        self.hash_fields = hash_fields

        self.group_allocator = OVSGroupAllocator()

    def get_selection_method(self):
        selection_method = self.hash_method
        if self.hash_fields and self.hash_method == 'hash':
            selection_method += ",fields(%s)" % ','.join(self.hash_fields)

        return selection_method

    @log_decorator.log_info
    def create_object(self, prefix, *args, **kwargs):
        buckets = (
            {'buckets': kwargs['buckets']} if kwargs.get('buckets') else {}
        )

        group_id = self.group_allocator.get_new_id("Group ID for prefix %s" %
                                                   str(prefix))

        self.bridge.add_group(group_id=group_id,
                              type='select',
                              selection_method=self.get_selection_method(),
                              selection_method_param=self.hash_method_param,
                              **buckets)

        return group_id

    @log_decorator.log_info
    def delete_object(self, group_id):
        self.bridge.delete_group(group_id=group_id)
        self.group_allocator.release(group_id)


class NextHopGroupManagerProxy(dataplane_utils.ObjectLifecycleManagerProxy):

    def __init__(self, manager, parent_key, vrf_table, vrf_match, cookie_func):
        super(NextHopGroupManagerProxy, self).__init__(manager, parent_key)

        self.vrf_table = vrf_table
        self.vrf_match = vrf_match
        self.cookie_func = cookie_func

        self.bucket_allocators = (
            collections.defaultdict(OVSBucketAllocator)
        )

        self.prefix_nexthop_2_bucket = dict()

    def _update_group_buckets(self, group_id, prefix):
        buckets = []
        for prefix_nh, bucket in self.prefix_nexthop_2_bucket.items():
            if prefix == prefix_nh[0]:
                buckets.append('bucket=bucket_id=%d,%s' % (
                    bucket[0], dataplane_utils.join_s(*bucket[1])))

        self.manager.bridge.mod_group(
            group_id=group_id,
            type='select',
            selection_method=self.manager.get_selection_method(),
            selection_method_param=self.manager.hash_method_param,
            buckets=','.join(buckets))

    def new_nexthop(self, prefix, nexthop, actions=[]):
        bucket_allocator = self.bucket_allocators[prefix]
        bucket_id = bucket_allocator.get_new_id(
            "Bucket ID for prefix %s and nexthop %s" % (str(prefix), nexthop),
            hint_value=nexthop.lb_consistent_hash_order
        )
        bucket = 'bucket=bucket_id=%d,%s' % (bucket_id,
                                             dataplane_utils.join_s(*actions))

        self.prefix_nexthop_2_bucket[(prefix, nexthop)] = (bucket_id, actions)

        group_id, first = self.get_object(prefix, nexthop, buckets=bucket)
        if first:
            self.manager.bridge.add_flow_extended(
                flow_matches=[dict(table=self.vrf_table,
                                   cookie=self.cookie_func(add=True),
                                   priority=_priority_from_prefix(prefix),
                                   proto='ip'),
                              self.vrf_match,
                              _match_from_prefix(prefix)],
                actions=["group:%d" % group_id])
        else:
            self._update_group_buckets(group_id, prefix)

    def del_nexthop(self, prefix, nexthop):
        group_id = self.find_object(prefix)

        bucket_id, _ = self.prefix_nexthop_2_bucket.pop((prefix, nexthop))

        bucket_allocator = self.bucket_allocators[prefix]
        bucket_allocator.release(bucket_id)

        self._update_group_buckets(group_id, prefix)

        last = self.free_object(prefix, nexthop)

        if last:
            self.manager.bridge.delete_flows_extended(
                flow_matches=[dict(strict=True,
                                   table=self.vrf_table,
                                   cookie=self.cookie_func(add=False),
                                   priority=_priority_from_prefix(prefix),
                                   proto='ip'),
                              self.vrf_match,
                              _match_from_prefix(prefix)])

            del self.bucket_allocators[prefix]


class MPLSOVSDataplaneDriver(dp_drivers.DataplaneDriver):

    """Dataplane driver using OpenVSwitch

    Based on an OpenVSwitch 2.4 MPLS kernel dataplane implementation.

    This driver was successfully tested with the OVS 2.4 DKMS module.

    This driver uses MPLS-over-GRE by default. However, note well that current
    OVS implementation of MPLS-over-GRE is not yet conformant with RFC4023,
    because of an intermediate Eth header (MPLS-over-Eth-over-GRE).

    If MPLS-over-GRE is disabled (with mpls_over_gre=False), this driver
    currently requires that the OVS bridge be associated to the address used as
    the local_address in bgp.conf, to allow the linux IP stack to use the same
    physical interface as the one on which MPLS packets are forwarded. This
    requires to configure the OVS bridge so that it passes packets from the
    physical interface to the linux IP stack if they are not MPLS, and packets
    from the linux IP stack to the physical device.

    Howto allow the use of the OVS bridge interface also as an IP
    interface of the Linux kernel IP stack:
        ovs-ofctl del-flows br-int
        ovs-ofctl add-flow br-int in_port=LOCAL,action=output:1
        ovs-ofctl add-flow br-int in_port=1,action=output:LOCAL

    (on a debian or ubuntu system, this can be done part of the ovs bridge
    definition in /etc/network/interfaces, as post-up commands)

    The 'vrf_table' (resp. 'input_table') config parameters can be
    used to specify which OVS table will host the rules for traffic from VRFs
    (resp. for incoming traffic). Beware, this dataplane driver will
    *not* take care of setting up rules so that MPLS traffic or the traffic
    from attached ports is matched against rules in these tables.
    """

    dataplane_instance_class = MPLSOVSVRFDataplane
    type = consts.IPVPN
    ecmp_support = True
    required_ovs_version = "2.8.0"

    driver_opts = [
        cfg.StrOpt("mpls_interface",
                   help=("Interface used to send/receive MPLS traffic. "
                         "Use '*gre*' to choose automatic creation of a tunnel"
                         " port for MPLS/GRE encap")),
        cfg.StrOpt("mpls_over_gre",
                   choices=['auto', 'True', 'False'],
                   default="auto",
                   advanced=True,
                   help=("Force the use of MPLS/GRE even with "
                         "mpls_interface specified")),
        cfg.BoolOpt("proxy_arp", default=False,
                    advanced=True,
                    help=("Activate ARP responder per VRF for any IP "
                          "address")),
        cfg.BoolOpt("arp_responder", default=False,
                    advanced=True,
                    help=("ARP responder per VRF")),
        cfg.BoolOpt("vxlan_encap", default=False,
                    advanced=True,
                    help=("Be ready to receive VPN traffic as VXLAN, and to "
                          "preferrably send traffic as VXLAN when advertised "
                          "by the remote end")),
        cfg.StrOpt("ovs_bridge", default="br-mpls", advanced=True),
        cfg.IntOpt("input_table", default=0, advanced=True),
        cfg.IntOpt("ovs_table_id_start", default=1, advanced=True),
        cfg.StrOpt("gre_tunnel", default="mpls_gre", advanced=True,
                   help="OVS interface name for MPLS/GRE encap"),
        cfg.ListOpt("gre_tunnel_options", default=[],
                    item_type=types.String(),
                    help=("Options, comma-separated, passed to OVS for GRE "
                          "tunnel port creation (e.g. 'packet_type=legacy_l3"
                          ", ...') that will be added as OVS tunnel "
                          "interface options (e.g. 'options:packet_type="
                          "legacy_l3 options:...')")),
        cfg.IntOpt("ovsbr_interfaces_mtu", advanced=True),
        cfg.StrOpt("hash_method",
                   choices=["hash", "dp_hash"],
                   default="dp_hash",
                   advanced=True,
                   help=("Can be used to control the OVS group bucket "
                         "selection method (mapped to ovs "
                         "'selection_method')")),
        cfg.StrOpt("hash_method_param",
                   default=0,
                   advanced=True,
                   help=("Can be used to control the OVS group bucket "
                         "selection method (mapped to ovs "
                         "'selection_method_param')")),
        cfg.ListOpt("hash_fields", default=[], advanced=True,
                    help=("Can be used to control the fields used by the OVS "
                          "group bucket selection method (mapped to ovs "
                          "'fields')"))
    ]

    def __init__(self):
        super(MPLSOVSDataplaneDriver, self).__init__()

        config.set_default_root_helper()

        try:
            (o, _) = self._run_command("ovs-ofctl -V | head -1 |"
                                       " awk '{print $4}'")
            self.ovs_release = o[0]
            self.log.info("OVS version: %s", self.ovs_release)
        except Exception:
            self.log.warning("Could not determine OVS release")
            self.ovs_release = None

        self.mpls_interface = self.config.mpls_interface

        if self.config.mpls_over_gre != "auto":
            self.use_gre = True
        else:
            self.use_gre = not (self.mpls_interface and
                                self.mpls_interface != "*gre*")

        if not self.mpls_interface:
            if not self.use_gre:
                raise Exception("mpls_over_gre force-disabled, but no "
                                "mpls_interface specified")
            else:
                self.use_gre = True
                self.log.info("Defaulting to use of MPLS-over-GRE (no "
                              "mpls_interface specified)")
        elif self.mpls_interface == "*gre*":
            if not self.use_gre:
                raise Exception("mpls_over_gre force-disabled, but "
                                "mpls_interface set to '*gre', cannot "
                                "use bare MPLS")
            else:
                self.log.info("mpls_interface is '*gre*', will thus use "
                              "MPLS-over-GRE")
                self.use_gre = True
                self.mpls_interface = None
        else:
            if self.use_gre:
                self.log.warning("mpls_over_gre set to True, "
                                 "ignoring mpls_interface parameter")
                self.mpls_interface = None
            else:
                self.log.info("Will use bare MPLS on interface %s",
                              self.mpls_interface)

        self.input_table = self.config.input_table

        if self.config.ovs_table_id_start == self.input_table:
            raise Exception("invalid ovs_table_id_start (%d): can't use tables"
                            " same as input table (%d)" % (
                                self.config.ovs_table_id_start,
                                self.config.input_table))

        self.encap_in_table = self.config.ovs_table_id_start
        self.vrf_table = self.config.ovs_table_id_start+1

        self.all_tables = {'incoming': self.input_table,
                           'vrf': self.vrf_table,
                           'encap_in': self.encap_in_table}

        # Used to control whether this VRF will support
        # receiving traffic as VXLAN
        self.vxlan_encap = self.config.vxlan_encap

        # check OVS version
        if (not self.vxlan_encap and
                version.StrictVersion(self.ovs_release) <
                version.StrictVersion(self.required_ovs_version)):
            self.log.warning("%s requires at least OVS %s"
                             " (you are running %s)",
                             self.__class__.__name__,
                             self.required_ovs_version,
                             self.ovs_release)

        # unless useGRE is enabled, check that fping is installed
        if not self.use_gre:
            self._run_command("fping -v", raise_on_error=True)

        self.bridge = dataplane_utils.OVSBridgeWithGroups(
            dataplane_utils.OVSExtendedBridge(self.config.ovs_bridge)
        )
        # Check if OVS bridge exist
        if not self.bridge.bridge_exists(self.bridge.br_name):
            raise exc.OVSBridgeNotFound(self.bridge.br_name)

        self.bridge.use_at_least_protocol(ovs_const.OPENFLOW15)

        self.nh_group_mgr = NextHopGroupManager(self.bridge,
                                                self.config.hash_method,
                                                self.config.hash_method_param,
                                                self.config.hash_fields)

        if not self.use_gre:
            self.log.info("Will not force the use of GRE/MPLS, trying to bind "
                          "physical interface %s", self.mpls_interface)
            # Check if MPLS interface is attached to OVS bridge
            if not self.bridge.port_exists(self.mpls_interface):
                raise Exception("Specified mpls_interface %s is not plugged to"
                                " OVS bridge %s" % (self.mpls_interface,
                                                    self.bridge.br_name))
            else:
                self.ovs_mpls_if_port_number = self.bridge.get_port_ofport(
                    self.mpls_interface)

    def supported_encaps(self):
        if self.use_gre:
            yield exa.Encapsulation(exa.Encapsulation.Type.GRE)
            yield exa.Encapsulation(exa.Encapsulation.Type.DEFAULT)
            # we will accept routes with no encap
            # specified and force the use of GRE
        else:
            yield exa.Encapsulation(exa.Encapsulation.Type.MPLS)
            # we also accept route with no encap specified
            yield exa.Encapsulation(exa.Encapsulation.Type.DEFAULT)

        if self.vxlan_encap:
            yield exa.Encapsulation(exa.Encapsulation.Type.VXLAN)

    def mpls_in_port(self):
        if self.use_gre:
            return self.gre_tunnel_port_number
        else:
            return self.ovs_mpls_if_port_number

    @log_decorator.log_info
    def reset_state(self):
        # Flush all MPLS and ARP flows, all groups, if bridge exists

        if self.bridge.bridge_exists(self.bridge.br_name):
            self.log.info("Cleaning up OVS rules")

            self.bridge.delete_flows(table=self.input_table,
                                     cookie=ovs_lib.COOKIE_ANY,
                                     proto='mpls')
            if self.vxlan_encap:
                try:
                    self.bridge.delete_flows(
                        table=self.input_table,
                        in_port=self.find_ovs_port(VXLAN_TUNNEL))
                except Exception:
                    self.log.info("no VXLAN tunnel port, nothing to clean up")
                # the above won't clean up flows if the vxlan_tunnel interface
                # has changed...
                self.bridge.delete_flows(table=self.input_table,
                                         cookie=ovs_lib.COOKIE_ANY,
                                         tun_id='2/1')
                self.bridge.delete_flows(table=self.input_table,
                                         cookie=ovs_lib.COOKIE_ANY,
                                         tun_id='1/1')

            # clean input_table rule for plugged ports
            # NOTE(tmorin): would be cleaner using a cookie
            self.bridge.delete_flows(table=self.input_table,
                                     cookie=ovs_lib.COOKIE_ANY,
                                     proto='ip')
            self.bridge.delete_flows(table=self.input_table,
                                     cookie=ovs_lib.COOKIE_ANY,
                                     proto='arp')

            self.bridge.delete_flows(table=self.encap_in_table,
                                     cookie=ovs_lib.COOKIE_ANY)
            self.bridge.delete_flows(table=self.vrf_table,
                                     cookie=ovs_lib.COOKIE_ANY)

            # clean all groups
            self.bridge.delete_group()

            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug("All our rules have been flushed:\n%s",
                               '\n'.join(self.bridge.dump_all_flows()))
                self.log.debug("All groups have been flushed:\n%s",
                               self.bridge.run_ofctl("dump-groups", []))
        else:
            self.log.info("No OVS bridge (%s), no need to cleanup OVS rules",
                          self.bridge.br_name)

    def initialize(self):
        if self.use_gre:
            self.log.info("Setting up tunnel for MPLS/GRE (%s)",
                          self.config.gre_tunnel)

            self.bridge.delete_port(self.config.gre_tunnel)

            gre_tunnel_options = dict(
                o.split('=') for o in self.config.gre_tunnel_options)
            gre_tunnel_attrs = [
                ('type', 'gre'),
                ('options', dict({'local_ip': self.get_local_address(),
                                  'remote_ip': 'flow'},
                                 **gre_tunnel_options))
            ]

            self.gre_tunnel_port_number = (
                self.bridge.add_port(self.config.gre_tunnel, *gre_tunnel_attrs)
            )
            self.mpls_if_mac_address = None
        else:
            # Find ethX MPLS interface MAC address
            try:
                self.mpls_if_mac_address = net_utils.get_device_mac(
                    self._run_command,
                    self.mpls_interface)
            except Exception:
                # Interface without MAC address (patch port case), use MPLS
                # bridge MAC address instead
                self.mpls_if_mac_address = net_utils.get_device_mac(
                    self._run_command,
                    self.bridge)

        self.bridge.add_flow(table=self.input_table,
                             priority=DEFAULT_RULE_PRIORITY,
                             in_port=self.mpls_in_port(),
                             proto='mpls',
                             actions="resubmit(,%d)" % self.encap_in_table)

        if self.vxlan_encap:
            self.log.info("Enabling VXLAN encapsulation")
            self.bridge.delete_port(VXLAN_TUNNEL)

            vxlan_tunnel_attrs = [
                ('type', 'vxlan'),
                ('options', {'local_ip': self.get_local_address(),
                             'remote_ip': 'flow',
                             'key': 'flow'})
            ]
            self.vxlan_tunnel_port_number = (
                self.bridge.add_port(VXLAN_TUNNEL, *vxlan_tunnel_attrs)
            )

            self.bridge.add_flow(table=self.input_table,
                                 priority=DEFAULT_RULE_PRIORITY,
                                 in_port=self.vxlan_tunnel_port_number,
                                 actions="resubmit(,%d)" % self.encap_in_table)

    def validate_directions(self, direction):
        # this driver supports all combinations of directions
        pass

    def find_ovs_port(self, dev_name):
        """Find OVS port number from port name"""

        ofport = self.bridge.get_port_ofport(dev_name)

        if ofport is None:
            raise Exception("OVS port not found for device %s" % dev_name)

        return ofport

    # Looking glass code ####

    def get_lg_map(self):
        return {
            "flows": (lg.SUBTREE, self.get_lg_ovs_flows),
            "ports": (lg.SUBTREE, self.get_lg_ovs_ports)
        }

    def get_lg_local_info(self, path_prefix):
        d = {
            "ovs_bridge": self.bridge.br_name,
            "mpls_interface": self.mpls_interface,
            "gre": {'enabled': self.use_gre},
            "vxlan": {'enabled': self.vxlan_encap},
            "ovs_version": self.ovs_release,
            "tables": self.all_tables
        }

        if self.use_gre:
            d["gre"].update({'gre_tunnel_port': self.config.gre_tunnel})
        if self.vxlan_encap:
            d["gre"].update({'vxlan_tunnel_port': VXLAN_TUNNEL})
        return d

    def get_lg_ovs_flows(self, path_prefix, cookie_spec=None):
        output = {}
        for (table_name, table_id) in self.all_tables.items():
            output.update({
                "%s (%d)" % (table_name, table_id): self._run_command(
                    "ovs-ofctl -O %s dump-flows --names %s '%s' %s" % (
                        ovs_const.OPENFLOW15,
                        self.bridge.br_name,
                        dataplane_utils.join_s("table=%d" % table_id,
                                               cookie_spec),
                        OVS_DUMP_FLOW_FILTER),
                    run_as_root=True, shell=True
                    )[0]
            })
        return output

    def get_lg_ovs_ports(self, path_prefix):
        (output, _) = self._run_command(
            "ovs-ofctl -O %s show %s |grep addr" % (ovs_const.OPENFLOW15,
                                                    self.bridge.br_name),
            run_as_root=True,
            acceptable_return_codes=[0, 1],
            shell=True)
        # FIXME: does it properly show the GRE tunnel interface ?
        return output
