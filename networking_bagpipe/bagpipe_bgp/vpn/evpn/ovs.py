# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

# Copyright 2018 Orange
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

import collections

from oslo_config import cfg
from oslo_log import log as logging

from networking_bagpipe.bagpipe_bgp.common import log_decorator
from networking_bagpipe.bagpipe_bgp import constants as consts
from networking_bagpipe.bagpipe_bgp.engine import exa
from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers as dp_drivers
from networking_bagpipe.bagpipe_bgp.vpn import evpn

from neutron.agent.common import ovs_lib
from neutron.plugins.ml2.drivers.openvswitch.agent.common import \
    constants as ovs_const
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import \
    br_tun
from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_neutron_agent

from neutron_lib import constants as n_consts
from neutron_lib import exceptions

LOG = logging.getLogger(__name__)

FLOOD = "flood"
FLOW_PRIORITY = 5


# largely copied from networking_sfc.services.sfc.common.ovs_ext_lib
class OVSBridgeWithGroups(object):

    def __init__(self, ovs_bridge):
        self.bridge = ovs_bridge

        # OpenFlow 1.1 is needed to manipulate groups
        self.bridge.use_at_least_protocol(ovs_const.OPENFLOW11)

    # proxy most methods to self.bridge
    def __getattr__(self, name):
        return getattr(self.bridge, name)

    def do_action_groups(self, action, kwargs_list):
        group_strs = [_build_group_expr_str(kw, action) for kw in kwargs_list]
        if action == 'add' or action == 'del':
            cmd = '%s-groups' % action
        elif action == 'mod':
            cmd = '%s-group' % action
        else:
            msg = _("Action is illegal")
            raise exceptions.InvalidInput(error_message=msg)
        self.run_ofctl(cmd, ['--may-create', '-'], '\n'.join(group_strs))

    @log_decorator.log_info
    def add_group(self, **kwargs):
        self.do_action_groups('add', [kwargs])

    @log_decorator.log_info
    def mod_group(self, **kwargs):
        self.do_action_groups('mod', [kwargs])

    @log_decorator.log_info
    def delete_group(self, **kwargs):
        self.do_action_groups('del', [kwargs])

    def dump_group_for_id(self, group_id):
        retval = None
        group_str = "%d" % group_id
        group = self.run_ofctl("dump-groups", [group_str])
        if group:
            retval = '\n'.join(item for item in group.splitlines()
                               if ovs_lib.is_a_flow_line(item))
        return retval

    def get_bridge_ports(self):
        port_name_list = self.bridge.get_port_name_list()
        of_portno_list = list()
        for port_name in port_name_list:
            of_portno_list.append(self.bridge.get_port_ofport(port_name))
        return of_portno_list


def _build_group_expr_str(group_dict, cmd):
    group_expr_arr = []
    buckets = None
    group_id = None

    if cmd != 'del':
        if "group_id" not in group_dict:
            msg = _("Must specify one group Id on group addition"
                    " or modification")
            raise exceptions.InvalidInput(error_message=msg)
        group_id = "group_id=%s" % group_dict.pop('group_id')

        if "buckets" not in group_dict:
            msg = _("Must specify one or more buckets on group addition"
                    " or modification")
            raise exceptions.InvalidInput(error_message=msg)
        buckets = "%s" % group_dict.pop('buckets')

    if group_id:
        group_expr_arr.append(group_id)

    for key, value in group_dict.items():
        group_expr_arr.append("%s=%s" % (key, value))

    if buckets:
        group_expr_arr.append(buckets)

    return ','.join(group_expr_arr)


class OVSEVIDataplane(evpn.VPNInstanceDataplane):

    def __init__(self, *args, **kwargs):
        super(OVSEVIDataplane, self).__init__(*args, **kwargs)

        self.bridge = self.driver.bridge
        # OpenFlow 1.3 is needed for mod_vlan_vid
        self.bridge.use_at_least_protocol(ovs_const.OPENFLOW13)

        self.tunnel_mgr = self.driver.tunnel_mgr
        self.flooding_ports = set()
        self.vlan = None
        self.local_ip = self.driver.get_local_address()

    def cleanup(self):
        self.bridge.delete_flows(strict=True,
                                 table=ovs_const.FLOOD_TO_TUN,
                                 priority=FLOW_PRIORITY,
                                 dl_vlan=self.vlan)
        self.bridge.delete_group(group_id=self.vlan)

    @log_decorator.log_info
    def vif_plugged(self, mac_address, ip_address_prefix, localport, label,
                    direction):
        if 'vlan' not in localport:
            raise Exception("missing localport['vlan'] parameter")
        if self.vlan and localport['vlan'] != self.vlan:
            raise Exception("inconsistent vlan")
        else:
            self.vlan = localport['vlan']

        # map traffic to this EVI VNI to the right table, similarly as in
        # OVSTunnelBridge.provision_local_vlan
        self.bridge.add_flow(table=ovs_const.VXLAN_TUN_TO_LV,
                             priority=FLOW_PRIORITY,
                             tun_id=self.instance_label,
                             actions=("push_vlan:0x8100,mod_vlan_vid:%d,"
                                      "resubmit(,%s)" %
                                      (self.vlan, ovs_const.LEARN_FROM_TUN)))

    @log_decorator.log_info
    def vif_unplugged(self, mac_address, ip_address_prefix, localport, label,
                      direction, last_endpoint=True):
        self.log.debug("nothing to do on unplug")

    def _local_vni_actions(self, vni):
        # "load:0->NXM_OF_IN_PORT[]" allows the packets coming from br-int
        # via patch-port to go back to br-int via the same port
        return "load:0->NXM_OF_IN_PORT[],set_tunnel:%d,resubmit(,%s)" % (
            vni, ovs_const.VXLAN_TUN_TO_LV)

    def _tun_mgr_handle(self, vni, mac):
        return (self.instance_id, vni, mac)

    @log_decorator.log_info
    def setup_dataplane_for_remote_endpoint(self, prefix, remote_pe, vni, nlri,
                                            encaps):
        mac = prefix
        ip = nlri.ip

        # what is done here is similar as
        # OVSTunnelBridge.install_unicast_to_tun, but with local delivery to
        # table VXLAN_TUN_TO_LV for routes advertized locally
        if remote_pe == self.local_ip:
            actions = self._local_vni_actions(vni)
        else:
            port = self.tunnel_mgr.tunnel_for_remote_ip(
                remote_pe, self._tun_mgr_handle(vni, mac))
            actions = "set_tunnel:%d,output:%s" % (vni, port)
        self.bridge.add_flow(table=ovs_const.UCAST_TO_TUN,
                             priority=FLOW_PRIORITY,
                             dl_vlan=self.vlan,
                             dl_dst=mac,
                             actions="strip_vlan,%s" % actions)

        # add ARP responder
        if ip:
            self.bridge.install_arp_responder(self.vlan, str(ip), str(mac))

    @log_decorator.log
    def remove_dataplane_for_remote_endpoint(self, prefix, remote_pe, vni,
                                             nlri):
        mac = prefix
        ip = nlri.ip

        self.bridge.delete_unicast_to_tun(self.vlan, mac)

        if remote_pe != self.local_ip:
            self.tunnel_mgr.free_tunnel(remote_pe,
                                        self._tun_mgr_handle(vni, mac))

        # cleanup ARP responder
        if ip:
            self.bridge.delete_arp_responder(self.vlan, str(ip))

    @log_decorator.log_info
    def add_dataplane_for_bum_endpoint(self, remote_pe, vni, nlri, encaps):

        if remote_pe == self.local_ip:
            port = "local"
        else:
            port = self.tunnel_mgr.tunnel_for_remote_ip(
                remote_pe, self._tun_mgr_handle(vni, FLOOD))
        self.flooding_ports.add((port, vni))

        self._update_flooding_buckets()

    @log_decorator.log_info
    def remove_dataplane_for_bum_endpoint(self, remote_pe, vni, nlri):

        if remote_pe == self.local_ip:
            port = "local"
        else:
            port = self.tunnel_mgr.tunnel_for_remote_ip(remote_pe)

        self.flooding_ports.remove((port, vni))

        self._update_flooding_buckets()

        if remote_pe != self.local_ip:
            self.tunnel_mgr.free_tunnel(
                remote_pe, self._tun_mgr_handle(vni, FLOOD))

    def _update_flooding_buckets(self):
        buckets = []
        for port, vni in self.flooding_ports:
            if port == "local":
                buckets.append("bucket=strip_vlan,%s" %
                               self._local_vni_actions(vni))
            else:
                buckets.append("bucket=strip_vlan,set_tunnel:%d,output:%s" %
                               (vni, port))
        self.bridge.mod_group(group_id=self.vlan,
                              type='all',
                              buckets=','.join(buckets))
        self.bridge.add_flow(table=ovs_const.FLOOD_TO_TUN,
                             priority=FLOW_PRIORITY,
                             dl_vlan=self.vlan,
                             actions="group:%d" % self.vlan)
        self.log.debug("buckets: %s", buckets)

    def set_gateway_port(self, linuxif, gateway_ip):
        # nothing to do, because we make the assumption that the
        # IPVPN driver is 'ovs' as well, and setup in conjunction
        # with Neutron OVS BGPVPN extension which does the plugging
        # between L2 and L3
        pass

    def gateway_port_down(self, linuxif):
        pass

    # Looking glass ####

    def get_lg_local_info(self, path_prefix):
        return {
            "vlan": self.vlan,
            "flooding-ports": [{"port": str(port), "vni": vni}
                               for port, vni in self.flooding_ports]
        }


class TunnelManager(object):

    def __init__(self, bridge, local_ip):
        self.tunnels = dict()
        self.bridge = bridge
        self.local_ip = local_ip
        self.tunnel_used_for = collections.defaultdict(set)

    @log_decorator.log_info
    def tunnel_for_remote_ip(self, remote_ip, use=None):
        tunnel = self.tunnels.get(remote_ip)
        if tunnel:
            LOG.debug("existing tunnel for %s: %s", remote_ip, tunnel)
        else:
            if not use:
                raise Exception("non-existing tunnel for %s", remote_ip)

            port_name = ovs_neutron_agent.OVSNeutronAgent.get_tunnel_name(
                n_consts.TYPE_VXLAN, self.local_ip, remote_ip)
            tunnel = self.bridge.add_tunnel_port(port_name,
                                                 remote_ip,
                                                 self.local_ip,
                                                 n_consts.TYPE_VXLAN)

            self.bridge.setup_tunnel_port(n_consts.TYPE_VXLAN, tunnel)
            self.tunnels[remote_ip] = tunnel
            LOG.debug("tunnel for %s: %s (%s)", remote_ip, port_name, tunnel)

        if use:
            self.tunnel_used_for[remote_ip].add(use)

        return tunnel

    @log_decorator.log_info
    def free_tunnel(self, remote_ip, use):
        if remote_ip not in self.tunnel_used_for:
            LOG.debug("no tunnel to free for %s", remote_ip)
            return

        self.tunnel_used_for[remote_ip].discard(use)
        if not self.tunnel_used_for[remote_ip]:
            tunnel = self.tunnels[remote_ip]

            LOG.debug("%s was last user for %s, clearing port", use,
                      remote_ip)
            self.bridge.delete_port(tunnel)

            del self.tunnels[remote_ip]
            del self.tunnel_used_for[remote_ip]
        else:
            LOG.debug("remaining users for tunnel %s: %s", remote_ip,
                      self.tunnel_used_for[remote_ip])

    def infos(self):
        return self.tunnels


class OVSDataplaneDriver(dp_drivers.DataplaneDriver):

    dataplane_instance_class = OVSEVIDataplane
    type = consts.EVPN
    ecmp_support = False
    encaps = [exa.Encapsulation(exa.Encapsulation.Type.VXLAN)]

    driver_opts = [
        cfg.StrOpt("ovs_bridge", default="br-tun",
                   help=("Name of the OVS bridge to use, this has to be the "
                         "same as the tunneling bridge of the Neutron OVS "
                         "agent, usually br-tun")),
    ]

    def __init__(self, *args, **kwargs):
        super(OVSDataplaneDriver, self).__init__(*args, **kwargs)
        self.bridge = OVSBridgeWithGroups(
            br_tun.OVSTunnelBridge(self.config.ovs_bridge)
        )
        self.tunnel_mgr = TunnelManager(self.bridge,
                                        self.get_local_address())

    def needs_cleanup_assist(self):
        return True

    def reset_state(self):
        # cleanup is taken care of by OVS Neutron Agent
        pass

    # Looking glass ####

    def get_lg_local_info(self, path_prefix):
        return {
            "tunnels": self.tunnel_mgr.infos(),
        }
