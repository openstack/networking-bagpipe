# Copyright (c) 2015 Orange.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
L2 Agent extension to support bagpipe networking-bgpvpn driver RPCs in the
OpenVSwitch agent
"""

import copy
import itertools
import netaddr

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from networking_bagpipe._i18n import _
from networking_bagpipe.agent import agent_base_info
from networking_bagpipe.agent import bagpipe_bgp_agent
from networking_bagpipe.agent.bgpvpn import constants as bgpvpn_const
from networking_bagpipe.agent.bgpvpn import rpc_agent as bgpvpn_rpc
from networking_bagpipe.agent.bgpvpn.rpc_client import topics_BAGPIPE_BGPVPN
from networking_bagpipe.agent.common import constants as b_const
from networking_bagpipe.driver import type_route_target

from neutron.agent.common import ovs_lib
from neutron.common import topics
from neutron.conf.agent import common as config
from neutron.conf.plugins.ml2.drivers import ovs_conf
from neutron_lib.agent import l2_extension
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const

from neutron.plugins.ml2.drivers.linuxbridge.agent.common \
    import constants as lnxbridge_agt_constants
from neutron.plugins.ml2.drivers.linuxbridge.agent.linuxbridge_neutron_agent \
    import LinuxBridgeManager
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants as ovs_agt_constants
from neutron.plugins.ml2.drivers.openvswitch.agent.ovs_neutron_agent \
    import OVSNeutronAgent
from neutron.plugins.ml2.drivers.openvswitch.agent import vlanmanager

LOG = logging.getLogger(__name__)

bagpipe_bgpvpn_opts = [
    cfg.StrOpt('mpls_bridge', default='br-mpls',
               help=_("OVS MPLS bridge to use")),
]

# these options are for internal use only (fullstack tests), and hence
# better kept in a separate table not looked at by oslo gen confi hooks
internal_opts = [
    cfg.StrOpt('tun_to_mpls_peer_patch_port', default='patch-to-mpls',
               help=_("OVS Peer patch port in tunnel bridge to MPLS bridge ")),
    cfg.StrOpt('mpls_to_tun_peer_patch_port', default='patch-from-tun',
               help=_("OVS Peer patch port in MPLS bridge to tunnel bridge ")),
    cfg.StrOpt('mpls_to_int_peer_patch_port', default='patch-mpls-to-int',
               help=_("OVS Peer patch port in MPLS bridge to int bridge ")),
    cfg.StrOpt('int_to_mpls_peer_patch_port', default='patch-int-from-mpls',
               help=_("OVS Peer patch port in int bridge to MPLS bridge ")),
]

cfg.CONF.register_opts(bagpipe_bgpvpn_opts, "BAGPIPE")
cfg.CONF.register_opts(internal_opts, "BAGPIPE")
ovs_conf.register_ovs_agent_opts()
config.register_agent_state_opts_helper(cfg.CONF)


NO_NEED_FOR_VNI = -1


class DummyOVSAgent(OVSNeutronAgent):
    # this class is used only to 'borrow' setup_entry_for_arp_reply
    # from OVSNeutronAgent
    arp_responder_enabled = True

    def __init__(self):
        pass


def has_attachement(bgpvpn_info, vpn_type):
    return (vpn_type in bgpvpn_info and (
            bgpvpn_info[vpn_type].get(b_const.RT_IMPORT) or
            bgpvpn_info[vpn_type].get(b_const.RT_EXPORT))
            )


class BagpipeBgpvpnAgentExtension(l2_extension.L2AgentExtension,
                                  agent_base_info.BaseInfoManager,
                                  bgpvpn_rpc.BGPVPNAgentRpcCallBackMixin):

    def __init__(self):
        super(BagpipeBgpvpnAgentExtension, self).__init__()
        self.ports = set()
        self.network_segmentation_ids = dict()

    @log_helpers.log_method_call
    def consume_api(self, agent_api):
        self.agent_api = agent_api

    @log_helpers.log_method_call
    def initialize(self, connection, driver_type):
        self.driver_type = driver_type
        if self._is_ovs_extension():
            self.int_br = self.agent_api.request_int_br()
            self.tun_br = self.agent_api.request_tun_br()

            if self.tun_br is None:
                raise Exception("tunneling is not enabled in OVS agent, "
                                "however bagpipe_bgpvpn extensions needs it")

            self.bagpipe_bgp_agent = (
                bagpipe_bgp_agent.BaGPipeBGPAgent.get_instance(
                    n_const.AGENT_TYPE_OVS)
            )

            self._setup_mpls_br()

            self.vlan_manager = vlanmanager.LocalVlanManager()

            registry.subscribe(self.ovs_restarted,
                               resources.AGENT,
                               events.OVS_RESTARTED)

        elif self._is_linuxbridge_extension():
            self.bagpipe_bgp_agent = (
                bagpipe_bgp_agent.BaGPipeBGPAgent.get_instance(
                    n_const.AGENT_TYPE_LINUXBRIDGE)
            )
        else:
            raise Exception("driver type not supported: %s", driver_type)

        self._setup_rpc(connection)

        self.bagpipe_bgp_agent.register_build_callback(
            bgpvpn_const.BGPVPN_SERVICE,
            self.build_bgpvpn_attach_info)

        self.bagpipe_bgp_agent.register_port_list(bgpvpn_const.BGPVPN_SERVICE,
                                                  self.ports)

    def _is_ovs_extension(self):
        return self.driver_type == ovs_agt_constants.EXTENSION_DRIVER_TYPE

    def _is_linuxbridge_extension(self):
        return (
            self.driver_type == lnxbridge_agt_constants.EXTENSION_DRIVER_TYPE)

    def _setup_rpc(self, connection):
        connection.create_consumer(topics.get_topic_name(topics.AGENT,
                                                         topics_BAGPIPE_BGPVPN,
                                                         topics.UPDATE),
                                   [self], fanout=True)
        connection.create_consumer(topics.get_topic_name(topics.AGENT,
                                                         topics_BAGPIPE_BGPVPN,
                                                         topics.UPDATE,
                                                         cfg.CONF.host),
                                   [self], fanout=False)

    def _setup_mpls_br(self):
        '''Setup the MPLS bridge for bagpipe-bgp.

        Creates MPLS bridge, and links it to the integration and tunnel
        bridges using patch ports.

        :param mpls_br: the name of the MPLS bridge.
        '''
        mpls_br = cfg.CONF.BAGPIPE.mpls_bridge
        self.mpls_br = ovs_lib.OVSBridge(mpls_br)

        if not self.mpls_br.bridge_exists(mpls_br):
            LOG.error("Unable to enable MPLS on this agent, MPLS bridge "
                      "%(mpls_br)s doesn't exist. Agent terminated!",
                      {"mpls_br": mpls_br})
            exit(1)

        # patch ports for traffic from tun bridge to mpls bridge
        self.patch_tun_to_mpls_ofport = self.tun_br.add_patch_port(
            cfg.CONF.BAGPIPE.tun_to_mpls_peer_patch_port,
            cfg.CONF.BAGPIPE.mpls_to_tun_peer_patch_port)
        self.patch_mpls_to_tun_ofport = self.mpls_br.add_patch_port(
            cfg.CONF.BAGPIPE.mpls_to_tun_peer_patch_port,
            cfg.CONF.BAGPIPE.tun_to_mpls_peer_patch_port)

        # patch ports for traffic from mpls bridge to int bridge
        self.patch_mpls_to_int_ofport = self.mpls_br.add_patch_port(
            cfg.CONF.BAGPIPE.mpls_to_int_peer_patch_port,
            cfg.CONF.BAGPIPE.int_to_mpls_peer_patch_port)
        self.patch_int_to_mpls_ofport = self.int_br.add_patch_port(
            cfg.CONF.BAGPIPE.int_to_mpls_peer_patch_port,
            cfg.CONF.BAGPIPE.mpls_to_int_peer_patch_port)

        if (int(self.patch_tun_to_mpls_ofport) < 0 or
                int(self.patch_mpls_to_tun_ofport) < 0 or
                int(self.patch_int_to_mpls_ofport) < 0 or
                int(self.patch_mpls_to_int_ofport) < 0):
            LOG.error("Failed to create OVS patch port. Cannot have "
                      "MPLS enabled on this agent, since this version "
                      "of OVS does not support patch ports. "
                      "Agent terminated!")
            exit(1)

        patch_int_ofport = self.tun_br.get_port_ofport(
            cfg.CONF.OVS.tun_peer_patch_port)

        # In br-tun, redirect all traffic from VMs toward a BGPVPN
        # default gateway MAC address to the MPLS bridge.
        #
        # (priority >0 is needed or we hit the rule redirecting unicast to
        # the UCAST_TO_TUN table)
        self.tun_br.add_flow(
            table=ovs_agt_constants.PATCH_LV_TO_TUN,
            priority=1,
            in_port=patch_int_ofport,
            dl_dst=bgpvpn_const.DEFAULT_GATEWAY_MAC,
            actions="output:%s" % self.patch_tun_to_mpls_ofport
        )

        # Redirect traffic from the MPLS bridge to br-int
        self.tun_br.add_flow(in_port=self.patch_tun_to_mpls_ofport,
                             actions="output:%s" % patch_int_ofport)

    def ovs_restarted(self, resources, event, trigger):
        self._setup_mpls_br()
        self.ovs_restarted_bgpvpn()
        # TODO(tmorin): need to handle restart on bagpipe-bgp side, in the
        # meantime after an OVS restart, restarting bagpipe-bgp is required

    @log_helpers.log_method_call
    def _enable_gw_redirect(self, vlan, gateway_ip):
        # Add ARP responder entry for default gateway in br-tun

        # We may compete with the ARP responder entry for the real MAC
        # if the router is on a network node and we are a compute node,
        # so we must add our rule with a higher priority. Using a different
        # priority also means that arp_responder will not remove our ARP
        # responding flows and we won't remove theirs.

        # NOTE(tmorin): consider adding priority to install_arp_responder
        # and then use it here

        # (mostly copy-pasted ovs_ofctl....install_arp_responder)
        actions = ovs_agt_constants.ARP_RESPONDER_ACTIONS % {
            'mac': netaddr.EUI(bgpvpn_const.DEFAULT_GATEWAY_MAC,
                               dialect=netaddr.mac_unix),
            'ip': netaddr.IPAddress(gateway_ip),
        }
        self.tun_br.add_flow(table=ovs_agt_constants.ARP_RESPONDER,
                             priority=2,  # see above
                             dl_vlan=vlan,
                             proto='arp',
                             arp_op=0x01,
                             arp_tpa='%s' % gateway_ip,
                             actions=actions)

    @log_helpers.log_method_call
    def _disable_gw_redirect(self, vlan, gateway_ip):
        # Remove ARP responder entry for default gateway in br-tun
        self.tun_br.delete_flows(
            strict=True,
            table=ovs_agt_constants.ARP_RESPONDER,
            priority=2,
            dl_vlan=vlan,
            proto='arp',
            arp_op=0x01,
            arp_tpa='%s' % gateway_ip)

    @log_helpers.log_method_call
    def _hide_real_gw_arp(self, vlan, gateway_info):
        # Kill ARP replies for the gateway IP coming on br-int from the real
        # router, if any.
        #
        # NOTE(tmorin): we assume that the router MAC exists only in this vlan.
        # Doing filtering based on the local vlan would be better, but
        # we can't do this in br-int because this bridge does tagging based
        # on ovs-vsctl port tags.
        self.int_br.add_flow(table=ovs_agt_constants.LOCAL_SWITCHING,
                             priority=2,
                             proto='arp',
                             arp_op=0x2,
                             dl_src=gateway_info.mac,
                             arp_sha=gateway_info.mac,
                             arp_spa=gateway_info.ip,
                             actions="drop")

        # ARP requests from the real gateway need to
        # have their IP address changed to hide the gateway
        # address or the VMs will use it to update their
        # ARP cache implicitly. Below we overwrite it with 0.0.0.0.
        self.int_br.add_flow(table=ovs_agt_constants.LOCAL_SWITCHING,
                             priority=2,
                             proto='arp',
                             arp_op=0x01,
                             dl_src=gateway_info.mac,
                             arp_spa=gateway_info.ip,
                             arp_sha=gateway_info.mac,
                             actions="load:0x0->NXM_OF_ARP_SPA[],NORMAL")

    @log_helpers.log_method_call
    def _unhide_real_gw_arp(self, vlan, gateway_mac):
        LOG.debug("unblocking ARP from real gateway for vlan %d (%s)",
                  vlan, gateway_mac)
        self.int_br.delete_flows(table=ovs_agt_constants.LOCAL_SWITCHING,
                                 proto='arp',
                                 dl_src=gateway_mac,
                                 arp_sha=gateway_mac)

    @log_helpers.log_method_call
    def _check_arp_voodoo_plug(self, net_info, gateway_info):

        if not self._is_ovs_extension():
            return

        # See if we need to update gateway redirection and gateway ARP
        # voodoo

        vlan = self.vlan_manager.get(net_info.id).vlan

        # NOTE(tmorin): can be improved, only needed on first plug...
        self._enable_gw_redirect(vlan, gateway_info.ip)

        # update real gateway ARP blocking...
        # remove old ARP blocking ?
        if net_info.gateway_info.mac is not None:
            self._unhide_real_gw_arp(vlan, net_info.gateway_info.mac)
        # add new ARP blocking ?
        if gateway_info.mac:
            self._hide_real_gw_arp(vlan, gateway_info)

    @log_helpers.log_method_call
    def _check_arp_voodoo_unplug(self, net_id):

        if not self._is_ovs_extension():
            return

        net_info = self.networks_info.get(net_id)

        if not net_info:
            return

        # if last port for this network, then cleanup gateway redirection
        # NOTE(tmorin): shouldn't we check for last *ipvpn* attachment?
        if len(net_info.ports) == 1:
            LOG.debug("last unplug, undoing voodoo ARP")
            # NOTE(tmorin): vlan lookup might break if port is already
            # unplugged from bridge ?
            vlan = self.vlan_manager.get(net_id).vlan
            self._disable_gw_redirect(vlan, net_info.gateway_info.ip)
            if net_info.gateway_info.mac is not None:
                self._unhide_real_gw_arp(vlan, net_info.gateway_info.mac)

    def _is_last_bgpvpn_info(self, net_info, service_info):
        if not net_info.service_infos:
            return

        orig_info = copy.deepcopy(net_info.service_infos)

        for vpn_type in bgpvpn_const.BGPVPN_TYPES:
            if vpn_type in service_info:
                if vpn_type in orig_info:
                    for rt_type in b_const.RT_TYPES:
                        if rt_type in service_info[vpn_type]:
                            orig_info[vpn_type][rt_type] = list(
                                set(orig_info[vpn_type][rt_type]) -
                                set(service_info[vpn_type][rt_type]))

                    if (not orig_info[vpn_type][b_const.RT_IMPORT] and
                            not orig_info[vpn_type][b_const.RT_EXPORT]):
                        del(orig_info[vpn_type])

        return (not orig_info, orig_info)

    @log_helpers.log_method_call
    def build_bgpvpn_attach_info(self, port_id):
        if port_id not in self.ports_info:
            LOG.warning("%s service has no PortInfo for port %s",
                        bgpvpn_const.BGPVPN_SERVICE, port_id)
            return {}

        port_info = self.ports_info[port_id]

        attach_info = {
            'network_id': port_info.network.id,
            'ip_address': port_info.ip_address,
            'mac_address': port_info.mac_address,
            'gateway_ip': port_info.network.gateway_info.ip,
            'local_port': port_info.local_port
        }

        service_infos = [port_info.service_infos,
                         port_info.network.service_infos]

        for bgpvpn_type, service_info in list(
                itertools.product(bgpvpn_const.BGPVPN_TYPES,
                                  service_infos)):
            if bgpvpn_type in service_info:
                bagpipe_vpn_type = bgpvpn_const.BGPVPN_TYPES_MAP[bgpvpn_type]
                if bagpipe_vpn_type not in attach_info:
                    attach_info[bagpipe_vpn_type] = dict()

                for rt_type in b_const.RT_TYPES:
                    if rt_type not in attach_info[bagpipe_vpn_type]:
                        attach_info[bagpipe_vpn_type][rt_type] = list()

                    attach_info[bagpipe_vpn_type][rt_type] += (
                        service_info[bgpvpn_type][rt_type]
                    )

        if self._is_ovs_extension():
            # Add OVS VLAN information
            vlan = self.vlan_manager.get(port_info.network.id).vlan

            # no OVS driver yet for EVPN
            if b_const.EVPN in attach_info:
                LOG.warning("BGPVPN type L2 (EVPN) is not supported with "
                            "OVS yet")

            if has_attachement(attach_info, b_const.IPVPN):
                attach_info[b_const.IPVPN].update({
                    'local_port': {
                        'ovs': {
                            'plugged': True,
                            'port_number': self.patch_mpls_to_tun_ofport,
                            'vlan': vlan
                        }
                    }
                })

                # Add fallback information if needed as well
                if port_info.network.gateway_info.mac:
                    attach_info[b_const.IPVPN].update({
                        'fallback': {
                            'dst_mac': port_info.network.gateway_info.mac,
                            'src_mac': bgpvpn_const.FALLBACK_SRC_MAC,
                            'ovs_port_number': self.patch_mpls_to_int_ofport
                        }
                    })
        else:  # linuxbridge
            if has_attachement(attach_info, b_const.EVPN):
                attach_info[b_const.EVPN]['linuxbr'] = (
                    LinuxBridgeManager.get_bridge_name(port_info.network.id)
                )
            if has_attachement(attach_info, b_const.IPVPN):
                # the interface we need to pass to bagpipe is the
                # bridge
                attach_info[b_const.IPVPN]['local_port'] = {
                    'linuxif':
                        LinuxBridgeManager.get_bridge_name(
                            port_info.network.id)
                }
                # NOTE(tmorin): fallback support still missing

        if has_attachement(attach_info, b_const.EVPN):
            # if the network is a VXLAN network, then reuse same VNI
            # in bagpipe-bgp
            vni = self.network_segmentation_ids.get(port_info.network.id)
            if vni is None:
                LOG.debug("no vni found for %s, returning nothing",
                          port_info.network.id)
                # NOTE(tmorin): if no VNI was found, we do nothing for E-VPN
                # bagpipe_bgpvpn extension handle_port will eventually
                # be called, then VNI will be known, and handle_port
                # will call port_plug again
                # (this will be made much more readable once
                # we move to a design where a port up event is all handled
                # by handle_port and an RPC pull)
                del attach_info[b_const.EVPN]
            elif vni == NO_NEED_FOR_VNI:
                LOG.debug("no VNI reuse, because 'route_target' type driver "
                          "in use")
            else:
                LOG.debug("vni %s found for %s", vni, port_info.network.id)
                attach_info[b_const.EVPN]['vni'] = vni

        if not (has_attachement(attach_info, b_const.EVPN) or
                has_attachement(attach_info, b_const.IPVPN)):
            return {}

        return attach_info

    def _build_bgpvpn_detach_info(self, port_id, service_infos):
        port_info = self.ports_info[port_id]

        detach_infos = {}
        for bgpvpn_type in service_infos.keys():
            if bgpvpn_type in bgpvpn_const.BGPVPN_TYPES:
                service_type = bgpvpn_const.BGPVPN_TYPES_MAP[bgpvpn_type]
                detach_infos.update({
                    service_type: {
                        'network_id': port_info.network.id,
                        'ip_address': port_info.ip_address,
                        'mac_address': port_info.mac_address,
                        'local_port': port_info.local_port
                    }
                })

                if self._is_ovs_extension():
                    # no OVS driver yet for EVPN
                    if b_const.EVPN in detach_infos:
                        LOG.warning("BGPVPN type L2 (EVPN) is not supported "
                                    "with OVS yet")
                        del detach_infos[b_const.EVPN]

        return detach_infos

    def ovs_restarted_bgpvpn(self):
        for net_info in self.networks_info.values():
            if net_info.ports and net_info.gateway_info != b_const.NO_GW_INFO:
                if has_attachement(net_info.service_infos,
                                   bgpvpn_const.BGPVPN_L3):
                    self._check_arp_voodoo_plug(net_info,
                                                net_info.gateway_info)

    @log_helpers.log_method_call
    def create_bgpvpn(self, context, bgpvpn):
        self.update_bgpvpn(context, bgpvpn)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-bgp-agent')
    def update_bgpvpn(self, context, bgpvpn):
        # we don't use 'id' anymore, remove it
        bgpvpn.pop('id', None)

        net_id = bgpvpn.pop('network_id')

        net_info = self.networks_info.get(net_id)

        if not net_info:
            LOG.debug("update_bgpvpn(%s), but no BGPVPN info for this "
                      "network, not doing anything", bgpvpn)
            return

        new_gw_info = b_const.GatewayInfo(
            bgpvpn.pop('gateway_mac', None),
            net_info.gateway_info.ip
        )

        if has_attachement(bgpvpn, bgpvpn_const.BGPVPN_L3):
            self._check_arp_voodoo_plug(net_info, new_gw_info)

        net_info.set_gateway_info(new_gw_info)

        net_info.add_service_info(bgpvpn)

        for port_info in net_info.ports:
            self.bagpipe_bgp_agent.do_port_plug(port_info.id)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-bgp-agent')
    def delete_bgpvpn(self, context, bgpvpn):
        # we don't use 'id' anymore, remove it
        bgpvpn.pop('id', None)

        net_id = bgpvpn.pop('network_id')

        net_info = self.networks_info.get(net_id)

        if not net_info:
            LOG.debug("delete_bgpvpn(%s), but no BGPVPN info for this "
                      "network, not doing anything", bgpvpn)
            return

        # Check if remaining BGPVPN informations, otherwise unplug
        # port from bagpipe-bgp
        last_bgpvpn, updated_info = (
            self._is_last_bgpvpn_info(net_info, bgpvpn)
        )

        if (last_bgpvpn or
                not has_attachement(updated_info, bgpvpn_const.BGPVPN_L3)):
            self._check_arp_voodoo_unplug(net_id)

        if last_bgpvpn:
            service_info = copy.copy(net_info.service_infos)
            net_info.service_infos = {}

            for port_info in net_info.ports:
                detach_info = (
                    self._build_bgpvpn_detach_info(port_info.id,
                                                   service_info)
                )
                self.bagpipe_bgp_agent.do_port_plug_refresh(port_info.id,
                                                            detach_info)
        else:
            net_info.service_infos = updated_info

            for port_info in net_info.ports:
                self.bagpipe_bgp_agent.do_port_plug(port_info.id)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-bgp-agent')
    def bgpvpn_port_attach(self, context, port_bgpvpn_info):
        port_id = port_bgpvpn_info.pop('id')
        net_id = port_bgpvpn_info.pop('network_id')

        net_info, port_info = (
            self._get_network_port_infos(net_id, port_id)
        )

        # Set IP and MAC addresses in PortInfo
        ip_address = port_bgpvpn_info.pop('ip_address')
        mac_address = port_bgpvpn_info.pop('mac_address')
        port_info.set_ip_mac_infos(ip_address, mac_address)

        # Set gateway IP and MAC (if defined) addresses in NetworkInfo
        gateway_info = b_const.GatewayInfo(port_bgpvpn_info.pop('gateway_mac',
                                                                None),
                                           port_bgpvpn_info.pop('gateway_ip'))

        if has_attachement(port_bgpvpn_info, bgpvpn_const.BGPVPN_L3):
            self._check_arp_voodoo_plug(net_info, gateway_info)

        net_info.set_gateway_info(gateway_info)

        if self._is_ovs_extension():
            vlan = self.vlan_manager.get(net_id).vlan
            port_info.set_local_port('%s:%s' % (bgpvpn_const.LINUXIF_PREFIX,
                                                vlan))
        else:
            port_info.set_local_port(
                LinuxBridgeManager.get_tap_device_name(port_id)
            )

        self.ports.add(port_id)

        if port_bgpvpn_info:
            net_info.add_service_info(port_bgpvpn_info)
            self.bagpipe_bgp_agent.do_port_plug(port_id)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-bgp-agent')
    def bgpvpn_port_detach(self, context, port_bgpvpn_info):
        port_id = port_bgpvpn_info['id']
        net_id = port_bgpvpn_info['network_id']

        if port_id not in self.ports_info:
            LOG.warning("%s service inconsistent for port %s",
                        bgpvpn_const.BGPVPN_SERVICE, port_id)
            return

        LOG.debug("%s service detaching port %s from bagpipe-bgp",
                  bgpvpn_const.BGPVPN_SERVICE, port_id)
        try:
            network_info = self.networks_info[net_id]

            if has_attachement(network_info.service_infos,
                               bgpvpn_const.BGPVPN_L3):
                self._check_arp_voodoo_unplug(net_id)

            detach_info = self._build_bgpvpn_detach_info(
                port_id,
                network_info.service_infos
            )

            self._remove_network_port_infos(net_id, port_id)
            self.ports.remove(port_id)

            self.bagpipe_bgp_agent.do_port_plug_refresh(port_id,
                                                        detach_info)

        except bagpipe_bgp_agent.BaGPipeBGPException as e:
            LOG.error("%s service can't detach port from bagpipe-bgp %s",
                      bgpvpn_const.BGPVPN_SERVICE, str(e))

    @log_helpers.log_method_call
    def handle_port(self, context, data):
        # NOTE(tmorin): for linuxbridge, the vni is only known by handle_port
        # (no LocalVLANManager), so we need to store it so that it is available
        # when a port plug RPC is received.
        if self._is_linuxbridge_extension():
            if data['network_type'] == n_const.TYPE_VXLAN:
                self.network_segmentation_ids[data['network_id']] = (
                    data['segmentation_id'])

            # for type driver 'ROUTE_TARGET' we need to track the fact
            # that we don't need a VNI (using -1 special value)
            if data['network_type'] == type_route_target.TYPE_ROUTE_TARGET:
                    self.network_segmentation_ids[data['network_id']] = (
                        NO_NEED_FOR_VNI)

            # if handle_port is called after the port plug RPC, we
            # need to call do_port_plug again, this time the VNI
            # will be known
            self.bagpipe_bgp_agent.do_port_plug(data['port_id'])

    @log_helpers.log_method_call
    def delete_port(self, context, data):
        pass
