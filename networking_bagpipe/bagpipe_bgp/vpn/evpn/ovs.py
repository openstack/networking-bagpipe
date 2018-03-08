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

from oslo_config import cfg
from oslo_log import log as logging

from networking_bagpipe.bagpipe_bgp.common import config
from networking_bagpipe.bagpipe_bgp.common import dataplane_utils
from networking_bagpipe.bagpipe_bgp.common import log_decorator
from networking_bagpipe.bagpipe_bgp import constants as consts
from networking_bagpipe.bagpipe_bgp.engine import exa
from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers as dp_drivers
from networking_bagpipe.bagpipe_bgp.vpn import evpn

from neutron.plugins.ml2.drivers.openvswitch.agent.common import \
    constants as ovs_const
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import \
    br_tun
from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_neutron_agent

from neutron_lib import constants as n_consts

LOG = logging.getLogger(__name__)

FLOOD = "flood"
FLOW_PRIORITY = 5


class OVSEVIDataplane(evpn.VPNInstanceDataplane):

    def __init__(self, *args, **kwargs):
        super(OVSEVIDataplane, self).__init__(*args, **kwargs)

        self.bridge = self.driver.bridge
        # OpenFlow 1.3 is needed for mod_vlan_vid
        self.bridge.use_at_least_protocol(ovs_const.OPENFLOW13)

        self.tunnel_mgr = dataplane_utils.SharedObjectLifecycleManagerProxy(
            self.driver.tunnel_mgr,
            self.instance_id
        )
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
            port, _ = self.tunnel_mgr.get_object(remote_pe, (vni, mac))
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
            self.tunnel_mgr.free_object(remote_pe, (vni, mac))

        # cleanup ARP responder
        if ip:
            self.bridge.delete_arp_responder(self.vlan, str(ip))

    @log_decorator.log_info
    def add_dataplane_for_bum_endpoint(self, remote_pe, vni, nlri, encaps):

        if remote_pe == self.local_ip:
            port = "local"
        else:
            port, _ = self.tunnel_mgr.get_object(remote_pe, (vni, FLOOD))
        self.flooding_ports.add((port, vni))

        self._update_flooding_buckets()

    @log_decorator.log_info
    def remove_dataplane_for_bum_endpoint(self, remote_pe, vni, nlri):

        if remote_pe == self.local_ip:
            port = "local"
        else:
            port = self.tunnel_mgr.find_object(remote_pe)

        if port:
            self.flooding_ports.remove((port, vni))

            self._update_flooding_buckets()

            if remote_pe != self.local_ip:
                self.tunnel_mgr.free_object(remote_pe, (vni, FLOOD))

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


class TunnelManager(dataplane_utils.ObjectLifecycleManager):

    def __init__(self, bridge, local_ip):
        super(TunnelManager, self).__init__()

        self.bridge = bridge
        self.local_ip = local_ip

    @log_decorator.log_info
    def create_object(self, remote_ip, *args, **kwargs):
        port_name = ovs_neutron_agent.OVSNeutronAgent.get_tunnel_name(
            n_consts.TYPE_VXLAN, self.local_ip, remote_ip)
        tunnel = self.bridge.add_tunnel_port(port_name,
                                             remote_ip,
                                             self.local_ip,
                                             n_consts.TYPE_VXLAN)

        self.bridge.setup_tunnel_port(n_consts.TYPE_VXLAN, tunnel)
        LOG.debug("tunnel for %s: %s (%s)", remote_ip, port_name, tunnel)

        return tunnel

    @log_decorator.log_info
    def delete_object(self, tunnel):
        self.bridge.delete_port(tunnel)


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

        config.set_default_root_helper()

        self.bridge = dataplane_utils.OVSBridgeWithGroups(
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
