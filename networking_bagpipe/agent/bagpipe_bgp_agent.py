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
import socket

import httplib2
import itertools
import json

from copy import deepcopy

from collections import defaultdict
from collections import namedtuple

import netaddr

from oslo_config import cfg

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from oslo_concurrency import lockutils

from oslo_service import loopingcall

from networking_bagpipe._i18n import _

from networking_bagpipe.rpc import agent as bagpipe_agent_rpc
from networking_bagpipe.rpc.client import topics_BAGPIPE

from networking_bagpipe.agent.bgpvpn import rpc_agent as bgpvpn_agent_rpc
from networking_bagpipe.agent.bgpvpn.rpc_client import topics_BAGPIPE_BGPVPN

from neutron.agent.common import ovs_lib
from neutron.common import topics
from neutron.conf.agent import common as config

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc

from neutron.conf.plugins.ml2.drivers import ovs_conf

from neutron.plugins.ml2.drivers.linuxbridge.agent.linuxbridge_neutron_agent \
    import LinuxBridgeManager
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants\
    as a_const
from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_neutron_agent
from neutron.plugins.ml2.drivers.openvswitch.agent import vlanmanager

LOG = logging.getLogger(__name__)


# Having this at line 231 is apparently not enough, so adding here as well:
# pylint: disable=not-callable


DEFAULT_GATEWAY_MAC = "00:00:5e:00:43:64"
FALLBACK_SRC_MAC = "00:00:5e:2a:10:00"

BAGPIPE_L2_SERVICE = 'bagpipe_l2'
BGPVPN_SERVICE = 'bgpvpn'
BAGPIPE_SERVICES = [BAGPIPE_L2_SERVICE, BGPVPN_SERVICE]

# bagpipe-bgp VPN types
EVPN = 'evpn'
IPVPN = 'ipvpn'
VPN_TYPES = [EVPN, IPVPN]

# BGPVPN service VPN types
BGPVPN_L2 = 'l2vpn'
BGPVPN_L3 = 'l3vpn'
BGPVPN_TYPES = [BGPVPN_L2, BGPVPN_L3]
# Map from BGPVPN service VPN types to bagpipe-bgp VPN types
BGPVPN_TYPES_MAP = {BGPVPN_L2: EVPN, BGPVPN_L3: IPVPN}

RT_IMPORT = 'import_rt'
RT_EXPORT = 'export_rt'
RT_TYPES = [RT_IMPORT, RT_EXPORT]

LINUXIF_PREFIX = "patch2tun"

bagpipe_bgp_opts = [
    cfg.IntOpt('ping_interval', default=10,
               help=_("The number of seconds the bagpipe-bgp client will "
                      "wait between polling for restart detection.")),
    cfg.StrOpt('bagpipe_bgp_ip', default='127.0.0.1',
               help=_("bagpipe-bgp REST service IP address.")),
    cfg.IntOpt('bagpipe_bgp_port', default=8082,
               help=_("bagpipe-bgp REST service IP port.")),
    cfg.StrOpt('mpls_bridge', default='br-mpls',
               help=_("OVS MPLS bridge to use")),
    cfg.StrOpt('tun_to_mpls_peer_patch_port', default='patch-to-mpls',
               help=_("OVS Peer patch port in tunnel bridge to MPLS bridge "
                      "(traffic to MPLS bridge)")),
    cfg.StrOpt('tun_from_mpls_peer_patch_port', default='patch-from-mpls',
               help=_("OVS Peer patch port in tunnel bridge to MPLS bridge "
                      "(traffic from MPLS bridge)")),
    cfg.StrOpt('mpls_to_tun_peer_patch_port', default='patch-to-tun',
               help=_("OVS Peer patch port in MPLS bridge to tunnel bridge "
                      "(traffic to tunnel bridge)")),
    cfg.StrOpt('mpls_from_tun_peer_patch_port', default='patch-from-tun',
               help=_("OVS Peer patch port in MPLS bridge to tunnel bridge "
                      "(traffic from tunnel bridge)")),
    cfg.StrOpt('mpls_to_int_peer_patch_port', default='patch-mpls-to-int',
               help=_("OVS Peer patch port in MPLS bridge to int bridge "
                      "(traffic to int bridge)")),
    cfg.StrOpt('int_from_mpls_peer_patch_port', default='patch-int-from-mpls',
               help=_("OVS Peer patch port in int bridge to MPLS bridge "
                      "(traffic from MPLS bridge)")),
]

cfg.CONF.register_opts(bagpipe_bgp_opts, "BAGPIPE")
ovs_conf.register_ovs_agent_opts()
config.register_agent_state_opts_helper(cfg.CONF)


class BGPAttachmentNotFound(n_exc.NotFound):
    message = "Local port %(local_port)s details could not be found"


class BaGPipeBGPException(n_exc.NeutronException):
    message = "An exception occurred when calling bagpipe-bgp \
               REST service: %(reason)s"


class HTTPClientBase(object):
    """An HTTP client base class"""

    def __init__(self, host="127.0.0.1", port=8082,
                 client_name="HTTP client base"):
        """Create a new HTTP client

        :param host: HTTP server IP address
        :param port: HTTP server port
        """
        self.host = host
        self.port = port
        self.client_name = client_name

    def do_request(self, method, action, body=None):
        LOG.debug("bagpipe-bgp client request: %s %s [%s]" %
                  (method, action, str(body)))

        if isinstance(body, dict):
            body = json.dumps(body)
        try:
            headers = {'User-Agent': self.client_name,
                       "Content-Type": "application/json",
                       "Accept": "application/json"}
            uri = "http://%s:%s/%s" % (self.host, self.port, action)

            http = httplib2.Http()
            response, content = http.request(uri, method, body, headers)
            LOG.debug("bagpipe-bgp returns [%s:%s]" %
                      (str(response.status), content))

            if response.status == 200:
                if content and len(content) > 1:
                    return json.loads(content)
            else:
                reason = (
                    "An HTTP operation has failed on bagpipe-bgp."
                )
                raise BaGPipeBGPException(reason=reason)
        except (socket.error, IOError) as e:
            reason = "Failed to connect to bagpipe-bgp: %s" % str(e)
            raise BaGPipeBGPException(reason=reason)

    def get(self, action):
        return self.do_request("GET", action)

    def post(self, action, body=None):
        return self.do_request("POST", action, body=body)

    def put(self, action, body=None):
        return self.do_request("PUT", action, body=body)

    def delete(self, action):
        return self.do_request("DELETE", action)


class DummyOVSAgent(ovs_neutron_agent.OVSNeutronAgent):
    # this class is used only to 'borrow' setup_entry_for_arp_reply
    # from OVSNeutronAgent
    arp_responder_enabled = True

    def __init__(self):
        pass


def has_attachement(bgpvpn_info, vpn_type):
    return (vpn_type in bgpvpn_info and (
            bgpvpn_info[vpn_type].get(RT_IMPORT) or
            bgpvpn_info[vpn_type].get(RT_EXPORT))
            )


class keydefaultdict(defaultdict):
    """Inherit defaultdict class to customize default_factory.

    Override __missing__ method to construct custom object as default_factory
    passing an argument.

    For example:
    class C(object):
        def __init__(self, value):
            self.value = value

    d = keydefaultdict(C)
    d[key] returns C(key)
    """
    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        else:
            # pylint: disable=not-callable
            ret = self[key] = getattr(self, 'default_factory')(key)
            return ret


GatewayInfo = namedtuple('GatewayInfo', ['mac', 'ip'])
NO_GW_INFO = GatewayInfo(None, None)


class CommonInfo(object):

    def __init__(self, id):
        self.id = id
        self.service_infos = dict()

    def add_service_info(self, service_name, service_info):
        if not service_info:
            return

        if service_info != self.service_infos.get(service_name, {}):
            self.service_infos[service_name] = service_info


class PortInfo(CommonInfo):

    def __init__(self, port_id):
        super(PortInfo, self).__init__(port_id)

        self.ip_address = None
        self.mac_address = None
        self.network = None
        self.local_port = dict()

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.id == other.id)

    def __hash__(self):
        return hash(self.id)

    def set_local_port(self, linuxif):
        self.local_port = dict(linuxif=linuxif)

    def set_ip_mac_infos(self, ip_address, mac_address):
        self.ip_address = ip_address
        self.mac_address = mac_address

    def set_network(self, network):
        if not self.network:
            self.network = network
        else:
            LOG.warning('Network reference has already been set for port')


class NetworkInfo(CommonInfo):

    def __init__(self, network_id):
        super(NetworkInfo, self).__init__(network_id)

        self.gateway_info = NO_GW_INFO
        self.ports = set()

    def set_gateway_info(self, gateway_info):
        self.gateway_info = gateway_info


class BaGPipeBGPAgent(HTTPClientBase,
                      bagpipe_agent_rpc.BaGPipeAgentRpcCallBackMixin,
                      bgpvpn_agent_rpc.BGPVPNAgentRpcCallBackMixin
                      ):
    """Implements a BaGPipe-BGP REST client"""

    # bagpipe-bgp status
    BAGPIPEBGP_UP = 'UP'
    BAGPIPEBGP_DOWN = 'DOWN'

    def __init__(self, agent_type, connection, int_br=None, tun_br=None):

        """Create a new BaGPipe-BGP REST service client.

        :param agent_type: bagpipe-bgp agent type (Linux bridge or OVS)
        :param connection: RPC Connection
        :param int_br: OVS integration bridge
        :param tun_br: OVS tunnel bridge
        """
        super(BaGPipeBGPAgent,
              self).__init__(cfg.CONF.BAGPIPE.bagpipe_bgp_ip,
                             cfg.CONF.BAGPIPE.bagpipe_bgp_port, agent_type)

        self.agent_type = agent_type

        self.ping_interval = cfg.CONF.BAGPIPE.ping_interval

        # Store all ports level network and service informations
        self.ports_info = keydefaultdict(PortInfo)
        # Store all networks level network and service informations
        self.networks_info = keydefaultdict(NetworkInfo)

        self.bagpipe_bgp_status = self.BAGPIPEBGP_DOWN
        self.seq_num = 0

        # OVS-specific setup
        if self.agent_type == n_const.AGENT_TYPE_OVS:
            self.int_br = int_br
            self.tun_br = tun_br
            self._setup_mpls_br()

            registry.subscribe(self.ovs_restarted,
                               resources.AGENT,
                               events.OVS_RESTARTED)

        # RPC setup
        if self.agent_type == n_const.AGENT_TYPE_LINUXBRIDGE:
            connection.create_consumer(topics.get_topic_name(topics.AGENT,
                                                             topics_BAGPIPE,
                                                             topics.UPDATE,
                                                             cfg.CONF.host),
                                       [self], fanout=False)
        else:
            LOG.info("bagpipe-l2 RPCs disabled for OVS bridge")

        connection.create_consumer(topics.get_topic_name(topics.AGENT,
                                                         topics_BAGPIPE_BGPVPN,
                                                         topics.UPDATE),
                                   [self], fanout=True)
        connection.create_consumer(topics.get_topic_name(topics.AGENT,
                                                         topics_BAGPIPE_BGPVPN,
                                                         topics.UPDATE,
                                                         cfg.CONF.host),
                                   [self], fanout=False)

        # Starts a greenthread for bagpipe-bgp status polling
        self._start_bagpipe_bgp_status_polling(self.ping_interval)

        self.vlan_manager = vlanmanager.LocalVlanManager()

    def _check_bagpipe_bgp_status(self):
        """Trigger refresh on bagpipe-bgp restarts

        Check if bagpipe-bgp has restarted while sending ping request
        to detect sequence number change.
        If a restart is detected, re-send all registered attachments to
        bagpipe-bgp.
        """
        new_seq_num = self._request_ping()

        # Check bagpipe-bgp restart
        if new_seq_num != self.seq_num:
            if new_seq_num != -1:
                if self.seq_num != 0:
                    LOG.warning("bagpipe-bgp restart detected...")
                else:
                    LOG.info("bagpipe-bgp successfully detected")

                self.seq_num = new_seq_num
                self.bagpipe_bgp_status = self.BAGPIPEBGP_UP

                # Re-send all registered ports to bagpipe-bgp
                if self.ports_info:
                    LOG.info("Sending all registered ports to bagpipe-bgp")
                    LOG.debug("Registered ports list: %s" %
                              self.ports_info)
                    for port_id in self.ports_info:
                        self._do_port_plug(port_id)
                else:
                    LOG.info("No attachment to send to bagpipe-bgp")
            else:
                self.bagpipe_bgp_status = self.BAGPIPEBGP_DOWN

    def _start_bagpipe_bgp_status_polling(self, ping_interval=10):
        # Start bagpipe-bgp status polling at regular interval
        status_loop = loopingcall.FixedIntervalLoopingCall(
            self._check_bagpipe_bgp_status)
        status_loop.start(interval=ping_interval,
                          initial_delay=ping_interval)  # TM: why not zero ?

    def _get_network_port_infos(self, net_id, port_id):
        net_info = self.networks_info[net_id]
        port_info = self.ports_info[port_id]
        net_info.ports.add(port_info)
        port_info.set_network(net_info)

        return net_info, port_info

    def _remove_network_port_infos(self, net_id, port_id):
        port_info = self.ports_info.get(port_id)
        net_info = self.networks_info.get(net_id)

        if port_info:
            del self.ports_info[port_id]

        if net_info:
            net_info.ports.discard(port_info)
            if not net_info.ports:
                del self.networks_info[net_id]

    def _get_common_attach_info(self, port_info):
        """Format common attach informations

        {
            local_port: {
                linuxif: <LINUX_IF>
            },
            ip_address: <PORT_IP>,
            mac_address: <PORT_MAC>,
            gateway_ip: <NETWORK_GATEWAY_IP>
        }
        """
        net_info = port_info.network
        common_plug_details = {'local_port': port_info.local_port,
                               'ip_address': port_info.ip_address,
                               'mac_address': port_info.mac_address,
                               'gateway_ip': net_info.gateway_info.ip
                               }

        return common_plug_details

    def _compile_port_attach_info(self, port_id):
        port_info = self.ports_info.get(port_id)

        if not port_info:
            LOG.warning("No PortInfo found for port %s", port_id)
            return []

        net_info = port_info.network

        services = list(set(net_info.service_infos.keys()) |
                        set(port_info.service_infos.keys()))

        service_attach_info = {}
        for service in services:
            service_info = {}
            if net_info.service_infos.get(service, {}):
                service_info.update(deepcopy(net_info.service_infos[service]))
            if port_info.service_infos.get(service, {}):
                service_info.update(deepcopy(port_info.service_infos[service]))

            service_attach_info[service] = (
                getattr(self,
                        '_compile_%s_attach_info' % service)(service_info,
                                                             port_info)
            )

        attach_list = defaultdict(list)
        for vpn_type in VPN_TYPES:
            attach_info = {}

            for service in services:
                if vpn_type in service_attach_info[service]:
                    if not attach_info:
                        attach_info = self._get_common_attach_info(port_info)
                        attach_info.update({'vpn_instance_id': '%s_%s' %
                                            (net_info.id, vpn_type)})

                    service_vpn_info = service_attach_info[service][vpn_type]

                    if vpn_type not in attach_info:
                        attach_info.update(dict(vpn_type=vpn_type))

                    # Check if static routes
                    static_routes = service_vpn_info.pop('static_routes', [])
                    if static_routes:
                        static_info = deepcopy(attach_info)
                        static_info.update({'advertise_subnet': True})
                        for static_route in static_routes:
                            static_info['ip_address'] = static_route
                            static_info.update(service_vpn_info)

                            attach_list[vpn_type].append(static_info)

                    for rt_type in RT_TYPES:
                        if rt_type in service_vpn_info:
                            if rt_type not in attach_info:
                                attach_info[rt_type] = []

                            attach_info[rt_type] += (
                                service_vpn_info.pop(rt_type)
                            )

                    # Check if plugging an EVPN into an IPVPN
                    if vpn_type == IPVPN and EVPN in attach_list:
                        attach_info['local_port'] = {
                            EVPN: {
                                'id': '%s_evpn' % net_info.id
                            }
                        }
                        service_vpn_info.pop('local_port', {})
                    else:
                        attach_info['local_port'].update(
                            service_vpn_info.pop('local_port', {})
                        )

                    attach_info.update(service_vpn_info)

            if attach_info:
                attach_list[vpn_type].append(attach_info)

        return attach_list

    def _request_ping(self):
        """Send ping request to bagpipe-bgp to get sequence number"""
        try:
            response = self.get('ping')
            LOG.debug("bagpipe-bgp PING response received with "
                      "sequence number %s" % response)
            return response
        except BaGPipeBGPException as e:
            LOG.warning(str(e))
            return -1

    def _send_attach_local_port(self, local_port_details):
        """Send local port attach request to BaGPipe-BGP if running"""
        if self.bagpipe_bgp_status is self.BAGPIPEBGP_UP:
            try:
                self.post('attach_localport', local_port_details)
                LOG.debug("Local port has been attached to bagpipe-bgp with "
                          "details %s" % local_port_details)
            except BaGPipeBGPException as e:
                LOG.error("Can't attach local port on bagpipe-bgp: %s", str(e))
        else:
            LOG.debug("Local port not yet attached to bagpipe-bgp (not up)")

    def _send_detach_local_port(self, local_port_details):
        """Send local port detach request to BaGPipe-BGP if running"""
        if self.bagpipe_bgp_status is self.BAGPIPEBGP_UP:
            try:
                self.post('detach_localport', local_port_details)
                LOG.debug("Local port has been detached from bagpipe-bgp "
                          "with details %s" % local_port_details)
            except BaGPipeBGPException as e:
                LOG.error("Can't detach local port from bagpipe-bgp: %s",
                          str(e))
                raise
        else:
            LOG.debug("Local port not yet detached from bagpipe-bgp (not up)")

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
            cfg.CONF.BAGPIPE.mpls_from_tun_peer_patch_port)
        self.patch_mpls_from_tun_ofport = self.mpls_br.add_patch_port(
            cfg.CONF.BAGPIPE.mpls_from_tun_peer_patch_port,
            cfg.CONF.BAGPIPE.tun_to_mpls_peer_patch_port)

        # patch ports for traffic from mpls bridge to tun bridge
        self.patch_mpls_to_tun_ofport = self.mpls_br.add_patch_port(
            cfg.CONF.BAGPIPE.mpls_to_tun_peer_patch_port,
            cfg.CONF.BAGPIPE.tun_from_mpls_peer_patch_port)
        self.patch_tun_from_mpls_ofport = self.tun_br.add_patch_port(
            cfg.CONF.BAGPIPE.tun_from_mpls_peer_patch_port,
            cfg.CONF.BAGPIPE.mpls_to_tun_peer_patch_port)

        # patch ports for traffic from mpls bridge to int bridge
        self.patch_mpls_to_int_ofport = self.mpls_br.add_patch_port(
            cfg.CONF.BAGPIPE.mpls_to_int_peer_patch_port,
            cfg.CONF.BAGPIPE.int_from_mpls_peer_patch_port)
        self.patch_int_from_mpls_ofport = self.int_br.add_patch_port(
            cfg.CONF.BAGPIPE.int_from_mpls_peer_patch_port,
            cfg.CONF.BAGPIPE.mpls_to_int_peer_patch_port)

        if (int(self.patch_tun_to_mpls_ofport) < 0 or
                int(self.patch_mpls_from_tun_ofport) < 0 or
                int(self.patch_mpls_to_tun_ofport) < 0 or
                int(self.patch_tun_from_mpls_ofport) < 0 or
                int(self.patch_int_from_mpls_ofport) < 0 or
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
            table=a_const.PATCH_LV_TO_TUN,
            priority=1,
            in_port=patch_int_ofport,
            dl_dst=DEFAULT_GATEWAY_MAC,
            actions="output:%s" % self.patch_tun_to_mpls_ofport
        )

        # Redirect traffic from the MPLS bridge to br-int
        self.tun_br.add_flow(in_port=self.patch_tun_from_mpls_ofport,
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
        actions = a_const.ARP_RESPONDER_ACTIONS % {
            'mac': netaddr.EUI(DEFAULT_GATEWAY_MAC, dialect=netaddr.mac_unix),
            'ip': netaddr.IPAddress(gateway_ip),
        }
        self.tun_br.add_flow(table=a_const.ARP_RESPONDER,
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
            table=a_const.ARP_RESPONDER,
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
        self.int_br.add_flow(table=a_const.LOCAL_SWITCHING,
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
        self.int_br.add_flow(table=a_const.LOCAL_SWITCHING,
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
        self.int_br.delete_flows(table=a_const.LOCAL_SWITCHING,
                                 proto='arp',
                                 dl_src=gateway_mac,
                                 arp_sha=gateway_mac)

    def _do_port_plug(self, port_id):
        """Send port attach request to bagpipe-bgp."""
        all_plug_details = self._compile_port_attach_info(port_id)

        # First plug E-VPNs because they could be plugged into IP-VPNs
        for vpn_type in [t for t in VPN_TYPES
                         if t in all_plug_details]:
            for plug_detail in all_plug_details[vpn_type]:
                self._send_attach_local_port(plug_detail)

    def _do_port_unplug(self, port_id):
        """Send port detach request to bagpipe-bgp."""
        all_unplug_details = self._compile_port_attach_info(port_id)

        # First unplug IP-VPNs because E-VPNs could be plugged into them
        for vpn_type in [t for t in VPN_TYPES[::-1]
                         if t in all_unplug_details]:
            for unplug_detail in all_unplug_details[vpn_type]:
                self._send_detach_local_port(unplug_detail)

    @log_helpers.log_method_call
    def _check_arp_voodoo_plug(self, net_info, gateway_info):

        if (self.agent_type != n_const.AGENT_TYPE_OVS):
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

        if (self.agent_type != n_const.AGENT_TYPE_OVS):
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

    def _compile_bagpipe_l2_attach_info(self, service_info, port_info):
        attach_info = {
            EVPN: {
                RT_IMPORT: [service_info[EVPN][RT_IMPORT]],
                RT_EXPORT: [service_info[EVPN][RT_EXPORT]]
            }
        }

        attach_info[EVPN].update(dict(
            linuxbr=LinuxBridgeManager.get_bridge_name(port_info.network.id)))

        return attach_info

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-bgp-agent')
    def bagpipe_port_attach(self, context, port_bagpipe_info):
        port_id = port_bagpipe_info.pop('id')
        net_id = port_bagpipe_info.pop('network_id')

        net_info, port_info = self._get_network_port_infos(net_id, port_id)

        # Set IP and MAC adresses in PortInfo
        ip_address = port_bagpipe_info.pop('ip_address')
        mac_address = port_bagpipe_info.pop('mac_address')
        port_info.set_ip_mac_infos(ip_address, mac_address)

        # Set gateway IP address in NetworkInfo
        gateway_info = GatewayInfo(None,
                                   port_bagpipe_info.pop('gateway_ip'))
        net_info.set_gateway_info(gateway_info)

        port_info.set_local_port(
            LinuxBridgeManager.get_tap_device_name(port_id)
        )

        net_info.add_service_info(BAGPIPE_L2_SERVICE, port_bagpipe_info)

        self._do_port_plug(port_id)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-bgp-agent')
    def bagpipe_port_detach(self, context, port_bagpipe_info):
        port_id = port_bagpipe_info['id']
        net_id = port_bagpipe_info['network_id']

        LOG.debug("Detaching port %s from bagpipe-bgp", port_id)
        if self.ports_info.get(port_id):
            try:
                self._do_port_unplug(port_id)
            except BaGPipeBGPException as e:
                LOG.error("Can't detach port from bagpipe-bgp: %s", str(e))
            finally:
                self._remove_network_port_infos(net_id, port_id)
        else:
            LOG.warning("bagpipe-bgp agent inconsistent for BaGPipe L2 or "
                        "updated with another detach")

    def _is_last_bgpvpn_info(self, net_info, service_info):
        if BGPVPN_SERVICE not in net_info.service_infos:
            return

        orig_info = deepcopy(net_info.service_infos[BGPVPN_SERVICE])

        for vpn_type in BGPVPN_TYPES:
            if vpn_type in service_info:
                if vpn_type in orig_info:
                    for rt_type in RT_TYPES:
                        if rt_type in service_info[vpn_type]:
                            orig_info[vpn_type][rt_type] = list(
                                set(orig_info[vpn_type][rt_type]) -
                                set(service_info[vpn_type][rt_type]))

                            if not orig_info[vpn_type][rt_type]:
                                del(orig_info[vpn_type][rt_type])

                    if not orig_info[vpn_type]:
                        del(orig_info[vpn_type])

        return (not orig_info, orig_info)

    def _compile_bgpvpn_attach_info(self, service_info, port_info):
        attach_info = {}

        for bgpvpn_type, rt_type in list(
                itertools.product(BGPVPN_TYPES, RT_TYPES)):
            if rt_type in service_info.get(bgpvpn_type, {}):
                bagpipe_bgp_vpn_type = BGPVPN_TYPES_MAP[bgpvpn_type]
                if bagpipe_bgp_vpn_type not in attach_info:
                    attach_info[bagpipe_bgp_vpn_type] = defaultdict(list)

                attach_info[bagpipe_bgp_vpn_type][rt_type] += (
                    service_info[bgpvpn_type][rt_type]
                )

        if self.agent_type == n_const.AGENT_TYPE_OVS:
            # Add OVS VLAN information
            vlan = self.vlan_manager.get(port_info.network.id).vlan
            for vpn_type in (vt for vt in VPN_TYPES if vt in attach_info):
                attach_info[vpn_type].update({
                    'local_port': {
                        'ovs': {
                            'plugged': True,
                            'port_number': self.patch_mpls_from_tun_ofport,
                            'to_vm_port_number': self.patch_mpls_to_tun_ofport,
                            'vlan': vlan
                        }
                    }
                })

            if has_attachement(attach_info, IPVPN):
                # Add fallback information if needed as well
                if port_info.network.gateway_info.mac:
                    attach_info[IPVPN].update({
                        'fallback': {
                            'dst_mac': port_info.network.gateway_info.mac,
                            'src_mac': FALLBACK_SRC_MAC,
                            'ovs_port_number': self.patch_mpls_to_int_ofport
                        }
                    })
        else:
            for vpn_type in VPN_TYPES:
                if has_attachement(attach_info, vpn_type):
                    attach_info[vpn_type].update(
                        dict(linuxbr=LinuxBridgeManager.get_bridge_name(
                             port_info.network.id))
                    )

        return attach_info

    def ovs_restarted_bgpvpn(self):
        for net_info in self.networks_info.values():
            if net_info.ports and net_info.gateway_info != NO_GW_INFO:
                bgpvpn_info = net_info.service_infos.get(BGPVPN_SERVICE)
                if has_attachement(bgpvpn_info, BGPVPN_L3):
                    self._check_arp_voodoo_plug(net_info,
                                                net_info.gateway_info)

    @log_helpers.log_method_call
    def create_bgpvpn(self, context, bgpvpn):
        self.update_bgpvpn(context, bgpvpn)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-bgp-agent')
    def update_bgpvpn(self, context, bgpvpn):
        net_id = bgpvpn.pop('network_id')

        net_info = self.networks_info.get(net_id)

        if not net_info:
            return

        new_gw_info = GatewayInfo(
            bgpvpn.pop('gateway_mac', None),
            net_info.gateway_info.ip
        )

        if has_attachement(bgpvpn, BGPVPN_L3):
            self._check_arp_voodoo_plug(net_info, new_gw_info)

        net_info.set_gateway_info(new_gw_info)

        net_info.add_service_info(BGPVPN_SERVICE, bgpvpn)

        for port_info in net_info.ports:
            self._do_port_plug(port_info.id)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-bgp-agent')
    def delete_bgpvpn(self, context, bgpvpn):
        net_id = bgpvpn.pop('network_id')

        net_info = self.networks_info.get(net_id)

        if not net_info:
            return

        # Check if remaining BGPVPN informations, otherwise unplug
        # port from bagpipe-bgp
        last_bgpvpn, updated_info = (
            self._is_last_bgpvpn_info(net_info, bgpvpn)
        )

        if self.agent_type == n_const.AGENT_TYPE_OVS:
            if (last_bgpvpn or
                    not has_attachement(updated_info, BGPVPN_L3)):
                self._check_arp_voodoo_unplug(net_id)

        if last_bgpvpn:
            if len(net_info.service_infos) == 1:
                for port_info in net_info.ports:
                    self._do_port_unplug(port_info.id)

                del(net_info.service_infos[BGPVPN_SERVICE])
            else:
                del(net_info.service_infos[BGPVPN_SERVICE])

                for port_info in net_info.ports:
                    self._do_port_plug(port_info.id)
        else:
            net_info.service_infos[BGPVPN_SERVICE] = updated_info

            for port_info in net_info.ports:
                self._do_port_plug(port_info.id)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-bgp-agent')
    def bgpvpn_port_attach(self, context, port_bgpvpn_info):
        port_id = port_bgpvpn_info.pop('id')
        net_id = port_bgpvpn_info.pop('network_id')

        net_info, port_info = self._get_network_port_infos(net_id, port_id)

        # Set IP and MAC adresses in PortInfo
        ip_address = port_bgpvpn_info.pop('ip_address')
        mac_address = port_bgpvpn_info.pop('mac_address')
        port_info.set_ip_mac_infos(ip_address, mac_address)

        # Set gateway IP and MAC (if defined) addresses in NetworkInfo
        gateway_info = GatewayInfo(port_bgpvpn_info.pop('gateway_mac', None),
                                   port_bgpvpn_info.pop('gateway_ip'))

        if has_attachement(port_bgpvpn_info, BGPVPN_L3):
            self._check_arp_voodoo_plug(net_info, gateway_info)

        net_info.set_gateway_info(gateway_info)

        if self.agent_type == n_const.AGENT_TYPE_OVS:
            vlan = self.vlan_manager.get(net_id).vlan
            port_info.set_local_port('%s:%s' % (LINUXIF_PREFIX, vlan))
        else:
            port_info.set_local_port(
                LinuxBridgeManager.get_tap_device_name(port_id)
            )

        net_info.add_service_info(BGPVPN_SERVICE, port_bgpvpn_info)

        self._do_port_plug(port_id)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-bgp-agent')
    def bgpvpn_port_detach(self, context, port_bgpvpn_info):
        port_id = port_bgpvpn_info['id']
        net_id = port_bgpvpn_info['network_id']

        if self.ports_info.get(port_id):
            try:
                self._do_port_unplug(port_id)
                if self.agent_type == n_const.AGENT_TYPE_OVS:
                    net_info = self.networks_info.get(net_id)
                    bgpvpn_info = net_info.service_infos.get(BGPVPN_SERVICE)

                    if has_attachement(bgpvpn_info, BGPVPN_L3):
                        self._check_arp_voodoo_unplug(net_id)
            except BaGPipeBGPException as e:
                LOG.error("Can't detach BGPVPN port from bagpipe-bgp %s",
                          str(e))
            finally:
                self._remove_network_port_infos(net_id, port_id)
        else:
            LOG.warning('bagpipe-bgp agent inconsistent for BGPVPN or updated '
                        'with another detach')
