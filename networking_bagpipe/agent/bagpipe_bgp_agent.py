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
import json

from copy import deepcopy

from collections import defaultdict
from collections import namedtuple
from collections import OrderedDict

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

from neutron.agent.common import config
from neutron.agent.common import ovs_lib

from neutron.common import topics

from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc

from neutron.plugins.ml2.drivers.linuxbridge.agent.linuxbridge_neutron_agent \
    import LinuxBridgeManager
from neutron.plugins.ml2.drivers.openvswitch.agent.common import config\
    as ovs_config
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants\
    as a_const
from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_neutron_agent

from neutron.plugins.ml2.drivers.openvswitch.agent import \
    ovs_agent_extension_api

LOG = logging.getLogger(__name__)

DEFAULT_GATEWAY_MAC = "00:00:5e:00:43:64"
FALLBACK_SRC_MAC = "00:00:5e:2a:10:00"

BAGPIPE_NOTIFIER = 'bagpipe'
BGPVPN_NOTIFIER = 'bgpvpn'
BAGPIPE_NOTIFIERS = [BAGPIPE_NOTIFIER, BGPVPN_NOTIFIER]

EVPN = 'evpn'
IPVPN = 'ipvpn'
VPN_TYPES = [EVPN, IPVPN]

BGPVPN_L2 = 'l2vpn'
BGPVPN_L3 = 'l3vpn'
BGPVPN_TYPES = [BGPVPN_L2, BGPVPN_L3]
BGPVPN_TYPES_MAP = {BGPVPN_L2: EVPN, BGPVPN_L3: IPVPN}

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
cfg.CONF.register_opts(ovs_config.ovs_opts, "OVS")
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


GatewayInfo = namedtuple('GatewayInfo', ['mac', 'ip'])
NO_GW_INFO = GatewayInfo(None, None)


def default_gw_info():
    return GatewayInfo(mac=None, ip=None)


def has_attachement(bgpvpn_info, vpn_type):
    return (bgpvpn_info[vpn_type].get('import_rt') or
            bgpvpn_info[vpn_type].get('export_rt'))


def has_ipvpn_attachement(bgpvpn_info):
    return has_attachement(bgpvpn_info, IPVPN)


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

        self.reg_attachments = defaultdict(list)
        self.gateway_info_for_net = defaultdict(default_gw_info)

        self.bagpipe_bgp_status = self.BAGPIPEBGP_DOWN
        self.seq_num = 0

        # OVS-specific variables:
        if self.agent_type == n_const.AGENT_TYPE_OVS:
            self.int_br = int_br
            self.tun_br = tun_br
            self.setup_mpls_br(cfg.CONF.BAGPIPE.mpls_bridge)

        # RPC setpup
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

    def _check_bagpipe_bgp_status(self):
        """Trigger refresh on bagpipe-bgp restarts

        Check if bagpipe-bgp has restarted while sending ping request
        to detect sequence number change.
        If a restart is detected, re-send all registered attachments to
        bagpipe-bgp.
        """
        new_seq_num = self.request_ping()

        # Check bagpipe-bgp restart
        if new_seq_num != self.seq_num:
            if new_seq_num != -1:
                if self.seq_num != 0:
                    LOG.warning("bagpipe-bgp restart detected...")
                else:
                    LOG.info("bagpipe-bgp successfully detected")

                self.seq_num = new_seq_num
                self.bagpipe_bgp_status = self.BAGPIPEBGP_UP

                # Re-send all registered attachments to bagpipe-bgp
                if self.reg_attachments:
                    LOG.info("Sending all registered attachments to "
                             "bagpipe-bgp")
                    LOG.debug("Registered attachments list: %s" %
                              self.reg_attachments)
                    for __, attachment_list in (
                            self.reg_attachments.iteritems()):
                        if attachment_list:
                            for attachment in attachment_list:
                                self._do_local_port_plug(attachment)
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

    def _get_reg_attachment_for_port(self, network_id, local_port_id):
        # Retrieve local port index and attachement details in BGP
        # registered attachments list for the specified network and port
        # identifiers

        LOG.debug("Getting registered attachment for port %s on network %s" %
                  (local_port_id, network_id))

        index = -1
        details = None
        for i, attachment in enumerate(self.reg_attachments[network_id]):
            if (attachment['port_id'] == local_port_id):
                LOG.debug("Registered attachment found at index %s: %s" %
                          (i, attachment))
                index = i
                details = attachment
                break

        if index == -1:
            LOG.info("No registered attachment found for port %s",
                     local_port_id)
            raise BGPAttachmentNotFound(local_port=local_port_id)

        return index, details

    def _copy_local_port_common_details(self, local_port_details):
        local_port_copy = {}
        for key in ['local_port']:
            local_port_copy[key] = local_port_details[key]

        for optional in ['linuxbr']:
            if optional in local_port_details:
                local_port_copy[optional] = local_port_details[optional]

        return local_port_copy

    def _gen_fallback_info(self, dst_mac):
        return {'fallback': {'dst_mac': dst_mac,
                             'src_mac': FALLBACK_SRC_MAC,
                             'ovs_port_number': self.patch_mpls_to_int_ofport
                             }
                }

    def _add_fallback_info(self, source_details, details, vpn_type):
        # if a gateway_mac is known, we will add fallback information
        # to 'details'

        if (self.agent_type == n_const.AGENT_TYPE_OVS and
                vpn_type == IPVPN and source_details.get('gateway_mac')):
            details.update(
                self._gen_fallback_info(source_details.get('gateway_mac'))
            )

    def _copy_notifier_vpn_details(self, notifier_details, vpn_type):
        notifier_copy = {}
        for key in ['mac_address', 'ip_address', 'gateway_ip',
                    'import_rt', 'export_rt']:
            notifier_copy[key] = notifier_details[key]

        for optional in ['readvertise', 'attract_traffic']:
            if optional in notifier_details:
                notifier_copy[optional] = notifier_details[optional]

        self._add_fallback_info(notifier_details, notifier_copy, vpn_type)

        return notifier_copy

    def _populate_vpntype_ipaddress2details(self, vpn_type, notifier,
                                            local_port_details,
                                            vpntype_ipaddress2details):
        # (used only as a helper for _get_local_port_plug_details)
        # will populate vpntype_ipaddress2details dict

        if (notifier in local_port_details and
                vpn_type in local_port_details[notifier] and
                has_attachement(local_port_details[notifier], vpn_type)):
            notifier_details = local_port_details[notifier][vpn_type]
            LOG.debug("Notifier %s details: %s" % (vpn_type,
                                                   notifier_details))

            if ((vpn_type, notifier_details['ip_address']) in
                    vpntype_ipaddress2details):
                plug_details = vpntype_ipaddress2details[
                    (vpn_type, notifier_details['ip_address'])
                    ]

                plug_details['import_rt'] += notifier_details['import_rt']
                plug_details['export_rt'] += notifier_details['export_rt']

                vpntype_ipaddress2details[
                    (vpn_type, notifier_details['ip_address'])
                    ].update(plug_details)
            else:
                plug_details = {
                    'vpn_type': vpn_type,
                    'vpn_instance_id': '%s_%s' %
                    (local_port_details['vpn_instance_id'], vpn_type),
                }

                plug_details.update(
                    self._copy_local_port_common_details(local_port_details))

                if IPVPN == vpn_type:
                    for vpntype_ipaddress in vpntype_ipaddress2details:
                        if EVPN in vpntype_ipaddress:
                            plug_details['local_port'] = {EVPN: {
                                'id': '%s_evpn' %
                                local_port_details['vpn_instance_id']}
                                }

                plug_details.update(
                    self._copy_notifier_vpn_details(notifier_details, vpn_type)
                )

                vpntype_ipaddress2details[(vpn_type,
                                           notifier_details['ip_address'])
                                          ] = deepcopy(plug_details)

            if 'static_routes' in notifier_details:
                for static_route in notifier_details['static_routes']:
                    plug_details['ip_address'] = static_route
                    plug_details.update({'advertise_subnet': True})
                    vpntype_ipaddress2details[
                        (vpn_type, static_route)] = deepcopy(plug_details)

    def _get_local_port_plug_details(self, local_port_details, vpn_types=None,
                                     notifiers=None):
        # Construct plug details list for specified notifiers corresponding to
        # the given port

        all_plug_details = {}
        vpntype_ipaddress2details = OrderedDict()

        plug_types = vpn_types if vpn_types else VPN_TYPES
        plug_notifiers = notifiers if notifiers else BAGPIPE_NOTIFIERS

        # NOTE(tmorin): could use itertools.product
        for (vpn_type, notifier) in [
                (x, y) for x in plug_types for y in plug_notifiers]:
            self._populate_vpntype_ipaddress2details(vpn_type,
                                                     notifier,
                                                     local_port_details,
                                                     vpntype_ipaddress2details)

        LOG.debug('Local port (VPN type, IP address) map details %s' %
                  vpntype_ipaddress2details)

        for (vpntype_ipaddress, plug_details) in (vpntype_ipaddress2details.
                                                  iteritems()):
            if vpntype_ipaddress[0] in all_plug_details:
                all_plug_details[vpntype_ipaddress[0]].append(plug_details)
            else:
                all_plug_details[vpntype_ipaddress[0]] = list([plug_details])

        LOG.debug('Local port %s details %s' % (local_port_details['port_id'],
                                                all_plug_details))

        return all_plug_details

    # bagpipe-bgp REST API requests
    # ----------------------------------------
    def request_ping(self):
        """Send ping request to bagpipe-bgp to get sequence number"""
        try:
            response = self.get('ping')
            LOG.debug("bagpipe-bgp PING response received with "
                      "sequence number %s" % response)
            return response
        except BaGPipeBGPException as e:
            LOG.warning(str(e))
            return -1

    def send_attach_local_port(self, local_port_details):
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

    def send_detach_local_port(self, local_port_details):
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

    def setup_mpls_br(self, mpls_br):
        '''Setup the MPLS bridge for bagpipe-bgp.

        Creates MPLS bridge, and links it to the integration and tunnel
        bridges using patch ports.

        :param mpls_br: the name of the MPLS bridge.
        '''
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

    def get_local_vlan(self, port_id):
        vif_port = self.int_br.get_vif_port_by_id(port_id)
        if vif_port is None:
            LOG.info("port by ids: %s",
                     self.int_br.get_vifs_by_ids(
                         list(self.int_br.get_vif_port_set())
                         )
                     )
            raise Exception("port %s not found on int-br" % port_id)
        port_tag_dict = self.int_br.get_port_tag_dict()
        return port_tag_dict[vif_port.port_name]

    def _get_local_port_for_attach(self, port_id, net_id):
        if self.agent_type == n_const.AGENT_TYPE_LINUXBRIDGE:
            port_name = LinuxBridgeManager.get_tap_device_name(port_id)
            bridge_name = LinuxBridgeManager.get_bridge_name(net_id)

            return {
                'linuxbr': bridge_name,
                'local_port': {
                    'linuxif': port_name
                }
            }
        elif self.agent_type == n_const.AGENT_TYPE_OVS:
            port = self.int_br.get_vif_port_by_id(port_id)
            try:
                vlan = self.get_local_vlan(port_id)

                return {
                    'local_port': {
                        'linuxif': port.port_name,
                        'ovs': {
                            'plugged': True,
                            'port_number': self.patch_mpls_from_tun_ofport,
                            'to_vm_port_number': self.patch_mpls_to_tun_ofport,
                            'vlan': vlan
                        }
                    }
                }
            except Exception as e:
                LOG.error("could not find vlan for port %s: %s", port_id, e)

    def _copy_port_network_details(self, port_details, vpn_type):
        network_details = {}
        for key in ['ip_address', 'mac_address', 'gateway_ip', 'gateway_mac']:
            network_details[key] = port_details.get(key)

        self._add_fallback_info(port_details, network_details, vpn_type)

        return network_details

    def _format_port_details(self, port_details, notifier):
        """Format port details as follows:

        {
            mac_address: <PORT_MAC>,
            ip_address: <PORT_IP>,
            gateway_ip: <PORT_GATEWAY>,
            gateway_mac: <GW_MAC>,
            evpn | ipvpn: {
                import_rts: [<ASN:NN>],
                export_rts: [<ASN:NN>]
            }
        }

        to

        {
            evpn | ipvpn: {
                mac_address: <PORT_MAC>,
                ip_address: <PORT_IP>,
                gateway_ip: <PORT_GATEWAY>,
                fallback: {...}
                import_rts: [<ASN:NN>],
                export_rts: [<ASN:NN>]
            }
        }
        """
        copy_details = deepcopy(port_details)
        formatted_details = {}
        for vpn_type in VPN_TYPES:
            if vpn_type in copy_details:
                formatted_details[vpn_type] = copy_details.pop(vpn_type)
                formatted_details[vpn_type].update(copy_details)

            elif notifier == BGPVPN_NOTIFIER:
                formatted_details[vpn_type] = (
                    self._copy_port_network_details(copy_details, vpn_type)
                )

        return formatted_details

    @lockutils.synchronized('bagpipe-bgp-agent')
    def _add_local_port_details(self, notifier, network_id, port_id,
                                port_info):
        """Create/update local port details in registered attachments list

        As follows:
        {
            port_id: <PORT_UUID>,
            vpn_instance_id: <NETWORK_UUID|PORT_UUID>,
            local_port: {
                linuxif: <PORT_NAME>,

                # Optional parameter only used in OVS agent
                ovs: {
                    plugged: True,
                    port_number: <PATCH_MPLS_FROM_TUN_OFPORT>,
                    to_vm_port_number: <PATCH_MPLS_TO_TUN_OFPORT>,
                    vlan: <LOCAL_VLAN_IDENTIFIER>
                }
            }

            # Optional parameter only used in Linux Bridge agent
            linuxbr: <LINUX_BRIDGE_NAME>,

            bagpipe: {
                evpn | ipvpn: {
                    mac_address: <PORT_MAC>,
                    ip_address: <PORT_IP>,
                    gateway_ip: <PORT_GATEWAY>,
                    import_rts: [<ASN:NN>, ...],
                    export_rts: [<ASN:NN>, ...]
                    ...
                }
            },
            bgpvpn: {
                evpn | ipvpn: {
                    mac_address: <PORT_MAC>,
                    ip_address: <PORT_IP>,
                    gateway_ip: <PORT_GATEWAY>,
                    import_rts: [<ASN:NN>, ...],
                    export_rts: [<ASN:NN>, ...]
                    ...
                }
            }
        }

        and return formatted port details to notifier for plug/unplug action.
        """
        try:
            # Update local port details to registered attachments list
            index, port_details = self._get_reg_attachment_for_port(network_id,
                                                                    port_id)

            # Format port details from notified informations
            formatted_details = self._format_port_details(port_info, notifier)

            if notifier in port_details:
                port_details[notifier].update(formatted_details)
            else:
                port_details[notifier] = formatted_details

            self.reg_attachments[network_id][index] = port_details
        except BGPAttachmentNotFound:
            LOG.info("Adding local port to attachments list")
            # Add local port details to registered attachments list
            port_details = {'port_id': port_id}

            # Update with bagpipe-bgp local_port details depending on
            # agent type
            port_details.update(self._get_local_port_for_attach(port_id,
                                                                network_id))

            if 'vpn_instance_id' not in port_info:
                port_details['vpn_instance_id'] = network_id
            else:
                port_details['vpn_instance_id'] = (
                    port_info.pop('vpn_instance_id'))

            # Format port details from notified informations
            port_details[notifier] = self._format_port_details(port_info,
                                                               notifier)
            self.reg_attachments[network_id].append(port_details)
        finally:
            LOG.debug("Updated attachments list: %s" %
                      self.reg_attachments[network_id])

        return port_details

    @lockutils.synchronized('bagpipe-bgp-agent')
    def _remove_registered_attachment(self, net_id, index,
                                      notifier, delete=True):
        """Remove/update a registered attachment for a notifier

        Remove/update notifier registered attachment at this index
        for the specified network, only if no
        exception occurred on bagpipe-bgp.
        """
        if (notifier in self.reg_attachments[net_id][index]):
            if notifier == BGPVPN_NOTIFIER and not delete:
                bgpvpn_reg_attachment = (
                    self.reg_attachments[net_id][index][notifier]
                )
                for vpn_type in VPN_TYPES:
                    if vpn_type in bgpvpn_reg_attachment:
                        for rt_type in ['import_rt', 'export_rt']:
                            if rt_type in bgpvpn_reg_attachment[vpn_type]:
                                del bgpvpn_reg_attachment[vpn_type][rt_type]
            elif delete:
                del self.reg_attachments[net_id][index][notifier]

            LOG.debug("Checking to remove attachment: %s",
                      self.reg_attachments[net_id][index])
            if not any(key in self.reg_attachments[net_id][index]
                       for key in BAGPIPE_NOTIFIERS):
                LOG.debug("Deleting attachment...")
                del self.reg_attachments[net_id][index]

                # Check if removing last registered attachment
                if not self.reg_attachments[net_id]:
                    LOG.debug("No attachment on network, deleting...")
                    del self.reg_attachments[net_id]

    @log_helpers.log_method_call
    def _enable_gw_redirect(self, vlan, gateway_ip):
        # Add ARP responder entry for default gateway in br-tun

        # We may compete with the ARP responder entry for the real MAC
        # if the router is on a network node and we are a compute node,
        # so we must add our rule with a higher priority

        # TODO(tmorin): Ideally we should use install_arp_responder, after
        # extending it to accept a 'priority' parameter, but we'd need to make
        # sure that delete_arp_responder (including the OF native
        # implementation) delete only rule with its cookie

        # (mostly copy-pasted ovs_ofctl....install_arp_responder)
        actions = a_const.ARP_RESPONDER_ACTIONS % {
            'mac': netaddr.EUI(DEFAULT_GATEWAY_MAC, dialect=netaddr.mac_unix),
            'ip': netaddr.IPAddress(gateway_ip),
        }
        self.tun_br.add_flow(table=a_const.ARP_RESPONDER,
                             priority=2,  # see above
                             dl_vlan=vlan,
                             proto='arp',
                             arp_op=0x01,  # the rule in install_arp_responder
                                           # does not restrict to requests,
                                           # but it seems what is right to do
                             arp_tpa='%s' % gateway_ip,
                             actions=actions)

    @log_helpers.log_method_call
    def _disable_gw_redirect(self, vlan, gateway_ip):
        # Remove ARP responder entry for default gateway in br-tun

        # NOTE(tmorin): do a clean self.tun_br.delete_flows call once native
        # ofswitch stops overloading delete_flows with an implementation
        # not behaving like the ovs_lib one.
        # (see https://bugs.launchpad.net/neutron/+bug/1628455 )
        ovs_agent_extension_api.OVSCookieBridge.delete_flows(
            self.tun_br,
            table=a_const.ARP_RESPONDER,
            dl_vlan=vlan,
            proto='arp',
            arp_op=0x01,
            arp_tpa='%s' % gateway_ip)

        # TODO(tmorin): nothing currently prevents the base agent from
        # deleting our rule on Router unplug (because its delete_flows is
        # not restricted to rules having its own cookie)

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
    def _unhide_real_gw_arp(self, vlan, gateway_info):
        LOG.debug("unblocking ARP from real gateway for vlan %d (%s)",
                  vlan, gateway_info)
        self.int_br.delete_flows(table=a_const.LOCAL_SWITCHING,
                                 proto='arp',
                                 dl_src=gateway_info.mac,
                                 arp_sha=gateway_info.mac)

    def _do_local_port_plug(self, local_port_details):
        """Send local port attach request to bagpipe-bgp."""
        all_plug_details = (
            self._get_local_port_plug_details(local_port_details)
        )

        # First plug E-VPNs because they could be plugged into IP-VPNs
        for vpn_type in [t for t in VPN_TYPES
                         if t in all_plug_details]:
            for plug_detail in all_plug_details[vpn_type]:
                self.send_attach_local_port(plug_detail)

    def _do_local_port_unplug(self, local_port_details, vpn_types=None,
                              notifiers=None):
        """Send local port detach request to bagpipe-bgp."""
        all_unplug_details = (
            self._get_local_port_plug_details(local_port_details,
                                              vpn_types=vpn_types,
                                              notifiers=notifiers)
        )

        # First unplug IP-VPNs because E-VPNs could be plugged into them
        for vpn_type in [t for t in VPN_TYPES[::-1]
                         if t in all_unplug_details]:
            for unplug_detail in all_unplug_details[vpn_type]:
                self.send_detach_local_port(unplug_detail)

    @log_helpers.log_method_call
    def _check_arp_voodoo_plug(self, net_id, port_id, gateway_info):

        if (self.agent_type != n_const.AGENT_TYPE_OVS):
            return

        # See if we need to update gateway redirection and gateway ARP
        # voodoo

        vlan = self.get_local_vlan(port_id)

        # NOTE(tmorin): can be improved, only needed on first plug...
        self._enable_gw_redirect(vlan, gateway_info.ip)

        # update real gateway ARP blocking...
        # remove old ARP blocking ?
        if (net_id in self.gateway_info_for_net and
                self.gateway_info_for_net.get(net_id).mac is not None):
            self._unhide_real_gw_arp(vlan,
                                     self.gateway_info_for_net.get(net_id))
        # add new ARP blocking ?
        if gateway_info.mac:
            self._hide_real_gw_arp(vlan, gateway_info)

    @log_helpers.log_method_call
    def _check_arp_voodoo_unplug(self, net_id, port_id):

        if (self.agent_type != n_const.AGENT_TYPE_OVS):
            return

        # if last port for this network, then cleanup gateway redirection
        # NOTE(tmorin): shouldn't we check for last *ipvpn* attachment?
        if len(self.reg_attachments.get(net_id)) == 1:
            LOG.debug("last unplug, undoing voodoo ARP")
            # NOTE(tmorin): vlan lookup might break if port is already
            # unplugged from bridge ?
            vlan = self.get_local_vlan(port_id)
            self._disable_gw_redirect(vlan,
                                      self.gateway_info_for_net[net_id].ip)
            if self.gateway_info_for_net.get(net_id).mac is not None:
                self._unhide_real_gw_arp(vlan,
                                         self.gateway_info_for_net[net_id])

    # BaGPipe RPC callbacks
    # ----------------------
    def bagpipe_port_attach(self, context, port_bagpipe_info):
        LOG.debug("bagpipe_port_attach received with port info: %s",
                  port_bagpipe_info)
        port_id = port_bagpipe_info.pop('id')
        net_id = port_bagpipe_info.pop('network_id')

        # Add/Update local port details in registered attachments list
        port_details = self._add_local_port_details(BAGPIPE_NOTIFIER,
                                                    net_id,
                                                    port_id,
                                                    port_bagpipe_info)

        # Attach port on bagpipe-bgp
        LOG.debug(
            "Attaching BaGPipe L2 port %s on bagpipe-bgp with "
            "details %s", port_details['local_port']['linuxif'], port_details)

        self._do_local_port_plug(port_details)

    def bagpipe_port_detach(self, context, port_bagpipe_info):
        LOG.debug("bagpipe_port_detach received with port info %s",
                  port_bagpipe_info)
        port_id = port_bagpipe_info['id']
        net_id = port_bagpipe_info['network_id']

        # Detach port from bagpipe-bgp
        LOG.debug("Detaching port %s from bagpipe-bgp", port_id)
        try:
            index, port_details = self._get_reg_attachment_for_port(net_id,
                                                                    port_id)
        except BGPAttachmentNotFound as e:
            LOG.error("bagpipe-bgp agent inconsistent for BaGPipe L2 or "
                      "updated with another detach: %s", str(e))
        else:
            try:
                self._do_local_port_unplug(port_details)
            except BaGPipeBGPException as e:
                LOG.error("Can't detach port from bagpipe-bgp: %s", str(e))
            finally:
                self._remove_registered_attachment(net_id, index,
                                                   BAGPIPE_NOTIFIER)

    # BGPVPN callbacks
    # -----------------------------
    def _update_local_port_bgpvpn_details(self, network_id, index,
                                          evpn, ipvpn):
        attachment = self.reg_attachments[network_id][index]

        if evpn:
            if EVPN in attachment[BGPVPN_NOTIFIER]:
                attachment[BGPVPN_NOTIFIER][EVPN].update(evpn)

        if ipvpn:
            if IPVPN in attachment[BGPVPN_NOTIFIER]:
                attachment[BGPVPN_NOTIFIER][IPVPN].update(ipvpn)

        self.reg_attachments[network_id][index] = attachment

        return attachment

    @log_helpers.log_method_call
    def _attach_all_ports_on_bgpvpn(self, network_id, bgpvpn):
        # Attach all ports on BaGPipe-BGP for to the specified BGP VPN

        evpn = bgpvpn.get(EVPN, bgpvpn.get(BGPVPN_L2))
        ipvpn = bgpvpn.get(IPVPN, bgpvpn.get(BGPVPN_L3))

        new_gw_info = GatewayInfo(
            bgpvpn.get('gateway_mac'),
            self.gateway_info_for_net[network_id].ip
        )

        for index, __ in enumerate(self.reg_attachments[network_id]):
            updated_attachment = (
                self._update_local_port_bgpvpn_details(network_id, index,
                                                       evpn, ipvpn)
            )

            if has_ipvpn_attachement(updated_attachment.get(BGPVPN_NOTIFIER)):
                if new_gw_info != NO_GW_INFO:
                    self._check_arp_voodoo_plug(
                        network_id,
                        updated_attachment['port_id'],
                        new_gw_info
                    )
                if new_gw_info.mac:
                    updated_attachment.get(BGPVPN_NOTIFIER).get(IPVPN).update(
                        {'gateway_mac': new_gw_info.mac}
                    )

            self._do_local_port_plug(updated_attachment)

        if bgpvpn.get('gateway_mac'):
            self.gateway_info_for_net[network_id] = new_gw_info

    @log_helpers.log_method_call
    def _detach_all_ports_from_bgpvpn(self, network_id):
        # Detach all ports from BaGPipe-BGP for the specified BGP VPN

        for index, port_details in enumerate(self.reg_attachments[network_id]):
            try:
                self._do_local_port_unplug(port_details,
                                           notifiers=[BGPVPN_NOTIFIER])
                if has_ipvpn_attachement(port_details.get(BGPVPN_NOTIFIER)):
                    self._check_arp_voodoo_unplug(network_id,
                                                  port_details['port_id'])
            except BaGPipeBGPException as e:
                LOG.error("Can't detach port from bagpipe-bgp: %s", str(e))
            finally:
                self._remove_registered_attachment(network_id, index,
                                                   BGPVPN_NOTIFIER,
                                                   delete=False)

    @log_helpers.log_method_call
    def create_bgpvpn(self, context, bgpvpn):
        self.update_bgpvpn(context, bgpvpn)

    @log_helpers.log_method_call
    def update_bgpvpn(self, context, bgpvpn):
        self._attach_all_ports_on_bgpvpn(bgpvpn['network_id'], bgpvpn)

    @log_helpers.log_method_call
    def delete_bgpvpn(self, context, bgpvpn):
        self._detach_all_ports_from_bgpvpn(bgpvpn['network_id'])

    @log_helpers.log_method_call
    def bgpvpn_port_attach(self, context, port_bgpvpn_info):
        port_id = port_bgpvpn_info.pop('id')
        net_id = port_bgpvpn_info.pop('network_id')

        # Map l2vpn, l3vpn keys to evpn, ipvpn ones
        for bgpvpn_type in BGPVPN_TYPES:
            if bgpvpn_type in port_bgpvpn_info:
                port_bgpvpn_info[BGPVPN_TYPES_MAP[bgpvpn_type]] = (
                    port_bgpvpn_info.pop(bgpvpn_type)
                )

        gateway_info = GatewayInfo(port_bgpvpn_info.get('gateway_mac'),
                                   port_bgpvpn_info.get('gateway_ip'))

        if IPVPN in port_bgpvpn_info:
            self._check_arp_voodoo_plug(net_id, port_id, gateway_info)

        # Remember the gateway MAC
        self.gateway_info_for_net[net_id] = gateway_info

        # Add/Update port BGPVPN details in registered attachments list
        port_details = self._add_local_port_details(BGPVPN_NOTIFIER,
                                                    net_id,
                                                    port_id,
                                                    port_bgpvpn_info)

        # Attach port on bagpipe-bgp
        LOG.debug("Attaching BGPVPN port %s on bagpipe-bgp with details %s" %
                  (port_details['local_port']['linuxif'], port_details))

        self._do_local_port_plug(port_details)

    @log_helpers.log_method_call
    def bgpvpn_port_detach(self, context, port_bgpvpn_info):
        port_id = port_bgpvpn_info['id']
        net_id = port_bgpvpn_info['network_id']

        # Retrieve local port details index in BGP registered attachment list
        try:
            index, details = self._get_reg_attachment_for_port(net_id,
                                                               port_id)
        except BGPAttachmentNotFound as e:
            LOG.warning("BGPVPN port detach, but no previous attachment found:"
                        " %s", str(e))
        else:
            try:
                self._do_local_port_unplug(details)

                if has_ipvpn_attachement(details.get(BGPVPN_NOTIFIER)):
                    self._check_arp_voodoo_unplug(net_id, port_id)
            except BaGPipeBGPException as e:
                LOG.error("Can't detach BGPVPN port from bagpipe-bgp %s",
                          str(e))
            finally:
                self._remove_registered_attachment(net_id, index,
                                                   BGPVPN_NOTIFIER)
