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

import itertools

import socket

import httplib2
import json

from collections import defaultdict

from oslo.config import cfg

from oslo_log import log as logging

from oslo_concurrency import lockutils

from neutron.agent.common import config
from neutron.agent.common import ovs_lib
from neutron.common import constants as q_const
from neutron.common import exceptions as q_exc
from neutron.common import topics
from neutron.openstack.common import loopingcall

from networking_bagpipe_l2.rpc import agent as bagpipe_agent_rpc
from networking_bagpipe_l2.rpc.client import topics_BAGPIPE

from networking_bagpipe_l2.agent.bgpvpn import rpc_agent as bgpvpn_agent_rpc
from networking_bagpipe_l2.agent.bgpvpn.rpc_client import topics_BAGPIPE_BGPVPN

from neutron.plugins.openvswitch.common import constants

LOG = logging.getLogger(__name__)

DEFAULT_GATEWAY_MAC = "00:00:5e:00:43:64"

bagpipe_bgp_opts = [
    cfg.IntOpt('ping_interval', default=10,
               help=_("The number of seconds the BGP component client will "
                      "wait between polling for restart detection.")),
    cfg.StrOpt('bagpipe_bgp_ip', default='127.0.0.1',
               help=_("BGP component REST service IP address.")),
    cfg.IntOpt('bagpipe_bgp_port', default=8082,
               help=_("BGP component REST service IP port.")),
    cfg.StrOpt('mpls_bridge', default='br-mpls',
               help=_("OVS MPLS bridge to use")),
    cfg.StrOpt('tun_to_mpls_peer_patch_port', default='patch-to-mpls',
               help=_("OVS Peer patch port in tunnel bridge to MPLS bridge"
                      "(traffic to MPLS bridge)")),
    cfg.StrOpt('tun_from_mpls_peer_patch_port', default='patch-from-mpls',
               help=_("OVS Peer patch port in tunnel bridge to MPLS bridge "
                      "(traffic from MPLS bridge)")),
    cfg.StrOpt('mpls_to_tun_peer_patch_port', default='patch-to-tun',
               help=_("OVS Peer patch port in MPLS bridge to tunnel bridge"
                      "(traffic to tunnel bridge)")),
    cfg.StrOpt('mpls_from_tun_peer_patch_port', default='patch-from-tun',
               help=_("OVS Peer patch port in MPLS bridge to tunnel bridge "
                      "(traffic from tunnel bridge)")),
]
cfg.CONF.register_opts(bagpipe_bgp_opts, "BAGPIPE")
config.register_agent_state_opts_helper(cfg.CONF)


class BGPAttachmentNotFound(q_exc.NotFound):
    message = "Local port %(local_port)s details could not be found"


class BaGPipeBGPException(q_exc.NeutronException):
    message = "An exception occurred when calling BaGPipe BGP component \
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
        LOG.debug("BaGPipe BGP component client request: %s %s [%s]" %
                  (method, action, str(body)))

        if type(body) is dict:
            body = json.dumps(body)
        try:
            headers = {'User-Agent': self.client_name,
                       "Content-Type": "application/json",
                       "Accept": "application/json"}
            uri = "http://%s:%s/%s" % (self.host, self.port, action)

            http = httplib2.Http()
            response, content = http.request(uri, method, body, headers)
            LOG.debug("BaGPipe BGP component returns [%s:%s]" %
                      (str(response.status), content))

            if response.status == 200:
                if content and len(content) > 1:
                    return json.loads(content)
            else:
                reason = (
                    "An HTTP operation has failed on BaGPipe BGP component."
                )
                raise BaGPipeBGPException(reason=reason)
        except (socket.error, IOError) as e:
            reason = "Failed to connect to BaGPipe BGP component: %s" % str(e)
            raise BaGPipeBGPException(reason=reason)

    def get(self, action):
        return self.do_request("GET", action)

    def post(self, action, body=None):
        return self.do_request("POST", action, body=body)

    def put(self, action, body=None):
        return self.do_request("PUT", action, body=body)

    def delete(self, action):
        return self.do_request("DELETE", action)


class BaGPipeBGPAgent(HTTPClientBase,
                      bagpipe_agent_rpc.BaGPipeAgentRpcCallBackMixin,
                      bgpvpn_agent_rpc.BGPVPNAgentRpcCallBackMixin
                      ):
    """Implements a BaGPipe-BGP REST client"""

    # BaGPipe BGP component status
    BAGPIPEBGP_UP = 'UP'
    BAGPIPEBGP_DOWN = 'DOWN'

    def __init__(self, agent_type, br_mgr=None,
                 int_br=None, tun_br=None, patch_int_ofport=0,
                 local_vlan_map={}, setup_entry_for_arp_reply=None):
        """Create a new BaGPipe-BGP REST service client.

        :param agent_type: BaGPipe BGP agent type (Linux bridge or OVS)
        :param br_mgr: Linux Bridge manager
        :param int_br: OVS integration bridge
        :param tun_br: OVS tunnel bridge
        :param patch_int_ofport: Patch port linking OVS integration and
                                 tunnel bridges
        :param local_vlan_map: OVS agent LocalVLANMapping objects list, that
                               tracks (vlan, lsw_id, vif_ids) mapping
        :param setup_entry_for_arp_reply: OVS agent method that set ARP
                                          responder entry
        """
        super(BaGPipeBGPAgent,
              self).__init__(cfg.CONF.BAGPIPE.bagpipe_bgp_ip,
                             cfg.CONF.BAGPIPE.bagpipe_bgp_port, agent_type)

        self.agent_type = agent_type
        self.br_mgr = br_mgr
        self.int_br = int_br
        self.tun_br = tun_br
        self.patch_int_ofport = patch_int_ofport
        self.local_vlan_map = local_vlan_map
        self.setup_entry_for_arp_reply = setup_entry_for_arp_reply

        self.ping_interval = cfg.CONF.BAGPIPE.ping_interval

        self.reg_attachments = defaultdict(list)
        self.bagpipe_bgp_status = self.BAGPIPEBGP_DOWN
        self.seq_num = 0

        if self.agent_type == q_const.AGENT_TYPE_OVS:
            self.setup_mpls_br(cfg.CONF.BAGPIPE.mpls_bridge)

        # Starts a greenthread for BaGPipe BGP component status polling
        self._start_bagpipe_bgp_status_polling(self.ping_interval)

    def _check_bagpipe_bgp_status(self):
        """Trigger refresh on bagpipe-bgp restarts

        Check if BaGPipe BGP component has restarted while sending ping request
        to detect sequence number change.
        If a restart is detected, re-send all registered attachments to BaGPipe
        BGP component.
        """
        new_seq_num = self.request_ping()

        # Check BaGPipe BGP component restart
        if new_seq_num != self.seq_num:
            if new_seq_num != -1:
                if self.seq_num != 0:
                    LOG.warning("BaGPipe BGP component restart detected...")
                else:
                    LOG.info("BaGPipe BGP component successfully detected")

                self.seq_num = new_seq_num
                self.bagpipe_bgp_status = self.BAGPIPEBGP_UP

                # Re-send all registered attachments to BGP component
                if self.reg_attachments:
                    LOG.info("Sending all registered attachments to BaGPipe "
                             "BGP component")
                    LOG.debug("Registered attachments list: %s" %
                              self.reg_attachments)
                    for _, attachment_list in self.reg_attachments.iteritems():
                        if attachment_list:
                            for attachment in attachment_list:
                                self._do_local_port_bagpipe_plug(attachment)
                                self._do_local_port_bgpvpn_plug(attachment)
                else:
                    LOG.info("No attachment to send to BaGPipe BGP component")
            else:
                self.bagpipe_bgp_status = self.BAGPIPEBGP_DOWN

    def _start_bagpipe_bgp_status_polling(self, ping_interval=10):
        # Start BaGPipe BGP component status polling at regular interval
        status_loop = loopingcall.FixedIntervalLoopingCall(
            self._check_bagpipe_bgp_status)
        status_loop.start(interval=ping_interval,
                          initial_delay=ping_interval)  # TM: why not zero ?

    def _get_reg_attachment_for_port(self, network_id, local_port_id):
        # Retrieve local port index and details in BGP registered attachments
        # list for the specified network and port identifiers

        LOG.debug("Getting local port details for port %s on network %s" %
                  (local_port_id, network_id))

        index = -1
        details = None
        for i, attachment in enumerate(self.reg_attachments[network_id]):
            if (attachment['port_id'] == local_port_id):
                LOG.debug("Local port details found at index %s: %s" %
                          (i, attachment))
                index = i
                details = attachment
                break

        if index == -1:
            LOG.info("No details found for local port %s", local_port_id)
            raise BGPAttachmentNotFound(local_port=local_port_id)

        return index, details

    @lockutils.synchronized('bagpipe-bgp-agent')
    def _remove_reg_attachment_for_index(self, network_id, index):
        # Remove local port details at index in BGP registered attachments list
        # for the specified network

        LOG.debug(
            "Removing attachment %s", self.reg_attachments[network_id][index]
        )
        if not any(key in self.reg_attachments[network_id][index]
                   for key in ('evpn', 'evpn_bgpvpn', 'ipvpn_bgpvpn')):
            LOG.debug("Deleting attachment...")
            del self.reg_attachments[network_id][index]

            # Check if removing last registered attachment
            if not self.reg_attachments[network_id]:
                LOG.debug("No attachment on network, deleting...")
                del self.reg_attachments[network_id]

    def _concatenate_route_target(self, route_target1, route_target2):
        return dict([(k, list(route_target1[k]).append(route_target2[k]))
                    for k in route_target1 if k in route_target2])

    def _remove_route_target(self, route_target1, route_target2):
        return dict([(k, [rt for rt in route_target1[k]
                          if rt not in route_target2[k]])
                    for k in route_target1 if k in route_target2])

    def _copy_local_port_and_network_details(self, local_port_details):
        local_port_copy = {}
        for key in ('local_port', 'mac_address', 'ip_address', 'gateway_ip'):
            local_port_copy[key] = local_port_details[key]

        if 'linuxbr' in local_port_details:
            local_port_copy['linuxbr'] = local_port_details['linuxbr']

        return local_port_copy

    def _get_local_port_with_evpn_details(self, local_port_details,
                                          evpn_bgpvpn=None):
        local_port_evpn_details = (
            self._copy_local_port_and_network_details(local_port_details)
        )
        local_port_evpn_details['vpn_instance_id'] = (
            '%s_evpn' % local_port_details['vpn_instance_id']
        )
        local_port_evpn_details['vpn_type'] = 'evpn'

        if 'evpn_bgpvpn' in local_port_details:
            if evpn_bgpvpn:
                local_port_evpn_details.update(evpn_bgpvpn)
            else:
                if 'evpn' in local_port_details:
                    evpn_details = (
                        self._concatenate_route_target(
                            local_port_details['evpn'],
                            local_port_details['evpn_bgpvpn']
                        )
                    )
                    local_port_evpn_details.update(evpn_details)
                else:
                    local_port_evpn_details.update(
                        local_port_details['evpn_bgpvpn']
                    )
        else:
            if 'evpn' in local_port_details:
                local_port_evpn_details.update(local_port_details['evpn'])

        LOG.debug('Local port E-VPN details %s' % local_port_evpn_details)
        return local_port_evpn_details

    def _get_local_port_with_ipvpn_details(self, local_port_details,
                                           ipvpn_bgpvpn=None):
        local_port_ipvpn_details = (
            self._copy_local_port_and_network_details(local_port_details)
        )
        local_port_ipvpn_details['vpn_instance_id'] = (
            '%s_ipvpn' % local_port_details['vpn_instance_id']
        )
        local_port_ipvpn_details['vpn_type'] = 'ipvpn'

        # Check if ipvpn has to be plugged into an evpn
        if any(key in local_port_details for key in ('evpn', 'evpn_bgpvpn')):
            LOG.debug("IP-VPN has to be plugged into E-VPN")
            local_port_ipvpn_details['local_port'] = (
                {'evpn': {
                    'id': '%s_evpn' % local_port_details['vpn_instance_id']}}
            )

        if ipvpn_bgpvpn:
            local_port_ipvpn_details.update(ipvpn_bgpvpn)
        else:
            local_port_ipvpn_details.update(local_port_details['ipvpn_bgpvpn'])

        LOG.debug('Local port IP-VPN details %s' % local_port_ipvpn_details)
        return local_port_ipvpn_details

    # BaGPipe BGP component REST API requests
    # ----------------------------------------
    def request_ping(self):
        """Send ping request to BaGPipe BGP component to get sequence number"""
        try:
            response = self.get('ping')
            LOG.debug("BaGPipe BGP component PING response received with "
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
                LOG.debug("Local port has been attached on BGP component with "
                          "details %s" % local_port_details)
            except BaGPipeBGPException as e:
                LOG.error("Can't attach local port on BaGPipe BGP "
                          "component: %s", str(e))

    def send_detach_local_port(self, local_port_details):
        """Send local port detach request to BaGPipe-BGP if running"""
        if self.bagpipe_bgp_status is self.BAGPIPEBGP_UP:
            try:
                self.post('detach_localport', local_port_details)
                LOG.debug("Local port has been detached from BaGPipe BGP "
                          "component with details %s" % local_port_details)
            except BaGPipeBGPException as e:
                LOG.error("Can't detach local port from BaGPipe BGP "
                          "component: %s", str(e))
                raise

    def setup_mpls_br(self, mpls_br):
        '''Setup the MPLS bridge for BaGPipe BGP VPN.

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

        # patch ports for traffic from tun to mpls
        self.patch_tun_to_mpls_ofport = self.tun_br.add_patch_port(
            cfg.CONF.BAGPIPE.tun_to_mpls_peer_patch_port,
            cfg.CONF.BAGPIPE.mpls_from_tun_peer_patch_port)
        self.patch_mpls_from_tun_ofport = self.mpls_br.add_patch_port(
            cfg.CONF.BAGPIPE.mpls_from_tun_peer_patch_port,
            cfg.CONF.BAGPIPE.tun_to_mpls_peer_patch_port)

        # patch ports for traffic from mpls to tun
        self.patch_mpls_to_tun_ofport = self.mpls_br.add_patch_port(
            cfg.CONF.BAGPIPE.mpls_to_tun_peer_patch_port,
            cfg.CONF.BAGPIPE.tun_from_mpls_peer_patch_port)
        self.patch_tun_from_mpls_ofport = self.tun_br.add_patch_port(
            cfg.CONF.BAGPIPE.tun_from_mpls_peer_patch_port,
            cfg.CONF.BAGPIPE.mpls_to_tun_peer_patch_port)

        if (int(self.patch_tun_to_mpls_ofport) < 0 or
                int(self.patch_mpls_from_tun_ofport) < 0 or
                int(self.patch_mpls_to_tun_ofport) < 0 or
                int(self.patch_tun_from_mpls_ofport) < 0):
            LOG.error("Failed to create OVS patch port. Cannot have "
                      "MPLS enabled on this agent, since this version "
                      "of OVS does not support patch ports. "
                      "Agent terminated!")
            exit(1)

        # In br-tun, redirect all traffic from VMs toward default gateway MAC
        # address to the MPLS bridge.  Redirect traffic from the MPLS bridge to
        # br-int.

        # priority >0 is needed or we hit the rule redirecting unicast to
        # the UCAST_TO_TUN table
        self.tun_br.add_flow(
            table=constants.PATCH_LV_TO_TUN,
            priority=1,
            in_port=self.patch_int_ofport,
            dl_dst=DEFAULT_GATEWAY_MAC,
            actions="output:%s" % self.patch_tun_to_mpls_ofport
        )

        self.tun_br.add_flow(in_port=self.patch_tun_from_mpls_ofport,
                             actions="output:%s" % self.patch_int_ofport)

    def _get_port_details_for_attach(self, port_id, net_uuid):
        details = {
            'port_id': port_id,
            'vpn_instance_id': net_uuid
        }
        if self.agent_type == q_const.AGENT_TYPE_LINUXBRIDGE:
            port_name = self.br_mgr.get_tap_device_name(port_id)
            bridge_name = self.br_mgr.get_bridge_name(net_uuid)

            details.update({
                'linuxbr': bridge_name,
                'local_port': {
                    'linuxif': port_name
                }
            })
        elif self.agent_type == q_const.AGENT_TYPE_OVS:
            port = self.int_br.get_vif_port_by_id(port_id)
            lvm = self.local_vlan_map[net_uuid]

            details.update({
                'local_port': {
                    'linuxif': port.port_name,
                    'ovs': {
                        'plugged': True,
                        'port_number': self.patch_mpls_from_tun_ofport,
                        'to_vm_port_number': self.patch_mpls_to_tun_ofport,
                        'vlan': lvm.vlan
                    }
                }
            })

        return details

    @lockutils.synchronized('bagpipe-bgp-agent')
    def _add_local_port_details(self, network_id, port_id, port_info):
        # Update local port details to registered attachments list
        try:
            index, details = self._get_reg_attachment_for_port(network_id,
                                                               port_id)

            # Update local port details with BaGPipe informations
            if 'evpn' in port_info:
                details['evpn'] = port_info['evpn']

            # Update local port details with BGP VPN informations
            if 'l3vpn' in port_info:
                details['ipvpn_bgpvpn'] = port_info['l3vpn']

            if 'l2vpn' in port_info:
                details['evpn_bgpvpn'] = port_info['l2vpn']

            self.reg_attachments[network_id][index] = details
        except BGPAttachmentNotFound:
            # Add local port details to registered attachments list
            details = self._get_port_details_for_attach(port_id, network_id)

            if 'l3vpn' in port_info:
                port_info['ipvpn_bgpvpn'] = port_info.pop('l3vpn')

            if 'l2vpn' in port_info:
                port_info['evpn_bgpvpn'] = port_info.pop('l2vpn')

            # Route targets, IP, MAC, and gateway information is passed as-is
            details.update(port_info)
            self.reg_attachments[network_id].append(details)
        finally:
            return details

    # BaGPipe RPC callbacks
    # ----------------------
    def _do_local_port_bagpipe_plug(self, local_port_details):
        # Send local port attach request to BaGPipe BGP if plugged on a BaGPipe
        # network.

        if 'evpn' in local_port_details:
            local_port_evpn_details = (
                self._get_local_port_with_evpn_details(local_port_details)
            )
            self.send_attach_local_port(local_port_evpn_details)

    def _do_local_port_bagpipe_unplug(self, network_id, index):
        # Send local port detach request to BaGPipe BGP if plugged on
        # a BaGPipe network and update BGP registered attachments list

        local_port_details = self.reg_attachments[network_id][index]

        if 'evpn' in local_port_details:
            try:
                local_port_evpn_details = (
                    self._get_local_port_with_evpn_details(local_port_details)
                )
                self.send_detach_local_port(local_port_evpn_details)

                # Remove local port BaGPipe informations from local port
                # details in registered attachments list, only if no exception
                # occurred on BaGPipe BGP
                del local_port_details['evpn']
                self.reg_attachments[network_id][index] = local_port_details
            except BaGPipeBGPException:
                pass

    def setup_rpc(self, endpoints, connection, main_topic):

        endpoints.append(self)

        # This mimics code in neutron.agent.rpc that create_consumers,
        # code which we can not easily extend/reuse for our purpose yet
        # (another alternative would be to make setup_rpc extensible
        #  for additional consumers)

        prefix = main_topic
        topic_details = [[topics_BAGPIPE, topics.UPDATE, cfg.CONF.host],
                         [topics_BAGPIPE_BGPVPN, topics.UPDATE, cfg.CONF.host]
                         ]

        # what is below is a copy-paste from rpc.create_consumers
        # we just skip create_connection
        for details in topic_details:
            topic, operation, node_name = itertools.islice(
                itertools.chain(details, [None]), 3)

            topic_name = topics.get_topic_name(prefix, topic, operation)
            connection.create_consumer(topic_name, endpoints, fanout=True)
            if node_name:
                node_topic_name = '%s.%s' % (topic_name, node_name)
                connection.create_consumer(node_topic_name,
                                           endpoints,
                                           fanout=False)
        # we now need to trigger consumption on new server...
        connection.consume_in_threads()

    def bagpipe_port_attach(self, context, port_bagpipe_info):
        LOG.debug("bagpipe_port_attach received with port info: %s",
                  port_bagpipe_info)
        port_id = port_bagpipe_info.pop('id')
        net_uuid = port_bagpipe_info.pop('network_id')

        # Add/Update local port details in registered attachments list
        port_details = self._add_local_port_details(net_uuid,
                                                    port_id,
                                                    port_bagpipe_info)

        # Attach port on BaGPipe BGP component
        LOG.debug(
            "Attaching port %s on BaGPipe BGP component with details %s",
            port_details['local_port']['linuxif'], port_details)

        self._do_local_port_bagpipe_plug(port_details)

    def bagpipe_port_detach(self, context, port_bagpipe_info):
        LOG.debug("bagpipe_port_detach received with port info %s",
                  port_bagpipe_info)
        port_id = port_bagpipe_info['id']
        net_uuid = port_bagpipe_info['network_id']

        # Detach port from BaGPipe BGP component
        LOG.debug("Detaching port %s from BaGPipe BGP component", port_id)
        try:
            index, _ = self._get_reg_attachment_for_port(net_uuid, port_id)
            self._do_local_port_bagpipe_unplug(net_uuid, index)
            self._remove_reg_attachment_for_index(net_uuid, index)
        except BGPAttachmentNotFound as e:
            LOG.error("Can't detach port from BaGPipe BGP "
                      "component: %s", str(e))

    # BGP VPN connection callbacks
    # -----------------------------
    def _update_local_port_bgpvpn_details(self, network_id, index,
                                          ipvpn_bgpvpn, evpn_bgpvpn):
        attachment = self.reg_attachments[network_id][index]

        if ipvpn_bgpvpn:
            attachment['ipvpn_bgpvpn'] = ipvpn_bgpvpn

        if evpn_bgpvpn:
            attachment['evpn_bgpvpn'] = evpn_bgpvpn

        self.reg_attachments[network_id][index] = attachment

        return attachment

    def _attach_all_ports_on_bgpvpn_network(self, network_id, ipvpn_bgpvpn,
                                            evpn_bgpvpn):
        # Attach all ports on BaGPipe-BGP for to the specified BGP VPN network

        LOG.debug("Attaching all BGP registered attachments on BGP VPN "
                  "network %s with %s - %s" %
                  (network_id, ipvpn_bgpvpn, evpn_bgpvpn))

        for index, _ in enumerate(self.reg_attachments[network_id]):
            updated_attachment = (
                self._update_local_port_bgpvpn_details(network_id,
                                                       index,
                                                       ipvpn_bgpvpn,
                                                       evpn_bgpvpn)
            )

            self._do_local_port_bgpvpn_plug(updated_attachment)

    def _detach_all_ports_from_bgpvpn_network(self, network_id, ipvpn_bgpvpn,
                                              evpn_bgpvpn):
        # Detach all ports from BaGPipe-BGP for the specified BGP VPN network

        LOG.debug("Detaching all BGP registered attachments from BGP VPN "
                  "network %s" % network_id)

        for index, _ in enumerate(self.reg_attachments[network_id]):
            self._do_local_port_bgpvpn_unplug(network_id,
                                              index,
                                              ipvpn_bgpvpn,
                                              evpn_bgpvpn)

    def _do_local_port_bgpvpn_plug(self, local_port_details):
        # Send local port attach request to BaGPipe BGP component if plugged
        # on a BGP VPN network.

        if 'evpn_bgpvpn' in local_port_details:
            local_port_evpn_details = (
                self._get_local_port_with_evpn_details(local_port_details)
            )
            self.send_attach_local_port(local_port_evpn_details)

        if 'ipvpn_bgpvpn' in local_port_details:
            local_port_ipvpn_details = (
                self._get_local_port_with_ipvpn_details(local_port_details)
            )
            self.send_attach_local_port(local_port_ipvpn_details)

    def _do_local_port_bgpvpn_unplug(self, network_id, index,
                                     ipvpn_bgpvpn=None, evpn_bgpvpn=None):
        # Send local port detach request to BaGPipe BGP if plugged
        # on a BGP VPN network and update BGP registered attachments list.

        local_port_details = self.reg_attachments[network_id][index]

        # TODO(tmorin): factor out the two cases for ipvpn and evpn
        # TODO(tmorin): check error handling on bagpipe-bgp exceptions
        if 'ipvpn_bgpvpn' in local_port_details:
            try:
                if ipvpn_bgpvpn:
                    local_port_ipvpn_details = (
                        self._get_local_port_with_ipvpn_details(
                            local_port_details,
                            ipvpn_bgpvpn)
                    )
                else:
                    local_port_ipvpn_details = (
                        self._get_local_port_with_ipvpn_details(
                            local_port_details
                        )
                    )
                    ipvpn_bgpvpn = local_port_details['ipvpn_bgpvpn']

                self.send_detach_local_port(local_port_ipvpn_details)

                # Remove local port BGP VPN informations from local port
                # details in registered attachments list, only if no exception
                # occurred on BaGPipe BGP
                updated_ipvpn = (
                    self._remove_route_target(
                        local_port_details['ipvpn_bgpvpn'],
                        ipvpn_bgpvpn
                    )
                )

                if updated_ipvpn['import_rt'] or updated_ipvpn['export_rt']:
                    local_port_details['ipvpn_bgpvpn'] = updated_ipvpn
                else:
                    del local_port_details['ipvpn_bgpvpn']

                self.reg_attachments[network_id][index] = local_port_details
            except BaGPipeBGPException:
                pass

        if 'evpn_bgpvpn' in local_port_details:
            try:
                if evpn_bgpvpn:
                    local_port_evpn_details = (
                        self._get_local_port_with_evpn_details(
                            local_port_details,
                            evpn_bgpvpn
                        )
                    )
                else:
                    local_port_evpn_details = (
                        self._get_local_port_with_evpn_details(
                            local_port_details
                        )
                    )
                    evpn_bgpvpn = local_port_details['evpn_bgpvpn']

                self.send_detach_local_port(local_port_evpn_details)

                # Remove local port BGP VPN informations from local port
                # details in registered attachments list, only if no exception
                # occurred on BaGPipe BGP
                updated_evpn = (
                    self._remove_route_target(
                        local_port_details['evpn_bgpvpn'],
                        evpn_bgpvpn
                    )
                )

                if updated_evpn['import_rt'] or updated_evpn['export_rt']:
                    local_port_details['evpn_bgpvpn'] = updated_evpn
                else:
                    del local_port_details['evpn_bgpvpn']

                self.reg_attachments[network_id][index] = local_port_details
            except BaGPipeBGPException:
                pass

    def create_bgpvpn_connection(self, context, bgpvpn_connection):
        LOG.debug("create_bgpvpn_connection received with details %s",
                  bgpvpn_connection)
        net_uuid = bgpvpn_connection['network_id']
        ipvpn_bgpvpn = (
            bgpvpn_connection['l3vpn'] if 'l3vpn' in bgpvpn_connection else {}
        )
        evpn_bgpvpn = (
            bgpvpn_connection['l2vpn'] if 'l2vpn' in bgpvpn_connection else {}
        )

        self._attach_all_ports_on_bgpvpn_network(net_uuid, ipvpn_bgpvpn,
                                                 evpn_bgpvpn)

    def update_bgpvpn_connection(self, context, bgpvpn_connection):
        LOG.debug("update_bgpvpn_connection received with details %s",
                  bgpvpn_connection)
        net_uuid = bgpvpn_connection['network_id']
        ipvpn_bgpvpn = (
            bgpvpn_connection['l3vpn'] if 'l3vpn' in bgpvpn_connection else {}
        )
        evpn_bgpvpn = (
            bgpvpn_connection['l2vpn'] if 'l2vpn' in bgpvpn_connection else {}
        )

        if 'old_network_id' in bgpvpn_connection:
            old_net_uuid = bgpvpn_connection['old_network_id']
            if net_uuid is None:
                self._detach_all_ports_from_bgpvpn_network(old_net_uuid,
                                                           ipvpn_bgpvpn,
                                                           evpn_bgpvpn)
            else:
                if old_net_uuid is not None:
                    self._detach_all_ports_from_bgpvpn_network(old_net_uuid,
                                                               ipvpn_bgpvpn,
                                                               evpn_bgpvpn)

                self._attach_all_ports_on_bgpvpn_network(net_uuid,
                                                         ipvpn_bgpvpn,
                                                         evpn_bgpvpn)
        else:
            # Only route targets have been updated
            self._attach_all_ports_on_bgpvpn_network(net_uuid,
                                                     ipvpn_bgpvpn,
                                                     evpn_bgpvpn)

    def delete_bgpvpn_connection(self, context, bgpvpn_connection):
        LOG.debug("delete_bgpvpn_connection received with details %s",
                  bgpvpn_connection)
        net_uuid = bgpvpn_connection['network_id']
        ipvpn_bgpvpn = (
            bgpvpn_connection['l3vpn'] if 'l3vpn' in bgpvpn_connection else {}
        )
        evpn_bgpvpn = (
            bgpvpn_connection['l2vpn'] if 'l2vpn' in bgpvpn_connection else {}
        )

        self._detach_all_ports_from_bgpvpn_network(net_uuid,
                                                   ipvpn_bgpvpn,
                                                   evpn_bgpvpn)

    def bgpvpn_port_attach(self, context, port_bgpvpn_info):
        LOG.debug("bgpvpn_port_attach received with port info: %s",
                  port_bgpvpn_info)
        port_id = port_bgpvpn_info['id']
        net_uuid = port_bgpvpn_info['network_id']

        if self.agent_type == q_const.AGENT_TYPE_OVS:
            lvm = self.local_vlan_map[net_uuid]
            # Add ARP responder entry for default gateway in OVS tunnel bridge
            self.setup_entry_for_arp_reply(self.tun_br, 'add', lvm.vlan,
                                           DEFAULT_GATEWAY_MAC,
                                           port_bgpvpn_info['gateway_ip'])

        # Add/Update port BGP VPN details in registered attachments list
        port_details = self._add_local_port_details(net_uuid,
                                                    port_id,
                                                    port_bgpvpn_info)

        # Attach port on BaGPipe BGP component
        LOG.debug("Attaching BGP VPN port %s on BaGPipe BGP component with "
                  "details %s" %
                  (port_details['local_port']['linuxif'], port_details))

        self._do_local_port_bgpvpn_plug(port_details)

    def bgpvpn_port_detach(self, context, port_bgpvpn_info):
        LOG.debug("bgpvpn_port_detach received with port info: %s",
                  port_bgpvpn_info)
        port_id = port_bgpvpn_info['id']
        net_uuid = port_bgpvpn_info['network_id']

        # Detach BGP VPN port from BaGPipe BGP component
        LOG.debug("Detaching BGP VPN port %s from BaGPipe BGP component",
                  port_id)

        # Retrieve local port details index in BGP registered attachment list
        try:
            index, _ = self._get_reg_attachment_for_port(net_uuid, port_id)
            self._do_local_port_bgpvpn_unplug(net_uuid, index)
            self._remove_reg_attachment_for_index(net_uuid, index)
        except BGPAttachmentNotFound as e:
            LOG.error("Can't detach BGP VPN port from BaGPipe BGP "
                      "component: %s", str(e))
