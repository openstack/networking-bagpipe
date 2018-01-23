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

from oslo_config import cfg

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from oslo_concurrency import lockutils

from oslo_service import loopingcall

from networking_bagpipe._i18n import _

from networking_bagpipe.bagpipe_bgp import constants as bbgp_const

from neutron.conf.agent import common as config

from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc

LOG = logging.getLogger(__name__)


# Having this at line 231 is apparently not enough, so adding here as well:
# pylint: disable=not-callable

bagpipe_bgp_opts = [
    cfg.IntOpt('ping_interval', default=10,
               help=_("The number of seconds the bagpipe-bgp client will "
                      "wait between polling for restart detection.")),
    cfg.PortOpt('bagpipe_bgp_port', default=8082,
                help=_("bagpipe-bgp REST service IP port.")),
]

# these options are for internal use only (fullstack tests), and hence
# better kept in a separate table not looked at by oslo gen confi hooks
internal_opts = [
    cfg.HostAddressOpt('bagpipe_bgp_ip', default='127.0.0.1',
                       help=_("bagpipe-bgp REST service IP address.")),
]

cfg.CONF.register_opts(bagpipe_bgp_opts, "BAGPIPE")
cfg.CONF.register_opts(internal_opts, "BAGPIPE")
config.register_agent_state_opts_helper(cfg.CONF)

# don't use bbgp_const.VPN_TYPES here, because here in this module
# we sometimes need to iterate the vpn types in a controlled order:
# EVPN first on attach, EVPN last on detach
VPN_TYPES = [bbgp_const.EVPN, bbgp_const.IPVPN]


class BaGPipeBGPException(n_exc.NeutronException):
    message = "An exception occurred when calling bagpipe-bgp \
               REST service: %(reason)s"


class SetJSONEncoder(json.JSONEncoder):
    # JSON encoder that encodes set like a list, this
    # allows to store list of RTs as sets and simplify the code
    # in many places
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


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
        LOG.debug("bagpipe-bgp client request: %(method)s %(action)s "
                  "[%(body)s]",
                  {'method': method, 'action': action, 'body': str(body)})

        if isinstance(body, dict):
            body = json.dumps(body, cls=SetJSONEncoder)
        try:
            headers = {'User-Agent': self.client_name,
                       "Content-Type": "application/json",
                       "Accept": "application/json"}
            uri = "http://%s:%s/%s" % (self.host, self.port, action)

            http = httplib2.Http()
            response, content = http.request(uri, method, body, headers)
            LOG.debug("bagpipe-bgp returns [%(status)s:%(content)s]",
                      {'status': str(response.status), 'content': content})

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


def get_default_vpn_instance_id(vpn_type, network_id):
    return '%s_%s' % (vpn_type, network_id)


class BaGPipeBGPAgent(HTTPClientBase):
    """Implements a BaGPipe-BGP REST client"""

    _instance = None

    # bagpipe-bgp status
    BAGPIPEBGP_UP = 'UP'
    BAGPIPEBGP_DOWN = 'DOWN'

    @classmethod
    @lockutils.synchronized('bagpipe-bgp-agent')
    def _create_instance(cls, agent_type):
        if not cls.has_instance():
            cls._instance = cls(agent_type)

    @classmethod
    def has_instance(cls):
        return cls._instance is not None

    @classmethod
    def clear_instance(cls):
        cls._instance = None

    @classmethod
    def get_instance(cls, agent_type):
        # double checked locking
        if not cls.has_instance():
            cls._create_instance(agent_type)
        else:
            if cls._instance.agent_type != agent_type:
                raise Exception("Agent already configured with another type")

        return cls._instance

    def __init__(self, agent_type):

        """Create a new BaGPipe-BGP REST service client.

        :param agent_type: bagpipe-bgp agent type (Linux bridge or OVS)

        """
        super(BaGPipeBGPAgent,
              self).__init__(cfg.CONF.BAGPIPE.bagpipe_bgp_ip,
                             cfg.CONF.BAGPIPE.bagpipe_bgp_port, agent_type)

        self.agent_type = agent_type

        self.ping_interval = cfg.CONF.BAGPIPE.ping_interval

        self.bagpipe_bgp_status = self.BAGPIPEBGP_DOWN
        self.seq_num = 0

        # Starts a greenthread for bagpipe-bgp status polling
        self._start_bagpipe_bgp_status_polling(self.ping_interval)

        # Maps registered service name to callback function used to build the
        # content of bagpipe-bgp API calls
        self.build_callbacks = dict()

        # Maps registered service name to list of ports for which a given
        # service is enabled
        self.port_lists = dict()

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
                ports = set()
                for port_list in self.port_lists.values():
                    ports |= port_list

                if ports:
                    LOG.info("Sending all registered ports to bagpipe-bgp")
                    LOG.debug("Registered ports list: %s", ports)
                    for port_id in ports:
                        self.do_port_plug(port_id)
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

    def _check_evpn2ipvpn_info(self, vpn_type, network_id, attach_list,
                               attach_info):
        # Check if plugging an EVPN into an IPVPN
        if (vpn_type == bbgp_const.IPVPN and bbgp_const.EVPN in attach_list):
            attach_info['local_port'] = {
                bbgp_const.EVPN: {
                    'id': get_default_vpn_instance_id('evpn', network_id)
                }
            }

    def _compile_port_attach_info(self, port_id):
        # this method returns information for all bagpipe-bgp attachments to
        # produce for a given port:
        # {
        #   'evpn': [
        #       {
        #          'vpn_instance_id':
        #          'ip_address'
        #          ..
        #          'import_rts': [...]
        #          'export_rts': [...]
        #       },
        #       ...
        #   ],
        #   'ipvpn': [
        #       {
        #          'vpn_instance_id':
        #          'ip_address'
        #          ..
        #          'import_rts': [...]
        #          'export_rts': [...]
        #       },
        #       ...
        #   ]
        # }
        #
        # This structure produces consolidated information across all services
        # for all Route Target parameters: the import_rt and export_rt
        # attributes accumulate the RTs of all the service producing
        # attachments for a given VPN instance (vpn instance id).
        #
        # Another consolidation that is done in the case where both EVPN and
        # IPVPN attachments are produced, and the agent is a linuxbridge agent.
        # In that case the IPVPN attachments are modified so that instead of
        # plugging the port into the IPVPN, the EVPN instance is plugged into
        # the IPVPN, which is necessary so that bagpipe-bgp will connect the
        # linux bridge to a linux VRF with a veth interface.
        #
        # NOTE(tmorin): the code does not do consistency checks for parameters
        # that would be conflicting between attachments, for instance if
        # an EVPN attachment would specify a VNI X and another a VNI Y.
        # For read-only parameters, bagpipe-bgp would be in charge of detecting
        # an attempt at overwriting the parameters with a different value and
        # raising an error.
        # For proper safeguarding, the code here would need to check
        # consistency across attachments of read-write values.

        service_attachments_map = {}
        for service, build_callback in self.build_callbacks.items():
            # what was returned by the callbacks before (a dict allowing to
            # describe one EVPN and one IPVPN attachment):
            # {
            #    'network_id':
            #    'ip_address'
            #    ..
            #    'evpn': {
            #         'import_rt': [...]
            #         'export_rt': [...]
            #         'static_routes': ...
            #    }
            #    'ipvpn': {
            #         'import_rt': [...]
            #         'export_rt': [...]
            #         'static_routes': ...
            #    }
            # }
            #
            # we expect the callback to return a dict or lists,
            # following this template:
            # {
            #    'network_id': # use to generate vpn_instance_id if
            #                  # vpn_instance_id is omitted below
            #    'evpn': [
            #       {
            #         'vpn_instance_id': ..
            #         'ip_address': ..
            #         ...
            #         'import_rt': [...]
            #         'export_rt': [...]
            #       },
            #       ...
            #    ],
            #    'ipvpn': [
            #    ]
            # }
            service_attachments_map[service] = build_callback(port_id)
            LOG.debug("port %s, attach info for %s: %s",
                      port_id, service, service_attachments_map[service])

        attach_list = {}

        # map in which we consolidate the RTs for a given vpn instance
        # vpn_instance_rts[vpn_instance_id]['import_rt'] = set()
        # vpn_instance_rts[vpn_instance_id]['export_rt'] = set()
        vpn_instance_rts = {}

        for vpn_type in VPN_TYPES:
            vpn_attachment_list = []

            for service in self.build_callbacks.keys():
                service_attachments = (
                    service_attachments_map[service].get(vpn_type)
                )

                if not service_attachments:
                    continue

                default_vpn_instance_id = get_default_vpn_instance_id(
                    vpn_type,
                    service_attachments_map[service]['network_id'])

                for service_attachment in service_attachments:

                    vpn_instance_id = service_attachment.setdefault(
                        'vpn_instance_id', default_vpn_instance_id)

                    service_attachment['vpn_type'] = vpn_type

                    # initialize consolidated RTs for this vpn_instance_id
                    # if this wasn't done yet
                    vpn_instance_rts.setdefault(vpn_instance_id, {
                        bbgp_const.RT_IMPORT: set(),
                        bbgp_const.RT_EXPORT: set()
                    })

                    for rt_type in (bbgp_const.RT_IMPORT,
                                    bbgp_const.RT_EXPORT):
                        # merge this service RTs with the RTs we already had
                        # for this vpn_instance_id
                        orig_rts = set(service_attachment[rt_type])
                        vpn_instance_rts[vpn_instance_id][rt_type] |= orig_rts
                        # have the RT information for this attachment
                        # point to the consolidated RT list
                        service_attachment[rt_type] = (
                            vpn_instance_rts[vpn_instance_id][rt_type])

                    LOG.debug("adding processed attachment: %s",
                              service_attachment)
                    vpn_attachment_list.append(service_attachment)

            if vpn_attachment_list:
                attach_list[vpn_type] = vpn_attachment_list

        if self.agent_type == n_const.AGENT_TYPE_LINUXBRIDGE:
            if (attach_list.get(bbgp_const.EVPN) and
                    attach_list.get(bbgp_const.IPVPN)):
                # go through all IPVPN attachments and rewrite local_port
                # to point to the evpn instance, rather than the VM port
                for attachment in attach_list[bbgp_const.IPVPN]:
                    attachment['local_port'] = {bbgp_const.EVPN: {
                        'id': attachment['vpn_instance_id'].replace('ipvpn',
                                                                    'evpn')
                        }
                    }

        LOG.debug("all attachments for port %s: %s", port_id, attach_list)
        return attach_list

    def _request_ping(self):
        """Send ping request to bagpipe-bgp to get sequence number"""
        try:
            response = self.get('ping')
            LOG.debug("bagpipe-bgp PING response received with "
                      "sequence number %s", response)
            return response
        except BaGPipeBGPException as e:
            LOG.warning(str(e))
            return -1

    @log_helpers.log_method_call
    def _send_attach_local_port(self, local_port_details):
        """Send local port attach request to BaGPipe-BGP if running"""
        if self.bagpipe_bgp_status is self.BAGPIPEBGP_UP:
            try:
                self.post('attach_localport', local_port_details)
                LOG.debug("Local port has been attached to bagpipe-bgp with "
                          "details %s", local_port_details)
            except BaGPipeBGPException as e:
                LOG.error("Can't attach local port on bagpipe-bgp: %s", str(e))
        else:
            LOG.debug("Local port not yet attached to bagpipe-bgp (not up)")

    @log_helpers.log_method_call
    def _send_detach_local_port(self, local_port_details):
        """Send local port detach request to BaGPipe-BGP if running"""
        if self.bagpipe_bgp_status is self.BAGPIPEBGP_UP:
            try:
                self.post('detach_localport', local_port_details)
                LOG.debug("Local port has been detached from bagpipe-bgp "
                          "with details %s", local_port_details)
            except BaGPipeBGPException as e:
                LOG.error("Can't detach local port from bagpipe-bgp: %s",
                          str(e))
                raise
        else:
            LOG.debug("Local port not yet detached from bagpipe-bgp (not up)")

    @log_helpers.log_method_call
    def _send_all_attachments(self, plug_details):
        # First plug E-VPNs because they could be plugged into IP-VPNs
        for vpn_type in [t for t in VPN_TYPES if t in plug_details]:
            for plug_detail in plug_details[vpn_type]:
                self._send_attach_local_port(plug_detail)

    @log_helpers.log_method_call
    def do_port_plug(self, port_id):
        """Send port attach request to bagpipe-bgp."""
        all_plug_details = self._compile_port_attach_info(port_id)

        self._send_all_attachments(all_plug_details)

    @log_helpers.log_method_call
    def do_port_plug_refresh(self, port_id, detach_infos):
        """Refresh port attach on bagpipe-bgp

        Send port attach and/or detach request to bagpipe-bgp when necessary.

        detach_infos:
        {
            'network_id': ...
            'evpn': {
                ...
            }
            'ipvpn': {
                ...
            }
        }
        ]
        """
        self.do_port_plug_refresh_many(port_id, [detach_infos])

    @log_helpers.log_method_call
    def do_port_plug_refresh_many(self, port_id, detach_info_list):
        """Refresh port attach on bagpipe-bgp

        Send port attach and/or detach request to bagpipe-bgp when necessary.

        detach_infos, a list of:
        {
            'network_id': ...
            'evpn': {
                ...
            }
            'ipvpn': {
                ...
            }
        }
        ]
        """
        plug_details = self._compile_port_attach_info(port_id)

        for detach_infos in detach_info_list:
            network_id = detach_infos.pop('network_id')
            for detach_vpn_type, detach_info in list(detach_infos.items()):
                detach_info.setdefault(
                    'vpn_instance_id',
                    get_default_vpn_instance_id(detach_vpn_type,
                                                network_id))
                detach_info['vpn_type'] = detach_vpn_type

                # NOTE(tmorin): to be reconsidered
                self._check_evpn2ipvpn_info(detach_vpn_type, network_id,
                                            plug_details, detach_info)

            if detach_infos:
                # unplug IPVPN first, then EVPN (hence ::-1 below)
                for vpn_type in [t for t in VPN_TYPES[::-1]
                                 if t in detach_infos]:
                    self._send_detach_local_port(detach_infos[vpn_type])

        self._send_all_attachments(plug_details)

    @lockutils.synchronized('bagpipe-bgp-agent')
    def register_build_callback(self, service_name, callback):
        self.build_callbacks[service_name] = callback

    @lockutils.synchronized('bagpipe-bgp-agent')
    def register_port_list(self, service_name, port_list):
        self.port_lists[service_name] = port_list
