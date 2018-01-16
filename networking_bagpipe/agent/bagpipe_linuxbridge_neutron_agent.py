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

import sys

import eventlet
eventlet.monkey_patch()

from oslo_config import cfg

from oslo_concurrency import lockutils

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from oslo_service import service

from networking_bagpipe.agent import agent_base_info
from networking_bagpipe.bagpipe_bgp import constants as bbgp_const

from networking_bagpipe.agent import bagpipe_bgp_agent

from networking_bagpipe.driver.type_route_target import TYPE_ROUTE_TARGET

from networking_bagpipe.rpc import agent as bagpipe_rpc
from networking_bagpipe.rpc.client import topics_BAGPIPE

from neutron.common import topics

from neutron_lib.agent import l2_extension

from neutron.common import config as common_config

from neutron_lib import constants as n_const
from neutron_lib.utils import helpers

from neutron.plugins.ml2.drivers.agent import _common_agent as ca
from neutron.plugins.ml2.drivers.linuxbridge.agent.linuxbridge_neutron_agent \
    import LinuxBridgeManager

LOG = logging.getLogger(__name__)

BAGPIPE_L2_SERVICE = 'bagpipe_l2'

LB_BAGPIPE_AGENT_BINARY = 'neutron-bagpipe-linuxbridge-agent'


class LinuxBridgeManagerBaGPipe(LinuxBridgeManager):

    def ensure_physical_in_bridge(self, network_id,
                                  network_type,
                                  physical_network,
                                  segmentation_id):

        if network_type == TYPE_ROUTE_TARGET:
            bridge_name = self.get_bridge_name(network_id)
            return self.ensure_bridge(bridge_name)

        return (super(LinuxBridgeManagerBaGPipe, self)
                .ensure_physical_in_bridge(network_id,
                                           network_type,
                                           physical_network,
                                           segmentation_id))


class BagpipeAgentExtension(l2_extension.L2AgentExtension,
                            agent_base_info.BaseInfoManager,
                            bagpipe_rpc.BaGPipeAgentRpcCallBackMixin):

    def initialize(self, connection, driver_type):

        self.bagpipe_bgp_agent = (
            bagpipe_bgp_agent.BaGPipeBGPAgent.get_instance(
                n_const.AGENT_TYPE_LINUXBRIDGE)
        )

        self._setup_rpc(connection)

        self.bagpipe_bgp_agent.register_build_callback(
            BAGPIPE_L2_SERVICE,
            self.build_bagpipe_l2_attach_info)

        self.ports = set()
        self.bagpipe_bgp_agent.register_port_list(BAGPIPE_L2_SERVICE,
                                                  self.ports)

    def _setup_rpc(self, connection):
        connection.create_consumer(topics.get_topic_name(topics.AGENT,
                                                         topics_BAGPIPE,
                                                         topics.UPDATE,
                                                         cfg.CONF.host),
                                   [self], fanout=False)

    def build_bagpipe_l2_attach_info(self, port_id):
        if not self.ports_info.get(port_id):
            LOG.warning("%s service has no PortInfo for port %s",
                        BAGPIPE_L2_SERVICE, port_id)
            return {}

        port_info = self.ports_info[port_id]

        service_info = port_info.network.service_infos
        attach_info = {
            'network_id': port_info.network.id,
            bbgp_const.EVPN: [{
                'gateway_ip': port_info.network.gateway_info.ip,
                'local_port': port_info.local_port,
                'ip_address': port_info.ip_address,
                'mac_address': port_info.mac_address,
                'linuxbr': LinuxBridgeManager.get_bridge_name(
                    port_info.network.id
                ),
                bbgp_const.RT_IMPORT: [
                    service_info[bbgp_const.EVPN][bbgp_const.RT_IMPORT]],
                bbgp_const.RT_EXPORT: [
                    service_info[bbgp_const.EVPN][bbgp_const.RT_EXPORT]]
            }]
        }

        return attach_info

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-bgp-agent')
    def bagpipe_port_attach(self, context, port_bagpipe_info):
        port_id = port_bagpipe_info.pop('id')
        net_id = port_bagpipe_info.pop('network_id')

        net_info, port_info = (
            self._get_network_port_infos(net_id, port_id)
        )

        # Set IP and MAC adresses in PortInfo
        ip_address = port_bagpipe_info.pop('ip_address')
        mac_address = port_bagpipe_info.pop('mac_address')
        port_info.set_ip_mac_infos(ip_address, mac_address)

        # Set gateway IP address in NetworkInfo
        gateway_info = agent_base_info.GatewayInfo(
            None,
            port_bagpipe_info.pop('gateway_ip'))
        net_info.set_gateway_info(gateway_info)

        port_info.set_local_port(
            LinuxBridgeManager.get_tap_device_name(port_id)
        )

        net_info.add_service_info(port_bagpipe_info)
        self.ports.add(port_id)

        self.bagpipe_bgp_agent.do_port_plug(port_id)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-bgp-agent')
    def bagpipe_port_detach(self, context, port_bagpipe_info):
        port_id = port_bagpipe_info['id']
        net_id = port_bagpipe_info['network_id']

        if port_id not in self.ports_info:
            LOG.warning("%s service inconsistent for port %s",
                        BAGPIPE_L2_SERVICE, port_id)
            return

        LOG.debug("%s service detaching port %s from bagpipe-bgp",
                  BAGPIPE_L2_SERVICE, port_id)
        try:
            port_info = self.ports_info[port_id]

            detach_info = {
                'network_id': net_id,
                bbgp_const.EVPN: {
                    'ip_address': port_info.ip_address,
                    'mac_address': port_info.mac_address,
                    'local_port': port_info.local_port,
                }
            }

            self._remove_network_port_infos(net_id, port_id)
            self.ports.remove(port_id)

            self.bagpipe_bgp_agent.do_port_plug_refresh(port_id,
                                                        detach_info)
        except bagpipe_bgp_agent.BaGPipeBGPException as e:
            LOG.error("%s service can't detach port from bagpipe-bgp %s",
                      BAGPIPE_L2_SERVICE, str(e))

    def handle_port(self, context, data):
        pass

    def delete_port(self, context, data):
        pass


def main():
    common_config.init(sys.argv[1:])

    common_config.setup_logging()
    try:
        interface_mappings = helpers.parse_mappings(
            cfg.CONF.LINUX_BRIDGE.physical_interface_mappings)
    except ValueError as e:
        LOG.error("Parsing physical_interface_mappings failed: %s. "
                  "Agent terminated!", e)
        sys.exit(1)
    LOG.info("Interface mappings: %s", interface_mappings)

    try:
        bridge_mappings = helpers.parse_mappings(
            cfg.CONF.LINUX_BRIDGE.bridge_mappings)
    except ValueError as e:
        LOG.error("Parsing bridge_mappings failed: %s. "
                  "Agent terminated!", e)
        sys.exit(1)
    LOG.info("Bridge mappings: %s", bridge_mappings)

    manager = LinuxBridgeManagerBaGPipe(bridge_mappings, interface_mappings)

    polling_interval = cfg.CONF.AGENT.polling_interval
    quitting_rpc_timeout = cfg.CONF.AGENT.quitting_rpc_timeout
    agent = ca.CommonAgentLoop(manager, polling_interval, quitting_rpc_timeout,
                               n_const.AGENT_TYPE_LINUXBRIDGE,
                               LB_BAGPIPE_AGENT_BINARY)
    LOG.info("Agent initialized successfully, now running... ")
    launcher = service.launch(cfg.CONF, agent)
    launcher.wait()
