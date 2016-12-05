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

from oslo_log import log as logging

from oslo_service import service

from networking_bagpipe.agent import bagpipe_bgp_agent
from networking_bagpipe.driver.type_route_target import TYPE_ROUTE_TARGET

from neutron._i18n import _LE
from neutron._i18n import _LI

from neutron.agent.l2 import agent_extension

from neutron.common import config as common_config
from neutron.common import utils as n_utils

from neutron_lib import constants as n_const

from neutron.plugins.ml2.drivers.agent import _common_agent as ca
from neutron.plugins.ml2.drivers.linuxbridge.agent.linuxbridge_neutron_agent \
    import LinuxBridgeManager

LOG = logging.getLogger(__name__)

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


class BagpipeAgentExtension(agent_extension.AgentCoreResourceExtension):

    def initialize(self, connection, driver_type):

        # Create an HTTP client for BaGPipe BGP component REST service
        self.bagpipe_bgp_agent = bagpipe_bgp_agent.BaGPipeBGPAgent(
            n_const.AGENT_TYPE_LINUXBRIDGE,
            connection)

    def handle_port(self, context, data):
        pass

    def delete_port(self, context, data):
        pass


def main():
    common_config.init(sys.argv[1:])

    common_config.setup_logging()
    try:
        interface_mappings = n_utils.parse_mappings(
            cfg.CONF.LINUX_BRIDGE.physical_interface_mappings)
    except ValueError as e:
        LOG.error(_LE("Parsing physical_interface_mappings failed: %s. "
                      "Agent terminated!"), e)
        sys.exit(1)
    LOG.info(_LI("Interface mappings: %s"), interface_mappings)

    try:
        bridge_mappings = n_utils.parse_mappings(
            cfg.CONF.LINUX_BRIDGE.bridge_mappings)
    except ValueError as e:
        LOG.error(_LE("Parsing bridge_mappings failed: %s. "
                      "Agent terminated!"), e)
        sys.exit(1)
    LOG.info(_LI("Bridge mappings: %s"), bridge_mappings)

    manager = LinuxBridgeManagerBaGPipe(bridge_mappings, interface_mappings)

    polling_interval = cfg.CONF.AGENT.polling_interval
    quitting_rpc_timeout = cfg.CONF.AGENT.quitting_rpc_timeout
    agent = ca.CommonAgentLoop(manager, polling_interval, quitting_rpc_timeout,
                               n_const.AGENT_TYPE_LINUXBRIDGE,
                               LB_BAGPIPE_AGENT_BINARY)
    LOG.info(_LI("Agent initialized successfully, now running... "))
    launcher = service.launch(cfg.CONF, agent)
    launcher.wait()
