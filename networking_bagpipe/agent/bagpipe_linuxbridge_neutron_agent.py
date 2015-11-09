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

from neutron.common import config as common_config
from neutron.common import constants
from neutron.common import utils as n_utils

from neutron.i18n import _LE
from neutron.i18n import _LI

from neutron.plugins.common import constants as p_const

from neutron.plugins.ml2.drivers.linuxbridge.agent.linuxbridge_neutron_agent \
    import LinuxBridgeManager
from neutron.plugins.ml2.drivers.linuxbridge.agent.linuxbridge_neutron_agent \
    import LinuxBridgeNeutronAgentRPC

from networking_bagpipe.agent import bagpipe_bgp_agent

LOG = logging.getLogger(__name__)


class LinuxBridgeManagerBaGPipeL2(LinuxBridgeManager):

    def add_tap_interface(self, network_id, network_type, physical_network,
                          segmentation_id, tap_device_name):

        # We want to override the following in LinuxBridgeManager:
        #   if network_type == p_const.TYPE_LOCAL:
        #       self.ensure_local_bridge(network_id)
        # so that it also applies to TYPE_ROUTE_TARGET:
        # Let's cheat (a little bit only):
        return LinuxBridgeManager.add_tap_interface(self, network_id,
                                                    p_const.TYPE_LOCAL,  # <--
                                                    physical_network,
                                                    segmentation_id,
                                                    tap_device_name)


class BaGPipeLinuxBridgeNeutronAgentRPC(LinuxBridgeNeutronAgentRPC):

    def __init__(self, *args, **kwargs):
        # Creates an HTTP client for BaGPipe BGP component REST service
        # super __init__ will call .setup_rpc which we override
        # to add bgp_agent as a client
        super(BaGPipeLinuxBridgeNeutronAgentRPC, self).__init__(*args,
                                                                **kwargs)

        self.bgp_agent = (bagpipe_bgp_agent.BaGPipeBGPAgent(
            constants.AGENT_TYPE_LINUXBRIDGE,
            br_mgr=self.br_mgr)
        )

        self.bgp_agent.setup_rpc(self.endpoints, self.connection, self.topic)

    def setup_linux_bridge(self, interface_mappings):
        self.br_mgr = LinuxBridgeManagerBaGPipeL2(interface_mappings)


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

    polling_interval = cfg.CONF.AGENT.polling_interval
    agent = BaGPipeLinuxBridgeNeutronAgentRPC(interface_mappings,
                                              polling_interval)
    LOG.info(_LI("Agent initialized successfully, now running... "))
    launcher = service.launch(cfg.CONF, agent)
    launcher.wait()


if __name__ == "__main__":
    main()
