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
from oslo_log import helpers as log_helpers

from networking_bagpipe.agent import bagpipe_bgp_agent

from neutron_lib import constants as n_const

from neutron.agent.l2 import agent_extension
from neutron.plugins.ml2.drivers.linuxbridge.agent.common \
    import constants as lnxbridge_agt_constants
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants as ovs_agt_constants


class BagpipeBgpvpnAgentExtension(agent_extension.AgentCoreResourceExtension):

    @log_helpers.log_method_call
    def consume_api(self, agent_api):
        self.agent_api = agent_api

    @log_helpers.log_method_call
    def initialize(self, connection, driver_type):
        if driver_type == ovs_agt_constants.EXTENSION_DRIVER_TYPE:
            tun_br = self.agent_api.request_tun_br()

            if tun_br is None:
                raise Exception("tunneling is not enabled in OVS agent, "
                                "however bagpipe_bgpvpn extensions needs it")

            self.bagpipe_bgp_agent = bagpipe_bgp_agent.BaGPipeBGPAgent(
                n_const.AGENT_TYPE_OVS,
                connection,
                int_br=self.agent_api.request_int_br(),
                tun_br=tun_br,
            )
        elif driver_type == lnxbridge_agt_constants.EXTENSION_DRIVER_TYPE:
            self.bagpipe_bgp_agent = bagpipe_bgp_agent.BaGPipeBGPAgent(
                n_const.AGENT_TYPE_LINUXBRIDGE,
                connection,
            )
        else:
            raise Exception("driver type not supported: %s", driver_type)

    @log_helpers.log_method_call
    def handle_port(self, context, data):
        pass

    @log_helpers.log_method_call
    def delete_port(self, context, data):
        pass
