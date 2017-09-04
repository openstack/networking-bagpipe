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

import mock

from networking_bagpipe.agent import bagpipe_bgp_agent

from networking_bagpipe.agent.bgpvpn import agent_extension as bagpipe_agt_ext

from neutron.plugins.ml2.drivers.linuxbridge.agent.common \
    import constants as lnx_agt_constants
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants as ovs_agt_constants
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_agent_extension_api as ovs_ext_agt
from neutron.tests import base
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    import ovs_test_base


class TestOVSAgentExtension(ovs_test_base.OVSOFCtlTestBase):

    def setUp(self):
        super(TestOVSAgentExtension, self).setUp()
        self.agent_ext = bagpipe_agt_ext.BagpipeBgpvpnAgentExtension()
        self.connection = mock.Mock()

        self.mocked_bagpipe_bgp_agent = mock.Mock(
            spec=bagpipe_bgp_agent.BaGPipeBGPAgent
        )

    def test_initialize(self):
        int_br = self.br_int_cls("br-int")
        tun_br = self.br_tun_cls("br-tun")
        agent_extension_api = ovs_ext_agt.OVSAgentExtensionAPI(int_br,
                                                               tun_br)

        self.agent_ext.consume_api(agent_extension_api)

        with mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent.'
                        'BaGPipeBGPAgent.get_instance',
                        return_value=self.mocked_bagpipe_bgp_agent):
            self.agent_ext.initialize(self.connection,
                                      ovs_agt_constants.EXTENSION_DRIVER_TYPE,
                                      )


class TestLinuxbridgeAgentExtension(base.BaseTestCase):

    def setUp(self):
        super(TestLinuxbridgeAgentExtension, self).setUp()
        self.agent_ext = bagpipe_agt_ext.BagpipeBgpvpnAgentExtension()
        self.connection = mock.Mock()

        self.mocked_bagpipe_bgp_agent = mock.Mock(
            spec=bagpipe_bgp_agent.BaGPipeBGPAgent
        )

    def test_initialize(self):
        agent_extension_api = mock.Mock()

        self.agent_ext.consume_api(agent_extension_api)

        with mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent.'
                        'BaGPipeBGPAgent.get_instance',
                        return_value=self.mocked_bagpipe_bgp_agent):
            self.agent_ext.initialize(self.connection,
                                      lnx_agt_constants.EXTENSION_DRIVER_TYPE,
                                      )
