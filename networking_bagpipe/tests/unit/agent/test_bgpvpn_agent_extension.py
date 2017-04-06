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

from networking_bagpipe.agent.bgpvpn import agent_extension as bagpipe_agt_ext

from neutron.agent.common import ovs_lib
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants as ovs_agt_constants
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_agent_extension_api as ovs_ext_agt
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    import ovs_test_base

from neutron_lib import constants as const


class TestOVSAgentExtension(ovs_test_base.OVSOFCtlTestBase):

    def setUp(self):
        super(TestOVSAgentExtension, self).setUp()
        self.agent_ext = bagpipe_agt_ext.BagpipeBgpvpnAgentExtension()
        self.connection = mock.Mock()

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent.BaGPipeBGPAgent')
    def test_init(self, mocked_bagpipe_bgp_agent):
        int_br = self.br_int_cls("br-int")
        tun_br = self.br_tun_cls("br-tun")
        agent_extension_api = ovs_ext_agt.OVSAgentExtensionAPI(int_br,
                                                               tun_br)

        self.agent_ext.consume_api(agent_extension_api)
        self.agent_ext.initialize(self.connection,
                                  ovs_agt_constants.EXTENSION_DRIVER_TYPE,
                                  )

        mocked_bagpipe_bgp_agent.assert_called_once_with(
            const.AGENT_TYPE_OVS,
            self.connection,
            int_br=mock.ANY,
            tun_br=mock.ANY
            )

        call_kwargs = mocked_bagpipe_bgp_agent.call_args_list[0][1]

        self.assertIsInstance(call_kwargs['int_br'], ovs_lib.OVSBridge)
        self.assertIsInstance(call_kwargs['tun_br'], ovs_lib.OVSBridge)
