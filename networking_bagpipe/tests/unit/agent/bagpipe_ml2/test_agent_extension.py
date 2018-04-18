# Copyright (c) 2016 Orange.
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

from networking_bagpipe.agent.bagpipe_ml2 import agent_extension
from networking_bagpipe.bagpipe_bgp import constants as bbgp_const
from networking_bagpipe.tests.unit.agent import base


class TestBaGPipeAgentExtensionMixin(object):

    def _rts_for_network(self, network):
        rt = "64512:%s" % network['segmentation_id']
        return {
            "import_rt": [rt],
            "export_rt": [rt]
        }

    def test_bagpipe_l2_unsupported_network_type(self):
        # Set port network type to unsupported flat type
        port10_flat_net = self._port_data(base.PORT10)
        port10_flat_net['network_type'] = 'flat'

        self.agent_ext.handle_port(None, port10_flat_net)

        self.assertFalse(self.mocked_bagpipe_agent.do_port_plug.called)

        self._check_network_info(base.NETWORK1['id'], 0)

    def test_bagpipe_l2_attach_single_port(self):

        def check_build_cb(*args):
            # Verify build callback attachments
            local_port = self._get_expected_local_port(bbgp_const.EVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    evpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        local_port=local_port['local_port'],
                        linuxbr=local_port['linuxbr'],
                        vni=base.NETWORK1['segmentation_id'],
                        **self._rts_for_network(base.NETWORK1)
                    )]
                ),
                self.agent_ext.build_bagpipe_l2_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'], 1)

    def test_bagpipe_l2_attach_multiple_ports_same_network(self):

        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self._check_network_info(base.NETWORK1['id'], 1)

        def check_build_cb(*args):
            for port in [base.PORT10, base.PORT11]:
                local_port = self._get_expected_local_port(bbgp_const.EVPN,
                                                           base.NETWORK1['id'],
                                                           port['id'])
                self.assertDictEqual(
                    dict(
                        network_id=base.NETWORK1['id'],
                        evpn=[dict(
                            ip_address=port['ip_address'],
                            mac_address=port['mac_address'],
                            local_port=local_port['local_port'],
                            linuxbr=local_port['linuxbr'],
                            vni=base.NETWORK1['segmentation_id'],
                            **self._rts_for_network(base.NETWORK1)
                        )]
                    ),
                    self.agent_ext.build_bagpipe_l2_attach_info(port['id'])
                )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self.agent_ext.handle_port(None, self._port_data(base.PORT11))
        self._check_network_info(base.NETWORK1['id'], 2)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])]
        )

    def test_bagpipe_l2_detach_single_port(self):

        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self._check_network_info(base.NETWORK1['id'], 1)

        def check_build_cb(*args):
            # Verify build callback attachments
            self.assertDictEqual(
                {},
                self.agent_ext.build_bagpipe_l2_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self.agent_ext.delete_port(None, self._port_data(base.PORT10))

        self._check_network_info(base.NETWORK1['id'], 0)

        local_port = self._get_expected_local_port(bbgp_const.EVPN,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'])
        detach_info = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.EVPN: {
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': local_port['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info)]
        )


class LinuxBridgeAgentExtensionTest(base.BaseTestLinuxBridgeAgentExtension,
                                    TestBaGPipeAgentExtensionMixin):

    agent_extension_class = agent_extension.BagpipeML2AgentExtension
