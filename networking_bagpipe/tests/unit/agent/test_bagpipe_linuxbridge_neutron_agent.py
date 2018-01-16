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

import copy
import mock

from networking_bagpipe.bagpipe_bgp import constants as bbgp_const

from networking_bagpipe.agent import bagpipe_linuxbridge_neutron_agent as\
    linuxbridge_agent

from networking_bagpipe.tests.unit.agent import base


class TestBaGPipeAgentExtensionMixin(object):

    def _format_rt_as_list(self, rt):
        return {k: [v] for k, v in rt.items()}

    def test_bagpipe_l2_attach_single_port(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__

        self.agent_ext.bagpipe_port_attach(None, copy.copy(dummy_port10))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'],
                                 1,
                                 bbgp_const.EVPN,
                                 base.BAGPIPE_L2_RT1)

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
                    gateway_ip=base.NETWORK1['gateway_ip'],
                    local_port=local_port['local_port'],
                    linuxbr=local_port['linuxbr'],
                    **self._format_rt_as_list(base.BAGPIPE_L2_RT1)
                )]
            ),
            self.agent_ext.build_bagpipe_l2_attach_info(base.PORT10['id'])
        )

    def test_bagpipe_l2_attach_multiple_ports_same_network(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__
        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__

        self.agent_ext.bagpipe_port_attach(None, copy.copy(dummy_port10))
        self.agent_ext.bagpipe_port_attach(None, copy.copy(dummy_port11))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])]
        )

        self._check_network_info(base.NETWORK1['id'],
                                 2,
                                 bbgp_const.EVPN,
                                 base.BAGPIPE_L2_RT1)

        # Verify build callback attachments
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
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=local_port['local_port'],
                        linuxbr=local_port['linuxbr'],
                        **self._format_rt_as_list(base.BAGPIPE_L2_RT1)
                    )]
                ),
                self.agent_ext.build_bagpipe_l2_attach_info(port['id'])
            )

    def test_bagpipe_l2_attach_multiple_ports_different_networks(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__
        dummy_port20 = base.DummyPort(base.NETWORK2, base.PORT20,
                                      evpn=base.BAGPIPE_L2_RT2).__dict__

        self.agent_ext.bagpipe_port_attach(None, copy.copy(dummy_port10))
        self.agent_ext.bagpipe_port_attach(None, copy.copy(dummy_port20))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT20['id'])]
        )

        for network_id, evpn_rt in [
                (base.NETWORK1['id'], base.BAGPIPE_L2_RT1),
                (base.NETWORK2['id'], base.BAGPIPE_L2_RT2)]:
            self._check_network_info(network_id,
                                     1,
                                     bbgp_const.EVPN,
                                     evpn_rt)

        # Verify build callback attachments
        for network, port, rts in [(base.NETWORK1, base.PORT10,
                                    base.BAGPIPE_L2_RT1),
                                   (base.NETWORK2, base.PORT20,
                                    base.BAGPIPE_L2_RT2)]:
            local_port = self._get_expected_local_port(bbgp_const.EVPN,
                                                       network['id'],
                                                       port['id'])

            self.assertDictEqual(
                dict(
                    network_id=network['id'],
                    evpn=[dict(
                        ip_address=port['ip_address'],
                        mac_address=port['mac_address'],
                        gateway_ip=network['gateway_ip'],
                        local_port=local_port['local_port'],
                        linuxbr=local_port['linuxbr'],
                        **self._format_rt_as_list(rts)
                    )]
                ),
                self.agent_ext.build_bagpipe_l2_attach_info(port['id'])
            )

    def test_bagpipe_l2_detach_single_port(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        self.agent_ext.bagpipe_port_attach(None, dummy_port10)

        self.mocked_bagpipe_agent.reset_mock()

        self.agent_ext.bagpipe_port_detach(None, dummy_detach10)

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

        self._check_network_info(base.NETWORK1['id'], 0)
        self.assertEqual(0, len(self.agent_ext.networks_info),
                         "Registered attachments list must be empty: %s" %
                         self.agent_ext.networks_info)

    def test_bagpipe_l2_detach_multiple_ports_same_network(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__
        dummy_detach11 = dict(id=base.PORT11['id'],
                              network_id=base.NETWORK1['id'])

        # Attach 2 ports on network 1
        self.agent_ext.bagpipe_port_attach(None, dummy_port10)
        self.agent_ext.bagpipe_port_attach(None, dummy_port11)

        self.mocked_bagpipe_agent.reset_mock()

        # Detach 1 port from network 1
        self.agent_ext.bagpipe_port_detach(None, dummy_detach10)

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'],
                                 1,
                                 bbgp_const.EVPN,
                                 base.BAGPIPE_L2_RT1)

        # Detach remaining port from network 1
        self.agent_ext.bagpipe_port_detach(None, dummy_detach11)

        local_port10 = self._get_expected_local_port(bbgp_const.EVPN,
                                                     base.NETWORK1['id'],
                                                     base.PORT10['id'])
        detach_info10 = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.EVPN: {
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': local_port10['local_port']
            }
        }

        local_port11 = self._get_expected_local_port(bbgp_const.EVPN,
                                                     base.NETWORK1['id'],
                                                     base.PORT11['id'])
        detach_info11 = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.EVPN: {
                'ip_address': base.PORT11['ip_address'],
                'mac_address': base.PORT11['mac_address'],
                'local_port': local_port11['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info10),
             mock.call(base.PORT11['id'], detach_info11)]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 0)
        self.assertEqual(0, len(self.agent_ext.networks_info),
                         "Registered attachments list must be empty: %s" %
                         self.agent_ext.networks_info)

    def test_bagpipe_l2_detach_multiple_ports_different_networks(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__
        dummy_detach11 = dict(id=base.PORT11['id'],
                              network_id=base.NETWORK1['id'])

        dummy_port20 = base.DummyPort(base.NETWORK2, base.PORT20,
                                      evpn=base.BAGPIPE_L2_RT2).__dict__
        dummy_detach20 = dict(id=base.PORT20['id'],
                              network_id=base.NETWORK2['id'])

        dummy_port21 = base.DummyPort(base.NETWORK2, base.PORT21,
                                      evpn=base.BAGPIPE_L2_RT2).__dict__
        dummy_detach21 = dict(id=base.PORT21['id'],
                              network_id=base.NETWORK2['id'])

        # Attach 2 ports on network 1
        self.agent_ext.bagpipe_port_attach(None, dummy_port10)
        self.agent_ext.bagpipe_port_attach(None, dummy_port11)

        # Attach 2 ports on network 2
        self.agent_ext.bagpipe_port_attach(None, dummy_port20)
        self.agent_ext.bagpipe_port_attach(None, dummy_port21)

        self.mocked_bagpipe_agent.reset_mock()

        # Detach 1 port from each network
        self.agent_ext.bagpipe_port_detach(None, dummy_detach10)
        self.agent_ext.bagpipe_port_detach(None, dummy_detach20)

        local_port10 = self._get_expected_local_port(bbgp_const.EVPN,
                                                     base.NETWORK1['id'],
                                                     base.PORT10['id'])
        detach_info10 = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.EVPN: {
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': local_port10['local_port']
            }
        }

        local_port20 = self._get_expected_local_port(bbgp_const.EVPN,
                                                     base.NETWORK2['id'],
                                                     base.PORT20['id'])
        detach_info20 = {
            'network_id': base.NETWORK2['id'],
            bbgp_const.EVPN: {
                'ip_address': base.PORT20['ip_address'],
                'mac_address': base.PORT20['mac_address'],
                'local_port': local_port20['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info10),
             mock.call(base.PORT20['id'], detach_info20)]
        )

        # Verify attachments list consistency
        for network_id, evpn_rt in [
                (base.NETWORK1['id'], base.BAGPIPE_L2_RT1),
                (base.NETWORK2['id'], base.BAGPIPE_L2_RT2)]:
            self._check_network_info(network_id,
                                     1,
                                     bbgp_const.EVPN,
                                     evpn_rt)

        self.mocked_bagpipe_agent.reset_mock()

        # Detach remaining port from each network
        self.agent_ext.bagpipe_port_detach(None, dummy_detach11)
        self.agent_ext.bagpipe_port_detach(None, dummy_detach21)

        local_port11 = self._get_expected_local_port(bbgp_const.EVPN,
                                                     base.NETWORK1['id'],
                                                     base.PORT11['id'])
        detach_info11 = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.EVPN: {
                'ip_address': base.PORT11['ip_address'],
                'mac_address': base.PORT11['mac_address'],
                'local_port': local_port11['local_port']
            }
        }

        local_port21 = self._get_expected_local_port(bbgp_const.EVPN,
                                                     base.NETWORK2['id'],
                                                     base.PORT21['id'])
        detach_info21 = {
            'network_id': base.NETWORK2['id'],
            bbgp_const.EVPN: {
                'ip_address': base.PORT21['ip_address'],
                'mac_address': base.PORT21['mac_address'],
                'local_port': local_port21['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT11['id'], detach_info11),
             mock.call(base.PORT21['id'], detach_info21)]
        )

        # Verify attachments list consistency
        for network_id in [base.NETWORK1['id'], base.NETWORK2['id']]:
            self._check_network_info(network_id, 0)

        self.assertEqual(0, len(self.agent_ext.networks_info),
                         "Registered attachments list must be empty: %s" %
                         self.agent_ext.networks_info)


class LinuxBridgeAgentExtensionTest(base.BaseTestLinuxBridgeAgentExtension,
                                    TestBaGPipeAgentExtensionMixin):

    agent_extension_class = linuxbridge_agent.BagpipeAgentExtension
