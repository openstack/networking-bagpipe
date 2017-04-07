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

from networking_bagpipe.agent import bagpipe_bgp_agent as agent

from networking_bagpipe.tests.unit.agent.bagpipe_bgp_agent import base


class TestServiceBaGPipeL2Mixin(object):

    def test_bagpipe_l2_attach_single_port(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bagpipe_port_attach(None, dummy_port10)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_info(base.NETWORK1['id'],
                                     1,
                                     agent.BAGPIPE_L2_SERVICE,
                                     agent.EVPN,
                                     base.BAGPIPE_L2_RT1)

    def test_bagpipe_l2_attach_multiple_ports_same_network(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__
        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.EVPN,
                                              dummy_port11,
                                              self.DUMMY_VIF11)
            ]

            self.agent.bagpipe_port_attach(None, dummy_port10)
            self.agent.bagpipe_port_attach(None, dummy_port11)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_info(base.NETWORK1['id'],
                                     2,
                                     agent.BAGPIPE_L2_SERVICE,
                                     agent.EVPN,
                                     base.BAGPIPE_L2_RT1)

    def test_bagpipe_l2_attach_multiple_ports_different_networks(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__
        dummy_port20 = base.DummyPort(base.NETWORK2, base.PORT20,
                                      evpn=base.BAGPIPE_L2_RT2).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.EVPN,
                                              dummy_port20,
                                              self.DUMMY_VIF20)
            ]

            self.agent.bagpipe_port_attach(None, dummy_port10)
            self.agent.bagpipe_port_attach(None, dummy_port20)

            send_attach_fn.assert_has_calls(expected_calls)

            for network_id, evpn_rt in [
                    (base.NETWORK1['id'], base.BAGPIPE_L2_RT1),
                    (base.NETWORK2['id'], base.BAGPIPE_L2_RT2)]:
                self._check_network_info(network_id,
                                         1,
                                         agent.BAGPIPE_L2_SERVICE,
                                         agent.EVPN,
                                         evpn_rt)

    def test_bagpipe_l2_detach_single_port(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bagpipe_port_attach(None, dummy_port10)
            self.agent.bagpipe_port_detach(None, dummy_detach10)

            send_detach_fn.assert_has_calls(expected_calls)

            self._check_network_info(base.NETWORK1['id'], 0)
            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)

    def test_bagpipe_l2_detach_multiple_ports_same_network(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      evpn=base.BAGPIPE_L2_RT1).__dict__
        dummy_detach11 = dict(id=base.PORT11['id'],
                              network_id=base.NETWORK1['id'])

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.EVPN,
                                              dummy_port11,
                                              self.DUMMY_VIF11)
            ]

            # Attach 2 ports on network 1
            self.agent.bagpipe_port_attach(None, dummy_port10)
            self.agent.bagpipe_port_attach(None, dummy_port11)

            # Detach 1 port from network 1
            self.agent.bagpipe_port_detach(None, dummy_detach10)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'],
                                     1,
                                     agent.BAGPIPE_L2_SERVICE,
                                     agent.EVPN,
                                     base.BAGPIPE_L2_RT1)

            # Detach remaining port from network 1
            self.agent.bagpipe_port_detach(None, dummy_detach11)

            # Check if calls on BaGPipe BGP API are as expected
            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'], 0)
            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)

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

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.EVPN,
                                              dummy_port20,
                                              self.DUMMY_VIF20),
                self._mock_send_expected_call(agent.EVPN,
                                              dummy_port11,
                                              self.DUMMY_VIF11),
                self._mock_send_expected_call(agent.EVPN,
                                              dummy_port21,
                                              self.DUMMY_VIF21)
            ]

            # Attach 2 ports on network 1
            self.agent.bagpipe_port_attach(None, dummy_port10)
            self.agent.bagpipe_port_attach(None, dummy_port11)

            # Attach 2 ports on network 2
            self.agent.bagpipe_port_attach(None, dummy_port20)
            self.agent.bagpipe_port_attach(None, dummy_port21)

            # Detach 1 port from each network
            self.agent.bagpipe_port_detach(None, dummy_detach10)
            self.agent.bagpipe_port_detach(None, dummy_detach20)

            # Verify attachments list consistency
            for network_id, evpn_rt in [
                    (base.NETWORK1['id'], base.BAGPIPE_L2_RT1),
                    (base.NETWORK2['id'], base.BAGPIPE_L2_RT2)]:
                self._check_network_info(network_id,
                                         1,
                                         agent.BAGPIPE_L2_SERVICE,
                                         agent.EVPN,
                                         evpn_rt)

            # Detach remaining port from each network
            self.agent.bagpipe_port_detach(None, dummy_detach11)
            self.agent.bagpipe_port_detach(None, dummy_detach21)

            # Check if calls on BaGPipe BGP API are as expected
            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            for network_id in [base.NETWORK1['id'], base.NETWORK2['id']]:
                self._check_network_info(network_id, 0)

            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)


class TestServiceBaGPipeL2LinuxBridge(
        base.BaseTestBaGPipeBGPAgentLinuxBridge, TestServiceBaGPipeL2Mixin):
    pass
