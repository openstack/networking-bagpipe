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


class TestServiceCombinedMixin(object):

    def test_combined_attach_single_port_evpns(self):
        bagpipe_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                        evpn=base.BAGPIPE_L2_RT1).__dict__
        bgpvpn_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                       bgpvpn_port=True,
                                       evpn=base.BGPVPN_L2_RT10).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=base.BAGPIPE_L2_RT1)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_info(base.NETWORK1['id'],
                                     1,
                                     agent.BAGPIPE_L2_SERVICE,
                                     agent.EVPN,
                                     base.BAGPIPE_L2_RT1)
            self._check_network_info(base.NETWORK1['id'],
                                     1,
                                     agent.BGPVPN_SERVICE,
                                     agent.BGPVPN_L2,
                                     base.BGPVPN_L2_RT10)

    def test_combined_attach_single_port_different_vpns(self):
        bagpipe_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                        evpn=base.BAGPIPE_L2_RT1).__dict__
        bgpvpn_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                       bgpvpn_port=True,
                                       ipvpn=base.BGPVPN_L3_RT100).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_info(base.NETWORK1['id'],
                                     1,
                                     agent.BAGPIPE_L2_SERVICE,
                                     agent.EVPN,
                                     base.BAGPIPE_L2_RT1)
            self._check_network_info(base.NETWORK1['id'],
                                     1,
                                     agent.BGPVPN_SERVICE,
                                     agent.BGPVPN_L3,
                                     base.BGPVPN_L3_RT100)

    def test_combined_attach_multiple_ports_same_evpns(self):
        bagpipe_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                        evpn=base.BAGPIPE_L2_RT1).__dict__
        bgpvpn_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                       bgpvpn_port=True,
                                       evpn=base.BGPVPN_L2_RT10).__dict__

        bagpipe_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                        evpn=base.BAGPIPE_L2_RT1).__dict__
        bgpvpn_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                       bgpvpn_port=True,
                                       evpn=base.BGPVPN_L2_RT10).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=base.BAGPIPE_L2_RT1),
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port11,
                                              self.DUMMY_VIF11,
                                              others_rts=base.BGPVPN_L2_RT10),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              bgpvpn_port11,
                                              self.DUMMY_VIF11,
                                              others_rts=base.BAGPIPE_L2_RT1)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bagpipe_port_attach(None, bagpipe_port11)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port11)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_info(base.NETWORK1['id'],
                                     2,
                                     agent.BAGPIPE_L2_SERVICE,
                                     agent.EVPN,
                                     base.BAGPIPE_L2_RT1)
            self._check_network_info(base.NETWORK1['id'],
                                     2,
                                     agent.BGPVPN_SERVICE,
                                     agent.BGPVPN_L2,
                                     base.BGPVPN_L2_RT10)

    def test_combined_attach_multiple_ports_different_evpns(self):
        bagpipe_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                        evpn=base.BAGPIPE_L2_RT1).__dict__
        bgpvpn_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                       bgpvpn_port=True,
                                       evpn=base.BGPVPN_L2_RT10).__dict__

        bagpipe_port20 = base.DummyPort(base.NETWORK2, base.PORT20,
                                        evpn=base.BAGPIPE_L2_RT2).__dict__
        bgpvpn_port20 = base.DummyPort(base.NETWORK2, base.PORT20,
                                       bgpvpn_port=True,
                                       evpn=base.BGPVPN_L2_RT20).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=base.BAGPIPE_L2_RT1),
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port20,
                                              self.DUMMY_VIF20),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              bgpvpn_port20,
                                              self.DUMMY_VIF20,
                                              others_rts=base.BAGPIPE_L2_RT2)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bagpipe_port_attach(None, bagpipe_port20)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port20)

            send_attach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            for network_id, bagpipe_rts, bgpvpn_rts in [
                    (base.NETWORK1['id'], base.BAGPIPE_L2_RT1,
                     base.BGPVPN_L2_RT10),
                    (base.NETWORK2['id'], base.BAGPIPE_L2_RT2,
                     base.BGPVPN_L2_RT20)]:
                self._check_network_info(network_id,
                                         1,
                                         agent.BAGPIPE_L2_SERVICE,
                                         agent.EVPN,
                                         bagpipe_rts)
                self._check_network_info(network_id,
                                         1,
                                         agent.BGPVPN_SERVICE,
                                         agent.BGPVPN_L2,
                                         bgpvpn_rts)

    def test_combined_attach_multiple_ports_different_vpns(self):
        bagpipe_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                        evpn=base.BAGPIPE_L2_RT1).__dict__
        bgpvpn_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                       bgpvpn_port=True,
                                       ipvpn=base.BGPVPN_L3_RT100).__dict__

        bagpipe_port20 = base.DummyPort(base.NETWORK2, base.PORT20,
                                        evpn=base.BAGPIPE_L2_RT2).__dict__
        bgpvpn_port20 = base.DummyPort(base.NETWORK2, base.PORT20,
                                       bgpvpn_port=True,
                                       ipvpn=base.BGPVPN_L3_RT200).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True),
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port20,
                                              self.DUMMY_VIF20),
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port20,
                                              self.DUMMY_VIF20),
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              bgpvpn_port20,
                                              self.DUMMY_VIF20,
                                              evpn2ipvpn=True)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bagpipe_port_attach(None, bagpipe_port20)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port20)

            send_attach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            for network_id, bagpipe_rts, bgpvpn_rts in [
                    (base.NETWORK1['id'], base.BAGPIPE_L2_RT1,
                     base.BGPVPN_L3_RT100),
                    (base.NETWORK2['id'], base.BAGPIPE_L2_RT2,
                     base.BGPVPN_L3_RT200)]:
                self._check_network_info(network_id,
                                         1,
                                         agent.BAGPIPE_L2_SERVICE,
                                         agent.EVPN,
                                         bagpipe_rts)
                self._check_network_info(network_id,
                                         1,
                                         agent.BGPVPN_SERVICE,
                                         agent.BGPVPN_L3,
                                         bgpvpn_rts)

    def test_combined_detach_single_port_evpns1(self):
        bagpipe_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                        evpn=base.BAGPIPE_L2_RT1).__dict__
        bgpvpn_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                       bgpvpn_port=True,
                                       evpn=base.BGPVPN_L2_RT10).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=base.BAGPIPE_L2_RT1)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'], 0)

            self.agent.bagpipe_port_detach(None, dummy_detach10)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)

    def test_combined_detach_single_port_evpns2(self):
        bagpipe_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                        evpn=base.BAGPIPE_L2_RT1).__dict__
        bgpvpn_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                       bgpvpn_port=True,
                                       evpn=base.BGPVPN_L2_RT10).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        with mock.patch.object(
            self.agent,
            '_send_detach_local_port',
            side_effect=[None,
                         agent.BaGPipeBGPException(reason="Port not plugged")]
        ) as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=base.BGPVPN_L2_RT10)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bagpipe_port_detach(None, dummy_detach10)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'], 0)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)

    def test_combined_detach_single_port_different_vpns(self):
        bagpipe_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                        evpn=base.BAGPIPE_L2_RT1).__dict__
        bgpvpn_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                       bgpvpn_port=True,
                                       ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True),
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)
            self.agent.bagpipe_port_attach(None, bagpipe_port10)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)
            self.agent.bagpipe_port_detach(None, dummy_detach10)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)

    def test_combined_detach_multiple_ports_same_evpns(self):
        bagpipe_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                        evpn=base.BAGPIPE_L2_RT1).__dict__
        bgpvpn_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                       bgpvpn_port=True,
                                       evpn=base.BGPVPN_L2_RT10).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        bagpipe_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                        evpn=base.BAGPIPE_L2_RT1).__dict__
        bgpvpn_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                       bgpvpn_port=True,
                                       evpn=base.BGPVPN_L2_RT10).__dict__
        dummy_detach11 = dict(id=base.PORT11['id'],
                              network_id=base.NETWORK1['id'])

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=base.BAGPIPE_L2_RT1),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              bgpvpn_port11,
                                              self.DUMMY_VIF11,
                                              others_rts=base.BAGPIPE_L2_RT1)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bagpipe_port_attach(None, bagpipe_port11)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port11)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)
            self.agent.bagpipe_port_detach(None, dummy_detach10)

            self.agent.bgpvpn_port_detach(None, dummy_detach11)
            self.agent.bagpipe_port_detach(None, dummy_detach11)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)

    def test_combined_detach_multiple_ports_different_vpns(self):
        bagpipe_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                        evpn=base.BAGPIPE_L2_RT1).__dict__
        bgpvpn_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                       bgpvpn_port=True,
                                       ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        bagpipe_port20 = base.DummyPort(base.NETWORK2, base.PORT20,
                                        evpn=base.BAGPIPE_L2_RT2).__dict__
        bgpvpn_port20 = base.DummyPort(base.NETWORK2, base.PORT20,
                                       bgpvpn_port=True,
                                       ipvpn=base.BGPVPN_L3_RT200).__dict__
        dummy_detach20 = dict(id=base.PORT20['id'],
                              network_id=base.NETWORK2['id'])

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True),
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              bgpvpn_port20,
                                              self.DUMMY_VIF20,
                                              evpn2ipvpn=True),
                self._mock_send_expected_call(agent.EVPN,
                                              bagpipe_port20,
                                              self.DUMMY_VIF20)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bagpipe_port_attach(None, bagpipe_port20)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port20)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)
            self.agent.bagpipe_port_detach(None, dummy_detach10)

            self.agent.bgpvpn_port_detach(None, dummy_detach20)
            self.agent.bagpipe_port_detach(None, dummy_detach20)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            for network_id in [base.NETWORK1['id'], base.NETWORK2['id']]:
                self._check_network_info(network_id, 0)

            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)


class TestServiceCombinedLinuxBridge(
        base.BaseTestBaGPipeBGPAgentLinuxBridge, TestServiceCombinedMixin):
    pass
