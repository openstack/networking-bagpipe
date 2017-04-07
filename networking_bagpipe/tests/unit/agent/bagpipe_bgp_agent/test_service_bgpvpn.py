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

import copy

import mock

from networking_bagpipe.agent import bagpipe_bgp_agent as agent

from networking_bagpipe.tests.unit.agent.bagpipe_bgp_agent import base


class TestServiceBGPVPNMixin(object):

    def test_update_bgpvpn_no_plugged_ports(self):
        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l2vpn=base.BGPVPN_L2_RT10).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            self.agent.update_bgpvpn(None, dummy_bgpvpn1)

            self.assertEqual(0, send_attach_fn.call_count,
                             "Send attach mustn't be called")

    def test_update_bgpvpn_already_plugged_ports(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10).__dict__
        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11).__dict__

        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l3vpn=base.BGPVPN_L3_RT100).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.IPVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=base.BGPVPN_L3_RT100),
                self._mock_send_expected_call(agent.IPVPN,
                                              dummy_port11,
                                              self.DUMMY_VIF11,
                                              others_rts=base.BGPVPN_L3_RT100)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port11)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'],
                                     2)

            self.agent.update_bgpvpn(None, dummy_bgpvpn1)

            send_attach_fn.assert_has_calls(expected_calls, any_order=True)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'],
                                     2,
                                     agent.BGPVPN_SERVICE,
                                     agent.BGPVPN_L3,
                                     base.BGPVPN_L3_RT100)

    def test_update_bgpvpn_same_vpn_types(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10).__dict__

        dummy_port10bis = base.DummyPort(base.NETWORK1, base.PORT10,
                                         bgpvpn_port=True,
                                         evpn=base.BGPVPN_L2_RT20).__dict__

        evpn_rts = ({k: base.BGPVPN_L2_RT10[k] + base.BGPVPN_L2_RT20[k]
                    for k in agent.RT_TYPES})

        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l2vpn=evpn_rts).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port10bis,
                                              self.DUMMY_VIF10,
                                              others_rts=base.BGPVPN_L2_RT10)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)

            self.agent.update_bgpvpn(None, dummy_bgpvpn1)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_info(base.NETWORK1['id'],
                                     1,
                                     agent.BGPVPN_SERVICE,
                                     agent.BGPVPN_L2,
                                     evpn_rts)

    def test_update_bgpvpn_different_vpn_types(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10).__dict__

        dummy_port10bis = base.DummyPort(base.NETWORK1, base.PORT10,
                                         bgpvpn_port=True,
                                         evpn=base.BGPVPN_L2_RT10,
                                         ipvpn=base.BGPVPN_L3_RT100).__dict__

        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l2vpn=base.BGPVPN_L2_RT10,
                                         l3vpn=base.BGPVPN_L3_RT100).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port10bis,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              dummy_port10bis,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)

            self.agent.update_bgpvpn(None, dummy_bgpvpn1)

            send_attach_fn.assert_has_calls(expected_calls)

            for bgpvpn_type, bgpvpn_rts in [
                    (agent.BGPVPN_L2, base.BGPVPN_L2_RT10),
                    (agent.BGPVPN_L3, base.BGPVPN_L3_RT100)]:
                self._check_network_info(base.NETWORK1['id'],
                                         1,
                                         agent.BGPVPN_SERVICE,
                                         bgpvpn_type,
                                         bgpvpn_rts)

    def test_delete_bgpvpn_remaining_plugged_ports(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10).__dict__
        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10).__dict__

        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l2vpn=base.BGPVPN_L2_RT10).__dict__

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port11,
                                              self.DUMMY_VIF11)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port11)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'],
                                     2,
                                     agent.BGPVPN_SERVICE,
                                     agent.BGPVPN_L2,
                                     base.BGPVPN_L2_RT10)

            self.agent.delete_bgpvpn(None, dummy_bgpvpn1)

            send_detach_fn.assert_has_calls(expected_calls, any_order=True)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'],
                                     2)

    def test_delete_bgpvpn_remaining_plugged_ports_after_update(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10).__dict__
        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10).__dict__

        update_rts = ({k: base.BGPVPN_L2_RT10[k] + base.BGPVPN_L2_RT20[k]
                       for k in agent.RT_TYPES})

        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l2vpn=update_rts).__dict__

        dummy_bgpvpn1bis = base.DummyBGPVPN(base.NETWORK1,
                                            l2vpn=base.BGPVPN_L2_RT20).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=base.BGPVPN_L2_RT20),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port11,
                                              self.DUMMY_VIF11,
                                              others_rts=base.BGPVPN_L2_RT20),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port11,
                                              self.DUMMY_VIF11)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port11)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'],
                                     2,
                                     agent.BGPVPN_SERVICE,
                                     agent.BGPVPN_L2,
                                     base.BGPVPN_L2_RT10)

            send_attach_fn.reset_mock()

            self.agent.update_bgpvpn(None, dummy_bgpvpn1)

            self.agent.delete_bgpvpn(None, dummy_bgpvpn1bis)

            send_attach_fn.assert_has_calls(expected_calls, any_order=True)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'],
                                     2,
                                     agent.BGPVPN_SERVICE,
                                     agent.BGPVPN_L2,
                                     base.BGPVPN_L2_RT10)

    def test_delete_bgpvpn_no_plugged_ports(self):
        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l2vpn=base.BGPVPN_L2_RT10).__dict__

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            self.agent.delete_bgpvpn(None, dummy_bgpvpn1)

            self.assertEqual(0, send_detach_fn.call_count,
                             "Send detach mustn't be called")

    def test_delete_bgpvpn_had_plugged_ports(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L2_RT10).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L2_RT10).__dict__
        dummy_detach11 = dict(id=base.PORT11['id'],
                              network_id=base.NETWORK1['id'])

        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l3vpn=base.BGPVPN_L2_RT10).__dict__

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port11)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)
            self.agent.bgpvpn_port_detach(None, dummy_detach11)

            self.assertEqual(2, send_detach_fn.call_count,
                             "Send detach must be called twice")

            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)

            send_detach_fn.reset_mock()
            self.agent.delete_bgpvpn(None, dummy_bgpvpn1)

            self.assertEqual(0, send_detach_fn.call_count,
                             "Send detach isn't be called")

    def _test_bgpvpn_attach_single_port(self, bgpvpn_type, bgpvpn_rts):
        bgpvpn_info = {agent.BGPVPN_TYPES_MAP[bgpvpn_type]: bgpvpn_rts}
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      **bgpvpn_info).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(bgpvpn_type,
                                              dummy_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_info(base.NETWORK1['id'],
                                     1,
                                     agent.BGPVPN_SERVICE,
                                     bgpvpn_type,
                                     bgpvpn_rts)

    def test_bgpvpn_attach_single_port_l3_bgpvpn(self):
        self._test_bgpvpn_attach_single_port(agent.BGPVPN_L3,
                                             base.BGPVPN_L3_RT100)

    def test_bgpvpn_attach_single_port_bgpvpn(self):
        self._test_bgpvpn_attach_single_port(agent.BGPVPN_L2,
                                             base.BGPVPN_L2_RT10)

    def test_bgpvpn_attach_same_port_different_bgpvpn(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10).__dict__
        dummy_port10bis = base.DummyPort(base.NETWORK1, base.PORT10,
                                         bgpvpn_port=True,
                                         evpn=base.BGPVPN_L2_RT10,
                                         ipvpn=base.BGPVPN_L3_RT100).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port10bis,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              dummy_port10bis,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)

            self._check_network_info(base.NETWORK1['id'],
                                     1,
                                     agent.BGPVPN_SERVICE,
                                     agent.BGPVPN_L2,
                                     base.BGPVPN_L2_RT10)

            self.agent.bgpvpn_port_attach(None, dummy_port10bis)

            send_attach_fn.assert_has_calls(expected_calls)

            for bgpvpn_type, bgpvpn_rts in [
                    (agent.BGPVPN_L2, base.BGPVPN_L2_RT10),
                    (agent.BGPVPN_L3, base.BGPVPN_L3_RT100)]:
                self._check_network_info(base.NETWORK1['id'],
                                         1,
                                         agent.BGPVPN_SERVICE,
                                         bgpvpn_type,
                                         bgpvpn_rts)

    def test_bgpvpn_attach_single_port_multiple_bgpvpns(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              dummy_port10,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)

            send_attach_fn.assert_has_calls(expected_calls)

            for bgpvpn_type, bgpvpn_rts in [
                    (agent.BGPVPN_L2, base.BGPVPN_L2_RT10),
                    (agent.BGPVPN_L3, base.BGPVPN_L3_RT100)]:
                self._check_network_info(base.NETWORK1['id'],
                                         1,
                                         agent.BGPVPN_SERVICE,
                                         bgpvpn_type,
                                         bgpvpn_rts)

    def test_bgpvpn_attach_multiple_ports_same_bgpvpn(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              dummy_port11,
                                              self.DUMMY_VIF11)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port11)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_info(base.NETWORK1['id'],
                                     2,
                                     agent.BGPVPN_SERVICE,
                                     agent.BGPVPN_L3,
                                     base.BGPVPN_L3_RT100)

    def test_bgpvpn_attach_multiple_ports_different_bgpvpns(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_port20 = base.DummyPort(base.NETWORK2, base.PORT20,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT200).__dict__

        with mock.patch.object(self.agent,
                               '_send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              dummy_port20,
                                              self.DUMMY_VIF20)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port20)

            send_attach_fn.assert_has_calls(expected_calls)

            for network_id, bgpvpn_rts in [
                    (base.NETWORK1['id'], base.BGPVPN_L3_RT100),
                    (base.NETWORK2['id'], base.BGPVPN_L3_RT200)]:
                self._check_network_info(network_id,
                                         1,
                                         agent.BGPVPN_SERVICE,
                                         agent.BGPVPN_L3,
                                         bgpvpn_rts)

    def _test_bgpvpn_detach_single_port(self, bgpvpn_type, bgpvpn_rts):
        bgpvpn_info = {agent.BGPVPN_TYPES_MAP[bgpvpn_type]: bgpvpn_rts}
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      **bgpvpn_info).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(bgpvpn_type,
                                              dummy_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_detach(None, dummy_detach10)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)

    def test_bgpvpn_detach_single_port_l3_bgpvpn(self):
        self._test_bgpvpn_detach_single_port(agent.BGPVPN_L3,
                                             base.BGPVPN_L3_RT100)

    def test_bgpvpn_detach_single_port_bgpvpn(self):
        self._test_bgpvpn_detach_single_port(agent.BGPVPN_L2,
                                             base.BGPVPN_L2_RT10)

    def test_bgpvpn_detach_single_port_multiple_bgpvpns(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              dummy_port10,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True),
                self._mock_send_expected_call(agent.BGPVPN_L2,
                                              dummy_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_detach(None, dummy_detach10)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)

    def test_bgpvpn_detach_multiple_ports_same_bgpvpn(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_detach11 = dict(id=base.PORT11['id'],
                              network_id=base.NETWORK1['id'])

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              dummy_port11,
                                              self.DUMMY_VIF11)
            ]

            # Attach 2 ports on BGP VPN L3 1
            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port11)

            # Detach 1 port from BGP VPN L3 1
            self.agent.bgpvpn_port_detach(None, dummy_detach10)

            # Detach remaining port from BGP VPN L3 1
            self.agent.bgpvpn_port_detach(None, dummy_detach11)

            # Check if calls on BaGPipe BGP API are as expected
            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_info(base.NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)

    def test_bgpvpn_detach_multiple_ports_different_bgpvpns(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        dummy_port20 = base.DummyPort(base.NETWORK2, base.PORT20,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT200).__dict__
        dummy_detach20 = dict(id=base.PORT20['id'],
                              network_id=base.NETWORK2['id'])

        with mock.patch.object(self.agent,
                               '_send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(agent.BGPVPN_L3,
                                              dummy_port20,
                                              self.DUMMY_VIF20)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port20)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)
            self.agent.bgpvpn_port_detach(None, dummy_detach20)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            for network_id in [base.NETWORK1['id'], base.NETWORK2['id']]:
                self._check_network_info(network_id, 0)

            self.assertEqual(0, len(self.agent.networks_info),
                             "Registered attachments list must be empty: %s" %
                             self.agent.networks_info)


class TestServiceBGPVPNLinuxBridge(base.BaseTestBaGPipeBGPAgentLinuxBridge,
                                   TestServiceBGPVPNMixin):
    pass


class TestServiceBGPVPNOVS(base.BaseTestBaGPipeBGPAgentOVS,
                           TestServiceBGPVPNMixin):

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_update_bgpvpn_already_plugged_ports(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestServiceBGPVPNOVS,
                  self).test_update_bgpvpn_already_plugged_ports()
            self.assertEqual(1, gw_redir_fn.call_count)

    def test_update_bgpvpn_same_vpn_types(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestServiceBGPVPNOVS,
                  self).test_update_bgpvpn_same_vpn_types()

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_update_bgpvpn_different_vpn_types(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestServiceBGPVPNOVS,
                  self).test_update_bgpvpn_different_vpn_types()
            self.assertEqual(1, gw_redir_fn.call_count)

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_delete_bgpvpn_remaining_plugged_ports(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestServiceBGPVPNOVS,
                  self).test_delete_bgpvpn_remaining_plugged_ports()

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_delete_bgpvpn_had_plugged_ports(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestServiceBGPVPNOVS,
                  self).test_delete_bgpvpn_had_plugged_ports()

            self.assertEqual(2, gw_redir_fn.call_count)

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def _test_bgpvpn_attach_single_port(self, bgpvpn, network,
                                        gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestServiceBGPVPNOVS,
                  self)._test_bgpvpn_attach_single_port(bgpvpn, network)
            self.assertEqual(1 if bgpvpn == agent.BGPVPN_L3 else 0,
                             gw_redir_fn.call_count)

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_bgpvpn_attach_same_port_different_bgpvpn(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestServiceBGPVPNOVS,
                  self).test_bgpvpn_attach_same_port_different_bgpvpn()
            self.assertEqual(1, gw_redir_fn.call_count)

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_bgpvpn_attach_single_port_multiple_bgpvpns(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestServiceBGPVPNOVS,
                  self).test_bgpvpn_attach_single_port_multiple_bgpvpns()
            self.assertEqual(1, gw_redir_fn.call_count)

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_bgpvpn_attach_multiple_ports_same_bgpvpn(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestServiceBGPVPNOVS,
                  self).test_bgpvpn_attach_multiple_ports_same_bgpvpn()
            self.assertEqual(2, gw_redir_fn.call_count)

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_bgpvpn_attach_multiple_ports_different_bgpvpns(self,
                                                            gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF20]):
            super(TestServiceBGPVPNOVS,
                  self).test_bgpvpn_attach_multiple_ports_different_bgpvpns()
            self.assertEqual(2, gw_redir_fn.call_count)

    def _test_bgpvpn_detach_single_port(self, bgpvpn, network):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestServiceBGPVPNOVS,
                  self)._test_bgpvpn_detach_single_port(bgpvpn, network)

    def test_bgpvpn_detach_single_port_multiple_bgpvpns(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestServiceBGPVPNOVS,
                  self).test_bgpvpn_detach_single_port_multiple_bgpvpns()

    def test_bgpvpn_detach_multiple_ports_same_bgpvpn(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestServiceBGPVPNOVS,
                  self).test_bgpvpn_detach_multiple_ports_same_bgpvpn()

    def test_bgpvpn_detach_multiple_ports_different_bgpvpns(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF20]):
            super(TestServiceBGPVPNOVS,
                  self).test_bgpvpn_detach_multiple_ports_different_bgpvpns()

    # Test fallback and ARP gateway voodoo

    def test_fallback(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestServiceBGPVPNOVS,
                  self).test_update_bgpvpn_already_plugged_ports()

            port10_with_gw_mac = base.DummyPort(base.NETWORK1,
                                                base.PORT10).__dict__
            port10_with_gw_mac.update({'gateway_mac': GW_MAC})
            port10_with_gw_mac.update(
                base.DummyBGPVPN(base.NETWORK1,
                                 l3vpn=base.BGPVPN_L3_RT100).__dict__)
            with mock.patch.object(self.agent, '_send_attach_local_port') as\
                    send_attach_fn:
                self.agent.bgpvpn_port_attach(None,
                                              copy.copy(port10_with_gw_mac))

                fallback = {'dst_mac': GW_MAC,
                            'ovs_port_number': base.PATCH_MPLS_TO_INT_OFPORT,
                            'src_mac': '00:00:5e:2a:10:00'}

                expected_calls = [
                    self._mock_send_expected_call(agent.BGPVPN_L3,
                                                  port10_with_gw_mac,
                                                  self.DUMMY_VIF10,
                                                  fallback=fallback),
                ]

                send_attach_fn.assert_has_calls(expected_calls)

    def test_gateway_arp_voodoo(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent.int_br,
                                  'add_flow') as add_flow, \
                mock.patch.object(self.agent.tun_br,
                                  'delete_flows') as tun_delete_flows,\
                mock.patch.object(self.agent.int_br,
                                  'delete_flows') as int_delete_flows:
            super(TestServiceBGPVPNOVS,
                  self).test_update_bgpvpn_already_plugged_ports()

            port10_with_gw_mac = base.DummyPort(base.NETWORK1,
                                                base.PORT10).__dict__
            port10_with_gw_mac.update({'gateway_mac': GW_MAC})
            port10_with_gw_mac.update(
                base.DummyBGPVPN(base.NETWORK1,
                                 l3vpn=base.BGPVPN_L3_RT100).__dict__)

            self.agent.bgpvpn_port_attach(None, copy.copy(port10_with_gw_mac))

            self.assertEqual(2, add_flow.call_count)

            add_flow.assert_has_calls([
                mock.call(table=mock.ANY,
                          priority=2,
                          proto='arp',
                          arp_op=0x2,
                          dl_src=GW_MAC,
                          arp_sha=GW_MAC,
                          arp_spa='10.0.0.1',
                          actions="drop"),
                mock.call(table=mock.ANY,
                          priority=2,
                          proto='arp',
                          arp_op=0x01,
                          dl_src=GW_MAC,
                          arp_spa='10.0.0.1',
                          arp_sha=GW_MAC,
                          actions="load:0x0->NXM_OF_ARP_SPA[],NORMAL"
                          )
            ])

            self.agent.bgpvpn_port_detach(None,
                                          base.DummyPort(base.NETWORK1,
                                                         base.PORT10).__dict__)

            self.assertEqual(0, tun_delete_flows.call_count)
            self.assertEqual(0, int_delete_flows.call_count)

            self.agent.bgpvpn_port_detach(None,
                                          base.DummyPort(base.NETWORK1,
                                                         base.PORT11).__dict__)

            self.assertEqual(1, tun_delete_flows.call_count)
            self.assertEqual(1, int_delete_flows.call_count)

            tun_delete_flows.assert_has_calls([
                mock.call(table=mock.ANY,
                          priority=2,
                          strict=True,
                          proto='arp',
                          arp_op=0x01,
                          arp_tpa='10.0.0.1',
                          dl_vlan=mock.ANY,
                          )])
            int_delete_flows.assert_has_calls([
                mock.call(table=mock.ANY,
                          proto='arp',
                          dl_src=GW_MAC,
                          arp_sha=GW_MAC),
            ])

    def test_gateway_arp_voodoo_update_bgpvpn_after_plug(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent.int_br,
                                  'add_flow') as add_flow:
            port10 = base.DummyPort(base.NETWORK1, base.PORT10).__dict__
            port10.update({'gateway_mac': GW_MAC})

            self.agent.bgpvpn_port_attach(None, copy.copy(port10))

            dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                             l3vpn=base.BGPVPN_L3_RT100,
                                             gateway_mac=GW_MAC).__dict__

            with mock.patch.object(self.agent, '_send_attach_local_port') as\
                    send_attach_fn:

                self.agent.update_bgpvpn(None, copy.copy(dummy_bgpvpn1))

                self.assertEqual(2, add_flow.call_count)

                add_flow.assert_has_calls([
                    mock.call(table=mock.ANY,
                              priority=2,
                              proto='arp',
                              arp_op=0x2,
                              dl_src=GW_MAC,
                              arp_sha=GW_MAC,
                              arp_spa='10.0.0.1',
                              actions="drop"),
                    mock.call(table=mock.ANY,
                              priority=2,
                              proto='arp',
                              arp_op=0x01,
                              dl_src=GW_MAC,
                              arp_spa='10.0.0.1',
                              arp_sha=GW_MAC,
                              actions="load:0x0->NXM_OF_ARP_SPA[],NORMAL"
                              )
                ])

                fallback = {'dst_mac': GW_MAC,
                            'ovs_port_number': base.PATCH_MPLS_TO_INT_OFPORT,
                            'src_mac': '00:00:5e:2a:10:00'}

                expected_calls = [
                    self._mock_send_expected_call(
                        agent.IPVPN,
                        port10,
                        self.DUMMY_VIF10,
                        others_rts=base.BGPVPN_L3_RT100,
                        fallback=fallback),
                ]

                send_attach_fn.assert_has_calls(expected_calls)

                self.agent.delete_bgpvpn(None, copy.copy(dummy_bgpvpn1))

                add_flow.reset_mock()
                self.assertEqual(0, add_flow.call_count)

                self.agent.update_bgpvpn(None, copy.copy(dummy_bgpvpn1))

                self.assertEqual(2, add_flow.call_count)

    def test_gateway_plug_before_update(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10]), \
                mock.patch.object(self.agent.int_br,
                                  'add_flow') as add_flow:
            port10 = base.DummyPort(base.NETWORK1, base.PORT10).__dict__

            self.agent.bgpvpn_port_attach(None, copy.copy(port10))

            dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                             l3vpn=base.BGPVPN_L3_RT100,
                                             gateway_mac=GW_MAC).__dict__

            with mock.patch.object(self.agent, '_send_attach_local_port') as\
                    send_attach_fn:

                self.agent.update_bgpvpn(None, copy.copy(dummy_bgpvpn1))

                self.assertEqual(2, add_flow.call_count)

                add_flow.assert_has_calls([
                    mock.call(table=mock.ANY,
                              priority=2,
                              proto='arp',
                              arp_op=0x2,
                              dl_src=GW_MAC,
                              arp_sha=GW_MAC,
                              arp_spa='10.0.0.1',
                              actions="drop"),
                    mock.call(table=mock.ANY,
                              priority=2,
                              proto='arp',
                              arp_op=0x01,
                              dl_src=GW_MAC,
                              arp_spa='10.0.0.1',
                              arp_sha=GW_MAC,
                              actions="load:0x0->NXM_OF_ARP_SPA[],NORMAL"
                              )
                ])

                fallback = {'dst_mac': GW_MAC,
                            'ovs_port_number': base.PATCH_MPLS_TO_INT_OFPORT,
                            'src_mac': '00:00:5e:2a:10:00'}

                expected_calls = [
                    self._mock_send_expected_call(
                        agent.IPVPN,
                        port10,
                        self.DUMMY_VIF10,
                        others_rts=base.BGPVPN_L3_RT100,
                        fallback=fallback),
                ]

                send_attach_fn.assert_has_calls(expected_calls)

                self.agent.delete_bgpvpn(None, copy.copy(dummy_bgpvpn1))

                add_flow.reset_mock()
                self.assertEqual(0, add_flow.call_count)

                self.agent.update_bgpvpn(None, dummy_bgpvpn1)

                self.assertEqual(2, add_flow.call_count)

    def test_evpn_no_gateway_arp_voodoo(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent.int_br,
                                  'add_flow') as add_flow, \
                mock.patch.object(self.agent.int_br,
                                  'delete_flows') as delete_flows:

            port10_with_gw_mac = base.DummyPort(base.NETWORK1,
                                                base.PORT10).__dict__
            port10_with_gw_mac.update({'gateway_mac': GW_MAC})
            port10_with_gw_mac.update(
                base.DummyBGPVPN(base.NETWORK1,
                                 l2vpn=base.BGPVPN_L2_RT10).__dict__)

            self.agent.bgpvpn_port_attach(None, copy.copy(port10_with_gw_mac))

            self.assertEqual(0, add_flow.call_count)

            self.agent.bgpvpn_port_detach(None,
                                          base.DummyPort(base.NETWORK1,
                                                         base.PORT10).__dict__)
            self.assertEqual(0, delete_flows.call_count)

            self.agent.bgpvpn_port_detach(None,
                                          base.DummyPort(base.NETWORK1,
                                                         base.PORT11).__dict__)

            self.assertEqual(0, delete_flows.call_count)

    def test_gateway_arp_voodoo_ovs_restart(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent.int_br,
                                  'add_flow') as add_flow:
            port10 = base.DummyPort(base.NETWORK1, base.PORT10).__dict__
            port10.update({'gateway_mac': GW_MAC})

            self.agent.bgpvpn_port_attach(None, copy.copy(port10))

            dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                             l3vpn=base.BGPVPN_L3_RT100,
                                             gateway_mac=GW_MAC).__dict__

            self.agent.update_bgpvpn(None, dummy_bgpvpn1)

            self.assertEqual(2, add_flow.call_count)

            expected_calls = [
                mock.call(table=mock.ANY,
                          priority=2,
                          proto='arp',
                          arp_op=0x2,
                          dl_src=GW_MAC,
                          arp_sha=GW_MAC,
                          arp_spa='10.0.0.1',
                          actions="drop"),
                mock.call(table=mock.ANY,
                          priority=2,
                          proto='arp',
                          arp_op=0x01,
                          dl_src=GW_MAC,
                          arp_spa='10.0.0.1',
                          arp_sha=GW_MAC,
                          actions="load:0x0->NXM_OF_ARP_SPA[],NORMAL"
                          )
            ]
            add_flow.assert_has_calls(expected_calls)

            add_flow.reset_mock()

            self.agent.ovs_restarted_bgpvpn()

            add_flow.assert_has_calls(expected_calls)
