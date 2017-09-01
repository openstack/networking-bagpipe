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

from networking_bagpipe.agent.common import constants as b_const

from networking_bagpipe.agent.bgpvpn import agent_extension as bagpipe_agt_ext
from networking_bagpipe.agent.bgpvpn import constants as bgpvpn_const

from networking_bagpipe.tests.unit.agent import base


class TestBgpvpnAgentExtensionMixin(object):

    def _get_vpn_info(self, vpn_type, vpn_if, rts, fallback=None):
        vpn_info = {vpn_type: vpn_if}
        vpn_info[vpn_type].update(rts)

        if fallback:
            vpn_info[vpn_type].update(dict(fallback=fallback))

        return copy.deepcopy(vpn_info)

    def test_update_bgpvpn_no_plugged_ports(self):
        dummy_bgpvpn1 = base.DummyBGPVPN(
            base.NETWORK1,
            l2vpn=base.BGPVPN_L2_RT10).__dict__

        self.agent_ext.update_bgpvpn(None, dummy_bgpvpn1)

        self.assertEqual(0, self.mocked_bagpipe_agent.do_port_plug.call_count,
                         "Do port plug mustn't be called")

    def test_update_bgpvpn_already_plugged_ports(self):
        dummy_port10 = base.DummyPort(base.NETWORK1,
                                      base.PORT10).__dict__
        dummy_port11 = base.DummyPort(base.NETWORK1,
                                      base.PORT11).__dict__

        dummy_bgpvpn1 = base.DummyBGPVPN(
            base.NETWORK1,
            l3vpn=base.BGPVPN_L3_RT100).__dict__

        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port10))
        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port11))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'],
                                 2)

        self.agent_ext.update_bgpvpn(None, dummy_bgpvpn1)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'],
                                 2,
                                 bgpvpn_const.BGPVPN_L3,
                                 base.BGPVPN_L3_RT100)

        # Verify build callback attachments
        for port in [base.PORT10, base.PORT11]:
            local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                       base.NETWORK1['id'],
                                                       port['id'])

            self.assertEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ip_address=port['ip_address'],
                    mac_address=port['mac_address'],
                    gateway_ip=base.NETWORK1['gateway_ip'],
                    local_port=dict(linuxif=local_port['linuxif']),
                    **self._get_vpn_info(b_const.IPVPN,
                                         local_port['ipvpnif'],
                                         base.BGPVPN_L3_RT100)
                ),
                self.agent_ext.build_bgpvpn_attach_info(port['id'])
            )

    def test_update_bgpvpn_before_port_detach(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        dummy_bgpvpn1 = base.DummyBGPVPN(
            base.NETWORK1,
            l3vpn=base.BGPVPN_L3_RT100).__dict__

        self.agent_ext.bgpvpn_port_attach(None, dummy_port10)

        self.agent_ext.update_bgpvpn(None, dummy_bgpvpn1)

        self.agent_ext.bgpvpn_port_detach(None, dummy_detach10)

        local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'])
        detach_info = {
            b_const.IPVPN: {
                'network_id': base.NETWORK1['id'],
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': dict(linuxif=local_port['linuxif'])
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info)]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 0)

        self.assertEqual(0, len(self.agent_ext.networks_info),
                         "Registered attachments list must be empty: %s" %
                         self.agent_ext.networks_info)

    def test_update_bgpvpn_same_vpn_types(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__

        ipvpn_rts = ({k: base.BGPVPN_L3_RT100[k] + base.BGPVPN_L3_RT200[k]
                      for k in b_const.RT_TYPES})

        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l3vpn=ipvpn_rts).__dict__

        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port10))

        self.agent_ext.update_bgpvpn(None, dummy_bgpvpn1)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'],
                                 1,
                                 bgpvpn_const.BGPVPN_L3,
                                 ipvpn_rts)

        # Verify build callback attachments
        local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'])
        self.assertEqual(
            dict(
                network_id=base.NETWORK1['id'],
                ip_address=base.PORT10['ip_address'],
                mac_address=base.PORT10['mac_address'],
                gateway_ip=base.NETWORK1['gateway_ip'],
                local_port=dict(linuxif=local_port['linuxif']),
                **self._get_vpn_info(b_const.IPVPN,
                                     local_port['ipvpnif'],
                                     ipvpn_rts)
            ),
            self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
        )

    def test_delete_bgpvpn_remaining_plugged_ports(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__

        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l3vpn=base.BGPVPN_L3_RT100).__dict__

        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port10))
        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port11))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'],
                                 2,
                                 bgpvpn_const.BGPVPN_L3,
                                 base.BGPVPN_L3_RT100)

        self.mocked_bagpipe_agent.reset_mock()

        self.agent_ext.delete_bgpvpn(None, dummy_bgpvpn1)

        local_port10 = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                     base.NETWORK1['id'],
                                                     base.PORT10['id'])
        detach_info10 = {
            b_const.IPVPN: dict(
                network_id=base.NETWORK1['id'],
                ip_address=base.PORT10['ip_address'],
                mac_address=base.PORT10['mac_address'],
                local_port=dict(linuxif=local_port10['linuxif'])
            )
        }

        local_port11 = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                     base.NETWORK1['id'],
                                                     base.PORT11['id'])
        detach_info11 = {
            b_const.IPVPN: dict(
                network_id=base.NETWORK1['id'],
                ip_address=base.PORT11['ip_address'],
                mac_address=base.PORT11['mac_address'],
                local_port=dict(linuxif=local_port11['linuxif'])
            )
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info10),
             mock.call(base.PORT11['id'], detach_info11)],
            any_order=True
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'],
                                 2)

        # Verify build callback attachments
        self.assertEqual(
            dict(
                network_id=base.NETWORK1['id'],
                ip_address=base.PORT10['ip_address'],
                mac_address=base.PORT10['mac_address'],
                gateway_ip=base.NETWORK1['gateway_ip'],
                local_port=dict(linuxif=local_port10['linuxif'])
            ),
            self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
        )

    def test_delete_bgpvpn_remaining_plugged_ports_after_update(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__

        update_rts = ({k: base.BGPVPN_L3_RT100[k] + base.BGPVPN_L3_RT200[k]
                       for k in b_const.RT_TYPES})

        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l3vpn=update_rts).__dict__

        dummy_bgpvpn1bis = base.DummyBGPVPN(
            base.NETWORK1,
            l3vpn=base.BGPVPN_L3_RT200).__dict__

        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port10))
        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port11))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'],
                                 2,
                                 bgpvpn_const.BGPVPN_L3,
                                 base.BGPVPN_L3_RT100)

        self.mocked_bagpipe_agent.reset_mock()

        self.agent_ext.update_bgpvpn(None, dummy_bgpvpn1)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

        self.mocked_bagpipe_agent.reset_mock()

        self.agent_ext.delete_bgpvpn(None, dummy_bgpvpn1bis)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'],
                                 2,
                                 bgpvpn_const.BGPVPN_L3,
                                 base.BGPVPN_L3_RT100)

        # Verify build callback attachments
        for port in [base.PORT10, base.PORT10]:
            local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                       base.NETWORK1['id'],
                                                       port['id'])

            self.assertEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ip_address=port['ip_address'],
                    mac_address=port['mac_address'],
                    gateway_ip=base.NETWORK1['gateway_ip'],
                    local_port=dict(linuxif=local_port['linuxif']),
                    **self._get_vpn_info(b_const.IPVPN,
                                         local_port['ipvpnif'],
                                         base.BGPVPN_L3_RT100)
                ),
                self.agent_ext.build_bgpvpn_attach_info(port['id'])
            )

    def test_delete_bgpvpn_no_plugged_ports(self):
        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l3vpn=base.BGPVPN_L3_RT100).__dict__

        self.agent_ext.delete_bgpvpn(None, dummy_bgpvpn1)

        self.assertEqual(0, self.mocked_bagpipe_agent.do_port_plug.call_count,
                         "Do port plug mustn't be called")

    def test_delete_bgpvpn_had_plugged_ports(self):
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

        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l3vpn=base.BGPVPN_L3_RT100).__dict__

        self.agent_ext.bgpvpn_port_attach(None, dummy_port10)
        self.agent_ext.bgpvpn_port_attach(None, dummy_port11)

        self.agent_ext.bgpvpn_port_detach(None, dummy_detach10)
        self.agent_ext.bgpvpn_port_detach(None, dummy_detach11)

        self.assertEqual(
            2, self.mocked_bagpipe_agent.do_port_plug_refresh.call_count,
            "Do port unplug must be called twice")

        self.assertEqual(0, len(self.agent_ext.networks_info),
                         "Registered attachments list must be empty: %s" %
                         self.agent_ext.networks_info)

        self.mocked_bagpipe_agent.reset_mock()

        self.agent_ext.delete_bgpvpn(None, dummy_bgpvpn1)

        self.assertEqual(
            0, self.mocked_bagpipe_agent.do_port_plug_refresh.call_count,
            "Do port plug refresh musn't be called")

    def test_bgpvpn_attach_single_port_l3_bgpvpn(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__

        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port10))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'],
                                 1,
                                 bgpvpn_const.BGPVPN_L3,
                                 base.BGPVPN_L3_RT100)

        # Verify build callback attachments
        local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'])

        self.assertEqual(
            dict(
                network_id=base.NETWORK1['id'],
                ip_address=base.PORT10['ip_address'],
                mac_address=base.PORT10['mac_address'],
                gateway_ip=base.NETWORK1['gateway_ip'],
                local_port=dict(linuxif=local_port['linuxif']),
                **self._get_vpn_info(b_const.IPVPN,
                                     local_port['ipvpnif'],
                                     base.BGPVPN_L3_RT100)
            ),
            self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
        )

    def test_bgpvpn_attach_single_port_multiple_bgpvpns(self):
        ipvpn_rts = ({k: base.BGPVPN_L3_RT100[k] + base.BGPVPN_L3_RT200[k]
                      for k in b_const.RT_TYPES})

        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=ipvpn_rts).__dict__

        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port10))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'],
                                 1,
                                 bgpvpn_const.BGPVPN_L3,
                                 ipvpn_rts)

        # Verify build callback attachments
        local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'])

        self.assertEqual(
            dict(
                network_id=base.NETWORK1['id'],
                ip_address=base.PORT10['ip_address'],
                mac_address=base.PORT10['mac_address'],
                gateway_ip=base.NETWORK1['gateway_ip'],
                local_port=dict(linuxif=local_port['linuxif']),
                **self._get_vpn_info(b_const.IPVPN,
                                     local_port['ipvpnif'],
                                     ipvpn_rts)
            ),
            self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
        )

    def test_bgpvpn_attach_multiple_ports_same_bgpvpn(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_port11 = base.DummyPort(base.NETWORK1, base.PORT11,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__

        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port10))
        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port11))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])]
        )

        self._check_network_info(base.NETWORK1['id'],
                                 2,
                                 bgpvpn_const.BGPVPN_L3,
                                 base.BGPVPN_L3_RT100)

        # Verify build callback attachments
        for port in [base.PORT10, base.PORT10]:
            local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                       base.NETWORK1['id'],
                                                       port['id'])

            self.assertEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ip_address=port['ip_address'],
                    mac_address=port['mac_address'],
                    gateway_ip=base.NETWORK1['gateway_ip'],
                    local_port=dict(linuxif=local_port['linuxif']),
                    **self._get_vpn_info(b_const.IPVPN,
                                         local_port['ipvpnif'],
                                         base.BGPVPN_L3_RT100)
                ),
                self.agent_ext.build_bgpvpn_attach_info(port['id'])
            )

    def test_bgpvpn_attach_multiple_ports_different_bgpvpns(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_port20 = base.DummyPort(base.NETWORK2, base.PORT20,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT200).__dict__

        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port10))
        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port20))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT20['id'])]
        )

        for network_id, bgpvpn_rts in [
                (base.NETWORK1['id'], base.BGPVPN_L3_RT100),
                (base.NETWORK2['id'], base.BGPVPN_L3_RT200)]:
            self._check_network_info(network_id,
                                     1,
                                     bgpvpn_const.BGPVPN_L3,
                                     bgpvpn_rts)

        # Verify build callback attachments
        for port, network, rts in [(base.PORT10, base.NETWORK1,
                                    base.BGPVPN_L3_RT100),
                                   (base.PORT20, base.NETWORK2,
                                    base.BGPVPN_L3_RT200)]:
            local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                       network['id'],
                                                       port['id'])

            self.assertEqual(
                dict(
                    network_id=network['id'],
                    ip_address=port['ip_address'],
                    mac_address=port['mac_address'],
                    gateway_ip=network['gateway_ip'],
                    local_port=dict(linuxif=local_port['linuxif']),
                    **self._get_vpn_info(b_const.IPVPN,
                                         local_port['ipvpnif'],
                                         rts)
                ),
                self.agent_ext.build_bgpvpn_attach_info(port['id'])
            )

    def test_bgpvpn_detach_single_port_l3_bgpvpn(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        self.agent_ext.bgpvpn_port_attach(None, dummy_port10)

        self.mocked_bagpipe_agent.reset_mock()

        self.agent_ext.bgpvpn_port_detach(None, dummy_detach10)

        local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'])
        detach_info = {
            b_const.IPVPN: {
                'network_id': base.NETWORK1['id'],
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': dict(linuxif=local_port['linuxif'])
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info)]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 0)

        self.assertEqual(0, len(self.agent_ext.networks_info),
                         "Registered attachments list must be empty: %s" %
                         self.agent_ext.networks_info)

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

        # Attach 2 ports on BGP VPN L3 1
        self.agent_ext.bgpvpn_port_attach(None, dummy_port10)
        self.agent_ext.bgpvpn_port_attach(None, dummy_port11)

        # Detach remaining ports from BGP VPN L3 1
        self.agent_ext.bgpvpn_port_detach(None, dummy_detach10)
        self.agent_ext.bgpvpn_port_detach(None, dummy_detach11)

        local_port10 = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                     base.NETWORK1['id'],
                                                     base.PORT10['id'])
        detach_info10 = {
            b_const.IPVPN: {
                'network_id': base.NETWORK1['id'],
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': dict(linuxif=local_port10['linuxif'])
            }
        }

        local_port11 = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                     base.NETWORK1['id'],
                                                     base.PORT11['id'])
        detach_info11 = {
            b_const.IPVPN: {
                'network_id': base.NETWORK1['id'],
                'ip_address': base.PORT11['ip_address'],
                'mac_address': base.PORT11['mac_address'],
                'local_port': dict(linuxif=local_port11['linuxif'])
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

        self.agent_ext.bgpvpn_port_attach(None, dummy_port10)
        self.agent_ext.bgpvpn_port_attach(None, dummy_port20)

        # Detach all ports from L3 BGP VPNs
        self.agent_ext.bgpvpn_port_detach(None, dummy_detach10)
        self.agent_ext.bgpvpn_port_detach(None, dummy_detach20)

        local_port10 = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                     base.NETWORK1['id'],
                                                     base.PORT10['id'])
        detach_info10 = {
            b_const.IPVPN: {
                'network_id': base.NETWORK1['id'],
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': dict(linuxif=local_port10['linuxif'])
            }
        }

        local_port20 = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                     base.NETWORK2['id'],
                                                     base.PORT20['id'])
        detach_info20 = {
            b_const.IPVPN: {
                'network_id': base.NETWORK2['id'],
                'ip_address': base.PORT20['ip_address'],
                'mac_address': base.PORT20['mac_address'],
                'local_port': dict(linuxif=local_port20['linuxif'])
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info10),
             mock.call(base.PORT20['id'], detach_info20)]
        )

        # Verify attachments list consistency
        for network_id in [base.NETWORK1['id'], base.NETWORK2['id']]:
            self._check_network_info(network_id, 0)

        self.assertEqual(0, len(self.agent_ext.networks_info),
                         "Registered attachments list must be empty: %s" %
                         self.agent_ext.networks_info)


class TestOVSAgentExtension(base.BaseTestOVSAgentExtension,
                            TestBgpvpnAgentExtensionMixin):

    agent_extension_class = bagpipe_agt_ext.BagpipeBgpvpnAgentExtension

    # Test fallback and ARP gateway voodoo
    def test_fallback(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent_ext.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestOVSAgentExtension,
                  self).test_update_bgpvpn_already_plugged_ports()

            port10_with_gw_mac = base.DummyPort(base.NETWORK1,
                                                base.PORT10).__dict__
            port10_with_gw_mac.update({'gateway_mac': GW_MAC,
                                       'l3vpn': base.BGPVPN_L3_RT100})

            self.agent_ext.bgpvpn_port_attach(None,
                                              copy.copy(port10_with_gw_mac))

            fallback = {'dst_mac': GW_MAC,
                        'ovs_port_number': base.PATCH_MPLS_TO_INT_OFPORT,
                        'src_mac': '00:00:5e:2a:10:00'}

            local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])

            self.assertEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ip_address=base.PORT10['ip_address'],
                    mac_address=base.PORT10['mac_address'],
                    gateway_ip=base.NETWORK1['gateway_ip'],
                    local_port=dict(linuxif=local_port['linuxif']),
                    **self._get_vpn_info(b_const.IPVPN,
                                         local_port['ipvpnif'],
                                         base.BGPVPN_L3_RT100,
                                         fallback=fallback)
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

    def test_gateway_arp_voodoo(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent_ext.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent_ext.int_br,
                                  'add_flow') as add_flow, \
                mock.patch.object(self.agent_ext.tun_br,
                                  'delete_flows') as tun_delete_flows,\
                mock.patch.object(self.agent_ext.int_br,
                                  'delete_flows') as int_delete_flows:
            super(TestOVSAgentExtension,
                  self).test_update_bgpvpn_already_plugged_ports()

            port10_with_gw_mac = base.DummyPort(base.NETWORK1,
                                                base.PORT10).__dict__
            port10_with_gw_mac.update({'gateway_mac': GW_MAC,
                                       'l3vpn': base.BGPVPN_L3_RT100})

            self.agent_ext.bgpvpn_port_attach(None,
                                              copy.copy(port10_with_gw_mac))

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

            self.agent_ext.bgpvpn_port_detach(
                None, base.DummyPort(base.NETWORK1, base.PORT10).__dict__
            )

            self.assertEqual(0, tun_delete_flows.call_count)
            self.assertEqual(0, int_delete_flows.call_count)

            self.agent_ext.bgpvpn_port_detach(
                None, base.DummyPort(base.NETWORK1, base.PORT11).__dict__
            )
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

        with mock.patch.object(self.agent_ext.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent_ext.int_br,
                                  'add_flow') as add_flow:
            port10 = base.DummyPort(base.NETWORK1, base.PORT10).__dict__
            port10.update({'gateway_mac': GW_MAC})

            self.agent_ext.bgpvpn_port_attach(None, copy.copy(port10))

            dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                             l3vpn=base.BGPVPN_L3_RT100,
                                             gateway_mac=GW_MAC).__dict__

            self.agent_ext.update_bgpvpn(None, copy.copy(dummy_bgpvpn1))

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

            self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
                [mock.call(base.PORT10['id'])]
            )

            self.agent_ext.delete_bgpvpn(None, copy.copy(dummy_bgpvpn1))

            add_flow.reset_mock()
            self.assertEqual(0, add_flow.call_count)

            self.agent_ext.update_bgpvpn(None, copy.copy(dummy_bgpvpn1))

            self.assertEqual(2, add_flow.call_count)

            local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])

            self.assertEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ip_address=base.PORT10['ip_address'],
                    mac_address=base.PORT10['mac_address'],
                    gateway_ip=base.NETWORK1['gateway_ip'],
                    local_port=dict(linuxif=local_port['linuxif']),
                    **self._get_vpn_info(b_const.IPVPN,
                                         local_port['ipvpnif'],
                                         base.BGPVPN_L3_RT100,
                                         fallback=fallback)
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

    def test_gateway_plug_before_update(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent_ext.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10]), \
                mock.patch.object(self.agent_ext.int_br,
                                  'add_flow') as add_flow:
            port10 = base.DummyPort(base.NETWORK1, base.PORT10).__dict__

            self.agent_ext.bgpvpn_port_attach(None, copy.copy(port10))

            dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                             l3vpn=base.BGPVPN_L3_RT100,
                                             gateway_mac=GW_MAC).__dict__

            self.agent_ext.update_bgpvpn(None, copy.copy(dummy_bgpvpn1))

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

            self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
                [mock.call(base.PORT10['id'])]
            )

            self.agent_ext.delete_bgpvpn(None, copy.copy(dummy_bgpvpn1))

            add_flow.reset_mock()
            self.assertEqual(0, add_flow.call_count)

            self.agent_ext.update_bgpvpn(None, dummy_bgpvpn1)

            self.assertEqual(2, add_flow.call_count)

            local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])

            self.assertEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ip_address=base.PORT10['ip_address'],
                    mac_address=base.PORT10['mac_address'],
                    gateway_ip=base.NETWORK1['gateway_ip'],
                    local_port=dict(linuxif=local_port['linuxif']),
                    **self._get_vpn_info(b_const.IPVPN,
                                         local_port['ipvpnif'],
                                         base.BGPVPN_L3_RT100,
                                         fallback=fallback)
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

    def test_evpn_no_gateway_arp_voodoo(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent_ext.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent_ext.int_br,
                                  'add_flow') as add_flow, \
                mock.patch.object(self.agent_ext.int_br,
                                  'delete_flows') as delete_flows:

            port10_with_gw_mac = base.DummyPort(base.NETWORK1,
                                                base.PORT10).__dict__
            port10_with_gw_mac.update({'gateway_mac': GW_MAC})
            port10_with_gw_mac.update(
                base.DummyBGPVPN(base.NETWORK1,
                                 l2vpn=base.BGPVPN_L2_RT10).__dict__)

            self.agent_ext.bgpvpn_port_attach(None,
                                              copy.copy(port10_with_gw_mac))

            self.assertEqual(0, add_flow.call_count)

            self.agent_ext.bgpvpn_port_detach(
                None, base.DummyPort(base.NETWORK1, base.PORT10).__dict__
            )
            self.assertEqual(0, delete_flows.call_count)

    def test_gateway_arp_voodoo_ovs_restart(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent_ext.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent_ext.int_br,
                                  'add_flow') as add_flow:
            port10 = base.DummyPort(base.NETWORK1, base.PORT10).__dict__
            port10.update({'gateway_mac': GW_MAC})

            self.agent_ext.bgpvpn_port_attach(None, copy.copy(port10))

            dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                             l3vpn=base.BGPVPN_L3_RT100,
                                             gateway_mac=GW_MAC).__dict__

            self.agent_ext.update_bgpvpn(None, dummy_bgpvpn1)

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

            self.agent_ext.ovs_restarted_bgpvpn()

            add_flow.assert_has_calls(expected_calls)


class TestLinuxBridgeAgentExtension(base.BaseTestLinuxBridgeAgentExtension,
                                    TestBgpvpnAgentExtensionMixin):

    agent_extension_class = bagpipe_agt_ext.BagpipeBgpvpnAgentExtension

    def test_update_bgpvpn_different_vpn_types(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10).__dict__

        dummy_bgpvpn1 = base.DummyBGPVPN(base.NETWORK1,
                                         l2vpn=base.BGPVPN_L2_RT10,
                                         l3vpn=base.BGPVPN_L3_RT100).__dict__

        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port10))

        self.agent_ext.update_bgpvpn(None, dummy_bgpvpn1)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        for bgpvpn_type, bgpvpn_rts in [
                (bgpvpn_const.BGPVPN_L2, base.BGPVPN_L2_RT10),
                (bgpvpn_const.BGPVPN_L3, base.BGPVPN_L3_RT100)]:
            self._check_network_info(base.NETWORK1['id'],
                                     1,
                                     bgpvpn_type,
                                     bgpvpn_rts)

        # Verify build callback attachments
        local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'])

        vpns_info = self._get_vpn_info(b_const.EVPN,
                                       local_port['evpnif'],
                                       base.BGPVPN_L2_RT10)
        vpns_info.update(self._get_vpn_info(b_const.IPVPN,
                                            local_port['ipvpnif'],
                                            base.BGPVPN_L3_RT100))

        self.assertEqual(
            dict(
                network_id=base.NETWORK1['id'],
                ip_address=base.PORT10['ip_address'],
                mac_address=base.PORT10['mac_address'],
                gateway_ip=base.NETWORK1['gateway_ip'],
                local_port=dict(linuxif=local_port['linuxif']),
                **vpns_info
            ),
            self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
        )

    def test_bgpvpn_attach_single_port_bgpvpn(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10).__dict__

        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port10))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'],
                                 1,
                                 bgpvpn_const.BGPVPN_L2,
                                 base.BGPVPN_L2_RT10)

        # Verify build callback attachments
        local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L2,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'])

        self.assertEqual(
            dict(
                network_id=base.NETWORK1['id'],
                ip_address=base.PORT10['ip_address'],
                mac_address=base.PORT10['mac_address'],
                gateway_ip=base.NETWORK1['gateway_ip'],
                local_port=dict(linuxif=local_port['linuxif']),
                **self._get_vpn_info(b_const.EVPN,
                                     local_port['evpnif'],
                                     base.BGPVPN_L2_RT10)
            ),
            self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
        )

    def test_bgpvpn_attach_same_port_different_bgpvpn_types(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10).__dict__
        dummy_port10bis = base.DummyPort(base.NETWORK1, base.PORT10,
                                         bgpvpn_port=True,
                                         evpn=base.BGPVPN_L2_RT10,
                                         ipvpn=base.BGPVPN_L3_RT100).__dict__

        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port10))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'],
                                 1,
                                 bgpvpn_const.BGPVPN_L2,
                                 base.BGPVPN_L2_RT10)

        self.mocked_bagpipe_agent.reset_mock()

        self.agent_ext.bgpvpn_port_attach(None, copy.copy(dummy_port10bis))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        for bgpvpn_type, bgpvpn_rts in [
                (bgpvpn_const.BGPVPN_L2, base.BGPVPN_L2_RT10),
                (bgpvpn_const.BGPVPN_L3, base.BGPVPN_L3_RT100)]:
            self._check_network_info(base.NETWORK1['id'],
                                     1,
                                     bgpvpn_type,
                                     bgpvpn_rts)

        # Verify build callback attachments
        local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'])

        vpns_info = self._get_vpn_info(b_const.EVPN,
                                       local_port['evpnif'],
                                       base.BGPVPN_L2_RT10)
        vpns_info.update(self._get_vpn_info(b_const.IPVPN,
                                            local_port['ipvpnif'],
                                            base.BGPVPN_L3_RT100))

        self.assertEqual(
            dict(
                network_id=base.NETWORK1['id'],
                ip_address=base.PORT10['ip_address'],
                mac_address=base.PORT10['mac_address'],
                gateway_ip=base.NETWORK1['gateway_ip'],
                local_port=dict(linuxif=local_port['linuxif']),
                **vpns_info
            ),
            self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
        )

    def test_bgpvpn_detach_single_port_bgpvpn(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        self.agent_ext.bgpvpn_port_attach(None, dummy_port10)

        self.mocked_bagpipe_agent.reset_mock()

        self.agent_ext.bgpvpn_port_detach(None, dummy_detach10)

        local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L2,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'])
        detach_info = {
            b_const.EVPN: {
                'network_id': base.NETWORK1['id'],
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': dict(linuxif=local_port['linuxif'])
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info)]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 0)

        self.assertEqual(0, len(self.agent_ext.networks_info),
                         "Registered attachments list must be empty: %s" %
                         self.agent_ext.networks_info)

    def test_bgpvpn_detach_single_port_multiple_bgpvpns(self):
        dummy_port10 = base.DummyPort(base.NETWORK1, base.PORT10,
                                      bgpvpn_port=True,
                                      evpn=base.BGPVPN_L2_RT10,
                                      ipvpn=base.BGPVPN_L3_RT100).__dict__
        dummy_detach10 = dict(id=base.PORT10['id'],
                              network_id=base.NETWORK1['id'])

        self.agent_ext.bgpvpn_port_attach(None, dummy_port10)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self.mocked_bagpipe_agent.reset_mock()

        self.agent_ext.bgpvpn_port_detach(None, dummy_detach10)

        local_port = self._get_expected_local_port(bgpvpn_const.BGPVPN_L3,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'])
        detach_info = {
            b_const.EVPN: {
                'network_id': base.NETWORK1['id'],
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': dict(linuxif=local_port['linuxif'])
            },
            b_const.IPVPN: {
                'network_id': base.NETWORK1['id'],
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': dict(linuxif=local_port['linuxif'])
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info)]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 0)

        self.assertEqual(0, len(self.agent_ext.networks_info),
                         "Registered attachments list must be empty: %s" %
                         self.agent_ext.networks_info)
