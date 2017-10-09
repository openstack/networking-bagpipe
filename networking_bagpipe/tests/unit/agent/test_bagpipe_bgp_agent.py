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
from networking_bagpipe.agent.common import constants as b_const

from networking_bagpipe.tests.unit.agent.common \
    import constants as const

from neutron.tests import base


class TestBaGPipeBGPAgentSingleService(base.BaseTestCase):

    def setUp(self):
        super(TestBaGPipeBGPAgentSingleService, self).setUp()

        self.agent = agent.BaGPipeBGPAgent('SINGLE_SERVICE')
        self.agent._send_attach_local_port = mock.Mock()
        self.agent._send_detach_local_port = mock.Mock()

        self.service1 = mock.Mock(name='SERVICE1')
        self.agent.register_build_callback(self.service1.name,
                                           self.service1._build_port_info)

    def _test_port_plug(self, vpn_type, rts):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update({vpn_type: rts})
        port_info1.update(**const.NETWORK_INFO1)

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           vpn_type),
                vpn_type=vpn_type,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **rts
            ))
        ])

    def test_evpn_port_plug(self):
        self._test_port_plug(b_const.EVPN, const.EVPN_RT1)

    def test_ipvpn_port_plug(self):
        self._test_port_plug(b_const.IPVPN, const.IPVPN_RT100)

    def test_evpn2ipvpn_port_plug(self):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update(dict(evpn=const.EVPN_RT1,
                               ipvpn=const.IPVPN_RT100,
                               **const.NETWORK_INFO1))

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.EVPN),
                vpn_type=b_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **const.EVPN_RT1
            )),
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.IPVPN),
                vpn_type=b_const.IPVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port={
                    b_const.EVPN: {
                        'id': '%s_%s' % (const.NETWORK_INFO1['network_id'],
                                         b_const.EVPN)
                    }
                },
                **const.IPVPN_RT100
            ))
        ])

    def test_epvpn_port_plug_updated_local_port(self):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update(dict(evpn=dict(local_port=const.UPDATED_LOCAL_PORT1,
                                         **const.EVPN_RT1),
                               **const.NETWORK_INFO1))

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.EVPN),
                vpn_type=b_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.UPDATED_LOCAL_PORT1,
                **const.EVPN_RT1
            ))
        ])

    def test_epvpn_port_plug_gateway_mac_added(self):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update(dict(evpn=dict(gateway_mac=const.GW_MAC_PORT1,
                                         **const.EVPN_RT1),
                               **const.NETWORK_INFO1))

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.EVPN),
                vpn_type=b_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                gateway_mac=const.GW_MAC_PORT1,
                **const.EVPN_RT1
            ))
        ])

    def test_epvpn_port_plug_static_routes(self):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update(dict(evpn=dict(static_routes=[const.STATIC_ROUTE1],
                                         **const.EVPN_RT1),
                               **const.NETWORK_INFO1))

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.EVPN),
                vpn_type=b_const.EVPN,
                ip_address=const.STATIC_ROUTE1,
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                advertise_subnet=True,
                **const.EVPN_RT1
            )),
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.EVPN),
                vpn_type=b_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **const.EVPN_RT1
            )),
        ])

    def _test_port_plug_refresh_without_detach(self, vpn_type, rts):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update({vpn_type: rts})
        port_info1.update(**const.NETWORK_INFO1)

        detach_info1 = {
            vpn_type: dict(network_id=const.NETWORK_INFO1['network_id'],
                           **const.PORT_INFO1)
        }

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        self.agent.do_port_plug_refresh(None, detach_info1)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           vpn_type),
                vpn_type=vpn_type,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **rts
            ))
        ])

        self.agent._send_detach_local_port.assert_not_called()

    def test_evpn_port_plug_refresh_without_detach(self):
        self._test_port_plug_refresh_without_detach(b_const.EVPN,
                                                    const.EVPN_RT1)

    def test_ipvpn_port_plug_refresh_without_detach(self):
        self._test_port_plug_refresh_without_detach(b_const.IPVPN,
                                                    const.IPVPN_RT100)

    def _test_port_plug_refresh_with_detach(self, vpn_type, rts):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update({vpn_type: rts})
        port_info1.update(**const.NETWORK_INFO1)

        detach_info1 = {
            vpn_type: dict(network_id=const.NETWORK_INFO1['network_id'],
                           **const.PORT_INFO1)
        }

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        self.agent.do_port_plug_refresh(None, detach_info1)

        self.agent._send_attach_local_port.assert_not_called()

        self.agent._send_detach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           vpn_type),
                vpn_type=vpn_type,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                local_port=const.PORT_INFO1['local_port']
            ))
        ])

    def test_evpn_port_plug_refresh_with_detach(self):
        self._test_port_plug_refresh_without_detach(b_const.EVPN,
                                                    const.EVPN_RT1)

    def test_ipvpn_port_plug_refresh_with_detach(self):
        self._test_port_plug_refresh_without_detach(b_const.IPVPN,
                                                    const.IPVPN_RT100)

    def test_evpn2ipvpn_port_plug_refresh_with_detach(self):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update(dict(evpn=const.EVPN_RT1,
                               **const.NETWORK_INFO1))

        detach_info1 = {
            b_const.IPVPN: dict(network_id=const.NETWORK_INFO1['network_id'],
                                **const.PORT_INFO1)
        }

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        self.agent.do_port_plug_refresh(None, detach_info1)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.EVPN),
                vpn_type=b_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **const.EVPN_RT1
            ))
        ])

        self.agent._send_detach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.IPVPN),
                vpn_type=b_const.IPVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                local_port={
                    b_const.EVPN: {
                        'id': '%s_%s' % (const.NETWORK_INFO1['network_id'],
                                         b_const.EVPN)
                    }
                }
            ))
        ])


class RTList(list):

    def __eq__(self, other):
        return set(self) == set(other)


class TestBaGPipeBGPAgentMultipleServices(base.BaseTestCase):

    def setUp(self):
        super(TestBaGPipeBGPAgentMultipleServices, self).setUp()

        self.agent = agent.BaGPipeBGPAgent('MULTIPLE_SERVICES')
        self.agent._send_attach_local_port = mock.Mock()
        self.agent._send_detach_local_port = mock.Mock()

        self.service1 = mock.Mock(name='SERVICE1')
        self.agent.register_build_callback(self.service1.name,
                                           self.service1._build_port_info)

        self.service2 = mock.Mock(name='SERVICE2')
        self.agent.register_build_callback(self.service2.name,
                                           self.service2._build_port_info)

    def _merge_rts(self, rt1, rt2):
        return {k: RTList(rt1[k] + rt2[k]) for k in rt1}

    def test_evpns_port_plug(self):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update(dict(evpn=const.EVPN_RT1,
                               **const.NETWORK_INFO1))

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        port_info1bis = copy.copy(const.PORT_INFO1)
        port_info1bis.update(dict(evpn=const.EVPN_RT2,
                                  **const.NETWORK_INFO1))

        self.service2._build_port_info.return_value = (
            copy.deepcopy(port_info1bis)
        )

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.EVPN),
                vpn_type=b_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **self._merge_rts(const.EVPN_RT1, const.EVPN_RT2)
            ))
        ])

    def test_ipvpns_port_plug(self):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update(dict(ipvpn=const.IPVPN_RT100,
                               **const.NETWORK_INFO1))

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        port_info1bis = copy.copy(const.PORT_INFO1)
        port_info1bis.update(dict(ipvpn=const.IPVPN_RT200,
                                  **const.NETWORK_INFO1))

        self.service2._build_port_info.return_value = (
            copy.deepcopy(port_info1bis)
        )

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.IPVPN),
                vpn_type=b_const.IPVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **self._merge_rts(const.IPVPN_RT100, const.IPVPN_RT200)
            ))
        ])

    def test_evpn2ipvpn_port_plug(self):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update(dict(evpn=const.EVPN_RT1,
                               **const.NETWORK_INFO1))

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        port_info1bis = copy.copy(const.PORT_INFO1)
        port_info1bis.update(dict(ipvpn=const.IPVPN_RT100,
                                  **const.NETWORK_INFO1))

        self.service2._build_port_info.return_value = (
            copy.deepcopy(port_info1bis)
        )

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.EVPN),
                vpn_type=b_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **const.EVPN_RT1
            )),
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.IPVPN),
                vpn_type=b_const.IPVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port={
                    b_const.EVPN: {
                        'id': '%s_%s' % (const.NETWORK_INFO1['network_id'],
                                         b_const.EVPN)
                    }
                },
                **const.IPVPN_RT100
            ))
        ])

    def test_evpns_port_plug_refresh_without_detach(self):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update(dict(evpn=const.EVPN_RT1,
                               **const.NETWORK_INFO1))

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        self.service2._build_port_info.return_value = {}

        detach_info1 = {
            b_const.EVPN: dict(network_id=const.NETWORK_INFO1['network_id'],
                               **const.PORT_INFO1)
        }

        self.agent.do_port_plug_refresh(None, detach_info1)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.EVPN),
                vpn_type=b_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **const.EVPN_RT1
            ))
        ])

    def test_ipvpns_port_plug_refresh_without_detach(self):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update(dict(ipvpn=const.IPVPN_RT100,
                               **const.NETWORK_INFO1))

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        self.service2._build_port_info.return_value = {}

        detach_info1 = {
            b_const.IPVPN: dict(network_id=const.NETWORK_INFO1['network_id'],
                                **const.PORT_INFO1)
        }

        self.agent.do_port_plug_refresh(None, detach_info1)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.IPVPN),
                vpn_type=b_const.IPVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **const.IPVPN_RT100
            ))
        ])

    def test_evpn2ipvpn_port_plug_refresh_with_detach(self):
        port_info1 = copy.copy(const.PORT_INFO1)
        port_info1.update(dict(evpn=const.EVPN_RT1,
                               **const.NETWORK_INFO1))

        detach_info1 = {
            b_const.IPVPN: dict(network_id=const.NETWORK_INFO1['network_id'],
                                **const.PORT_INFO1)
        }

        self.service1._build_port_info.return_value = (
            copy.deepcopy(port_info1)
        )

        self.service2._build_port_info.return_value = {}

        self.agent.do_port_plug_refresh(None, detach_info1)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.EVPN),
                vpn_type=b_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **const.EVPN_RT1
            ))
        ])

        self.agent._send_detach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (const.NETWORK_INFO1['network_id'],
                                           b_const.IPVPN),
                vpn_type=b_const.IPVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                local_port={
                    b_const.EVPN: {
                        'id': '%s_%s' % (const.NETWORK_INFO1['network_id'],
                                         b_const.EVPN)
                    }
                }
            ))
        ])
