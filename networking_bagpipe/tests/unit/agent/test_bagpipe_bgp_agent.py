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
import testtools

from networking_bagpipe.agent import bagpipe_bgp_agent as agent
from networking_bagpipe.bagpipe_bgp import constants as bbgp_const

from networking_bagpipe.tests.unit.agent.common \
    import constants as const

from neutron.tests import base


def rts_as_set(rts):
    return {k: set(rt_list)
            for k, rt_list in rts.items()}


def _attachments_gen(vpn_type, network, port, rts):
    attachment = {
        'network_id': network['network_id'],
        vpn_type: [dict(
            gateway_ip=network['gateway_ip'],
            **port
        )]
    }
    attachment[vpn_type][0].update(**rts_as_set(rts))
    return attachment


class TestBaGPipeBGPAgentSingleService(base.BaseTestCase):

    def setUp(self):
        super(TestBaGPipeBGPAgentSingleService, self).setUp()

        self.agent = agent.BaGPipeBGPAgent('Linux bridge agent')
        self.agent._send_attach_local_port = mock.Mock()
        self.agent._send_detach_local_port = mock.Mock()

        self.service1 = mock.Mock(name='SERVICE1')
        self.agent.register_build_callback(self.service1.name,
                                           self.service1._build_port_info)

    def _test_port_plug(self, vpn_type, rts):
        attachments = _attachments_gen(vpn_type, const.NETWORK_INFO1,
                                       const.PORT_INFO1, rts)

        self.service1._build_port_info.return_value = attachments

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (vpn_type,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=vpn_type,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **rts_as_set(rts)
            ))
        ])

    def test_evpn_port_plug(self):
        self._test_port_plug(bbgp_const.EVPN, const.EVPN_RT1)

    def test_ipvpn_port_plug(self):
        self._test_port_plug(bbgp_const.IPVPN, const.IPVPN_RT100)

    def test_evpn2ipvpn_port_plug(self):
        attachments = _attachments_gen('evpn', const.NETWORK_INFO1,
                                       const.PORT_INFO1, const.EVPN_RT1)
        attachments.update(_attachments_gen('ipvpn', const.NETWORK_INFO1,
                                            const.PORT_INFO1,
                                            const.IPVPN_RT100))

        self.service1._build_port_info.return_value = attachments

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.EVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **rts_as_set(const.EVPN_RT1)
            )),
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.IPVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.IPVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port={
                    bbgp_const.EVPN: {
                        'id': '%s_%s' % (bbgp_const.EVPN,
                                         const.NETWORK_INFO1['network_id'])
                    }
                },
                **rts_as_set(const.IPVPN_RT100)
            ))
        ])

    def test_epvpn_port_plug_updated_local_port(self):
        attachments = _attachments_gen('evpn', const.NETWORK_INFO1,
                                       const.PORT_INFO1, const.EVPN_RT1)
        attachments['evpn'][0]['local_port'] = const.UPDATED_LOCAL_PORT1

        self.service1._build_port_info.return_value = attachments

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.EVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.UPDATED_LOCAL_PORT1,
                **rts_as_set(const.EVPN_RT1)
            ))
        ])

    def _test_port_plug_refresh_without_detach(self, vpn_type, rts):
        attachments = _attachments_gen(vpn_type, const.NETWORK_INFO1,
                                       const.PORT_INFO1, rts)

        detach_info1 = {
            'network_id': const.NETWORK_INFO1['network_id'],
            vpn_type: dict(**const.PORT_INFO1)
        }

        self.service1._build_port_info.return_value = attachments

        self.agent.do_port_plug_refresh(None, detach_info1)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (vpn_type,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=vpn_type,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **rts_as_set(rts)
            ))
        ])

        self.agent._send_detach_local_port.assert_not_called()

    @testtools.skip("skip until bug 1744344 is resolved")
    def test_evpn_port_plug_refresh_without_detach(self):
        self._test_port_plug_refresh_without_detach(bbgp_const.EVPN,
                                                    const.EVPN_RT1)

    @testtools.skip("skip until bug 1744344 is resolved")
    def test_ipvpn_port_plug_refresh_without_detach(self):
        self._test_port_plug_refresh_without_detach(bbgp_const.IPVPN,
                                                    const.IPVPN_RT100)

    def _test_port_plug_refresh_with_detach(self, vpn_type, rts):
        attachments = _attachments_gen(vpn_type, const.NETWORK_INFO1,
                                       const.PORT_INFO1, rts)

        detach_info1 = {
            'network_id': const.NETWORK_INFO1['network_id'],
            vpn_type: dict(**const.PORT_INFO1)
        }

        self.service1._build_port_info.return_value = attachments

        self.agent.do_port_plug_refresh(None, detach_info1)

        self.agent._send_attach_local_port.assert_not_called()

        self.agent._send_detach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (vpn_type,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=vpn_type,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                local_port=const.PORT_INFO1['local_port']
            ))
        ])

    @testtools.skip("skip until bug 1744344 is resolved")
    def test_evpn_port_plug_refresh_with_detach(self):
        self._test_port_plug_refresh_with_detach(bbgp_const.EVPN,
                                                 const.EVPN_RT1)

    @testtools.skip("skip until bug 1744344 is resolved")
    def test_ipvpn_port_plug_refresh_with_detach(self):
        self._test_port_plug_refresh_with_detach(bbgp_const.IPVPN,
                                                 const.IPVPN_RT100)

    def test_evpn2ipvpn_port_plug_refresh_with_detach(self):
        attachments = _attachments_gen('evpn', const.NETWORK_INFO1,
                                       const.PORT_INFO1, const.EVPN_RT1)

        detach_info1 = {
            'network_id': const.NETWORK_INFO1['network_id'],
            'ipvpn': dict(**const.PORT_INFO1)
        }

        self.service1._build_port_info.return_value = attachments

        self.agent.do_port_plug_refresh(None, detach_info1)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.EVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **rts_as_set(const.EVPN_RT1)
            ))
        ])

        self.agent._send_detach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.IPVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.IPVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                local_port={
                    bbgp_const.EVPN: {
                        'id': '%s_%s' % (bbgp_const.EVPN,
                                         const.NETWORK_INFO1['network_id'])
                    }
                }
            ))
        ])


class TestBaGPipeBGPAgentMultipleServices(base.BaseTestCase):

    def setUp(self):
        super(TestBaGPipeBGPAgentMultipleServices, self).setUp()

        self.agent = agent.BaGPipeBGPAgent('Linux bridge agent')
        self.agent._send_attach_local_port = mock.Mock()
        self.agent._send_detach_local_port = mock.Mock()

        self.service1 = mock.Mock(name='SERVICE1')
        self.agent.register_build_callback(self.service1.name,
                                           self.service1._build_port_info)

        self.service2 = mock.Mock(name='SERVICE2')
        self.agent.register_build_callback(self.service2.name,
                                           self.service2._build_port_info)

    def _merge_rts(self, rt1, rt2):
        return {k: set(rt1[k] + rt2[k]) for k in rt1}

    def test_evpns_port_plug(self):
        attachments_1 = _attachments_gen('evpn', const.NETWORK_INFO1,
                                         const.PORT_INFO1, const.EVPN_RT1)
        self.service1._build_port_info.return_value = attachments_1

        attachments_2 = _attachments_gen('evpn', const.NETWORK_INFO1,
                                         const.PORT_INFO1, const.EVPN_RT2)
        self.service2._build_port_info.return_value = attachments_2

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.EVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **self._merge_rts(const.EVPN_RT1, const.EVPN_RT2)
            ))
        ])

    def test_ipvpns_port_plug(self):
        attachments_1 = _attachments_gen('ipvpn', const.NETWORK_INFO1,
                                         const.PORT_INFO1, const.IPVPN_RT100)
        self.service1._build_port_info.return_value = attachments_1

        attachments_2 = _attachments_gen('ipvpn', const.NETWORK_INFO1,
                                         const.PORT_INFO1, const.IPVPN_RT200)
        self.service2._build_port_info.return_value = attachments_2

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.IPVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.IPVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **self._merge_rts(const.IPVPN_RT100, const.IPVPN_RT200)
            ))
        ])

    def test_evpn2ipvpn_port_plug(self):
        attachments_1 = _attachments_gen('evpn', const.NETWORK_INFO1,
                                         const.PORT_INFO1, const.EVPN_RT1)
        self.service1._build_port_info.return_value = attachments_1

        attachments_2 = _attachments_gen('ipvpn', const.NETWORK_INFO1,
                                         const.PORT_INFO1, const.IPVPN_RT100)
        self.service2._build_port_info.return_value = attachments_2

        self.agent.do_port_plug(None)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.EVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **rts_as_set(const.EVPN_RT1)
            )),
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.IPVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.IPVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port={
                    bbgp_const.EVPN: {
                        'id': '%s_%s' % (bbgp_const.EVPN,
                                         const.NETWORK_INFO1['network_id'])
                    }
                },
                **rts_as_set(const.IPVPN_RT100)
            ))
        ])

    def test_evpns_port_plug_refresh_without_detach(self):
        attachments_1 = _attachments_gen('evpn', const.NETWORK_INFO1,
                                         const.PORT_INFO1, const.EVPN_RT1)
        self.service1._build_port_info.return_value = attachments_1

        self.service2._build_port_info.return_value = {}

        detach_info1 = {
            'network_id': const.NETWORK_INFO1['network_id'],
            bbgp_const.EVPN: dict(**const.PORT_INFO1)
        }

        self.agent.do_port_plug_refresh(None, detach_info1)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.EVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **rts_as_set(const.EVPN_RT1)
            ))
        ])

    def test_ipvpns_port_plug_refresh_without_detach(self):
        attachments_1 = _attachments_gen('ipvpn', const.NETWORK_INFO1,
                                         const.PORT_INFO1, const.IPVPN_RT100)
        self.service1._build_port_info.return_value = attachments_1

        self.service2._build_port_info.return_value = {}

        detach_info1 = {
            'network_id': const.NETWORK_INFO1['network_id'],
            bbgp_const.IPVPN: dict(**const.PORT_INFO1)
        }

        self.agent.do_port_plug_refresh(None, detach_info1)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.IPVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.IPVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **rts_as_set(const.IPVPN_RT100)
            ))
        ])

    def test_evpn2ipvpn_port_plug_refresh_with_detach(self):
        attachments_1 = _attachments_gen('evpn', const.NETWORK_INFO1,
                                         const.PORT_INFO1, const.EVPN_RT1)
        self.service1._build_port_info.return_value = attachments_1

        self.service2._build_port_info.return_value = {}

        detach_info1 = {
            'network_id': const.NETWORK_INFO1['network_id'],
            bbgp_const.IPVPN: dict(**const.PORT_INFO1)
        }

        self.agent.do_port_plug_refresh(None, detach_info1)

        self.agent._send_attach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.EVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.EVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                gateway_ip=const.NETWORK_INFO1['gateway_ip'],
                local_port=const.PORT_INFO1['local_port'],
                **rts_as_set(const.EVPN_RT1)
            ))
        ])

        self.agent._send_detach_local_port.assert_has_calls([
            mock.call(dict(
                vpn_instance_id='%s_%s' % (bbgp_const.IPVPN,
                                           const.NETWORK_INFO1['network_id']),
                vpn_type=bbgp_const.IPVPN,
                ip_address=const.PORT_INFO1['ip_address'],
                mac_address=const.PORT_INFO1['mac_address'],
                local_port={
                    bbgp_const.EVPN: {
                        'id': '%s_%s' % (bbgp_const.EVPN,
                                         const.NETWORK_INFO1['network_id'])
                    }
                }
            ))
        ])
