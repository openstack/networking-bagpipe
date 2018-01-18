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

import netaddr

from oslo_utils import uuidutils

from networking_bagpipe.agent.bgpvpn import agent_extension as bagpipe_agt_ext
from networking_bagpipe.bagpipe_bgp import constants as bbgp_const
from networking_bagpipe.objects import bgpvpn as objects
from networking_bagpipe.tests.unit.agent import base

from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc

from neutron_lib.api.definitions import bgpvpn


class HashableDict(dict):

    def __init__(self, dictionary):
        _dict = copy.deepcopy(dictionary)
        for k, v in list(_dict.items()):
            if (isinstance(v, dict) and not isinstance(v, HashableDict)):
                _dict[k] = HashableDict(v)
        super(HashableDict, self).__init__(_dict)

    def __hash__(self):
        return hash(tuple(sorted(self.items())))


def make_list_hashable(list_):
    if isinstance(list_[0], dict):
        return [HashableDict(d) for d in list_]


class UnorderedList(list):

    def __eq__(self, other):
        return set(make_list_hashable(self)) == set(make_list_hashable(other))


class TestBgpvpnAgentExtensionMixin(object):

    def setUp(self):
        self.mocked_rpc_pull = mock.patch.object(
            self.agent_ext.rpc_pull_api, 'bulk_pull').start()

    @mock.patch.object(registry, 'register')
    @mock.patch.object(resources_rpc, 'ResourcesPushRpcCallback')
    def test_initialize_rpcs(self, rpc_mock, subscribe_mock):
        self.agent_ext._setup_mpls_br = mock.Mock()  # already called in setUp
        self.agent_ext.initialize(self.connection, self.driver_type)
        self.connection.create_consumer.assert_has_calls(
            [mock.call(
                resources_rpc.resource_type_versioned_topic(resource_type),
                [rpc_mock()],
                fanout=True)
             for resource_type in (
                 objects.BGPVPNNetAssociation.obj_name(),
                 objects.BGPVPNRouterAssociation.obj_name())],
            any_order=True
        )
        subscribe_mock.assert_has_calls(
            [
                mock.call(mock.ANY, objects.BGPVPNNetAssociation.obj_name()),
                mock.call(mock.ANY, objects.BGPVPNRouterAssociation.obj_name())
            ],
            any_order=True
        )

    def _expand_rts(self, rts):
        vpn_info = {}

        # rts are BGPVPN API resources rts
        vpn_info['import_rt'] = set(rts.get('route_targets') +
                                    rts.get('import_targets'))
        vpn_info['export_rt'] = set(rts.get('route_targets') +
                                    rts.get('export_targets'))

        return vpn_info

    def _port_data(self, port, delete=False):
        data = {
            'port_id': port['id']
        }
        if not delete:
            data.update({
                'port_id': port['id'],
                'network_id': base.port_2_net[port['id']]['id'],
                'segmentation_id': base.TEST_VNI,
                'network_type': 'vxlan',
                'device_owner': 'compute:None',
                'mac_address': port['mac_address'],
                'fixed_ips': [
                    {
                        'ip_address': port['ip_address'],
                    }
                ]
            })
        return data

    def _fake_bgpvpn(self, bgpvpn_type, **bgpvpn_params):
        return objects.BGPVPN(None,
                              id=uuidutils.generate_uuid(),
                              type=bgpvpn_type,
                              **bgpvpn_params)

    def _fake_net_assoc(self, network, bgpvpn_type, gateway_mac=None,
                        **bgpvpn_params):
        bgpvpn = self._fake_bgpvpn(bgpvpn_type, **bgpvpn_params)
        net_assoc = objects.BGPVPNNetAssociation(
            None,
            id=uuidutils.generate_uuid(),
            network_id=network['id'],
            bgpvpn_id=bgpvpn.id,
            bgpvpn=bgpvpn
        )

        net_assoc.subnets = [{
            'ip_version': 4,
            'cidr': "NOT_USED_TODAY",
            'gateway_ip': network['gateway_ip'],
            'gateway_mac': gateway_mac,
        }]

        return net_assoc

    def _fake_router_assoc(self, router, bgpvpn_type, networks,
                           **bgpvpn_params):
        bgpvpn = self._fake_bgpvpn(bgpvpn_type, **bgpvpn_params)
        router_assoc = objects.BGPVPNRouterAssociation(
            None,
            id=uuidutils.generate_uuid(),
            router_id=router['id'],
            bgpvpn_id=bgpvpn.id,
            bgpvpn=bgpvpn
        )

        router_assoc.connected_networks = [
            {'network_id': net['id'],
             'subnets': [{'ip_version': 4,
                          'cidr': "NOT_USED_TODAY",
                          'gateway_ip': net['gateway_ip'],
                          'gateway_mac': net.get('gateway_mac', None)}]}
            for net in networks]

        return router_assoc

    def _fake_port_assoc(self, port, bgpvpn_type, network, gateway_mac=None,
                         route_prefixes=None, id=None, **bgpvpn_params):
        bgpvpn = self._fake_bgpvpn(bgpvpn_type, **bgpvpn_params)
        port_assoc = objects.BGPVPNPortAssociation(
            None,
            id=id or uuidutils.generate_uuid(),
            port_id=port['id'],
            bgpvpn_id=bgpvpn.id,
            bgpvpn=bgpvpn
        )

        port_assoc.subnets = [{
            'ip_version': 4,
            'cidr': "NOT_USED_TODAY",
            'gateway_ip': network['gateway_ip'],
            'gateway_mac': gateway_mac,
        }]

        route_prefixes = route_prefixes or []
        port_assoc.routes = [
            objects.BGPVPNPortAssociationRoute(
                None,
                type='prefix',
                prefix=netaddr.IPNetwork(prefix),
                local_pref=local_pref)
            for prefix, local_pref in route_prefixes]

        return port_assoc

    def _fake_associations(self, net_assocs=None, router_assocs=None):
        assocs = mock.Mock()
        assocs.network_associations = net_assocs or []
        assocs.router_associations = router_assocs or []
        return assocs

    def _net_assoc_notif(self, net_assoc, event_type):
        self.agent_ext.handle_notification_net_assocs(
            None, objects.BGPVPNNetAssociation.obj_name(),
            [net_assoc], event_type)

    def _router_assoc_notif(self, router_assoc, event_type):
        self.agent_ext.handle_notification_router_assocs(
            None, objects.BGPVPNNetAssociation.obj_name(),
            [router_assoc], event_type)

    def _port_assoc_notif(self, port_assoc, event_type):
        self.agent_ext.handle_notification_port_assocs(
            None, objects.BGPVPNPortAssociation.obj_name(),
            [port_assoc], event_type)

    def test_net_assoc_no_plugged_ports(self):
        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L2,
                                         **base.BGPVPN_L2_RT10)
        self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

        self.assertEqual(0, self.mocked_bagpipe_agent.do_port_plug.call_count,
                         "Do port plug mustn't be called")

    def test_router_assoc_no_plugged_ports(self):
        router_assoc = self._fake_router_assoc(base.ROUTER1,
                                               bgpvpn.BGPVPN_L3,
                                               [base.NETWORK1],
                                               **base.BGPVPN_L3_RT100)
        self._router_assoc_notif(router_assoc, rpc_events.UPDATED)

        self.assertEqual(0, self.mocked_bagpipe_agent.do_port_plug.call_count,
                         "Do port plug mustn't be called")

    def test_net_assoc_already_plugged_ports(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L3,
                                         **base.BGPVPN_L3_RT100)

        # Verify build callback attachments
        def check_build_cb(*args):
            for port in [base.PORT10, base.PORT11]:
                local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                           base.NETWORK1['id'],
                                                           port['id'])
                self.assertDictEqual(
                    dict(
                        network_id=base.NETWORK1['id'],
                        ipvpn=[dict(
                            ip_address=port['ip_address'],
                            mac_address=port['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT100)
                        )]
                    ),
                    self.agent_ext.build_bgpvpn_attach_info(port['id'])
                )

        # we need to check what build_bgpvpn_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 2)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

    def test_router_assoc_already_plugged_ports(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        router_assoc = self._fake_router_assoc(base.ROUTER1,
                                               bgpvpn.BGPVPN_L3,
                                               [base.NETWORK1],
                                               **base.BGPVPN_L3_RT100)

        # Verify build callback attachments
        def check_build_cb(*args):
            for port in [base.PORT10, base.PORT11]:
                local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                           base.NETWORK1['id'],
                                                           port['id'])
                self.assertDictEqual(
                    dict(
                        network_id=base.NETWORK1['id'],
                        ipvpn=[dict(
                            ip_address=port['ip_address'],
                            mac_address=port['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT100)
                        )]
                    ),
                    self.agent_ext.build_bgpvpn_attach_info(port['id'])
                )

        # we need to check what build_bgpvpn_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._router_assoc_notif(router_assoc, rpc_events.UPDATED)

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 2)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

    def test_net_assoc_update_then_remove(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L3,
                                         **base.BGPVPN_L3_RT100)
        self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 2)
        self.mocked_bagpipe_agent.do_port_plug.reset_mock()

        self._net_assoc_notif(net_assoc, rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()
        self.assertEqual(
            self.mocked_bagpipe_agent.do_port_plug_refresh_many.call_count, 2)

    def test_router_assoc_update_then_remove(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        router_assoc = self._fake_router_assoc(base.ROUTER1,
                                               bgpvpn.BGPVPN_L3,
                                               [base.NETWORK1],
                                               **base.BGPVPN_L3_RT100)
        self._router_assoc_notif(router_assoc, rpc_events.UPDATED)

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 2)
        self.mocked_bagpipe_agent.do_port_plug.reset_mock()

        self._router_assoc_notif(router_assoc, rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()
        self.assertEqual(
            self.mocked_bagpipe_agent.do_port_plug_refresh_many.call_count, 2)

    def test_net_assoc_before_delete_port(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L3,
                                         **base.BGPVPN_L3_RT100)

        self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

        self.agent_ext.delete_port(None, self._port_data(base.PORT10,
                                                         delete=True))

        local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'],
                                                   detach=True)
        detach_info = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.IPVPN: {
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': local_port['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            [mock.call(base.PORT10['id'], [detach_info])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 0)

        self.assertEqual(0, len(self.agent_ext.networks_info),
                         "Registered attachments list must be empty: %s" %
                         self.agent_ext.networks_info)

    def test_two_net_assocs_same_bgpvpn_type(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L3,
                                         **base.BGPVPN_L3_RT100)
        self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        net_assoc_2 = self._fake_net_assoc(base.NETWORK1,
                                           bgpvpn.BGPVPN_L3,
                                           **base.BGPVPN_L3_RT200)

        def check_build_cb(*args):
            rts_1_2 = {k: rts + base.BGPVPN_L3_RT200[k]
                       for k, rts in base.BGPVPN_L3_RT100.items()}

            # Verify build callback attachments
            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=local_port['local_port'],
                        **self._expand_rts(rts_1_2)
                    )]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._net_assoc_notif(net_assoc_2, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'], 1)

    def test_delete_net_assoc_remaining_plugged_ports(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L3,
                                         **base.BGPVPN_L3_RT100)
        self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 2)

        self.mocked_bagpipe_agent.reset_mock()

        # prepare expected information for DELETE
        local_port10 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                     base.NETWORK1['id'],
                                                     base.PORT10['id'],
                                                     detach=True)
        detach_info10 = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.IPVPN: dict(
                ip_address=base.PORT10['ip_address'],
                mac_address=base.PORT10['mac_address'],
                local_port=local_port10['local_port']
            )
        }

        local_port11 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                     base.NETWORK1['id'],
                                                     base.PORT11['id'],
                                                     detach=True)
        detach_info11 = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.IPVPN: dict(
                ip_address=base.PORT11['ip_address'],
                mac_address=base.PORT11['mac_address'],
                local_port=local_port11['local_port']
            )
        }

        def check_b_cb(*args):
            self.assertDictEqual(
                {},
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
                )

        # we need to check that build_bgpvpn_attach_info contains the expected
        # content precisely at the time when do_port_plug_refresh is called
        self.mocked_bagpipe_agent.do_port_plug_refresh_many.side_effect = (
            check_b_cb)

        # Delete the network associations
        self._net_assoc_notif(net_assoc, rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            [mock.call(base.PORT10['id'], [detach_info10]),
             mock.call(base.PORT11['id'], [detach_info11])],
            any_order=True
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 2)

    def test_two_assocs_one_deleted_then_the_second_same_type(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L3,
                                         **base.BGPVPN_L3_RT100)
        self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

        net_assoc_2 = self._fake_net_assoc(base.NETWORK1,
                                           bgpvpn.BGPVPN_L3,
                                           **base.BGPVPN_L3_RT200)
        self._net_assoc_notif(net_assoc_2, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

        # delete first network association
        self.mocked_bagpipe_agent.reset_mock()

        def check_build_cb(*args):
            # Verify build callback attachments
            for port in [base.PORT10, base.PORT10]:
                local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                           base.NETWORK1['id'],
                                                           port['id'])
                self.assertDictEqual(
                    dict(
                        network_id=base.NETWORK1['id'],
                        ipvpn=[dict(
                            ip_address=port['ip_address'],
                            mac_address=port['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT200)
                        )]
                    ),
                    self.agent_ext.build_bgpvpn_attach_info(port['id'])
                )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._net_assoc_notif(net_assoc, rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )
        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_not_called()

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 2)

        # delete the second network association
        self.mocked_bagpipe_agent.reset_mock()

        def check_build_cb_empty(*args):
            # Verify build callback attachments
            for port in [base.PORT10, base.PORT10]:
                self.assertEqual(
                    {},
                    self.agent_ext.build_bgpvpn_attach_info(port['id'])
                )

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.side_effect = (
            check_build_cb_empty
        )

        self._net_assoc_notif(net_assoc_2, rpc_events.DELETED)

        local_port_1 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                     base.NETWORK1['id'],
                                                     base.PORT10['id'],
                                                     detach=True)

        detach_info_1 = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.IPVPN: {
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': local_port_1['local_port']
            }
        }

        local_port_2 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                     base.NETWORK1['id'],
                                                     base.PORT11['id'],
                                                     detach=True)

        detach_info_2 = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.IPVPN: {
                'ip_address': base.PORT11['ip_address'],
                'mac_address': base.PORT11['mac_address'],
                'local_port': local_port_2['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()
        self.assertEqual(
            2,
            self.mocked_bagpipe_agent.do_port_plug_refresh_many.call_count)

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            [mock.call(base.PORT10['id'], [detach_info_1]),
             mock.call(base.PORT11['id'], [detach_info_2])],
            any_order=True,
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 2)

    def test_two_assocs_one_deleted_then_the_second_different_types(self):
        if isinstance(self, TestOVSAgentExtension):
            self.skipTest("not relevant for OVS, because no EVPN driver")

        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L2,
                                         **base.BGPVPN_L2_RT10)
        self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

        net_assoc_2 = self._fake_net_assoc(base.NETWORK1,
                                           bgpvpn.BGPVPN_L3,
                                           **base.BGPVPN_L3_RT200)
        self._net_assoc_notif(net_assoc_2, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

        # delete first network association
        self.mocked_bagpipe_agent.reset_mock()

        def check_b_cb(*args):
            # Verify build callback attachments
            for port in [base.PORT10, base.PORT10]:
                local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                           base.NETWORK1['id'],
                                                           port['id'])
                self.assertDictEqual(
                    dict(
                        network_id=base.NETWORK1['id'],
                        ipvpn=[dict(
                            ip_address=port['ip_address'],
                            mac_address=port['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT200)
                        )]
                    ),
                    self.agent_ext.build_bgpvpn_attach_info(port['id'])
                )

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.side_effect = (
            check_b_cb)

        self._net_assoc_notif(net_assoc, rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 2)

        # check that the bgpvpn type of first assoc was removed
        local_port_1 = self._get_expected_local_port(bbgp_const.EVPN,
                                                     base.NETWORK1['id'],
                                                     base.PORT10['id'],
                                                     detach=True)

        detach_info_1 = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.EVPN: {
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': local_port_1['local_port']
            }
        }

        local_port_2 = self._get_expected_local_port(bbgp_const.EVPN,
                                                     base.NETWORK1['id'],
                                                     base.PORT11['id'],
                                                     detach=True)

        detach_info_2 = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.EVPN: {
                'ip_address': base.PORT11['ip_address'],
                'mac_address': base.PORT11['mac_address'],
                'local_port': local_port_2['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()
        self.assertEqual(
            2,
            self.mocked_bagpipe_agent.do_port_plug_refresh_many.call_count)

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            [mock.call(base.PORT10['id'], [detach_info_1]),
             mock.call(base.PORT11['id'], [detach_info_2])],
            any_order=True
        )

        # delete the second network association
        self.mocked_bagpipe_agent.reset_mock()

        def check_build_cb_empty(*args):
            # Verify build callback attachments
            for port in [base.PORT10, base.PORT10]:
                self.assertEqual(
                    {},
                    self.agent_ext.build_bgpvpn_attach_info(port['id'])
                )

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.side_effect = (
            check_build_cb_empty
        )

        self._net_assoc_notif(net_assoc_2, rpc_events.DELETED)

        local_port_2 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                     base.NETWORK1['id'],
                                                     base.PORT11['id'],
                                                     detach=True)

        detach_info_2 = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.IPVPN: {
                'ip_address': base.PORT11['ip_address'],
                'mac_address': base.PORT11['mac_address'],
                'local_port': local_port_2['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()
        self.assertEqual(
            2,
            self.mocked_bagpipe_agent.do_port_plug_refresh_many.call_count)

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            [mock.call(base.PORT11['id'], [detach_info_2])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 2)

    def test_delete_net_assoc_no_plugged_ports(self):
        net_assoc_2 = self._fake_net_assoc(base.NETWORK1,
                                           bgpvpn.BGPVPN_L3,
                                           **base.BGPVPN_L3_RT200)
        self._net_assoc_notif(net_assoc_2, rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()
        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_not_called()

    def test_net_assoc_with_plugged_ports(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L3,
                                         **base.BGPVPN_L3_RT100)
        self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.reset_mock()

        self.agent_ext.delete_port(None, self._port_data(base.PORT10,
                                                         delete=True))
        self.agent_ext.delete_port(None, self._port_data(base.PORT11,
                                                         delete=True))

        self.assertEqual(
            2, self.mocked_bagpipe_agent.do_port_plug_refresh_many.call_count)

        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()

        self.assertEqual(0, len(self.agent_ext.networks_info))

        self.mocked_bagpipe_agent.reset_mock()

        self._net_assoc_notif(net_assoc, rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_not_called()
        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()

    def test_net_assoc_single_port_l3_bgpvpn(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L3,
                                         **base.BGPVPN_L3_RT100)

        def check_build_cb(*args):
            # Verify build callback attachments
            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=local_port['local_port'],
                        **self._expand_rts(base.BGPVPN_L3_RT100)
                    )]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'], 1)

    def test_net_assoc_single_port_l2_bgpvpn(self):
        if isinstance(self, TestOVSAgentExtension):
            self.skipTest("not relevant for OVS, because no EVPN driver")

        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L2,
                                         **base.BGPVPN_L2_RT10)

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
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        vni=base.TEST_VNI,
                        **dict(list(local_port.items()) +
                               list(self._expand_rts(
                                    base.BGPVPN_L2_RT10).items()))
                    )]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'], 1)

    def test_net_assoc_single_port_multiple_bgpvpns(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        net_assoc_1 = self._fake_net_assoc(base.NETWORK1,
                                           bgpvpn.BGPVPN_L3,
                                           **base.BGPVPN_L3_RT100)
        net_assoc_2 = self._fake_net_assoc(base.NETWORK1,
                                           bgpvpn.BGPVPN_L3,
                                           **base.BGPVPN_L3_RT200)

        self._net_assoc_notif(net_assoc_1, rpc_events.UPDATED)

        def check_build_cb(*args):
            # Verify build callback attachments
            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])
            rts_1_2 = {k: rts + base.BGPVPN_L3_RT200[k]
                       for k, rts in base.BGPVPN_L3_RT100.items()}

            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=local_port['local_port'],
                        **self._expand_rts(rts_1_2)
                    )]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._net_assoc_notif(net_assoc_2, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

    def test_net_assoc_multiple_ports_different_bgpvpns(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT20))

        net_assoc_1 = self._fake_net_assoc(base.NETWORK1,
                                           bgpvpn.BGPVPN_L3,
                                           **base.BGPVPN_L3_RT100)
        net_assoc_2 = self._fake_net_assoc(base.NETWORK2,
                                           bgpvpn.BGPVPN_L3,
                                           **base.BGPVPN_L3_RT200)
        self._net_assoc_notif(net_assoc_1, rpc_events.UPDATED)

        def check_build_cb(*args):
            # Verify build callback attachments
            for port, network, rts in [(base.PORT10, base.NETWORK1,
                                        base.BGPVPN_L3_RT100),
                                       (base.PORT20, base.NETWORK2,
                                        base.BGPVPN_L3_RT200)]:
                local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                           network['id'],
                                                           port['id'])

                self.assertDictEqual(
                    dict(
                        network_id=network['id'],
                        ipvpn=[dict(
                            ip_address=port['ip_address'],
                            mac_address=port['mac_address'],
                            gateway_ip=network['gateway_ip'],
                            local_port=local_port['local_port'],
                            **self._expand_rts(rts)
                        )]
                    ),
                    self.agent_ext.build_bgpvpn_attach_info(port['id'])
                )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._net_assoc_notif(net_assoc_2, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT20['id'])]
        )

        self._check_network_info(base.NETWORK1['id'], 1)
        self._check_network_info(base.NETWORK2['id'], 1)

    def test_delete_net_assoc_multiple_bgpvpns_different_type(self):
        if isinstance(self, TestOVSAgentExtension):
            self.skipTest("not relevant for OVS, because no EVPN driver")

        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        net_assoc_1 = self._fake_net_assoc(base.NETWORK1,
                                           bgpvpn.BGPVPN_L3,
                                           **base.BGPVPN_L3_RT100)
        net_assoc_2 = self._fake_net_assoc(base.NETWORK1,
                                           bgpvpn.BGPVPN_L2,
                                           **base.BGPVPN_L2_RT10)
        self._net_assoc_notif(net_assoc_1, rpc_events.UPDATED)
        self._net_assoc_notif(net_assoc_2, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self.mocked_bagpipe_agent.reset_mock()

        self.agent_ext.delete_port(None, self._port_data(base.PORT10,
                                                         delete=True))

        local_port_l3 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                      base.NETWORK1['id'],
                                                      base.PORT10['id'],
                                                      detach=True)

        local_port_l2 = self._get_expected_local_port(bbgp_const.EVPN,
                                                      base.NETWORK1['id'],
                                                      base.PORT10['id'],
                                                      detach=True)
        detach_info = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.EVPN: {
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': local_port_l2['local_port']
            },
            bbgp_const.IPVPN: {
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': local_port_l3['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            [mock.call(base.PORT10['id'], [detach_info])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 0)

    def test_net_assoc_before_port_up(self):
        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L3,
                                         **base.BGPVPN_L3_RT100)

        self.mocked_rpc_pull.side_effect = [[net_assoc], [], []]

        def check_build_cb(*args):
            # Verify build callback attachments
            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=local_port['local_port'],
                        **self._expand_rts(base.BGPVPN_L3_RT100)
                    )]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'], 1)

    def test_router_assoc_before_port_up(self):
        router_assoc = self._fake_router_assoc(base.ROUTER1,
                                               bgpvpn.BGPVPN_L3,
                                               [base.NETWORK1],
                                               **base.BGPVPN_L3_RT100)

        self.mocked_rpc_pull.side_effect = [[], [router_assoc], []]

        def check_build_cb(*args):
            # Verify build callback attachments
            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=local_port['local_port'],
                        **self._expand_rts(base.BGPVPN_L3_RT100)
                    )]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'], 1)

    def test_format_bgpvpn_network_route_targets(self):
        n = base.NETWORK1
        assocs = [
            self._fake_net_assoc(n, bgpvpn.BGPVPN_L3,
                                 route_targets=['12345:1',
                                                '12345:2',
                                                '12345:3'],
                                 import_targets=['12345:2', '12345:5'],
                                 export_targets=['12345:3', '12345:8']
                                 ),
            self._fake_net_assoc(n, bgpvpn.BGPVPN_L3,
                                 route_targets=['12345:6', '12345:1'],
                                 import_targets=['12345:2'],
                                 export_targets=[]
                                 ),
            self._fake_net_assoc(n, bgpvpn.BGPVPN_L2,
                                 route_targets=['12347:1'],
                                 import_targets=['12347:1'],
                                 export_targets=[]
                                 )
        ]
        result_ipvpn = self.agent_ext._format_associations_route_targets(
            assocs, 'ipvpn')
        expected = {
            'import_rt': ['12345:1', '12345:2', '12345:3', '12345:5',
                          '12345:6'],
            'export_rt': ['12345:1', '12345:2', '12345:3', '12345:8',
                          '12345:6']
        }
        self.assertItemsEqual(result_ipvpn['import_rt'], expected['import_rt'])
        self.assertItemsEqual(result_ipvpn['export_rt'], expected['export_rt'])

        result_evpn = self.agent_ext._format_associations_route_targets(
            assocs, 'evpn')
        expected = {
            'import_rt': ['12347:1'],
            'export_rt': ['12347:1']
        }
        self.assertItemsEqual(result_evpn['import_rt'], expected['import_rt'])
        self.assertItemsEqual(result_evpn['export_rt'], expected['export_rt'])

    def test_port_association_before_port_up(self):
        port_assoc = self._fake_port_assoc(
            base.PORT10,
            bgpvpn.BGPVPN_L3,
            base.NETWORK1,
            route_prefixes=[("40.0.0.0/24", None),
                            ("60.0.0.0/24", 66)],
            route_targets=base.BGPVPN_L3_RT100['route_targets'],
            local_pref=44
        )

        self.mocked_rpc_pull.side_effect = [[], [], [port_assoc]]

        def check_build_cb(*args):
            # Verify build callback attachments
            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[
                        dict(
                            ip_address=base.PORT10['ip_address'],
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_pref=44,
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT100)
                        ),
                        dict(
                            ip_address='40.0.0.0/24',
                            advertise_subnet=True,
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_pref=44,
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT100)
                        ),
                        dict(
                            ip_address='60.0.0.0/24',
                            advertise_subnet=True,
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_pref=66,
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT100)
                        )
                    ]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        self._check_network_info(base.NETWORK1['id'], 1)

    def test_port_assoc_after_port_up(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        port_assoc = self._fake_port_assoc(base.PORT10,
                                           bgpvpn.BGPVPN_L3,
                                           base.NETWORK1,
                                           route_prefixes=[("40.0.0.0/24",
                                                            77)],
                                           **base.BGPVPN_L3_RT100)

        def check_build_cb(*args):
            # Verify build callback attachments
            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[
                        dict(
                            ip_address=base.PORT10['ip_address'],
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT100)
                        ),
                        dict(
                            ip_address='40.0.0.0/24',
                            advertise_subnet=True,
                            local_pref=77,
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT100)
                        )
                    ]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._port_assoc_notif(port_assoc, rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        # delete port association

        def check_build_cb2(*args):
            self.assertDictEqual(
                {},
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )
        self.mocked_bagpipe_agent.do_port_plug.reset_mock()

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.side_effect = (
            check_build_cb2)

        self._port_assoc_notif(port_assoc, rpc_events.DELETED)

        # check that a detach is produced for the removed prefix route

        local_port_l3 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                      base.NETWORK1['id'],
                                                      base.PORT10['id'],
                                                      detach=True)

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            [mock.call(base.PORT10['id'],
                       UnorderedList([
                           {'network_id': base.NETWORK1['id'],
                            bbgp_const.IPVPN: {
                                'ip_address': ip_address,
                                'mac_address': base.PORT10['mac_address'],
                                'local_port': local_port_l3['local_port']
                                }
                            } for ip_address in (base.PORT10['ip_address'],
                                                 "40.0.0.0/24")]))
             ]
        )
        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()

    def test_port_assoc_update_removes_a_prefix_route(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        port_assoc = self._fake_port_assoc(base.PORT10,
                                           bgpvpn.BGPVPN_L3,
                                           base.NETWORK1,
                                           route_prefixes=[("40.0.0.0/24",
                                                            None)],
                                           **base.BGPVPN_L3_RT100)

        self._port_assoc_notif(port_assoc, rpc_events.CREATED)

        # now remove the prefix route

        new_port_assoc = self._fake_port_assoc(base.PORT10,
                                               bgpvpn.BGPVPN_L3,
                                               base.NETWORK1,
                                               id=port_assoc.id,
                                               **base.BGPVPN_L3_RT100)

        def check_build_cb(*args):
            # Verify build callback attachments
            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=local_port['local_port'],
                        **self._expand_rts(base.BGPVPN_L3_RT100)
                    )]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._port_assoc_notif(new_port_assoc, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        # check that a detach is produced for the removed prefix route

        local_port_l3 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                      base.NETWORK1['id'],
                                                      base.PORT10['id'],
                                                      detach=True)

        detach_info = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.IPVPN: {
                'ip_address': "40.0.0.0/24",
                'mac_address': base.PORT10['mac_address'],
                'local_port': local_port_l3['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            [mock.call(base.PORT10['id'], [detach_info])]
        )

    def test_port_with_prefix_route_then_delete_port(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        port_assoc = self._fake_port_assoc(
            base.PORT10,
            bgpvpn.BGPVPN_L3,
            base.NETWORK1,
            route_prefixes=[("40.0.0.0/24", None),
                            ("60.0.0.0/16", None)],
            **base.BGPVPN_L3_RT100)

        self._port_assoc_notif(port_assoc, rpc_events.CREATED)

        # check that detach are produced for the deleted port

        local_port_l3 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                      base.NETWORK1['id'],
                                                      base.PORT10['id'],
                                                      detach=True)
        calls = [
            mock.call(base.PORT10['id'],
                      UnorderedList(
                          [{'network_id': base.NETWORK1['id'],
                            bbgp_const.IPVPN: {
                                'ip_address': ip_address,
                                'mac_address': base.PORT10['mac_address'],
                                'local_port': local_port_l3['local_port']
                                }
                            } for ip_address in (base.PORT10['ip_address'],
                                                 "40.0.0.0/24",
                                                 "60.0.0.0/16")
                           ]))
        ]

        self.agent_ext.delete_port(None, self._port_data(base.PORT10))

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            calls,
            any_order=True,
        )


class TestOVSAgentExtension(base.BaseTestOVSAgentExtension,
                            TestBgpvpnAgentExtensionMixin):

    agent_extension_class = bagpipe_agt_ext.BagpipeBgpvpnAgentExtension

    def setUp(self):
        base.BaseTestOVSAgentExtension.setUp(self)
        TestBgpvpnAgentExtensionMixin.setUp(self)

    # Test fallback and ARP gateway voodoo
    def test_fallback(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent_ext.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestOVSAgentExtension,
                  self).test_net_assoc_already_plugged_ports()

            net_assoc = self._fake_net_assoc(base.NETWORK1,
                                             bgpvpn.BGPVPN_L3,
                                             gateway_mac=GW_MAC,
                                             **base.BGPVPN_L3_RT100)

            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])

            def check_build_cb(*args):
                self.assertDictEqual(
                    dict(
                        network_id=base.NETWORK1['id'],
                        ipvpn=[dict(
                            ip_address=base.PORT10['ip_address'],
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            fallback={'dst_mac': GW_MAC,
                                      'ovs_port_number':
                                      base.PATCH_MPLS_TO_INT_OFPORT,
                                      'src_mac': '00:00:5e:2a:10:00'},
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT100)
                            )]
                    ),
                    self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
                )

            self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

            self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

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
                  self).test_net_assoc_already_plugged_ports()

            net_assoc = self._fake_net_assoc(base.NETWORK1,
                                             bgpvpn.BGPVPN_L3,
                                             gateway_mac=GW_MAC,
                                             **base.BGPVPN_L3_RT100)

            self.mocked_bagpipe_agent.do_port_plug.side_effect = None

            self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

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

            self.agent_ext.delete_port(None, self._port_data(base.PORT10,
                                                             delete=True))

            self.assertEqual(0, tun_delete_flows.call_count)
            self.assertEqual(0, int_delete_flows.call_count)

            self.agent_ext.delete_port(None, self._port_data(base.PORT11,
                                                             delete=True))

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

    def test_gateway_arp_voodoo_update_net_assoc_after_plug(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent_ext.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent_ext.int_br,
                                  'add_flow') as add_flow:

            net_assoc = self._fake_net_assoc(base.NETWORK1,
                                             bgpvpn.BGPVPN_L3,
                                             **base.BGPVPN_L3_RT100)

            self.mocked_rpc_pull.side_effect = [[net_assoc], [], []]

            self.agent_ext.handle_port(None, self._port_data(base.PORT10))

            net_assoc_updated = self._fake_net_assoc(base.NETWORK1,
                                                     bgpvpn.BGPVPN_L3,
                                                     gateway_mac=GW_MAC,
                                                     **base.BGPVPN_L3_RT100)
            self._net_assoc_notif(net_assoc_updated, rpc_events.UPDATED)

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

            self._net_assoc_notif(net_assoc_updated, rpc_events.DELETED)

            add_flow.reset_mock()
            self.assertEqual(0, add_flow.call_count)

            self._net_assoc_notif(net_assoc_updated, rpc_events.UPDATED)

            self.assertEqual(2, add_flow.call_count)

            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])

            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        fallback=fallback,
                        local_port=local_port['local_port'],
                        **self._expand_rts(base.BGPVPN_L3_RT100)
                    )]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

    def test_gateway_plug_before_update(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent_ext.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10]), \
                mock.patch.object(self.agent_ext.int_br,
                                  'add_flow') as add_flow, \
                mock.patch.object(self.agent_ext.int_br,
                                  'delete_flows') as int_delete_flows, \
                mock.patch.object(self.agent_ext.tun_br,
                                  'delete_flows') as tun_delete_flows:
            self.agent_ext.handle_port(None, self._port_data(base.PORT10))
            net_assoc = self._fake_net_assoc(base.NETWORK1,
                                             bgpvpn.BGPVPN_L3,
                                             gateway_mac=GW_MAC,
                                             **base.BGPVPN_L3_RT100)
            self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

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

            add_flow.reset_mock()
            int_delete_flows.reset_mock()
            tun_delete_flows.reset_mock()

            self._net_assoc_notif(net_assoc, rpc_events.DELETED)

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

            self.assertEqual(0, add_flow.call_count)

            add_flow.reset_mock()

            self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

            self.assertEqual(2, add_flow.call_count)

            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])

            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        fallback=fallback,
                        local_port=local_port['local_port'],
                        **self._expand_rts(base.BGPVPN_L3_RT100)
                    )]
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

            self.agent_ext.handle_port(None, self._port_data(base.PORT10))
            net_assoc = self._fake_net_assoc(base.NETWORK1,
                                             bgpvpn.BGPVPN_L2,
                                             gateway_mac=GW_MAC,
                                             **base.BGPVPN_L2_RT10)
            self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

            self.assertEqual(0, add_flow.call_count)

            self.agent_ext.delete_port(None, self._port_data(base.PORT10,
                                                             delete=True))

            self.assertEqual(0, delete_flows.call_count)

    def test_gateway_arp_voodoo_ovs_restart(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent_ext.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent_ext.int_br,
                                  'add_flow') as add_flow:

            self.agent_ext.handle_port(None, self._port_data(base.PORT10))
            net_assoc = self._fake_net_assoc(base.NETWORK1,
                                             bgpvpn.BGPVPN_L3,
                                             gateway_mac=GW_MAC,
                                             **base.BGPVPN_L3_RT100)
            self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

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

            with mock.patch.object(self.agent_ext, '_setup_mpls_br') as \
                    mock_setup_mpls_br:
                self.agent_ext.ovs_restarted(None, None, None)
                mock_setup_mpls_br.assert_called()

            add_flow.assert_has_calls(expected_calls)


class TestLinuxBridgeAgentExtension(base.BaseTestLinuxBridgeAgentExtension,
                                    TestBgpvpnAgentExtensionMixin):

    agent_extension_class = bagpipe_agt_ext.BagpipeBgpvpnAgentExtension

    def setUp(self):
        base.BaseTestLinuxBridgeAgentExtension.setUp(self)
        TestBgpvpnAgentExtensionMixin.setUp(self)
