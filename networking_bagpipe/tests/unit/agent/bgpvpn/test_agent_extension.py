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
from networking_bagpipe.agent.bgpvpn import constants as bgpvpn_const
from networking_bagpipe.bagpipe_bgp import constants as bbgp_const
from networking_bagpipe.objects import bgpvpn as objects
from networking_bagpipe.tests.unit.agent import base

from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants as ovs_agt_constants

from neutron_lib.api.definitions import bgpvpn
from neutron_lib import context


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
    if isinstance(list_[0], dict) and len(list_):
        return [HashableDict(d) for d in list_]


class UnorderedList(list):

    def __eq__(self, other):
        return set(make_list_hashable(self)) == set(make_list_hashable(other))


class StringContains(object):

    def __init__(self, *items):
        self.items = items

    def __eq__(self, other):
        return all([(item in other) for item in self.items])

    def __repr__(self):
        return 'StringContains(%s)' % ','.join(self.items)


class TestBgpvpnAgentExtensionMixin(object):

    def setUp(self):
        self.mocked_rpc_pull = mock.patch.object(
            self.agent_ext.rpc_pull_api, 'bulk_pull').start()
        self.context = context.get_admin_context()

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

    def _fake_bgpvpn(self, bgpvpn_type, id=None, **bgpvpn_params):
        return objects.BGPVPN(self.context,
                              id=id or uuidutils.generate_uuid(),
                              type=bgpvpn_type,
                              **bgpvpn_params)

    def _fake_net_assoc(self, network, bgpvpn_type, gateway_mac=None,
                        id=None, **bgpvpn_params):
        bgpvpn = self._fake_bgpvpn(bgpvpn_type,
                                   **bgpvpn_params)
        net_assoc = objects.BGPVPNNetAssociation(
            self.context,
            id=id or uuidutils.generate_uuid(),
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
            self.context,
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
                         route_prefixes=None, id=None, bgpvpn_routes=None,
                         advertise_fixed_ips=True,
                         **bgpvpn_params):
        bgpvpn = self._fake_bgpvpn(bgpvpn_type, **bgpvpn_params)
        port_assoc = objects.BGPVPNPortAssociation(
            self.context,
            id=id or uuidutils.generate_uuid(),
            port_id=port['id'],
            bgpvpn_id=bgpvpn.id,
            bgpvpn=bgpvpn,
            advertise_fixed_ips=advertise_fixed_ips
        )

        port_assoc.subnets = [{
            'ip_version': 4,
            'cidr': "NOT_USED_TODAY",
            'gateway_ip': network['gateway_ip'],
            'gateway_mac': gateway_mac,
        }]

        route_prefixes = route_prefixes or []
        bgpvpn_routes = bgpvpn_routes or []

        prefix_routes = [
            objects.BGPVPNPortAssociationRoute(
                self.context,
                type='prefix',
                prefix=netaddr.IPNetwork(prefix),
                local_pref=local_pref)
            for prefix, local_pref in route_prefixes]

        bgpvpn_routes_objs = [
            objects.BGPVPNPortAssociationRoute(
                self.context,
                type='bgpvpn',
                bgpvpn=bgpvpn_,
                bgpvpn_id=bgpvpn_.id,
                local_pref=local_pref)
            for bgpvpn_, local_pref in bgpvpn_routes]

        port_assoc.routes = prefix_routes + bgpvpn_routes_objs

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
                            description=mock.ANY,
                            instance_description=mock.ANY,
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

        return net_assoc

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
                            description=mock.ANY,
                            instance_description=mock.ANY,
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

    def test_net_assoc_update_rts_to_empty(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L3,
                                         **base.BGPVPN_L3_RT100)
        self._net_assoc_notif(net_assoc, rpc_events.CREATED)

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 1)
        self.mocked_bagpipe_agent.do_port_plug.reset_mock()

        net_assoc.bgpvpn.route_targets = []
        self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_called()
        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_not_called()

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
                        description=mock.ANY,
                        instance_description=mock.ANY,
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
                            description=mock.ANY,
                            instance_description=mock.ANY,
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
                            description=mock.ANY,
                            instance_description=mock.ANY,
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
                        description=mock.ANY,
                        instance_description=mock.ANY,
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
                        description=mock.ANY,
                        instance_description=mock.ANY,
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        vni=base.NETWORK1["segmentation_id"],
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
                        description=mock.ANY,
                        instance_description=mock.ANY,
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
                            description=mock.ANY,
                            instance_description=mock.ANY,
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
                        description=mock.ANY,
                        instance_description=mock.ANY,
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
                        description=mock.ANY,
                        instance_description=mock.ANY,
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
                                 )
        ]
        result = bagpipe_agt_ext.format_associations_route_targets(assocs)
        expected = {
            'import_rt': ['12345:1', '12345:2', '12345:3', '12345:5',
                          '12345:6'],
            'export_rt': ['12345:1', '12345:2', '12345:3', '12345:8',
                          '12345:6']
        }
        self.assertItemsEqual(result['import_rt'], expected['import_rt'])
        self.assertItemsEqual(result['export_rt'], expected['export_rt'])

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

        instance_id_base = 'ipvpn_portassoc_%s_prefix_' % port_assoc.id

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
                            description=mock.ANY,
                            instance_description=mock.ANY,
                            ip_address=base.PORT10['ip_address'],
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_pref=44,
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT100)
                        ),
                        dict(
                            description=mock.ANY,
                            instance_description=mock.ANY,
                            vpn_instance_id=(instance_id_base +
                                             '40_0_0_0_24'),
                            direction='to-port',
                            ip_address='40.0.0.0/24',
                            advertise_subnet=True,
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_pref=44,
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT100)
                        ),
                        dict(
                            description=mock.ANY,
                            instance_description=mock.ANY,
                            vpn_instance_id=(instance_id_base +
                                             '60_0_0_0_24'),
                            direction='to-port',
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

        instance_id_base = 'ipvpn_portassoc_%s_prefix_' % port_assoc.id

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
                            description=mock.ANY,
                            instance_description=mock.ANY,
                            ip_address=base.PORT10['ip_address'],
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT100)
                        ),
                        dict(
                            description=mock.ANY,
                            instance_description=mock.ANY,
                            vpn_instance_id=(instance_id_base +
                                             '40_0_0_0_24'),
                            direction='to-port',
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
                                'ip_address': base.PORT10['ip_address'],
                                'mac_address': base.PORT10['mac_address'],
                                'local_port': local_port_l3['local_port']
                                }
                            },
                           {'network_id': base.NETWORK1['id'],
                            bbgp_const.IPVPN: {
                                'ip_address': "40.0.0.0/24",
                                'vpn_instance_id': (instance_id_base +
                                                    '40_0_0_0_24'),
                                'mac_address': base.PORT10['mac_address'],
                                'local_port': local_port_l3['local_port']
                                }
                            }
                       ]))
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

        instance_id_base = 'ipvpn_portassoc_%s_prefix_' % port_assoc.id

        def check_build_cb(*args):
            # Verify build callback attachments
            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        description=mock.ANY,
                        instance_description=mock.ANY,
                        vpn_instance_id=(instance_id_base + '40_0_0_0_24'),
                        direction='to-port',
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=local_port['local_port'],
                        **self._expand_rts(base.BGPVPN_L3_RT100)
                    )]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.reset_mock()
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb
        self.mocked_bagpipe_agent.do_port_plug_refresh_many.reset_mock()

        self._port_assoc_notif(new_port_assoc, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()

        # check that a detach is produced for the removed prefix route

        local_port_l3 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                      base.NETWORK1['id'],
                                                      base.PORT10['id'],
                                                      detach=True)

        detach_info = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.IPVPN: {
                'vpn_instance_id': (instance_id_base + '40_0_0_0_24'),
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

        instance_id_base = 'ipvpn_portassoc_%s_prefix_' % port_assoc.id

        self._port_assoc_notif(port_assoc, rpc_events.CREATED)

        # check that detach are produced for the deleted port

        local_port_l3 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                      base.NETWORK1['id'],
                                                      base.PORT10['id'],
                                                      detach=True)
        calls = [
            mock.call(base.PORT10['id'],
                      UnorderedList([
                          {'network_id': base.NETWORK1['id'],
                           bbgp_const.IPVPN: {
                               'ip_address': base.PORT10['ip_address'],
                               'mac_address': base.PORT10['mac_address'],
                               'local_port': local_port_l3['local_port']
                               }
                           },
                          {'network_id': base.NETWORK1['id'],
                           bbgp_const.IPVPN: {
                               'ip_address': "40.0.0.0/24",
                               'vpn_instance_id': (instance_id_base +
                                                   '40_0_0_0_24'),
                               'mac_address': base.PORT10['mac_address'],
                               'local_port': local_port_l3['local_port']
                               }
                           },
                          {'network_id': base.NETWORK1['id'],
                           bbgp_const.IPVPN: {
                               'ip_address': "60.0.0.0/16",
                               'vpn_instance_id': (instance_id_base +
                                                   '60_0_0_0_16'),
                               'mac_address': base.PORT10['mac_address'],
                               'local_port': local_port_l3['local_port']
                               }
                           }
                      ]))
        ]

        self.agent_ext.delete_port(None, self._port_data(base.PORT10))

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            calls,
            any_order=True,
        )

    def test_port_assoc_adv_fixed_ips_false(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        port_assoc = self._fake_port_assoc(base.PORT10,
                                           bgpvpn.BGPVPN_L3,
                                           base.NETWORK1,
                                           route_prefixes=[("40.0.0.0/24",
                                                            None)],
                                           advertise_fixed_ips=False,
                                           **base.BGPVPN_L3_RT100)

        instance_id_base = 'ipvpn_portassoc_%s_prefix_' % port_assoc.id

        def check_build_cb(*args):
            # Verify build callback attachments
            local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        description=mock.ANY,
                        instance_description=mock.ANY,
                        vpn_instance_id=(instance_id_base + '40_0_0_0_24'),
                        direction='to-port',
                        ip_address="40.0.0.0/24",
                        advertise_subnet=True,
                        local_pref=None,
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=local_port['local_port'],
                        **self._expand_rts(base.BGPVPN_L3_RT100)
                    )]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        # trigger port assoc, check fixed IP not advertised (check_build_db)
        self._port_assoc_notif(port_assoc, rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        # tear down the port
        self.agent_ext.delete_port(None, self._port_data(base.PORT10,
                                                         delete=True))

        # check that a detach is produced for the prefix route only

        local_port_l3 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                      base.NETWORK1['id'],
                                                      base.PORT10['id'],
                                                      detach=True)
        detach_info = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.IPVPN: {
                'vpn_instance_id': (instance_id_base + '40_0_0_0_24'),
                'ip_address': "40.0.0.0/24",
                'mac_address': base.PORT10['mac_address'],
                'local_port': local_port_l3['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            [mock.call(base.PORT10['id'], [detach_info])]
        )

    def test_port_assoc_bgpvpn_routes(self):
        from_bgpvpns = [
            (self._fake_bgpvpn(bgpvpn.BGPVPN_L3, import_targets=['64512:96']),
             44),
            (self._fake_bgpvpn(bgpvpn.BGPVPN_L3, import_targets=['64512:97']),
             55)
        ]

        port_assoc = self._fake_port_assoc(
            base.PORT10,
            bgpvpn.BGPVPN_L3,
            base.NETWORK1,
            bgpvpn_routes=from_bgpvpns,
            export_targets=['64512:98'],
            import_targets=['64512:99']
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
                            description=mock.ANY,
                            instance_description=mock.ANY,
                            ip_address=base.PORT10['ip_address'],
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=local_port['local_port'],
                            export_rt=set(['64512:98']),
                            import_rt=set(['64512:99']),
                        ),
                        dict(
                            description=mock.ANY,
                            instance_description=mock.ANY,
                            vpn_instance_id=StringContains(
                                "ipvpn_portassoc",
                                port_assoc.id,
                                from_bgpvpns[0][0].id),
                            direction='to-port',
                            ip_address=base.PORT10['ip_address'],
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=local_port['local_port'],
                            readvertise={
                                'from_rt': set(['64512:96']),
                                'to_rt': set(['64512:98'])
                                },
                            import_rt=set(['64512:99']),
                            export_rt=set(['64512:98']),
                            local_pref=44,
                        ),
                        dict(
                            description=mock.ANY,
                            instance_description=mock.ANY,
                            vpn_instance_id=StringContains(
                                "ipvpn_portassoc",
                                port_assoc.id,
                                from_bgpvpns[1][0].id),
                            direction='to-port',
                            ip_address=base.PORT10['ip_address'],
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=local_port['local_port'],
                            readvertise={
                                'from_rt': set(['64512:97']),
                                'to_rt': set(['64512:98'])
                                },
                            import_rt=set(['64512:99']),
                            export_rt=set(['64512:98']),
                            local_pref=55,
                        ),
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

        # remove one of the BGPVPN leaking routes
        # (keep only the second one)

        from_bgpvpns_bis = [
            (self._fake_bgpvpn(bgpvpn.BGPVPN_L3,
                               id=from_bgpvpns[1][0].id,
                               import_targets=['64512:97']),
             55)
        ]

        new_port_assoc = self._fake_port_assoc(base.PORT10,
                                               bgpvpn.BGPVPN_L3,
                                               base.NETWORK1,
                                               id=port_assoc.id,
                                               bgpvpn_routes=from_bgpvpns_bis,
                                               export_targets=['64512:98'],
                                               import_targets=['64512:99']
                                               )

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
                            description=mock.ANY,
                            instance_description=mock.ANY,
                            ip_address=base.PORT10['ip_address'],
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=local_port['local_port'],
                            export_rt=set(['64512:98']),
                            import_rt=set(['64512:99']),
                        ),
                        dict(
                            description=mock.ANY,
                            instance_description=mock.ANY,
                            vpn_instance_id=StringContains(
                                "ipvpn_portassoc",
                                port_assoc.id,
                                from_bgpvpns[1][0].id),
                            direction='to-port',
                            ip_address=base.PORT10['ip_address'],
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=local_port['local_port'],
                            readvertise={
                                'from_rt': set(['64512:97']),
                                'to_rt': set(['64512:98'])
                                },
                            import_rt=set(['64512:99']),
                            export_rt=set(['64512:98']),
                            local_pref=55,
                        ),
                    ]
                ),
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.reset_mock()
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb
        self.mocked_bagpipe_agent.do_port_plug_refresh_many.reset_mock()

        self._port_assoc_notif(new_port_assoc, rpc_events.UPDATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()

        # check that a detach is produced for the removed prefix route

        local_port_l3 = self._get_expected_local_port(bbgp_const.IPVPN,
                                                      base.NETWORK1['id'],
                                                      base.PORT10['id'],
                                                      detach=True)
        detach_info = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.IPVPN: {
                'vpn_instance_id': StringContains("ipvpn_portassoc",
                                                  port_assoc.id,
                                                  from_bgpvpns[0][0].id),
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': local_port_l3['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            [mock.call(base.PORT10['id'], [detach_info])]
        )

        # now remove the port association

        def check_build_cb(*args):
            # Verify build callback attachments
            self.assertDictEqual(
                {},
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.reset_mock()
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb
        self.mocked_bagpipe_agent.do_port_plug_refresh_many.reset_mock()

        self._port_assoc_notif(new_port_assoc, rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()

        expected_vpn_instance_id = (
            'ipvpn_portassoc_%s_bgpvpn_%s' % (port_assoc.id,
                                              from_bgpvpns[1][0].id)
        )

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_has_calls(
            [mock.call(
                base.PORT10['id'],
                UnorderedList([
                    {'network_id': base.NETWORK1['id'],
                     bbgp_const.IPVPN: {
                         'ip_address': base.PORT10['ip_address'],
                         'mac_address': base.PORT10['mac_address'],
                         'local_port': local_port_l3['local_port']
                         }
                     },
                    {'network_id': base.NETWORK1['id'],
                     bbgp_const.IPVPN: {
                         'vpn_instance_id': expected_vpn_instance_id,
                         'ip_address': base.PORT10['ip_address'],
                         'mac_address': base.PORT10['mac_address'],
                         'local_port': local_port_l3['local_port']
                         }
                     },
                ]))
             ]
        )

    def test_net_assoc_l2_bgpvpn_vni(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L2,
                                         **base.BGPVPN_L2_RT10)
        net_assoc.bgpvpn.vni = 4242

        def check_build_cb(*args):
            # Verify build callback attachments
            local_port = self._get_expected_local_port(bbgp_const.EVPN,
                                                       base.NETWORK1['id'],
                                                       base.PORT10['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    evpn=[dict(
                        description=mock.ANY,
                        instance_description=mock.ANY,
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        vni=4242,
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

    def test_net_assoc_port_admin_state_down_up_down(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10,
                                                         admin_state_up=False))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        net_assoc = self._fake_net_assoc(base.NETWORK1,
                                         bgpvpn.BGPVPN_L3,
                                         **base.BGPVPN_L3_RT100)

        # Verify build callback attachments
        def check_build_cb(*args):
            self.assertDictEqual(
                {},
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        # we need to check what build_bgpvpn_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._net_assoc_notif(net_assoc, rpc_events.CREATED)

        # test transition to admin_state_up = True

        self.mocked_bagpipe_agent.do_port_plug.reset_mock()

        # Verify build callback attachments
        def check_build_cb_2(*args):
            self.assertNotEqual(
                0,
                len(self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id']))
            )
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb_2

        self.agent_ext.handle_port(None, self._port_data(base.PORT10,
                                                         admin_state_up=True))

        # test transition to admin_state_up = False

        self.mocked_bagpipe_agent.do_port_plug.reset_mock()

        def check_build_cb_3(*args):
            self.assertDictEqual(
                {},
                self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
            )

        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb_3

        self.agent_ext.handle_port(None, self._port_data(
            base.PORT10,
            admin_state_up=False))

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.\
            assert_called_once_with(base.PORT10['id'], mock.ANY)

    def test_net_assoc_port_admin_state_down_delete(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10,
                                                         admin_state_up=False))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        self._fake_net_assoc(base.NETWORK1,
                             bgpvpn.BGPVPN_L3,
                             **base.BGPVPN_L3_RT100)

        # test delete_port when port in admin_state_up = False

        self.agent_ext.delete_port(None, self._port_data(base.PORT10,
                                                         delete=True))

        self.mocked_bagpipe_agent.do_port_plug_refresh_many.assert_not_called()


class TestOVSAgentExtension(base.BaseTestOVSAgentExtension,
                            TestBgpvpnAgentExtensionMixin):

    agent_extension_class = bagpipe_agt_ext.BagpipeBgpvpnAgentExtension

    def setUp(self):
        base.BaseTestOVSAgentExtension.setUp(self)
        TestBgpvpnAgentExtensionMixin.setUp(self)

        # test what happened during initialize()

        self.tun_br.add_patch_port.assert_called_once()
        self.int_br.add_patch_port.assert_called_once()
        self.assertEqual(self.agent_ext.mpls_br.add_patch_port.call_count,
                         2)

        self.tun_br.add_flow.assert_has_calls([
            mock.call(table=ovs_agt_constants.PATCH_LV_TO_TUN,
                      priority=2,
                      dl_src=bgpvpn_const.FALLBACK_SRC_MAC,
                      dl_dst=mock.ANY,
                      actions=mock.ANY),
            mock.call(table=ovs_agt_constants.PATCH_LV_TO_TUN,
                      priority=2,
                      dl_src=bgpvpn_const.FALLBACK_SRC_MAC,
                      dl_dst=mock.ANY,
                      actions=mock.ANY),
            mock.call(in_port=base.PATCH_TUN_TO_MPLS,
                      actions="output:%d" % base.PATCH_TUN_TO_INT)
            ],
            any_order=True,
        )

        self.int_br.add_flow.assert_called_once_with(
            table=ovs_agt_constants.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
            priority=3,
            dl_src="00:00:5e:2a:10:00",
            actions="NORMAL",
        )

        self.int_br.add_flow.reset_mock()
        self.tun_br.add_flow.reset_mock()

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
                            description=mock.ANY,
                            instance_description=mock.ANY,
                            ip_address=base.PORT10['ip_address'],
                            mac_address=base.PORT10['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            fallback={'dst_mac': GW_MAC,
                                      'ovs_port_number':
                                          base.PATCH_MPLS_TO_INT,
                                      'src_mac': '00:00:5e:2a:10:00'},
                            local_port=local_port['local_port'],
                            **self._expand_rts(base.BGPVPN_L3_RT100)
                            )]
                    ),
                    self.agent_ext.build_bgpvpn_attach_info(base.PORT10['id'])
                )

            self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

            self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

    def test_gateway_redirection(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'
        vlan = base.LOCAL_VLAN_MAP[base.NETWORK1['id']]

        with mock.patch.object(self.agent_ext.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent_ext.int_br,
                                  'add_flow') as int_add_flow, \
                mock.patch.object(self.agent_ext.tun_br,
                                  'add_flow') as tun_add_flow, \
                mock.patch.object(self.agent_ext.tun_br,
                                  'delete_flows') as tun_delete_flows,\
                mock.patch.object(self.agent_ext.int_br,
                                  'delete_flows') as int_delete_flows:
            net_assoc_0 = super(TestOVSAgentExtension,
                                self).test_net_assoc_already_plugged_ports()

            int_add_flow.assert_not_called()

            tun_add_flow.assert_has_calls([
                mock.call(
                    table=ovs_agt_constants.ARP_RESPONDER,
                    priority=2,
                    dl_vlan=vlan,
                    proto='arp',
                    arp_op=0x01,
                    arp_tpa=base.NETWORK1['gateway_ip'],
                    actions=StringContains("5e004364"),
                ),
                mock.call(
                    in_port=base.PATCH_TUN_TO_INT,
                    dl_dst="00:00:5e:00:43:64",
                    actions="output:%s" % base.PATCH_TUN_TO_MPLS,
                    dl_vlan=vlan,
                    priority=mock.ANY,
                    table=mock.ANY
                )],
                any_order=True,
            )

            int_add_flow.reset_mock()
            tun_add_flow.reset_mock()
            tun_delete_flows.reset_mock()
            int_delete_flows.reset_mock()

            net_assoc = self._fake_net_assoc(base.NETWORK1,
                                             bgpvpn.BGPVPN_L3,
                                             id=net_assoc_0.id,
                                             gateway_mac=GW_MAC,
                                             **base.BGPVPN_L3_RT100)

            vlan = base.LOCAL_VLAN_MAP[base.NETWORK1['id']]

            self.mocked_bagpipe_agent.do_port_plug.side_effect = None

            self._net_assoc_notif(net_assoc, rpc_events.UPDATED)

            # we now have a router will a real GW MAC

            tun_delete_flows.assert_called_with(
                strict=True,
                table=ovs_agt_constants.ARP_RESPONDER,
                priority=2,
                dl_vlan=vlan,
                proto='arp',
                arp_op=0x01,
                arp_tpa=base.NETWORK1['gateway_ip'])

            # check that traffic to gw is sent to br-mpls
            tun_add_flow.assert_has_calls([
                mock.call(in_port=base.PATCH_TUN_TO_INT,
                          dl_dst=GW_MAC,
                          actions="output:%s" % base.PATCH_TUN_TO_MPLS,
                          dl_vlan=vlan,
                          priority=mock.ANY,
                          table=mock.ANY),
                mock.call(in_port=base.PATCH_TUN_TO_INT,
                          dl_dst="00:00:5e:00:43:64",
                          actions="output:%s" % base.PATCH_TUN_TO_MPLS,
                          dl_vlan=vlan,
                          priority=mock.ANY,
                          table=mock.ANY)
                ],
                any_order=True
            )

            int_add_flow.assert_called_once_with(
                table=ovs_agt_constants.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
                priority=2,
                reg6=vlan,
                dl_dst=GW_MAC,
                actions="push_vlan:0x8100,mod_vlan_vid:%d,output:%s" % (
                        vlan, base.PATCH_INT_TO_TUN)
            )

            int_add_flow.reset_mock()
            tun_add_flow.reset_mock()
            tun_delete_flows.reset_mock()
            int_delete_flows.reset_mock()

            # stop the redirection when association is cleared
            self._net_assoc_notif(net_assoc, rpc_events.DELETED)

            # ARP responder deletion
            tun_delete_flows.assert_has_calls([
                mock.call(
                    strict=True,
                    table=ovs_agt_constants.PATCH_LV_TO_TUN,
                    priority=1,
                    in_port=base.PATCH_TUN_TO_INT,
                    dl_vlan=vlan
                ),
                mock.call(
                    strict=True,
                    table=ovs_agt_constants.ARP_RESPONDER,
                    priority=2,
                    dl_vlan=vlan,
                    proto='arp',
                    arp_op=0x01,
                    arp_tpa=base.NETWORK1['gateway_ip'],
                    )
                ],
                any_order=True
            )
            int_delete_flows.assert_called_once_with(
                table=ovs_agt_constants.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
                reg6=vlan)

    def test_gateway_redirection_ovs_restart(self):
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

            add_flow.assert_called()

            add_flow.reset_mock()

            with mock.patch.object(self.agent_ext, '_setup_ovs_bridge') as \
                    mock_setup_mpls_br:
                self.agent_ext.ovs_restarted(None, None, None)
                mock_setup_mpls_br.assert_called()

            add_flow.assert_called()


class TestLinuxBridgeAgentExtension(base.BaseTestLinuxBridgeAgentExtension,
                                    TestBgpvpnAgentExtensionMixin):

    agent_extension_class = bagpipe_agt_ext.BagpipeBgpvpnAgentExtension

    def setUp(self):
        base.BaseTestLinuxBridgeAgentExtension.setUp(self)
        TestBgpvpnAgentExtensionMixin.setUp(self)
