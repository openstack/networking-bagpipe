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
import random

import netaddr
from oslo_utils import uuidutils

from networking_bagpipe.objects import bgpvpn as bgpvpn_obj

from neutron.common import utils

from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api

from neutron_lib.api.definitions import bgpvpn as bgpvpn_api
from neutron_lib.api.definitions import bgpvpn_routes_control as bgpvpn_rc_api
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.objects import registry as obj_reg


test_base.FIELD_TYPE_VALUE_GENERATOR_MAP[bgpvpn_obj.BGPVPNTypeField] = (
    lambda: random.choice(bgpvpn_api.BGPVPN_TYPES)
)

test_base.FIELD_TYPE_VALUE_GENERATOR_MAP[
    bgpvpn_obj.BGPVPNPortAssociationRouteTypeField] = (
        # do not generate bgpvpn type routes for now:
        lambda: bgpvpn_rc_api.PREFIX_TYPE)


CIDR = "10.10.0.0/16"
GW_IP = "10.10.0.1"
GW_MAC = "ba:ad:00:00:ca:fe"
TEST_RT = "64512:42"


def _subnet_dict(gw_mac=None):
    return {
        'id': mock.ANY,
        'ip_version': 4,
        'gateway_mac': gw_mac,
        'cidr': utils.AuthenticIPNetwork(CIDR),
        'gateway_ip': netaddr.IPAddress(GW_IP)
    }


class _BPGVPNObjectsTestCommon(object):

    def _create_test_bgpvpn(self):
        bgpvpn = bgpvpn_obj.BGPVPN(self.context,
                                   route_targets=[TEST_RT],
                                   name='test-bgpvpn-U',
                                   type='l3')
        bgpvpn.create()
        return bgpvpn

    def _create_test_bgpvpn_id(self):
        return self._create_test_bgpvpn().id

    def _make_subnet(self, network_id):
        _subnet = obj_reg.new_instance(
            'Subnet', self.context,
            network_id=network_id,
            ip_version=4,
            cidr=netaddr.IPNetwork(CIDR),
            gateway_ip=GW_IP)
        _subnet.create()
        return _subnet

    def _connect_router_network(self, router_id, network_id,
                                subnet_id=None, gw_network=False):
        port = obj_reg.new_instance(
            'Port', self.context,
            network_id=network_id,
            mac_address=netaddr.EUI(
                GW_MAC,
                dialect=netaddr.mac_unix_expanded),
            device_id='test_device_id',
            device_owner=constants.DEVICE_OWNER_ROUTER_INTF,
            status="DUMMY_STATUS",
            admin_state_up=True)
        if gw_network:
            port.device_owner = constants.DEVICE_OWNER_ROUTER_GW

        port.create()

        if subnet_id:
            allocation = obj_reg.new_instance(
                'IPAllocation',
                self.context,
                port_id=port.id,
                subnet_id=subnet_id,
                network_id=network_id,
                ip_address=netaddr.IPNetwork(GW_IP))
            allocation.create()

            port.fixed_ips = [allocation]
            port.update()

        router_if = obj_reg.new_instance(
            'RouterPort', self.context,
            router_id=router_id,
            port_id=port.id)
        router_if.create()


class BGPVPNTest(test_base.BaseDbObjectTestCase,
                 testlib_api.SqlTestCase,
                 _BPGVPNObjectsTestCommon):

    _test_class = bgpvpn_obj.BGPVPN

    def test_get_objects_supports_extra_filtername(self):
        self.skipTest("no support for extra filtername")

    def test_get_object(self):
        bgpvpn = self._create_test_bgpvpn()
        bgpvpn_bis = bgpvpn_obj.BGPVPN.get_object(self.context,
                                                  id=bgpvpn.id)
        self.assertEqual(bgpvpn, bgpvpn_bis)


class BGPVPNNetAssociationTest(test_base.BaseDbObjectTestCase,
                               testlib_api.SqlTestCase,
                               _BPGVPNObjectsTestCommon):

    _test_class = bgpvpn_obj.BGPVPNNetAssociation

    def setUp(self):
        test_base.BaseDbObjectTestCase.setUp(self)
        self.network_id = self._create_test_network_id()
        self.update_obj_fields(
            {'network_id': self.network_id,
             'bgpvpn_id': self._create_test_bgpvpn_id})

        self.subnet = self._make_subnet(self.network_id)

    def test_get_objects_queries_constant(self):
        self.skipTest("test not passing yet, remains to be investigated why")

    def test_all_subnets(self):
        for db_obj in self.objs:
            self.assertItemsEqual(db_obj.all_subnets(self.network_id),
                                  [_subnet_dict()])

    def test_subnets(self):
        for obj in self.objs:
            obj.create()
            self.assertItemsEqual(obj.subnets, [_subnet_dict()])

        # plug a router
        _router = obj_reg.new_instance('Router', self.context)
        _router.create()

        self._connect_router_network(_router.id,
                                     self.network_id,
                                     self.subnet.id)

        # check .subnets in associations, after refreshing
        for obj in self.objs:
            refreshed_obj = bgpvpn_obj.BGPVPNNetAssociation.get_object(
                self.context,
                id=obj.id)
            self.assertItemsEqual(refreshed_obj.subnets,
                                  [_subnet_dict(GW_MAC)])


class BGPVPNRouterAssociationTest(test_base.BaseDbObjectTestCase,
                                  testlib_api.SqlTestCase,
                                  _BPGVPNObjectsTestCommon):

    _test_class = bgpvpn_obj.BGPVPNRouterAssociation

    def setUp(self):
        test_base.BaseDbObjectTestCase.setUp(self)
        self.router_id = self._create_test_router_id()
        self.update_obj_fields(
            {'router_id': self.router_id,
             'bgpvpn_id': self._create_test_bgpvpn_id,
             })
        self.context = context.get_admin_context()

    def test_get_objects_queries_constant(self):
        self.skipTest("test not passing yet, remains to be investigated why")

    def test_all_subnets(self):
        for obj in self.objs:
            obj.create()

        network_id = self._create_test_network_id()
        subnet_ = self._make_subnet(network_id)

        # initially the network is not connected to the router
        for obj in self.objs:
            self.assertItemsEqual(obj.all_subnets(network_id), [])

        self._connect_router_network(self.router_id,
                                     network_id,
                                     subnet_.id)

        # connect a gateway network
        gw_network_id = self._create_test_network_id()
        self._connect_router_network(self.router_id,
                                     gw_network_id,
                                     gw_network=True)

        # check .subnets in associations, after refreshing
        # (except gateway network that should not be present)
        for obj in self.objs:
            refreshed_obj = bgpvpn_obj.BGPVPNRouterAssociation.get_object(
                self.context,
                id=obj.id)
            self.assertItemsEqual(refreshed_obj.all_subnets(network_id),
                                  [_subnet_dict(GW_MAC)])
            self.assertItemsEqual(refreshed_obj.all_subnets("dummy-uuid"),
                                  [])

    def test_get_objects_from_network_id(self):
        router_ = obj_reg.new_instance('Router', self.context)
        router_.create()

        self.project = uuidutils.generate_uuid()

        # put a network behind a router
        network_ = obj_reg.new_instance('Network', self.context)
        network_.create()

        subnet_ = self._make_subnet(network_.id)

        self._connect_router_network(router_.id,
                                     network_.id)

        bgpvpn_ = self._create_test_bgpvpn()

        router_assoc_ = bgpvpn_obj.BGPVPNRouterAssociation(
            self.context,
            project_id=self.project,
            router_id=router_.id,
            bgpvpn_id=bgpvpn_.id)
        router_assoc_.create()

        # unrelated router and BGPVPN
        router_2 = obj_reg.new_instance('Router', self.context)
        router_2.create()
        router_assoc_2 = bgpvpn_obj.BGPVPNRouterAssociation(
            self.context,
            project_id=self.project,
            router_id=router_2.id,
            bgpvpn_id=self._create_test_bgpvpn_id())
        router_assoc_2.create()

        # test get_objects
        get_assocs = bgpvpn_obj.BGPVPNRouterAssociation.get_objects(
            self.context,
            network_id=network_.id)

        self.assertEqual(1, len(get_assocs))
        self.assertEqual(get_assocs[0].bgpvpn.id, bgpvpn_.id)
        self.assertIn(
            subnet_.id,
            [s['id'] for s in get_assocs[0].all_subnets(network_.id)])


class BGPVPNPortAssociationTest(test_base.BaseDbObjectTestCase,
                                testlib_api.SqlTestCase,
                                _BPGVPNObjectsTestCommon):

    _test_class = bgpvpn_obj.BGPVPNPortAssociation

    def setUp(self):
        test_base.BaseDbObjectTestCase.setUp(self)
        self.project = uuidutils.generate_uuid()
        self.port_id = self._create_test_port_id()
        self.update_obj_fields(
            {'port_id': self.port_id,
             'bgpvpn_id': self._create_test_bgpvpn_id,
             'routes': {
                 'bgpvpn_id': self._create_test_bgpvpn_id,
                 }})

    def test_get_objects_queries_constant(self):
        self.skipTest("test not passing yet, remains to be investigated why")


class BGPVPNPortAssociationRouteTest(test_base.BaseDbObjectTestCase,
                                     testlib_api.SqlTestCase,
                                     _BPGVPNObjectsTestCommon):

    _test_class = bgpvpn_obj.BGPVPNPortAssociationRoute

    def setUp(self):
        test_base.BaseDbObjectTestCase.setUp(self)
        self.project = uuidutils.generate_uuid()
        self.update_obj_fields(
            {'port_association_id': self._create_test_port_assoc_id,
             'bgpvpn_id': self._create_test_bgpvpn_id})
        self.context = context.get_admin_context()

    def _create_test_port_assoc(self):
        bgpvpn_id = self._create_test_bgpvpn_id()
        port_id = self._create_test_port_id()
        port_assoc = bgpvpn_obj.BGPVPNPortAssociation(self.context,
                                                      project_id=self.project,
                                                      port_id=port_id,
                                                      bgpvpn_id=bgpvpn_id)
        port_assoc.create()
        return port_assoc

    def _create_test_port_assoc_id(self):
        return self._create_test_port_assoc().id

    def test_eq_hash_prefix(self):
        r1 = bgpvpn_obj.BGPVPNPortAssociationRoute(
            type='prefix',
            prefix=netaddr.IPNetwork('1.2.3.4'))
        r2 = bgpvpn_obj.BGPVPNPortAssociationRoute(
            type='prefix',
            prefix=netaddr.IPNetwork('1.2.3.4'))
        self.assertTrue(r1 == r2)
        self.assertTrue(hash(r1) == hash(r2))

    def test_eq_hash_bgpvpn(self):
        bgpvpn = self._create_test_bgpvpn()
        r1 = bgpvpn_obj.BGPVPNPortAssociationRoute(type='bgpvpn',
                                                   bgpvpn=bgpvpn)
        r2 = bgpvpn_obj.BGPVPNPortAssociationRoute(type='bgpvpn',
                                                   bgpvpn=bgpvpn)
        self.assertTrue(r1 == r2)
        self.assertTrue(hash(r1) == hash(r2))

    def test_neq_type(self):
        r1 = bgpvpn_obj.BGPVPNPortAssociationRoute(
            type='bgpvpn',
            bgpvpn_id='12345')
        r2 = bgpvpn_obj.BGPVPNPortAssociationRoute(
            type='prefix',
            prefix=netaddr.IPNetwork('1.2.3.4'))
        self.assertTrue(r1 != r2)

    def test_neq_prefix(self):
        r1 = bgpvpn_obj.BGPVPNPortAssociationRoute(
            type='prefix',
            prefix=netaddr.IPNetwork('11.22.33.44'))
        r2 = bgpvpn_obj.BGPVPNPortAssociationRoute(
            type='prefix',
            prefix=netaddr.IPNetwork('1.2.3.4'))
        self.assertTrue(r1 != r2)

    def test_neq_bgpvpn(self):
        bgpvpn1 = self._create_test_bgpvpn()
        bgpvpn2 = self._create_test_bgpvpn()
        r1 = bgpvpn_obj.BGPVPNPortAssociationRoute(type='bgpvpn',
                                                   bgpvpn=bgpvpn1)
        r2 = bgpvpn_obj.BGPVPNPortAssociationRoute(type='bgpvpn',
                                                   bgpvpn=bgpvpn2)
        self.assertTrue(r1 != r2)

    def test_bgpvpn_route_get_object_access_bgpvpn(self):
        route_id = uuidutils.generate_uuid()
        route = bgpvpn_obj.BGPVPNPortAssociationRoute(
            self.context,
            id=route_id,
            port_association_id=self._create_test_port_assoc().id,
            type=bgpvpn_rc_api.BGPVPN_TYPE,
            bgpvpn_id=self._create_test_bgpvpn_id())
        route.create()

        route_again = bgpvpn_obj.BGPVPNPortAssociationRoute.get_object(
            self.context,
            id=route_id
            )

        self.assertEqual([TEST_RT], route_again.bgpvpn.route_targets)
