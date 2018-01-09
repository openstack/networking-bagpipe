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

import random

import netaddr
from oslo_utils import uuidutils

from networking_bagpipe.objects import bgpvpn as bgpvpn_obj

from neutron.common import utils
from neutron.objects import ports
from neutron.objects import router
from neutron.objects import subnet

from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api

from neutron_lib.api.definitions import bgpvpn as bgpvpn_api
from neutron_lib.api.definitions import bgpvpn_routes_control as bgpvpn_rc_api
from neutron_lib import constants


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


def _subnet_dict(gw_mac=None):
    return {
        'ip_version': 4,
        'gateway_mac': gw_mac,
        'cidr': utils.AuthenticIPNetwork(CIDR),
        'gateway_ip': netaddr.IPAddress(GW_IP)
    }


class _BPGVPNObjectsTestCommon(object):

    def _create_test_bgpvpn(self):
        bgpvpn = bgpvpn_obj.BGPVPN(self.context,
                                   route_targets=['64512:42'],
                                   name='test-bgpvpn-U',
                                   type='l3')
        bgpvpn.create()
        return bgpvpn

    def _create_test_bgpvpn_id(self):
        return self._create_test_bgpvpn().id

    def _make_subnet(self, network_id):
        _subnet = subnet.Subnet(self.context,
                                network_id=network_id,
                                ip_version=4,
                                cidr=netaddr.IPNetwork(CIDR),
                                gateway_ip=GW_IP)
        _subnet.create()
        return _subnet

    def _connect_router_network(self, router_id, network_id,
                                subnet_id=None, gw_network=False):
        port = ports.Port(self.context,
                          network_id=network_id,
                          mac_address=netaddr.EUI(
                              GW_MAC,
                              dialect=netaddr.mac_unix_expanded),
                          device_id='test_device_id',
                          device_owner='router:dummy',
                          status="DUMMY_STATUS",
                          admin_state_up=True)
        if gw_network:
            port.device_owner = constants.DEVICE_OWNER_ROUTER_GW

        port.create()

        if subnet_id:
            allocation = ports.IPAllocation(
                self.context,
                port_id=port.id,
                subnet_id=subnet_id,
                network_id=network_id,
                ip_address=netaddr.IPNetwork(GW_IP))
            allocation.create()

            port.fixed_ips = [allocation]
            port.update()

        router_if = router.RouterPort(self.context,
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
        _router = router.Router(self.context)
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
             'bgpvpn_id': self._create_test_bgpvpn_id})

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
             'bgpvpn_id': self._create_test_bgpvpn_id})

    def test_get_objects_queries_constant(self):
        self.skipTest("test not passing yet, remains to be investigated why")


class BGPVPNPortAssociationRouteTest(test_base.BaseDbObjectTestCase,
                                     testlib_api.SqlTestCase,
                                     _BPGVPNObjectsTestCommon):

    _test_class = bgpvpn_obj.BGPVPNPortAssociationRoute

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

    def setUp(self):
        test_base.BaseDbObjectTestCase.setUp(self)
        self.project = uuidutils.generate_uuid()
        self.update_obj_fields(
            {'port_association_id': self._create_test_port_assoc_id})
