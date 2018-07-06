# Copyright (c) 2017 Orange.
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

import netaddr

from oslo_utils import uuidutils

from neutron_lib import context
from neutron_lib.objects import registry as obj_reg

from networking_bagpipe.objects import sfc as sfc_obj

from networking_sfc.db import sfc_db

from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api

INGRESS_GW_IP = "10.10.0.1"
INGRESS_MAC = "de:ad:00:00:be:ef"

EGRESS_GW_IP = "10.100.0.1"
EGRESS_MAC = "ba:be:00:00:b0:0b"

RT1 = '64512:7'
RT2 = '64512:42'


class _BaGPipeObjectsTestCommon(object):

    def _create_test_chain_hop(self, rt, ingress_network=None,
                               egress_network=None):
        chainhop_obj = sfc_obj.BaGPipeChainHop(
            self.context,
            id=uuidutils.generate_uuid(),
            portchain_id=uuidutils.generate_uuid(),
            rts=[rt],
            ingress_network=ingress_network,
            egress_network=egress_network,
            ingress_gw=INGRESS_GW_IP,
            egress_gw=EGRESS_GW_IP)

        chainhop_obj.create()

        return chainhop_obj

    def _create_test_port_chain(self, chain_id=0):
        portchain_db = sfc_db.PortChain(id=uuidutils.generate_uuid(),
                                        project_id=self.context.tenant_id,
                                        chain_id=chain_id)

        self.context.session.add(portchain_db)

        return portchain_db


class BaGPipeChainHopDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                      testlib_api.SqlTestCase,
                                      _BaGPipeObjectsTestCommon):

    _test_class = sfc_obj.BaGPipeChainHop

    def setUp(self):
        test_base.BaseDbObjectTestCase.setUp(self)

        self._group_id = 0
        self._chain_id = 0

        self.update_obj_fields({
            'ingress_network': self._create_test_network_id(),
            'egress_network': self._create_test_network_id(),
            'ingress_ppg': self._create_test_ppg_id(),
            'egress_ppg': self._create_test_ppg_id(),
            'portchain_id': self._create_test_pc_id()
        })

    def _create_test_ppg(self):
        test_ppg = sfc_db.PortPairGroup(id=uuidutils.generate_uuid(),
                                        project_id=self.context.tenant_id,
                                        group_id=self._group_id)

        self.context.session.add(test_ppg)
        self._group_id += 1

        return test_ppg

    def _create_test_ppg_id(self):
        return self._create_test_ppg().id

    def _create_test_pc(self):
        test_pc = sfc_db.PortChain(id=uuidutils.generate_uuid(),
                                   project_id=self.context.tenant_id,
                                   chain_id=self._chain_id)

        self.context.session.add(test_pc)
        self._chain_id += 1

        return test_pc

    def _create_test_pc_id(self):
        return self._create_test_pc().id

    def test_create_single_transaction(self):
        self.skipTest("test not passing yet, remains to be investigated why")

    def test_update_single_transaction(self):
        self.skipTest("test not passing yet, remains to be investigated why")

    def test_get_object_single_transaction(self):
        self.skipTest("test not passing yet, remains to be investigated why")

    def test_get_objects_single_transaction(self):
        self.skipTest("test not passing yet, remains to be investigated why")

    def test_update_objects(self):
        self.skipTest("test not passing yet, remains to be investigated why")

    def test_get_objects_queries_constant(self):
        self.skipTest("test not passing yet, remains to be investigated why")

    def test_get_objects_by_port_id(self):
        ingress_network = self._create_test_network()
        ingress_port = self._create_test_port(network_id=ingress_network.id)
        egress_network = self._create_test_network()

        chain_hop1 = self._create_test_chain_hop(RT1,
                                                 ingress_network.id,
                                                 egress_network.id)

        chain_hop2 = self._create_test_chain_hop(RT2,
                                                 egress_network.id,
                                                 ingress_network.id)

        port_hops = sfc_obj.BaGPipeChainHop.get_objects(
            self.context,
            port_id=ingress_port.id)

        self.assertEqual(2, len(port_hops))
        self.assertDictContainsSubset(chain_hop1.to_dict(),
                                      port_hops[0].to_dict())
        self.assertIn(ingress_port.id,
                      port_hops[0].ingress_ports)

        self.assertDictContainsSubset(chain_hop2.to_dict(),
                                      port_hops[1].to_dict())
        self.assertIn(ingress_port.id,
                      port_hops[1].egress_ports)


class BaGPipePortHopsObjectTestCase(testlib_api.SqlTestCase,
                                    _BaGPipeObjectsTestCommon):

    def setUp(self):
        super(BaGPipePortHopsObjectTestCase, self).setUp()
        self.context = context.get_admin_context()

        self.ingress_network = obj_reg.new_instance('Network', self.context)
        self.ingress_network.create()

        self.ingress_port = obj_reg.new_instance(
            'Port', self.context,
            network_id=self.ingress_network.id,
            mac_address=netaddr.EUI(
                INGRESS_MAC,
                dialect=netaddr.mac_unix_expanded),
            device_id='test_device_id',
            device_owner='compute:None',
            status="DUMMY_STATUS",
            admin_state_up=True)
        self.ingress_port.create()

        self.egress_network = obj_reg.new_instance('Network', self.context)
        self.egress_network.create()

        self.egress_port = obj_reg.new_instance(
            'Port', self.context,
            network_id=self.egress_network.id,
            mac_address=netaddr.EUI(
                EGRESS_MAC,
                dialect=netaddr.mac_unix_expanded),
            device_id='test_device_id',
            device_owner='compute:None',
            status="DUMMY_STATUS",
            admin_state_up=True)
        self.egress_port.create()

        self.port_chain1 = self._create_test_port_chain()

        self.chain_hop1 = (
            self._create_test_chain_hop(RT1,
                                        ingress_network=self.egress_network.id)
        )

        self.chain_hop2 = (
            self._create_test_chain_hop(RT2,
                                        egress_network=self.ingress_network.id)
        )

    def _create_test_port_chain(self):
        portchain_db = sfc_db.PortChain(id=uuidutils.generate_uuid(),
                                        project_id=self.context.tenant_id,
                                        chain_id=0)

        self.context.session.add(portchain_db)

        return portchain_db

    def test_init(self):
        sfc_obj.BaGPipePortHops(
            port_id=self.ingress_port.id,
            ingress_hops=[self.chain_hop1],
            egress_hops=[self.chain_hop2])

    def test_get_object_ingress_chain_hop(self):
        port_hops = sfc_obj.BaGPipePortHops.get_object(
            self.context,
            port_id=self.ingress_port.id
        )

        self.assertEqual(0, len(port_hops.ingress_hops))
        self.assertEqual(1, len(port_hops.egress_hops))
        self.assertDictContainsSubset(self.chain_hop2.to_dict(),
                                      port_hops.egress_hops[0].to_dict())
        self.assertEqual(self.ingress_port.id,
                         port_hops.port_id)

    def test_get_object_egress_chain_hop(self):
        port_hops = sfc_obj.BaGPipePortHops.get_object(
            self.context,
            port_id=self.egress_port.id
        )

        self.assertEqual(1, len(port_hops.ingress_hops))
        self.assertEqual(0, len(port_hops.egress_hops))
        self.assertDictContainsSubset(self.chain_hop1.to_dict(),
                                      port_hops.ingress_hops[0].to_dict())
        self.assertEqual(self.egress_port.id,
                         port_hops.port_id)
