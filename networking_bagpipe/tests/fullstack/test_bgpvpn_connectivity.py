# Copyright (c) 2016 Orange.
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

import itertools

from neutron_lib import constants
from oslo_utils import uuidutils
import testscenarios
import unittest

from neutron.tests.fullstack.resources import machine

from networking_bagpipe.tests.fullstack import base
from networking_bagpipe.tests.fullstack.resources.bgpvpn \
    import config as bgpvpn_cfg

load_tests = testscenarios.load_tests_apply_scenarios


class TestConnectivitySameBGPVPN(base.BaGPipeBaseFullStackTestCase):

    bagpipe_ml2 = False
    service_plugins = 'router,%s' % bgpvpn_cfg.BGPVPN_SERVICE

    of_interface = 'ovs-ofctl'
    bgpvpn = True

    port_per_compute_per_net = 2
    compute_node_count = 2

    scenarios = [
        ('OpenVSwitch MPLS-over-TEB-over-GRE', {
            'mech_drivers': 'openvswitch',
            'l2_agent_type': constants.AGENT_TYPE_OVS,
            'ipvpn_driver': 'ovs',
            'ipvpn_encap': 'mpls-gre'
        }),
        ('OpenVSwitch MPLS-over-GRE', {
            'mech_drivers': 'openvswitch',
            'l2_agent_type': constants.AGENT_TYPE_OVS,
            'ipvpn_driver': 'ovs',
            'ipvpn_encap': 'mpls-gre-l3'
        }),
        ('OpenVSwitch bare MPLS', {
            'mech_drivers': 'openvswitch',
            'l2_agent_type': constants.AGENT_TYPE_OVS,
            'ipvpn_driver': 'ovs',
            'ipvpn_encap': 'bare-mpls'
        }),
        ('Linuxbridge', {
            'mech_drivers': 'linuxbridge',
            'l2_agent_type': constants.AGENT_TYPE_LINUXBRIDGE,
            'ipvpn_driver': 'linux',
            'evpn_driver': 'linux',
            'ipvpn_encap': 'bare-mpls',
        })
    ]

    def test_l3_network_connectivity(self):
        tenant_uuid = uuidutils.generate_uuid()

        bgpvpn = self.safe_client.create_bgpvpn(tenant_uuid,
                                                route_targets=['64512:1'])

        network_ids = list()
        for subnet_cidr in (base.SUBNET_CIDR1, base.SUBNET_CIDR2):
            network_ids.append(
                self._create_net_subnet_bgpvpn_assoc(tenant_uuid, subnet_cidr,
                                                     bgpvpn['id'])[0]
            )

        fake_machines = list()
        for network_id in network_ids:
            fake_machines.extend([
                self.useFixture(
                    machine.FakeFullstackMachine(
                        self.environment.hosts[i],
                        network_id,
                        tenant_uuid,
                        self.safe_client))
                for i in
                range(self.compute_node_count)*self.port_per_compute_per_net])

        vms = machine.FakeFullstackMachinesList(fake_machines)

        vms.block_until_all_boot()
        vms.ping_all()

    def test_l3_router_connectivity(self):
        tenant_uuid = uuidutils.generate_uuid()

        bgpvpn = self.safe_client.create_bgpvpn(tenant_uuid,
                                                route_targets=['64512:1'])

        network1 = self.safe_client.create_network(tenant_uuid)
        subnet1 = self.safe_client.create_subnet(
            tenant_uuid, network1['id'], '10.0.0.0/24')

        network2 = self.safe_client.create_network(tenant_uuid)
        subnet2 = self.safe_client.create_subnet(
            tenant_uuid, network2['id'], '20.0.0.0/24')

        router = self.safe_client.create_router(tenant_uuid)
        self.safe_client.add_router_interface(router['id'], subnet1['id'])
        self.safe_client.add_router_interface(router['id'], subnet2['id'])

        self.safe_client.create_router_association(tenant_uuid,
                                                   bgpvpn['id'],
                                                   router['id'])

        network3 = self.safe_client.create_network(tenant_uuid)
        self.safe_client.create_subnet(
            tenant_uuid, network3['id'], '30.0.0.0/24')
        self.safe_client.create_network_association(tenant_uuid,
                                                    bgpvpn['id'],
                                                    network3['id'])

        fake_machines = list()
        for network in (network1, network2, network3):
            fake_machines.extend([
                self.useFixture(
                    machine.FakeFullstackMachine(
                        self.environment.hosts[i],
                        network['id'],
                        tenant_uuid,
                        self.safe_client))
                for i in
                range(self.compute_node_count)*self.port_per_compute_per_net])

        vms = machine.FakeFullstackMachinesList(fake_machines)

        vms.block_until_all_boot()
        vms.ping_all()

    @unittest.skip("Disabled because of bug 1715660 ( https://"
                   "bugs.launchpad.net/networking-bagpipe/+bug/1715660 )")
    def test_l2_network_connectivity(self):
        # create <n> fake machines in 2 different networks, all using
        # the same IP subnet, and check that each machine can reach all the
        # others. We create machines so that we confirm that connectivity
        # still works *inside* a given network, both locally on a compute
        # node, and across different compute nodes

        if self.evpn_driver is 'dummy':
            self.skipTest("L2VPN unsupported for this scenario")

        tenant_uuid = uuidutils.generate_uuid()

        bgpvpn = self.safe_client.create_bgpvpn(tenant_uuid,
                                                type="l2",
                                                route_targets=['64512:10'])

        fake_machines = list()
        for network in range(2):

            # we'll use the same subnet range for all networks, but
            # choose in this range distinct IP addresses for each fake machine

            network_id, subnet_id = self._create_net_subnet_bgpvpn_assoc(
                tenant_uuid,
                base.SUBNET_CIDR1,
                bgpvpn['id']
            )

            for compute, port_i in itertools.product(
                    range(self.compute_node_count),
                    range(self.port_per_compute_per_net)):

                # NOTE(tmorin): choice of fixed IP done this way for sake
                # of simplicity, of course, this breaks e.g. for
                # compute_node_count > 10
                fixed_ip = (base.SUBNET_CIDR1[:base.SUBNET_CIDR1.find('0/24')]
                            + str(100 * network + 10 * (compute+1) + port_i))

                neutron_port = self.safe_client.create_port(
                    network_id=network_id,
                    tenant_id=tenant_uuid,
                    hostname=self.environment.hosts[compute].hostname,
                    fixed_ips=[{"subnet_id": subnet_id,
                                "ip_address": fixed_ip}]
                )

                fake_machines.append(
                    self.useFixture(
                        machine.FakeFullstackMachine(
                            self.environment.hosts[compute],
                            network_id,
                            tenant_uuid,
                            self.safe_client,
                            neutron_port=neutron_port
                        )
                    )
                )

        vms = machine.FakeFullstackMachinesList(fake_machines)

        vms.block_until_all_boot()
        vms.ping_all()
