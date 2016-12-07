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


from neutron_lib import constants
from oslo_utils import uuidutils
import testscenarios

from neutron.tests.fullstack.resources import machine

from networking_bagpipe.tests.fullstack import base
from networking_bagpipe.tests.fullstack.resources.bgpvpn \
    import config as bgpvpn_cfg

load_tests = testscenarios.load_tests_apply_scenarios


class TestConnectivitySameBGPVPN(base.BaGPipeBaseFullStackTestCase):

    bagpipe_ml2 = False
    evpn_driver = None
    network_type = 'vxlan'
    mech_drivers = 'openvswitch'
    service_plugins = 'router,%s' % bgpvpn_cfg.BGPVPN_SERVICE

    l2_agent_type = constants.AGENT_TYPE_OVS
    of_interface = 'ovs-ofctl'

    scenarios = [
        ('OpenVSwitch MPLS-over-GRE', {'bgpvpn': True,
                                       'ipvpn_driver': 'ovs',
                                       'ipvpn_encap': 'mpls-gre'})]

    def test_network_connectivity(self):
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
                for i in range(3)])

        vms = machine.FakeFullstackMachinesList(fake_machines)

        vms.block_until_all_boot()
        vms.ping_all()

    def test_router_connectivity(self):
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
                for i in range(3)])

        vms = machine.FakeFullstackMachinesList(fake_machines)

        vms.block_until_all_boot()
        vms.ping_all()
