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

load_tests = testscenarios.load_tests_apply_scenarios


class TestBaGPipeML2ConnectivitySameNetwork(base.BaGPipeBaseFullStackTestCase):

    bgpvpn = False
    ipvpn_encap = None
    mech_drivers = 'bagpipe'
    service_plugins = 'router'

    l2_agent_type = constants.AGENT_TYPE_LINUXBRIDGE
    of_interface = None

    compute_node_count = 5
    port_per_compute_per_net = 2

    scenarios = [
        ('BaGPipe native VXLAN', {'bagpipe_ml2': True,
                                  'evpn_driver': 'linux'})]

    def test_connectivity(self):
        tenant_uuid = uuidutils.generate_uuid()

        network = self.safe_client.create_network(tenant_uuid)
        self.safe_client.create_subnet(
            tenant_uuid, network['id'], base.SUBNET_CIDR1)

        vms = machine.FakeFullstackMachinesList([
            self.useFixture(
                machine.FakeFullstackMachine(
                    self.environment.hosts[i],
                    network['id'],
                    tenant_uuid,
                    self.safe_client))
            for i in
            range(self.compute_node_count)*self.port_per_compute_per_net])

        vms.block_until_all_boot()
        vms.ping_all()
