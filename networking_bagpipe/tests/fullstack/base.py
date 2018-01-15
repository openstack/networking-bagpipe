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

from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment as neutron_env

from networking_bagpipe.tests.fullstack.resources.bgpvpn \
    import client as bgpvpn_client
from networking_bagpipe.tests.fullstack.resources.common \
    import environment as common_env

SUBNET_CIDR1 = '10.0.0.0/24'
SUBNET_CIDR2 = '20.0.0.0/24'
SUBNET_CIDR3 = '30.0.0.0/24'


class BaGPipeBaseFullStackTestCase(base.BaseFullStackTestCase):

    evpn_driver = 'dummy'
    ipvpn_driver = 'dummy'

    compute_node_count = 3
    port_per_compute_per_net = 2

    def setUp(self):
        host_descriptions = [
            neutron_env.HostDescription(of_interface=self.of_interface,
                                        l2_agent_type=self.l2_agent_type)
            for _ in range(self.compute_node_count)
        ]
        env = common_env.BaGPipeEnvironment(
            common_env.BaGPipeEnvironmentDescription(
                bagpipe_ml2=self.bagpipe_ml2,
                evpn_driver=self.evpn_driver,
                bgpvpn=self.bgpvpn,
                ipvpn_driver=self.ipvpn_driver,
                ipvpn_encap=self.ipvpn_encap,
                mech_drivers=self.mech_drivers,
                service_plugins=self.service_plugins
            ),
            host_descriptions)
        super(BaGPipeBaseFullStackTestCase, self).setUp(env)

        if self.bgpvpn:
            self.safe_client = self.useFixture(
                bgpvpn_client.BGPVPNClientFixture(self.client))

    def _create_net_subnet_bgpvpn_assoc(self, tenant_uuid, subnet_cidr,
                                        bgpvpn_id=None):
        network = self.safe_client.create_network(tenant_uuid)
        subnet = self.safe_client.create_subnet(
            tenant_uuid, network['id'], subnet_cidr)

        if bgpvpn_id:
            self.safe_client.create_network_association(tenant_uuid,
                                                        bgpvpn_id,
                                                        network['id'])

        return (network['id'], subnet['id'])

    def _create_router_bgpvpn_assoc(self, tenant_uuid, subnet_ids,
                                    bgpvpn_id=None):
        router = self.safe_client.create_router()

        for subnet_id in subnet_ids:
            self.safe_client.add_router_interface(router['id'], subnet_id)

        self.safe_client.create_router_association(tenant_uuid,
                                                   bgpvpn_id,
                                                   router['id'])
