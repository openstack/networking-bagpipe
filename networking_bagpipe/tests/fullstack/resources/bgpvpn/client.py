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

from neutron.common import utils
from neutron.tests.fullstack.resources import client as neutron_client


class BGPVPNClientFixture(neutron_client.ClientFixture):
    """Manage and cleanup BGPVPN resources."""

    def create_bgpvpn(self, tenant_id, name=None, **kwargs):
        resource_type = 'bgpvpn'

        name = name or utils.get_rand_name(prefix='bgpvpn')
        spec = {
            'tenant_id': tenant_id,
            'name': name
        }
        spec.update(kwargs)

        return self._create_resource(resource_type, spec)

    def create_network_association(self, tenant_id, bgpvpn_id, network_id):
        network_association = {
            'network_association': {
                'tenant_id': tenant_id,
                'network_id': network_id
            }
        }
        assoc = self.client.create_bgpvpn_network_assoc(
            bgpvpn_id,
            network_association)
        self.addCleanup(
            neutron_client._safe_method(
                self.client.delete_bgpvpn_network_assoc),
            bgpvpn_id, assoc['network_association']['id'])

    def create_router_association(self, tenant_id, bgpvpn_id, router_id):
        router_association = {
            'router_association': {
                'tenant_id': tenant_id,
                'router_id': router_id
            }
        }
        assoc = self.client.create_bgpvpn_router_assoc(
            bgpvpn_id,
            router_association)
        self.addCleanup(
            neutron_client._safe_method(
                self.client.delete_bgpvpn_router_assoc),
            bgpvpn_id, assoc['router_association']['id'])
