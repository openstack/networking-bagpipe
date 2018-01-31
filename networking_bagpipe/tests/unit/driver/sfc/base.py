# Copyright 2015 Futurewei. All rights reserved.
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

import contextlib

from oslo_config import cfg
from oslo_utils import uuidutils

from neutron_lib.api.definitions import provider_net as provider

from neutron.tests.unit.db import test_db_base_plugin_v2 as test_db_plugin

SRC_CIDR = '10.10.0.0/24'
SRC_GATEWAY = '10.10.0.1'

DEST_CIDR = '10.100.0.0/24'
DEST_GATEWAY = '10.100.0.1'


class NeutronDbPluginV2TestCase(test_db_plugin.NeutronDbPluginV2TestCase):
    def setUp(self, plugin=None, service_plugins=None, ext_mgr=None):

        if not plugin:
            plugin = 'neutron.plugins.ml2.plugin.Ml2Plugin'

        cfg.CONF.set_override('tenant_network_types', ['vxlan'], group='ml2')
        cfg.CONF.set_override(
            'vni_ranges', ['1:1000'], group='ml2_type_vxlan')
        cfg.CONF.set_override(
            'mechanism_drivers', ['linuxbridge'], group='ml2')

        super(NeutronDbPluginV2TestCase, self).setUp(
            ext_mgr=ext_mgr,
            plugin=plugin,
            service_plugins=service_plugins
        )

        self._tenant_id = uuidutils.generate_uuid()
        self._network = self._make_network(
            self.fmt, 'test_net',
            True)
        self._subnet = self._make_subnet(
            self.fmt, self._network, gateway='10.0.0.1',
            cidr='10.0.0.0/24', ip_version=4
        )

        self._src_net = self._make_network(
            self.fmt, 'src_net',
            True)
        self._src_subnet = self._make_subnet(
            self.fmt, self._src_net, gateway=SRC_GATEWAY,
            cidr=SRC_CIDR, ip_version=4
        )
        self._src_rt = (
            ':'.join(['64512',
                      str(self._src_net['network'][provider.SEGMENTATION_ID])
                      ])
        )

        self._dest_net = self._make_network(
            self.fmt, 'dest_net',
            True)
        self._dest_subnet = self._make_subnet(
            self.fmt, self._dest_net, gateway=DEST_GATEWAY,
            cidr=DEST_CIDR, ip_version=4
        )
        self._dest_rt = (
            ':'.join(['64512',
                      str(self._dest_net['network'][provider.SEGMENTATION_ID])
                      ])
        )

    def tearDown(self):
        super(NeutronDbPluginV2TestCase, self).tearDown()

    @contextlib.contextmanager
    def port(self, fmt=None, **kwargs):
        net_id = kwargs.get('network_id', self._network['network']['id'])
        port = self._make_port(fmt or self.fmt, net_id, **kwargs)
        yield port
