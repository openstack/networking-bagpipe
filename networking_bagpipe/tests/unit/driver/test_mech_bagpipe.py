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

from oslo_config import cfg

from neutron.tests.unit.plugins.ml2 import test_plugin

from neutron_lib import constants as n_consts


class TestBaGpipeML2MechDriver(test_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = ['bagpipe']

    def setUp(self):
        cfg.CONF.set_override('type_drivers',
                              n_consts.TYPE_VXLAN,
                              'ml2')
        cfg.CONF.set_override('tenant_network_types',
                              n_consts.TYPE_VXLAN,
                              'ml2')

        super(TestBaGpipeML2MechDriver, self).setUp()

    def test_setup(self):
        pass
