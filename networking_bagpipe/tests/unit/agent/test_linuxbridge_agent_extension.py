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

import mock

from neutron import context
from neutron.plugins.ml2.drivers.linuxbridge.agent.common import constants as\
    a_const
from neutron.tests import base

from networking_bagpipe.agent import bagpipe_linuxbridge_neutron_agent as\
    linuxbridge_agent


class LinuxbridgeAgentExtensionTest(base.BaseTestCase):

    def setUp(self):
        super(LinuxbridgeAgentExtensionTest, self).setUp()
        self.agent_ext = linuxbridge_agent.BagpipeAgentExtension()
        self.context = context.get_admin_context()
        self.connection = mock.Mock()

    def test_initialize_linuxbridge(self):
        self.agent_ext.initialize(self.connection,
                                  a_const.EXTENSION_DRIVER_TYPE)
