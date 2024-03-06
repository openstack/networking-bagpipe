# Copyright 2017 Orange
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from networking_bagpipe.bagpipe_bgp.common import config

from oslo_config.tests import test_types


class TestConfigInterfaceAddress(test_types.TypeTestHelper, unittest.TestCase):
    type = config.InterfaceAddress()

    def test_interface_address_ip(self):
        self.assertConvertedValue("127.0.0.1", "127.0.0.1")

    def test_interface_address(self):
        self.assertConvertedValue("lo", "127.0.0.1")

    def test_interface_address_non_existing(self):
        self.assertInvalid("non_existing_interface")
