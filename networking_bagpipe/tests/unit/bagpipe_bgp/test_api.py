# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

# Copyright 2014 Orange
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

import six
import testtools

from oslo_config import fixture as config_fixture

from networking_bagpipe.bagpipe_bgp.api import api
from networking_bagpipe.bagpipe_bgp.api import config as api_config
from networking_bagpipe.tests.unit.bagpipe_bgp import base


class TestAPI(base.TestCase):

    def setUp(self):
        super(TestAPI, self).setUp()
        cfg_fixture = self.useFixture(config_fixture.Config())
        cfg_fixture.register_opts(api_config.common_opts, "API")

    @testtools.skipIf(six.PY3, 'dataplane driver init fails under py3')
    def test_api_init(self):
        # instantiate the API, will fail if an exception is raised
        api.PecanAPI()
