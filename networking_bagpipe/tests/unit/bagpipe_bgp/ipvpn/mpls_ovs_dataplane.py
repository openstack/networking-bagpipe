# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

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

# NOTE(tmorin): unit tests for system interactions aren't that useful, which
# is why you will find very few things here. The code is is expected to be
# covered by tempest and fullstack test jobstores

from networking_bagpipe.bagpipe_bgp.vpn.ipvpn import mpls_ovs_dataplane
from networking_bagpipe.tests.unit.bagpipe_bgp import base as t


class TestMPLSOVSDataplaneDriver(t.TestCase):

    def _test_priority_for_prefix(self, prefix_list):
        # assuming that prefix_list is a list of prefixes of increasing length
        # check that each prefixes has a priority higher than the previous one
        previous_prio = 0
        previous_prefix = ""
        for prefix in prefix_list:
            prio = mpls_ovs_dataplane._priority_from_prefix(prefix)
            self.assertTrue(prio > previous_prio,
                            ("%s should have a priority higher than %s, "
                             "but 0x%x !> 0x%x") % (prefix, previous_prefix,
                                                    prio, previous_prio))
            previous_prio = prio
            previous_prefix = prefix

    def test_priority_for_prefix_v4(self):
        self._test_priority_for_prefix(
            ["0.0.0.0/0", "1.1.0.0/16", "2.2.2.0/24", "3.3.3.3/32"])

    def test_priority_for_prefix_v6(self):
        self._test_priority_for_prefix(
            ["::0/0", "2001:db8:8:4::2/64", "::1/128"])

    def test_fallback_priority(self):
        self.assertTrue(mpls_ovs_dataplane.FALLBACK_PRIORITY <
                        mpls_ovs_dataplane._priority_from_prefix("0.0.0.0/0"))
