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

import unittest

from networking_bagpipe.bagpipe_bgp.engine import exa
from networking_bagpipe.bagpipe_bgp.engine import ipvpn


TEST_RD = exa.RouteDistinguisher.fromElements("42.42.42.42", 5)


def _create_test_ipvpn_nlri(label, nexthop):
    return ipvpn.IPVPNRouteFactory(exa.AFI(exa.AFI.ipv4),
                                   "1.1.1.1/32", label, TEST_RD, nexthop)


class TestNLRIs(unittest.TestCase):

    def setUp(self):
        super(TestNLRIs, self).setUp()

    def tearDown(self):
        super(TestNLRIs, self).tearDown()

    # tests on MPLS VPN NLRIs

    def test_0_mpls_vpn_hash_equal(self):
        # Two indistinct VPN NLRI should
        # hash to the same value, and be equal

        nlri1 = _create_test_ipvpn_nlri(42, "45.45.45.45")
        nlri2 = _create_test_ipvpn_nlri(42, "45.45.45.45")

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test_1_mpls_vpn_hash_equal(self):
        # Two VPN NLRI distinct only by their *label* should
        # hash to the same value, and be equal

        nlri1 = _create_test_ipvpn_nlri(42, "45.45.45.45")
        nlri2 = _create_test_ipvpn_nlri(0, "45.45.45.45")

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test_2_mpls_vpn_hash_equal(self):
        # Two VPN NLRI distinct only by their *nexthop* should
        # hash to the same value, and be equal

        nlri1 = _create_test_ipvpn_nlri(42, "45.45.45.45")
        nlri2 = _create_test_ipvpn_nlri(42, "77.77.77.77")

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test_3_mpls_vpn_hash_equal(self):
        # Two VPN NLRI distinct only by their *action* should
        # hash to the same value, and be equal

        nlri1 = _create_test_ipvpn_nlri(42, "45.45.45.45")
        nlri1.action = exa.OUT.ANNOUNCE

        nlri2 = _create_test_ipvpn_nlri(42, "45.45.45.45")
        nlri2.action = exa.OUT.WITHDRAW

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)
