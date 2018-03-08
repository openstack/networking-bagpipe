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

import mock

from networking_bagpipe.bagpipe_bgp.common import dataplane_utils
from networking_bagpipe.bagpipe_bgp.vpn.ipvpn import mpls_ovs_dataplane
from networking_bagpipe.tests.unit.bagpipe_bgp import base as t

INSTANCE_ID = 77

LOCAL_IP = "1.1.1.1"
REMOTE_PE1 = "2.2.2.2"
REMOTE_PE2 = "3.3.3.3"

NH1 = mpls_ovs_dataplane.NextHop(1, LOCAL_IP, None, 0)
NH2 = mpls_ovs_dataplane.NextHop(2, LOCAL_IP, None, 1)

REMOTE_PREFIX1 = "11.0.0.2"


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


class TestNextHopGroupManager(t.TestCase):

    def setUp(self):
        super(TestNextHopGroupManager, self).setUp()

        self.bridge = mock.Mock(spec=dataplane_utils.OVSBridgeWithGroups)
        self.manager = mpls_ovs_dataplane.NextHopGroupManager(self.bridge,
                                                              None,
                                                              None,
                                                              None)

    def test_get_nexthop_group(self):
        nh_g1 = self.manager.get_object("2.2.2.2", NH1)

        self.bridge.add_group.assert_called_once_with(
            group_id=nh_g1,
            type='select',
            selection_method=None,
            selection_method_param=None,
            fields=None)

        self.bridge.add_group.reset_mock()

        nh_g2 = self.manager.get_object("2.2.2.2", NH2)
        self.bridge.add_group.assert_not_called()

        self.assertTrue(nh_g1 == nh_g2)

        self.bridge.add_group.reset_mock()

        nh_g3 = self.manager.get_object("3.3.3.3", NH1)
        self.bridge.add_group.assert_called_once()

        self.assertFalse(nh_g3 == nh_g1)

        self.assertTrue(len(self.manager.infos()))

    def test_free_object(self):
        nh_g1 = self.manager.get_object("2.2.2.2", NH1)
        self.manager.get_object("2.2.2.2", NH2)
        nh_g2 = self.manager.get_object("3.3.3.3", NH1)

        self.bridge.add_group.reset_mock()

        self.manager.free_object("2.2.2.2", NH1)
        self.bridge.delete_group.assert_not_called()
        nh_g1bis = self.manager.get_object("2.2.2.2")
        self.assertTrue(nh_g1bis == nh_g1)

        self.manager.free_object("2.2.2.2", NH2)
        self.bridge.delete_group.assert_called_once_with(nh_g1)

        self.bridge.delete_group.reset_mock()

        self.manager.free_object("3.3.3.3", NH1)
        self.bridge.delete_group.assert_called_once_with(nh_g2)


class FakeBridgeMockSpec(dataplane_utils.OVSBridgeWithGroups,
                         dataplane_utils.OVSExtendedBridge):
    pass


class FakeNLRI(object):

    def __init__(self, ip):
        self.ip = ip


class TestMPLSOVSVRFSDataplane(t.TestCase):

    def setUp(self):
        super(TestMPLSOVSVRFSDataplane, self).setUp()

        self.bridge = mock.Mock(spec=FakeBridgeMockSpec)

        self.nh_group_mgr = mock.Mock(
            spec=mpls_ovs_dataplane.NextHopGroupManager
        )
        self.nh_group_mgr.bridge = self.bridge
        self.nh_group_mgr.get_object.side_effect = [None, 0, 0]

        self.dp_driver = mock.Mock(
            spec=mpls_ovs_dataplane.MPLSOVSDataplaneDriver
        )
        self.dp_driver.bridge = self.bridge
        self.dp_driver.nh_group_mgr = self.nh_group_mgr
        self.dp_driver.vxlan_encap = False
        self.dp_driver.vrf_table = 3
        self.dp_driver.config = mock.Mock()
        self.dp_driver.config.arp_responder = False
        self.dp_driver.get_local_address.return_value = LOCAL_IP
        self.dp_driver.mpls_in_port.return_value = 1

        self.label = 99

        self.dataplane = mpls_ovs_dataplane.MPLSOVSVRFDataplane(
            self.dp_driver, INSTANCE_ID, "foo_external_instance_id",
            "10.0.0.1", "24", instance_label=self.label)
        self.dataplane._mtu_fixup = mock.Mock()
        self.dataplane._match_label_action = mock.Mock(return_value="")
        self.dataplane._match_output_action = mock.Mock(return_value="")

    def test_setup_dataplane_for_remote_endpoint(self):
        self.dataplane.setup_dataplane_for_remote_endpoint(
            REMOTE_PREFIX1, REMOTE_PE1, 42, FakeNLRI(REMOTE_PREFIX1), None)

        expected_nh = mpls_ovs_dataplane.NextHop(42, REMOTE_PE1, None, 0)
        self.nh_group_mgr.get_object.assert_called_with(
            REMOTE_PREFIX1, (INSTANCE_ID, mock.ANY), buckets=mock.ANY)
        nh1 = self.nh_group_mgr.get_object.call_args_list[1][0][1][1]
        self.assertEqual(expected_nh, nh1)

        self.bridge.add_flow.assert_called_once_with(
            table=3,
            cookie=mock.ANY,
            priority=mock.ANY,
            nw_dst=REMOTE_PREFIX1,
            actions="group:0")

        self.nh_group_mgr.get_object.reset_mock()
        self.bridge.add_flow.reset_mock()

        self.dataplane.setup_dataplane_for_remote_endpoint(
            REMOTE_PREFIX1, REMOTE_PE2, 43, FakeNLRI(REMOTE_PREFIX1), None, 1)

        self.nh_group_mgr.get_object.assert_called_with(
            REMOTE_PREFIX1)

        self.bridge.add_flow.assert_not_called()
        self.bridge.insert_bucket.assert_called_once_with(
            group_id=0,
            bucket_id=1,
            command_bucket_id="last",
            actions=mock.ANY)
