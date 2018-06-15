# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

# Copyright 2018 Orange
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

import mock

from networking_bagpipe.bagpipe_bgp.common import dataplane_utils
from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers as dp_drivers
from networking_bagpipe.bagpipe_bgp.vpn.evpn import ovs
from networking_bagpipe.tests.unit.bagpipe_bgp import base as t

from neutron.agent.common import ovs_lib
from neutron.plugins.ml2.drivers.openvswitch.agent.common import \
    constants as ovs_const
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import \
    br_tun

LOCAL_IP = "1.2.3.4"
MAC1 = "01:00:de:ad:be:ef"
MAC2 = "01:00:fe:ed:f0:0d"


class TestTunnelManager(t.TestCase):

    def setUp(self):
        super(TestTunnelManager, self).setUp()

        self.bridge = mock.Mock(spec=br_tun.OVSTunnelBridge)
        self.manager = ovs.TunnelManager(self.bridge, LOCAL_IP)

    def test_get_tunnel(self):
        t1, _ = self.manager.get_object("2.2.2.2", "A")
        self.bridge.add_tunnel_port.assert_called_once_with(mock.ANY,
                                                            "2.2.2.2",
                                                            LOCAL_IP,
                                                            mock.ANY)
        self.bridge.setup_tunnel_port.assert_called_once_with(mock.ANY, t1)

        self.bridge.add_tunnel_port.reset_mock()
        self.bridge.setup_tunnel_port.reset_mock()

        t2, _ = self.manager.get_object("2.2.2.2", "B")
        self.bridge.add_tunnel_port.assert_not_called()
        self.bridge.setup_tunnel_port.assert_not_called()

        self.assertTrue(t1 == t2)

        self.bridge.add_tunnel_port.reset_mock()
        self.bridge.setup_tunnel_port.reset_mock()

        t3, _ = self.manager.get_object("3.3.3.3", "A")
        self.bridge.add_tunnel_port.assert_called_once()
        self.bridge.setup_tunnel_port.assert_called_once()

        self.assertFalse(t3 != t1)

        self.assertTrue(len(self.manager.infos()))

    def test_free_object(self):
        t1, _ = self.manager.get_object("2.2.2.2", "A")
        self.manager.get_object("2.2.2.2", "B")
        t2, _ = self.manager.get_object("3.3.3.3", "A")

        self.bridge.add_tunnel_port.reset_mock()
        self.bridge.delete_port.reset_mock()
        self.bridge.setup_tunnel_port.reset_mock()

        self.manager.free_object("2.2.2.2", "A")
        self.bridge.delete_port.assert_not_called()
        t1bis = self.manager.find_object("2.2.2.2")
        self.assertTrue(t1bis == t1)

        self.bridge.add_tunnel_port.reset_mock()
        self.bridge.delete_port.reset_mock()
        self.bridge.setup_tunnel_port.reset_mock()

        self.manager.free_object("2.2.2.2", "B")
        self.bridge.delete_port.assert_called_once_with(t1)

        self.bridge.add_tunnel_port.reset_mock()
        self.bridge.delete_port.reset_mock()
        self.bridge.setup_tunnel_port.reset_mock()

        self.manager.free_object("3.3.3.3", "A")
        self.bridge.delete_port.assert_called_once_with(t2)


class FakeBridgeMockSpec(dataplane_utils.OVSBridgeWithGroups,
                         br_tun.OVSTunnelBridge,
                         ovs_lib.OVSBridge):
    pass


class FakeNLRI(object):

    def __init__(self, ip):
        self.ip = ip


class TestOVSEVIDataplane(t.TestCase):

    def setUp(self):
        super(TestOVSEVIDataplane, self).setUp()

        self.bridge = mock.Mock(spec=FakeBridgeMockSpec)
        self.tunnel_mgr = mock.Mock(spec=ovs.TunnelManager)
        self.tunnel_mgr.get_object.return_value = ("TUNNEL1", None)
        self.tunnel_mgr.find_object.return_value = "TUNNEL1"

        self.dp_driver = mock.Mock(spec=dp_drivers.DataplaneDriver)
        self.dp_driver.bridge = self.bridge
        self.dp_driver.tunnel_mgr = self.tunnel_mgr
        self.dp_driver.config = {}
        self.dp_driver.get_local_address.return_value = LOCAL_IP

        self.dataplane = ovs.OVSEVIDataplane(
            self.dp_driver, 77, "foo_external_instance_id",
            None, None, instance_label=99)
        self.vlan = 99

        self.dataplane.vif_plugged("MAC1", "10.0.0.1",
                                   {'vlan': self.vlan},
                                   None, None)
        self.bridge.add_flow.assert_called_once_with(
            table=ovs_const.VXLAN_TUN_TO_LV,
            priority=mock.ANY,
            tun_id=99,
            actions=mock.ANY)

    def test_setup_dataplane_for_remote_endpoint__local(self):
        self.dataplane.setup_dataplane_for_remote_endpoint(
            MAC1, LOCAL_IP, 42, FakeNLRI("11.0.0.1"), None)

        self.tunnel_mgr.get_object.assert_not_called()

    def test_setup_dataplane_for_remote_endpoint(self):
        self.dataplane.setup_dataplane_for_remote_endpoint(
            MAC1, "2.2.2.2", 42, FakeNLRI("11.0.0.1"), None)

        self.tunnel_mgr.get_object.assert_called_once_with(
            "2.2.2.2", (77, (42, MAC1)))

        self.bridge.add_flow.assert_called_with(
            table=ovs_const.UCAST_TO_TUN,
            priority=mock.ANY,
            dl_vlan=self.vlan,
            dl_dst=MAC1,
            actions=mock.ANY)

    def test_remove_dataplane_for_remote_endpoint__local(self):
        self.dataplane.remove_dataplane_for_remote_endpoint(
            MAC1, LOCAL_IP, 42, FakeNLRI("11.0.0.1"))

        self.bridge.delete_unicast_to_tun.assert_called_with(self.vlan, MAC1)

        self.tunnel_mgr.free_object.assert_not_called()

    def test_remove_dataplane_for_remote_endpoint(self):
        self.dataplane.remove_dataplane_for_remote_endpoint(
            MAC1, "2.2.2.2", 42, FakeNLRI("11.0.0.1"))

        self.bridge.delete_unicast_to_tun.assert_called_with(self.vlan, MAC1)

        self.tunnel_mgr.free_object.assert_called_with(
            "2.2.2.2", (77, (42, MAC1)))

    def test_add_dataplane_for_bum_endpoint__local(self):
        self.dataplane.add_dataplane_for_bum_endpoint(LOCAL_IP, 45,
                                                      None, None)

        self.tunnel_mgr.get_object.assert_not_called()

    def test_add_dataplane_for_bum_endpoint(self):
        self.dataplane.add_dataplane_for_bum_endpoint("2.2.2.2", 45,
                                                      None, None)

        self.tunnel_mgr.get_object.assert_called_with(
            "2.2.2.2", (77, (45, "flood")))

    def test_remove_dataplane_for_bum_endpoint__local(self):
        self.dataplane.add_dataplane_for_bum_endpoint(LOCAL_IP, 45,
                                                      None, None)
        self.tunnel_mgr.free_object.reset_mock()

        self.dataplane.remove_dataplane_for_bum_endpoint(LOCAL_IP, 45, None)

        self.tunnel_mgr.free_object.assert_not_called()

    def test_remove_dataplane_for_bum_endpoint(self):
        self.dataplane.add_dataplane_for_bum_endpoint("2.2.2.2", 45,
                                                      None, None)
        self.tunnel_mgr.free_object.reset_mock()

        self.dataplane.remove_dataplane_for_bum_endpoint("2.2.2.2", 45, None)

        self.tunnel_mgr.free_object.assert_called_with(
            "2.2.2.2", (77, (45, "flood")))
