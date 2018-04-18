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

import mock

from networking_bagpipe.bagpipe_bgp.common import exceptions
from networking_bagpipe.bagpipe_bgp.common import utils
from networking_bagpipe.bagpipe_bgp import constants as consts
from networking_bagpipe.bagpipe_bgp.vpn import manager
from networking_bagpipe.tests.unit.bagpipe_bgp import base as t


REDIRECTED_INSTANCE_ID1 = 'redirected-id1'
REDIRECTED_INSTANCE_ID2 = 'redirected-id2'

MAC = "00:00:de:ad:be:ef"
IP = "10.0.0.1/32"
BRIDGE_NAME = "br-test"
LOCAL_PORT = {'linuxif': 'tap1'}
VPN_EXT_ID = "ext_id_1"
VPN_EXT_ID_bis = "ext_id_2"
GW_IP = "10.0.0.1"
GW_MASK = 24
VNID = 255


class MockVPNInstance(object):

    type = consts.EVPN

    def __init__(self, vpn_manager, dataplane_driver,
                 external_instance_id, instance_id, import_rts, export_rts,
                 gateway_ip, mask, readvertise, attract_traffic, fallback=None,
                 **kwargs):
        self.manager = vpn_manager

        self.external_instance_id = external_instance_id
        self.instance_type = self.__class__.__name__
        self.instance_id = instance_id

        self.import_rts = import_rts
        self.export_rts = export_rts

        self.forced_vni = False

    def __repr__(self):
        return "%s:%s:%s" % (self.instance_type,
                             self.instance_id,
                             self.external_instance_id)

    @classmethod
    def validate_convert_attach_params(*args):
        pass

    @classmethod
    def validate_convert_detach_params(*args):
        pass

    def update_fallback(self, *args):
        pass

    def update_route_targets(self, *args):
        pass

    def vif_plugged(self, *args, **kwargs):
        pass

    def vif_unplugged(self, *args):
        pass

    def start(self):
        pass

    def stop_if_empty(self):
        pass

    def stop(self):
        pass

    def join(self):
        pass


class TestVPNManager(t.TestCase):

    def setUp(self):
        super(TestVPNManager, self).setUp()
        mock.patch("networking_bagpipe.bagpipe_bgp.vpn.dataplane_drivers."
                   "instantiate_dataplane_drivers",
                   return_value={
                       'evpn': mock.Mock(),
                       'ipvpn': mock.Mock()
                   }).start()
        self.manager = manager.VPNManager()

    def tearDown(self):
        super(TestVPNManager, self).tearDown()
        self.manager.stop()

    def test_redirect_traffic_single_instance(self):
        redirect_instance = self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID1, consts.IPVPN, t._rt_to_string(t.RT5)
        )

        # Check some VPN manager and redirect instance lists consistency
        self.assertIn(
            manager.redirect_instance_extid(consts.IPVPN,
                                            t._rt_to_string(t.RT5)),
            self.manager.vpn_instances)
        self.assertIn(REDIRECTED_INSTANCE_ID1,
                      redirect_instance.redirected_instances)

    def test_redirect_traffic_multiple_instance(self):
        redirect_instance_1 = self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID1, consts.IPVPN, t._rt_to_string(t.RT5)
        )
        redirect_instance_2 = self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID2, consts.IPVPN, t._rt_to_string(t.RT5)
        )

        # Check that same redirect instance is returned
        self.assertEqual(redirect_instance_2, redirect_instance_1)
        # Check some VPN manager and redirect instance lists consistency
        self.assertIn(
            manager.redirect_instance_extid(consts.IPVPN,
                                            t._rt_to_string(t.RT5)),
            self.manager.vpn_instances)
        self.assertIn(REDIRECTED_INSTANCE_ID1,
                      redirect_instance_1.redirected_instances)
        self.assertIn(REDIRECTED_INSTANCE_ID2,
                      redirect_instance_1.redirected_instances)

    def test_stop_redirect_traffic_multiple_instance(self):
        redirect_instance = self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID1, consts.IPVPN, t._rt_to_string(t.RT5)
        )
        self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID2, consts.IPVPN, t._rt_to_string(t.RT5)
        )

        # Check some VPN manager and redirect instance lists consistency
        self.manager.stop_redirect_to_vpn(REDIRECTED_INSTANCE_ID2,
                                          consts.IPVPN, t._rt_to_string(t.RT5))

        self.assertNotIn(REDIRECTED_INSTANCE_ID2,
                         redirect_instance.redirected_instances)

        self.manager.stop_redirect_to_vpn(REDIRECTED_INSTANCE_ID1,
                                          consts.IPVPN, t._rt_to_string(t.RT5))

        self.assertTrue(not self.manager.vpn_instances)

    def test_plug_vif_to_vpn_with_forced_vni(self):
        with mock.patch.object(self.manager, "_get_vpn_instance",
                               return_value=(mock.Mock(), False)
                               ) as mock_get_vpn_instance, \
                mock.patch.object(utils, "convert_route_targets"):
            self.manager.plug_vif_to_vpn(vpn_instance_id=VPN_EXT_ID,
                                         vpn_type=consts.EVPN,
                                         import_rt=[t.RT1],
                                         export_rt=[t.RT1],
                                         mac_address=MAC,
                                         ip_address=IP,
                                         gateway_ip=GW_IP,
                                         local_port=LOCAL_PORT,
                                         linuxbr=BRIDGE_NAME,
                                         vni=VNID)
        mock_get_vpn_instance.assert_called_once_with(
            VPN_EXT_ID, consts.EVPN, mock.ANY, mock.ANY, GW_IP, mock.ANY,
            None, None, None, linuxbr=BRIDGE_NAME, vni=VNID)

    def test_plug_vif_to_vpn_without_forced_vni(self):
        with mock.patch.object(self.manager, "_get_vpn_instance",
                               return_value=(mock.Mock(), False)
                               ) as mock_get_vpn_instance, \
                mock.patch.object(utils, "convert_route_targets"):
            self.manager.plug_vif_to_vpn(vpn_instance_id=VPN_EXT_ID,
                                         vpn_type=consts.EVPN,
                                         import_rt=[t.RT1],
                                         export_rt=[t.RT1],
                                         mac_address=MAC,
                                         ip_address=IP,
                                         gateway_ip=GW_IP,
                                         local_port=LOCAL_PORT,
                                         linuxbr=BRIDGE_NAME)

        mock_get_vpn_instance.assert_called_once_with(
            VPN_EXT_ID, consts.EVPN, mock.ANY, mock.ANY, GW_IP, mock.ANY,
            None, None, None, linuxbr=BRIDGE_NAME)

    def test_get_vpn_instance_with_forced_vni(self):
        instannce, _ = self.manager._get_vpn_instance(VPN_EXT_ID,
                                                      consts.IPVPN,
                                                      [], [],
                                                      GW_IP, GW_MASK,
                                                      None, None,
                                                      vni=VNID)
        instannce.start()

        self.assertEqual(VNID, instannce.instance_label,
                         "VPN instance label should be forced to VNID")

    def test_get_vpn_instance_without_forced_vni(self):
        instannce, _ = self.manager._get_vpn_instance(VPN_EXT_ID,
                                                      consts.IPVPN,
                                                      [], [],
                                                      GW_IP, GW_MASK,
                                                      None, None)

        instannce.start()

        self.assertIsNot(0, instannce.instance_label,
                         "VPN instance label should be assigned locally")

    def test_forced_vni_same_vni_twice(self):
        instannce, _ = self.manager._get_vpn_instance(VPN_EXT_ID,
                                                      consts.IPVPN,
                                                      [], [],
                                                      GW_IP, GW_MASK,
                                                      None, None,
                                                      vni=VNID)
        instannce.start()

        self.assertRaises(exceptions.APIAlreadyUsedVNI,
                          self.manager._get_vpn_instance,
                          VPN_EXT_ID_bis,
                          consts.EVPN,
                          [], [],
                          GW_IP, GW_MASK,
                          None, None,
                          vni=VNID)

        # unregister first VPN instance (free the VNI)
        self.manager.unregister_vpn_instance(instannce)

        # this time, using the VNI should work
        instance2, _ = self.manager._get_vpn_instance(VPN_EXT_ID,
                                                      consts.IPVPN,
                                                      [], [],
                                                      GW_IP, GW_MASK,
                                                      None, None,
                                                      vni=VNID)
        instance2.start()

    def test_instance_id_uniqueness(self):
        with mock.patch.object(manager.VPNManager, 'type2class',
                               {consts.IPVPN: MockVPNInstance,
                                consts.EVPN: MockVPNInstance
                                }):
            vpn_instance_unplug_args = dict(vpn_type=consts.EVPN,
                                            mac_address=MAC,
                                            ip_address=IP)
            vpn_instance_plug_args = dict(vpn_type=consts.EVPN,
                                          import_rts=['64512:74'],
                                          export_rts=[],
                                          mac_address=MAC,
                                          ip_address_prefix=IP,
                                          gateway_ip=GW_IP,
                                          local_port=LOCAL_PORT)
            BASE_VPN_EXT = "extid-"

            for i in (1, 2, 3, 4, 5):
                self.manager.plug_vif_to_vpn(
                    external_instance_id=BASE_VPN_EXT+str(i),
                    **vpn_instance_plug_args)

            for i in (2, 4):
                self.manager.unplug_vif_from_vpn(
                    external_instance_id=BASE_VPN_EXT+str(i),
                    **vpn_instance_unplug_args)

            for i in (6, 7, 8):
                self.manager.plug_vif_to_vpn(
                    external_instance_id=BASE_VPN_EXT+str(i),
                    **vpn_instance_plug_args)

            instance_ids = [i.instance_id
                            for i in self.manager.vpn_instances.values()]

            # ensure that each value is unique
            self.assertEqual(len(self.manager.vpn_instances.values()),
                             len(set(instance_ids)))

    def test_instance_id_max(self):
        with mock.patch.object(manager.VPNManager, 'type2class',
                               {consts.IPVPN: MockVPNInstance,
                                consts.EVPN: MockVPNInstance
                                }):
            self.manager.next_vpn_instance_id = 2**32 - 1

            self.manager.plug_vif_to_vpn(
                external_instance_id="dummy1",
                vpn_type=consts.EVPN,
                mac_address=MAC,
                import_rts=[],
                export_rts=[],
                ip_address_prefix=IP,
                local_port=LOCAL_PORT)

            self.assertRaises(
                manager.MaxInstanceIDReached,
                self.manager.plug_vif_to_vpn,
                external_instance_id="dummy2",
                vpn_type=consts.EVPN,
                import_rts=[],
                export_rts=[],
                mac_address=MAC,
                ip_address_prefix=IP,
                local_port=LOCAL_PORT)

    @mock.patch('networking_bagpipe.bagpipe_bgp.engine.bgp_manager.Manager')
    def test_manager_stop(self, mocked_bgp_manager):
        instance, _ = self.manager._get_vpn_instance(
            "TEST_VPN_INSTANCE", consts.IPVPN, [t.RT1], [t.RT1],
            "192.168.0.1", 24, {}, {})
        instance.start()

        self.manager.stop()
        self.assertTrue(not self.manager.vpn_instances)
