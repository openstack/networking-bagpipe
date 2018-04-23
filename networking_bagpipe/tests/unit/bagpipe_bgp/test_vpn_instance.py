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
"""

.. module:: test_vpn_instance
   :synopsis: module that defines several test cases for the vpn_instance
              module.
   TestInitVPNInstance defines a class dedicated to test init a VPNInstance
   with optional vni.
   TestVPNInstance class is dedicated to unit tests for VPNInstance class.
   Setup : Start VPNInstance thread instance.
   TearDown : Stop VPNInstance thread instance.
   VPNInstance is a base class for objects used to manage an E-VPN instance
   (EVI) or IP-VPN instance (VRF)
   Tests are organized as follow :
   - testAx use cases to test endpoints plug with different combinations of MAC
     and IP addresses on a port
   - testBx use cases to test endpoints plug with different combinations of MAC
     and IP addresses on different ports
   - testCx use cases to test endpoints unplug with different combinations of
     MAC and IP addresses as the one plugged on a port
   - testDx use cases to test endpoints unplug with different combinations of
     MAC and IP addresses as the ones plugged on different ports

"""

import mock
import testtools

from networking_bagpipe.bagpipe_bgp.common import exceptions as exc
from networking_bagpipe.bagpipe_bgp import engine
from networking_bagpipe.bagpipe_bgp.engine import exa
from networking_bagpipe.bagpipe_bgp.engine import flowspec
from networking_bagpipe.bagpipe_bgp.engine import ipvpn as ipvpn_routes
from networking_bagpipe.bagpipe_bgp.engine import worker
from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers
from networking_bagpipe.bagpipe_bgp.vpn import identifier_allocators
from networking_bagpipe.bagpipe_bgp.vpn import ipvpn
from networking_bagpipe.bagpipe_bgp.vpn import vpn_instance
from networking_bagpipe.tests.unit.bagpipe_bgp import base as t


MAC1 = "00:00:de:ad:be:ef"
IP1 = "10.0.0.1/32"
LOCAL_PORT1 = {'linuxif': 'tap1'}

MAC2 = "00:00:fe:ed:fa:ce"
IP2 = "10.0.0.2/32"
LOCAL_PORT2 = {'linuxif': 'tap2'}

MAC3 = "00:00:de:ad:c0:de"
IP3 = "10.0.0.3/32"
LOCAL_PORT3 = {'linuxif': 'tap3'}

MAC4 = "00:00:fe:ed:f0:0d"
IP4 = "10.0.0.4/32"
LOCAL_PORT4 = {'linuxif': 'tap4'}

RTRecord1 = exa.RTRecord.from_rt(t.RT1)
RTRecord2 = exa.RTRecord.from_rt(t.RT2)
RTRecord3 = exa.RTRecord.from_rt(t.RT3)
RTRecord4 = exa.RTRecord.from_rt(t.RT4)

VPN_ID = 1
VPN_EXT_ID = 1
GW_IP = "10.0.0.1"
GW_MASK = 24
VNID = 255


def _extract_nlri_from_call(vpn_inst, method, call_index=0):
    calls = getattr(vpn_inst, method).call_args_list
    return calls[call_index][0][0].nlri


def _extract_rt_from_call(vpn_inst, method, call_index=0):
    calls = getattr(vpn_inst, method).call_args_list
    return calls[call_index][0][0].route_targets


def _extract_rtrec_from_call(vpn_inst, method, call_index=0):
    calls = getattr(vpn_inst, method).call_args_list
    route = calls[call_index][0][0]
    return route.ecoms(exa.RTRecord)


def _extract_traffic_redirect_from_call(vpn_inst, method, call_index=0):
    calls = getattr(vpn_inst, method).call_args_list
    route = calls[call_index][0][0]
    for ecom in route.ecoms(exa.TrafficRedirect):
        return exa.RouteTarget(int(ecom.asn), int(ecom.target))
    return None


def _extract_traffic_classifier_from_call(vpn_inst, method, call_index=0):
    calls = getattr(vpn_inst, method).call_args_list
    traffic_classifier = vpn_instance.TrafficClassifier()
    traffic_classifier.map_redirect_rules_2_traffic_classifier(
        calls[call_index][0][0].nlri.rules)
    return traffic_classifier


class TestableVPNInstance(vpn_instance.VPNInstance):

    afi = exa.AFI(exa.AFI.ipv4)
    safi = exa.SAFI(exa.SAFI.mpls_vpn)

    def best_route_removed(self, entry, route):
        pass

    def new_best_route(self, entry, route, last):
        pass

    def route_to_tracked_entry(self, route):
        return route

    def generate_vif_bgp_route(self):
        pass


API_PARAMS = {
    'vpn_type': 'EVPN',
    'vpn_instance_id': 'testinstance',
    'mac_address': 'de:ad:00:00:be:ef',
    'ip_address': '192.168.0.1/24',
    'import_rt': ['64512:47'],
    'export_rt': ['64512:47'],
    'local_port': 'tap42'
}


def api_params():
    # return a new dict each time
    # to avoid concurrency issues
    return dict(API_PARAMS)


class TestVPNInstanceAPIChecks(testtools.TestCase):

    def _test_validate_convert_missing(self, method, missing_param,
                                       params=None):
        if params is None:
            params = api_params()
        params.pop(missing_param)
        self.assertRaises(exc.APIMissingParameterException, method, params)

    def test_validate_convert_attach(self):
        method = vpn_instance.VPNInstance.validate_convert_attach_params
        self._test_validate_convert_missing(method, 'vpn_instance_id')
        self._test_validate_convert_missing(method, 'mac_address')
        self._test_validate_convert_missing(method, 'local_port')
        self._test_validate_convert_missing(method, 'import_rt')
        self._test_validate_convert_missing(method, 'export_rt')

    def test_validate_convert_detach(self):
        method = vpn_instance.VPNInstance.validate_convert_detach_params
        self._test_validate_convert_missing(method, 'vpn_instance_id')
        self._test_validate_convert_missing(method, 'mac_address')
        self._test_validate_convert_missing(method, 'local_port')

    def test_api_internal_translation(self):
        params = api_params()
        vpn_instance.VPNInstance.validate_convert_attach_params(params)
        self.assertIn('external_instance_id', params)
        self.assertIn('import_rts', params)
        self.assertIn('export_rts', params)
        self.assertIn('localport', params)

    def test_check_vrf_gateway_ip(self):
        params = api_params()
        params['vpn_type'] = 'IPVPN'
        params['gateway_ip'] = '1.1.1.1'
        ipvpn.VRF.validate_convert_attach_params(params)
        self._test_validate_convert_missing(
            ipvpn.VRF.validate_convert_attach_params,
            'gateway_ip',
            params)

    def test_direction(self):
        params = api_params()
        vpn_instance.VPNInstance.validate_convert_attach_params(params)

    def test_direction_none(self):
        params = api_params()
        params['direction'] = None
        vpn_instance.VPNInstance.validate_convert_attach_params(params)

    def test_direction_ok(self):
        params = api_params()
        params['direction'] = 'to-port'
        vpn_instance.VPNInstance.validate_convert_attach_params(params)

        params = api_params()
        params['direction'] = 'from-port'
        vpn_instance.VPNInstance.validate_convert_attach_params(params)

    def test_direction_bogus(self):
        params = api_params()
        params['direction'] = 'floop'
        self.assertRaises(
            exc.APIException,
            vpn_instance.VPNInstance.validate_convert_attach_params,
            params)

    def test_mac_address_bogus(self):
        params = api_params()
        params['mac_address'] = 'gg:gg:gg:gg:gg:gg'
        self.assertRaises(
            exc.MalformedMACAddress,
            vpn_instance.VPNInstance.validate_convert_attach_params,
            params)

    def test_ip_address_bogus(self):
        params = api_params()
        params['ip_address'] = '257.303.1.'
        self.assertRaises(
            exc.MalformedIPAddress,
            vpn_instance.VPNInstance.validate_convert_attach_params,
            params)


class TestInitVPNInstance(testtools.TestCase):

    def setUp(self):
        super(TestInitVPNInstance, self).setUp()
        self.mock_manager = mock.Mock()
        self.mock_manager.label_allocator.release = mock.Mock()
        self.mock_dp_driver = mock.Mock()
        self.mock_dp_driver.initialize_dataplane_instance = mock.Mock()

    def test_init_stop_VPNInstance_with_forced_vni(self):
        # Initialize a VPNInstance with a forced VNID > 0
        vpn = TestableVPNInstance(self.mock_manager, self.mock_dp_driver,
                                  VPN_EXT_ID, VPN_ID,
                                  [t.RT1], [t.RT1],
                                  GW_IP, GW_MASK,
                                  None, None, vni=VNID)

        # Check that forced VNID is used as instance_label
        self.assertTrue(vpn.forced_vni)
        self.assertEqual(VNID, vpn.instance_label,
                         "VPN instance label should be forced to VNID")
        vpn.dp_driver.initialize_dataplane_instance.assert_called_once_with(
            VPN_ID, VPN_EXT_ID, GW_IP, GW_MASK, VNID)

        # Stop the VPNInstance to check that label release is not called
        vpn.stop()
        vpn.manager.label_allocator.release.assert_not_called()

    def test_init_stop_VPNInstance_without_forced_vni(self):
        # Initialize a VPNInstance with no vni
        vpn = TestableVPNInstance(self.mock_manager, self.mock_dp_driver,
                                  VPN_EXT_ID, VPN_ID, [t.RT1], [t.RT1],
                                  GW_IP, GW_MASK, None, None)

        # Check that VPN instance_label is locally-assigned
        self.assertFalse(vpn.forced_vni)
        vpn.dp_driver.initialize_dataplane_instance.assert_called_once_with(
            VPN_ID, VPN_EXT_ID, GW_IP, GW_MASK, vpn.instance_label)

        # Stop the VPNInstance to check that label release is called
        # with locally assigned instance label
        vpn.stop()
        vpn.manager.label_allocator.release.assert_called_once_with(
            vpn.instance_label)


class TestVPNInstance(t.BaseTestBagPipeBGP, testtools.TestCase):

    def setUp(self):
        super(TestVPNInstance, self).setUp()

        self.mock_dataplane = mock.Mock(
            spec=dataplane_drivers.VPNInstanceDataplane)

        mock_dp_driver = mock.Mock(
            spec=dataplane_drivers.DataplaneDriver)
        mock_dp_driver.initialize_dataplane_instance.return_value = (
            self.mock_dataplane
        )

        self.vpn = TestableVPNInstance(mock.Mock(name='VPNManager'),
                                       mock_dp_driver, 1, 1,
                                       [t.RT1], [t.RT1], '10.0.0.1', 24,
                                       None, None)

        self.vpn.synthesize_vif_bgp_route = mock.Mock(
            return_value=engine.RouteEntry(t.NLRI1, [t.RT1]))
        self.vpn._advertise_route = mock.Mock()
        self.vpn._withdraw_route = mock.Mock()
        self.vpn.start()

        self.set_event_target_worker(self.vpn)

    def tearDown(self):
        super(TestVPNInstance, self).tearDown()
        self.vpn.stop()
        self.vpn.join()

    def _get_ip_address(self, ip_address_prefix):
        return ip_address_prefix[0:ip_address_prefix.find('/')]

    def _validate_ip_address_2_mac_address_consistency(self, mac_address,
                                                       ip_address1,
                                                       ip_address2=None):
        # Validate IP address -> MAC address consistency
        self.assertIn(ip_address1, self.vpn.ip_address_2_mac)

        if ip_address2:
            self.assertIn(ip_address1, self.vpn.ip_address_2_mac)
            self.assertEqual(
                self.vpn.ip_address_2_mac[ip_address1],
                self.vpn.ip_address_2_mac[ip_address2])
        else:
            self.assertIn(
                mac_address, self.vpn.ip_address_2_mac[ip_address1])

    def _chk_mac_2_localport_data_consistency(self, mac_address, localport):
        # Validate MAC address -> Port informations consistency
        self.assertIn(mac_address, self.vpn.mac_2_localport_data)

        port_info = self.vpn.mac_2_localport_data[
            mac_address]['port_info']
        self.assertEqual(localport['linuxif'], port_info['linuxif'])

    def _validate_localport_2_endpoints_consistency(self, length, localport,
                                                    endpoints):
        # Validate Port -> Endpoint (MAC, IP) tuple consistency
        self.assertEqual(
            length,
            len(self.vpn.localport_2_endpoints[localport['linuxif']]))

        for endpoint in endpoints:
            self.assertIn(
                endpoint,
                self.vpn.localport_2_endpoints[localport['linuxif']])

    def test_validate_convert_params_duplicate_rts(self):
        test_params = {'vpn_instance_id': 'foo',
                       'mac_address': 'aa:bb:cc:dd:ee:ff',
                       'ip_address': '1.2.3.4',
                       'local_port': 'foo',
                       'import_rt': ['64512:1', '64512:1'],
                       'export_rt': '64512:4, 64512:4'}

        vpn_instance.VPNInstance.validate_convert_params(test_params)
        self.assertEqual(['64512:1'], test_params['import_rt'])
        self.assertEqual(['64512:4'], test_params['export_rt'])

    def test_a1_plug_endpoint_twice_same_port(self):
        # Plug one endpoint with same MAC and IP addresses twice on a port

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        self.vpn.dataplane.vif_plugged.assert_called_once()

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])

    def test_a2_plug_multiple_endpoints_with_same_ip_same_port(self):
        # Plug multiple endpoints with different MAC addresses and same IP
        # address on a port

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # An IP address correspond to only one MAC address, exception must be
        # raised
        self.assertRaises(exc.APIException,
                          self.vpn.vif_plugged,
                          MAC2, IP1, LOCAL_PORT1)
        self.vpn.dataplane.vif_plugged.assert_called_once()
        self.vpn._advertise_route.assert_called_once()

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(MAC2, self.vpn.mac_2_localport_data)

    def test_a3_plug_multiple_endpoints_with_same_mac_same_port(self):
        # Plug multiple endpoints with same MAC address and different IP
        # addresses on a port

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC1, IP2, LOCAL_PORT1)

        self.assertEqual(2, self.vpn.dataplane.vif_plugged.call_count,
                         "Port different IP addresses must be plugged on "
                         "dataplane")
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Route for port different IP addresses must be "
                         "advertised")
        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1, IP2)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            2, LOCAL_PORT1, [(MAC1, IP1), (MAC1, IP2)])

    def test_a4_plug_multiple_endpoints_same_port(self):
        # Plug multiple endpoints with different MAC and IP addresses on a port

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)

        self.assertEqual(2, self.vpn.dataplane.vif_plugged.call_count,
                         "Port different endpoints must be plugged on "
                         "dataplane")
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Route for port different endpoints must be "
                         "advertised")
        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._validate_ip_address_2_mac_address_consistency(MAC2, IP2)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._chk_mac_2_localport_data_consistency(MAC2, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            2, LOCAL_PORT1, [(MAC1, IP1), (MAC2, IP2)])

    def test_b1_plug_endpoint_twice_different_port(self):
        # Plug one endpoint with same MAC and IP addresses twice on different
        # ports

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # A port correspond to only one MAC address, exception must be raised
        self.assertRaises(exc.APIException,
                          self.vpn.vif_plugged,
                          MAC1, IP1, LOCAL_PORT2)
        self.vpn.dataplane.vif_plugged.assert_called_once()
        self.vpn._advertise_route.assert_called_once()

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(
            LOCAL_PORT2['linuxif'], self.vpn.localport_2_endpoints)

    def test_b2_plug_multiple_endpoints_with_same_ip_different_port(self):
        # Plug multiple endpoints with different MAC addresses and same IP
        # address on different port

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # An IP address correspond to only one MAC address, exception must be
        # raised
        self.assertRaises(exc.APIException,
                          self.vpn.vif_plugged,
                          MAC2, IP1, LOCAL_PORT2)
        self.vpn.dataplane.vif_plugged.assert_called_once()
        self.vpn._advertise_route.assert_called_once()

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(
            LOCAL_PORT2['linuxif'], self.vpn.localport_2_endpoints)

    def test_b4_plug_multiple_endpoints_with_same_mac_different_port(self):
        # Plug multiple endpoints with same MAC address and different IP
        # addresses on different ports

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # A port correspond to only one MAC address, exception must be raised
        self.assertRaises(exc.APIException,
                          self.vpn.vif_plugged,
                          MAC1, IP2, LOCAL_PORT2)
        self.vpn.dataplane.vif_plugged.assert_called_once()
        self.vpn._advertise_route.assert_called_once()

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(
            LOCAL_PORT2['linuxif'], self.vpn.localport_2_endpoints)

    def test_b5_plug_multiple_endpoints_different_port(self):
        # Plug multiple endpoints with different MAC and IP addresses on
        # different ports

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT2)

        self.assertEqual(2, self.vpn.dataplane.vif_plugged.call_count,
                         "All ports must be plugged on dataplane")
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Routes for all ports must be advertised")

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])

        self._validate_ip_address_2_mac_address_consistency(MAC2, IP2)
        self._chk_mac_2_localport_data_consistency(MAC2, LOCAL_PORT2)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT2, [(MAC2, IP2)])

    def test_c1_unplug_unique_endpoint_same_port(self):
        # Unplug one endpoint with same MAC and IP addresses as the one plugged
        # on port

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        label1 = self.vpn.mac_2_localport_data[MAC1]['label']

        self.vpn.vif_unplugged(MAC1, IP1)

        self.vpn.dataplane.vif_unplugged.assert_called_once()
        self.vpn.dataplane.vif_unplugged.assert_called_with(
            MAC1, self._get_ip_address(IP1), LOCAL_PORT1, label1, None, True)
        self.vpn._advertise_route.assert_called_once()
        self.vpn._withdraw_route.assert_called_once()

        self.assertEqual({}, self.vpn.mac_2_localport_data)
        self.assertEqual({}, self.vpn.ip_address_2_mac)
        self.assertEqual({}, self.vpn.localport_2_endpoints)

    def test_c2_unplug_unique_endpoint_with_same_ip_same_port(self):
        # Unplug one endpoint with different MAC addresses and same IP address
        # as the one plugged on port

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        self.assertRaises(exc.APIException,
                          self.vpn.vif_unplugged,
                          MAC2, IP1)

        self.vpn.dataplane.vif_unplugged.assert_not_called()
        self.vpn._advertise_route.assert_called_once()

        self.assertIn(MAC1, self.vpn.mac_2_localport_data)
        self.assertIn(IP1, self.vpn.ip_address_2_mac)
        self.assertIn(LOCAL_PORT1['linuxif'], self.vpn.localport_2_endpoints)

    def test_c3_unplug_unique_endpoint_with_same_mac_same_port(self):
        # Unplug one endpoint with same MAC address and different IP addresses
        # as the one plugged on port

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        self.assertRaises(exc.APIException,
                          self.vpn.vif_unplugged,
                          MAC1, IP2)

        self.vpn.dataplane.vif_unplugged.assert_not_called()
        self.vpn._advertise_route.assert_called_once()
        self.vpn._withdraw_route.assert_not_called()

        self.assertIn(MAC1, self.vpn.mac_2_localport_data)
        self.assertIn(IP1, self.vpn.ip_address_2_mac)
        self.assertIn(LOCAL_PORT1['linuxif'], self.vpn.localport_2_endpoints)

    def test_c4_unplug_one_endpoint_same_port(self):
        # Unplug only one endpoint with same MAC and IP addresses
        # corresponding to one plugged on port

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)

        label1 = self.vpn.mac_2_localport_data[MAC1]['label']

        self.vpn.vif_unplugged(MAC1, IP1)

        self.vpn.dataplane.vif_unplugged.assert_called_once()
        self.vpn.dataplane.vif_unplugged.assert_called_with(
            MAC1, self._get_ip_address(IP1), LOCAL_PORT1, label1, None, False)
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and only one withdrawn")
        self.vpn._withdraw_route.assert_called_once()

        self._validate_ip_address_2_mac_address_consistency(MAC2, IP2)
        self._chk_mac_2_localport_data_consistency(MAC2, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC2, IP2)])

    def test_c5_unplug_all_endpoints_same_port(self):
        # Unplug all endpoints with same MAC and IP addresses
        # corresponding to those plugged on port

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)

        label1 = self.vpn.mac_2_localport_data[MAC1]['label']
        label2 = self.vpn.mac_2_localport_data[MAC2]['label']

        self.vpn.vif_unplugged(MAC1, IP1)
        self.vpn.vif_unplugged(MAC2, IP2)

        self.assertEqual(2, self.vpn.dataplane.vif_unplugged.call_count,
                         "All port endpoints must be unplugged from dataplane")
        self.vpn.dataplane.vif_unplugged.assert_has_calls([
            mock.call(MAC1, self._get_ip_address(IP1),
                      LOCAL_PORT1, label1, None, False),
            mock.call(MAC2, self._get_ip_address(IP2),
                      LOCAL_PORT1, label2, None, True)
        ])
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and after withdrawn")
        self.assertEqual(2, self.vpn._withdraw_route.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and after withdrawn")

        self.assertEqual({}, self.vpn.mac_2_localport_data)
        self.assertEqual({}, self.vpn.ip_address_2_mac)
        self.assertEqual({}, self.vpn.localport_2_endpoints)

    def test_d1_unplug_unique_endpoints_different_port(self):
        # Unplug the endpoints with different MAC and IP addresses
        # corresponding to those plugged on different ports

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT2)

        label1 = self.vpn.mac_2_localport_data[MAC1]['label']
        label2 = self.vpn.mac_2_localport_data[MAC2]['label']

        self.vpn.vif_unplugged(MAC1, IP1)
        self.vpn.vif_unplugged(MAC2, IP2)

        self.assertEqual(2, self.vpn.dataplane.vif_unplugged.call_count,
                         "All different ports endpoints must be unplugged "
                         "from dataplane")

        self.vpn.dataplane.vif_unplugged.assert_has_calls([
            mock.call(MAC1, self._get_ip_address(IP1),
                      LOCAL_PORT1, label1, None, True),
            mock.call(MAC2, self._get_ip_address(IP2),
                      LOCAL_PORT2, label2, None, True)
        ])
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawn")
        self.assertEqual(2, self.vpn._withdraw_route.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawn")

        self.assertEqual({}, self.vpn.mac_2_localport_data)
        self.assertEqual({}, self.vpn.ip_address_2_mac)
        self.assertEqual({}, self.vpn.localport_2_endpoints)

    def test_d2_unplug_one_endpoint_same_ip_different_port(self):
        # Unplug one endpoint with different MAC or IP address corresponding to
        # one plugged on another port

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT2)

        self.assertRaises(exc.APIException,
                          self.vpn.vif_unplugged,
                          MAC1, IP2)

        self.vpn.dataplane.vif_unplugged.assert_not_called()
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Routes for all different ports endpoints must only "
                         "be advertised")

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])

        self._validate_ip_address_2_mac_address_consistency(MAC2, IP2)
        self._chk_mac_2_localport_data_consistency(MAC2, LOCAL_PORT2)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT2, [(MAC2, IP2)])

    def test_d3_unplug_multiple_endpoints_different_port(self):
        # Unplug multiple endpoints with same MAC and IP addresses
        # corresponding to those plugged on different ports

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC3, IP3, LOCAL_PORT2)
        self.vpn.vif_plugged(MAC4, IP4, LOCAL_PORT2)

        label1 = self.vpn.mac_2_localport_data[MAC1]['label']
        label2 = self.vpn.mac_2_localport_data[MAC2]['label']
        label3 = self.vpn.mac_2_localport_data[MAC3]['label']
        label4 = self.vpn.mac_2_localport_data[MAC4]['label']

        self.vpn.vif_unplugged(MAC1, IP1)
        self.vpn.vif_unplugged(MAC2, IP2)
        self.vpn.vif_unplugged(MAC3, IP3)
        self.vpn.vif_unplugged(MAC4, IP4)

        self.assertEqual(4, self.vpn.dataplane.vif_unplugged.call_count,
                         "All different ports endpoints must be unplugged "
                         "from dataplane")
        self.vpn.dataplane.vif_unplugged.assert_has_calls([
            mock.call(MAC1, self._get_ip_address(IP1),
                      LOCAL_PORT1, label1, None, False),
            mock.call(MAC2, self._get_ip_address(IP2),
                      LOCAL_PORT1, label2, None, True),
            mock.call(MAC3, self._get_ip_address(IP3),
                      LOCAL_PORT2, label3, None, False),
            mock.call(MAC4, self._get_ip_address(IP4),
                      LOCAL_PORT2, label4, None, True)
        ])
        self.assertEqual(4, self.vpn._withdraw_route.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawn")
        self.assertEqual(4, self.vpn._advertise_route.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawn")

        self.assertEqual({}, self.vpn.mac_2_localport_data)
        self.assertEqual({}, self.vpn.ip_address_2_mac)
        self.assertEqual({}, self.vpn.localport_2_endpoints)

    def test_plug_unplug_wildcard_ip(self):
        self.vpn.vif_plugged(MAC1, None, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC1, IP2, LOCAL_PORT1)

        # 3 advertisements should be seen: one without IP, then one for each IP
        self.assertEqual(3, self.vpn._advertise_route.call_count)
        # the wildcard should be removed
        self.assertEqual(1, self.vpn._withdraw_route.call_count)

        self.vpn.vif_unplugged(MAC1, None)
        # 3 withdraw should be seen, one for each IP, one without IP
        self.assertEqual(3, self.vpn._withdraw_route.call_count)

    def test_plug_unplug_wildcard_ip_no_ip(self):
        self.vpn.vif_plugged(MAC1, None, LOCAL_PORT1)
        self.assertEqual(1, self.vpn._advertise_route.call_count)
        self.vpn.vif_unplugged(MAC1, None)
        self.assertEqual(1, self.vpn._withdraw_route.call_count)

    def test_get_lg_localport_data(self):
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC3, IP3, LOCAL_PORT2)
        self.vpn.vif_plugged(MAC4, IP4, LOCAL_PORT2)

        self.vpn.get_lg_local_port_data("")

    # tests of update_route_targets

    def _test_update_rts_init(self):
        self.vpn._advertise_route.reset_mock()

        route = engine.RouteEntry(t.NLRI1, [t.RT1])
        self.vpn.endpoint_2_route = {None: route}

    def test_update_rts_1(self):
        self._test_update_rts_init()

        # no change -> no route update
        self.vpn.update_route_targets([t.RT1], [t.RT1])

        self.vpn._advertise_route.assert_not_called()

    def test_update_rts_2(self):
        self._test_update_rts_init()

        # change imports -> no route update
        self.vpn.update_route_targets([t.RT2], [t.RT1])

        self.vpn._advertise_route.assert_not_called()

    def test_update_rts_3(self):
        self._test_update_rts_init()

        # change exports
        # check that previously advertised routes are readvertised
        self.vpn.update_route_targets([t.RT1], [t.RT2])

        self.vpn._advertise_route.assert_called_once()

        self.assertIn(t.RT2, _extract_rt_from_call(self.vpn,
                                                   '_advertise_route'))
        self.assertNotIn(t.RT1, _extract_rt_from_call(self.vpn,
                                                      '_advertise_route'))

    def test_update_rts_3bis(self):
        self._test_update_rts_init()

        # change exports
        # check that previously advertised routes are readvertised
        self.vpn.update_route_targets([t.RT1], [t.RT1, t.RT2])

        self.vpn._advertise_route.assert_called_once()
        self.assertIn(t.RT2, _extract_rt_from_call(self.vpn,
                                                   '_advertise_route'))
        self.assertIn(t.RT1, _extract_rt_from_call(self.vpn,
                                                   '_advertise_route'))

    def test_cleanup_assist(self):
        # simulate a route injected in our VPNInstance

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        self._new_route_event(engine.RouteEvent.ADVERTISE,
                              self._fake_nlri("fake NLRI"),
                              [t.RT1, t.RT2], worker_a, t.NH1, 200)

        self.mock_dataplane.needs_cleanup_assist.return_value = True

        with mock.patch.object(self.vpn, 'best_route_removed') as mock_brr:
            self.vpn.stop()
            mock_brr.assert_called_once()

    def test_plug_endpoint_direction_to_port(self):
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, direction='to-port')

        self.vpn.dataplane.vif_plugged.assert_called_once()
        self.vpn._advertise_route.assert_called_once()

    def test_plug_endpoint_direction_from_port(self):
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, direction='from-port')

        self.vpn.dataplane.vif_plugged.assert_called_once()
        self.vpn._advertise_route.assert_not_called()


LOCAL_ADDRESS = '4.5.6.7'
NEXT_HOP = '45.45.45.45'

IP_ADDR_PREFIX1 = '1.1.1.1/32'
IP_ADDR_PREFIX2 = '2.2.2.2/32'
IP_ADDR_PREFIX3 = '3.3.3.3/32'

STATIC_ADDR_PREFIX1 = '10.10.10.10/32'
STATIC_ADDR_PREFIX2 = '20.20.20.20/32'

ATTRACT_TRAFFIC_1 = {'redirect_rts': [t.RT5],
                     'classifier': {'destinationPort': '80',
                                    'protocol': 'tcp'
                                    }
                     }

ATTRACT_STATIC_1 = {'to_rt': [t.RT4],
                    'static_destination_prefixes': [STATIC_ADDR_PREFIX1],
                    'redirect_rts': [t.RT5],
                    'classifier': {'destinationPort': '80',
                                   'protocol': 'tcp'
                                   }
                    }

ATTRACT_STATIC_2 = {'to_rt': [t.RT4],
                    'static_destination_prefixes': [STATIC_ADDR_PREFIX1,
                                                    STATIC_ADDR_PREFIX2],
                    'redirect_rts': [t.RT5],
                    'classifier': {'destinationPort': '80',
                                   'protocol': 'tcp'
                                   }
                    }

TC1 = vpn_instance.TrafficClassifier(destination_prefix="1.1.1.1/32",
                                     destination_port="80",
                                     protocol="tcp")

TC2 = vpn_instance.TrafficClassifier(destination_prefix="2.2.2.2/32",
                                     destination_port="80",
                                     protocol="tcp")

TC_STATIC1 = vpn_instance.TrafficClassifier(
    destination_prefix=STATIC_ADDR_PREFIX1,
    destination_port="80",
    protocol="tcp"
)

TC_STATIC2 = vpn_instance.TrafficClassifier(
    destination_prefix=STATIC_ADDR_PREFIX2,
    destination_port="80",
    protocol="tcp"
)


class TestVRF(t.BaseTestBagPipeBGP, testtools.TestCase):

    def setUp(self):
        super(TestVRF, self).setUp()

        self.mock_dp = mock.Mock(
            spec=ipvpn.DummyVPNInstanceDataplane)

        mock_dp_driver = mock.Mock(
            spec=ipvpn.DummyDataplaneDriver)

        mock_dp_driver.initialize_dataplane_instance.return_value = \
            self.mock_dp
        mock_dp_driver.get_local_address.return_value = LOCAL_ADDRESS
        mock_dp_driver.supported_encaps.return_value = \
            [exa.Encapsulation(exa.Encapsulation.Type.DEFAULT)]

        label_alloc = identifier_allocators.LabelAllocator()
        bgp_manager = mock.Mock()
        bgp_manager.get_local_address.return_value = LOCAL_ADDRESS
        rd_alloc = (
            identifier_allocators.RDAllocator(bgp_manager.get_local_address())
        )
        self.manager = mock.Mock(bgp_manager=bgp_manager,
                                 label_allocator=label_alloc,
                                 rd_allocator=rd_alloc)

        self.vpn = ipvpn.VRF(self.manager, mock_dp_driver, 1, 1,
                             [t.RT1], [t.RT1], '10.0.0.1', 24,
                             {'from_rt': [t.RT3],
                              'to_rt': [t.RT4]},
                             None)

        self.vpn._advertise_route = mock.Mock()
        self.vpn._withdraw_route = mock.Mock()
        self.vpn.start()

        self.set_event_target_worker(self.vpn)

    def _reset_mocks(self):
        self.vpn._advertise_route.reset_mock()
        self.vpn._withdraw_route.reset_mock()
        self.mock_dp.setup_dataplane_for_remote_endpoint.reset_mock()
        self.mock_dp.vif_plugged.reset_mock()
        self.mock_dp.vif_unplugged.reset_mock()

    def tearDown(self):
        super(TestVRF, self).tearDown()
        self.vpn.stop()
        self.vpn.join()

    def _config_vrf_with_attract_traffic(self, attract_traffic,
                                         no_readvertise=False):
        self.vpn.attract_traffic = True
        self.vpn.attract_rts = attract_traffic['redirect_rts']
        self.vpn.attract_classifier = attract_traffic['classifier']

        if no_readvertise:
            self.vpn.readvertise = False
            self.vpn.readvertise_from_rts = []
            self.vpn.readvertise_to_rts = attract_traffic['to_rt']
        else:
            if attract_traffic.get('to_rt'):
                self.assertEqual(self.vpn.readvertise_to_rts,
                                 attract_traffic['to_rt'])

        if (attract_traffic.get('to_rt') and
                attract_traffic.get('static_destination_prefixes')):
            self.vpn.attract_static_dest_prefixes = (
                attract_traffic['static_destination_prefixes']
            )

    def _mock_vpnmanager_for_attract_traffic(self):
        self.manager.redirect_traffic_to_vpn = mock.Mock(
            spec=ipvpn.VPNInstanceDataplane)
        self.manager.stop_redirect_to_vpn = mock.Mock()

    def _reset_mocks_vpnmanager(self):
        self.manager.redirect_traffic_to_vpn.reset_mock()
        self.manager.stop_redirect_to_vpn.reset_mock()

    def _generate_route_nlri(self, ip_address_prefix, nexthop=NEXT_HOP):
        # Parse address/mask
        (_, prefix_len) = self.vpn._parse_ipaddress_prefix(ip_address_prefix)

        prefix_rd = self.manager.rd_allocator.get_new_rd(
            "Route distinguisher for prefix %s" % ip_address_prefix
        )
        rd = prefix_rd if prefix_len == 32 else self.vpn.instance_rd

        label = self.manager.label_allocator.get_new_label(
            "Label for prefix %s" % ip_address_prefix
        )

        return ipvpn_routes.IPVPNRouteFactory(exa.AFI(exa.AFI.ipv4),
                                              ip_address_prefix,
                                              label, rd, nexthop)

    def _generate_flow_spec_nlri(self, classifier):
        rd = self.manager.rd_allocator.get_new_rd(
            "Route distinguisher for FlowSpec NLRI"
        )
        flow_nlri = flowspec.FlowRouteFactory(exa.AFI(exa.AFI.ipv4), rd)

        for rule in classifier.map_traffic_classifier_2_redirect_rules():
            flow_nlri.add(rule)

        return flow_nlri

    def test_validate_convert_attach(self):
        params = api_params()
        params.pop('ip_address')
        self.assertRaises(exc.APIMissingParameterException,
                          ipvpn.VRF.validate_convert_attach_params,
                          params)

    def test_validate_convert_detach(self):
        params = api_params()
        params.pop('ip_address')
        self.assertRaises(exc.APIMissingParameterException,
                          ipvpn.VRF.validate_convert_detach_params,
                          params)

    # unit test for IPVPN re-advertisement
    def test_re_advertisement_1(self):
        self._reset_mocks()

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri_1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri_1,
                              [t.RT1, t.RT2], worker_a, t.NH1, 200)
        # no re-advertisement supposed to happen
        self.vpn._advertise_route.assert_called_once()
        # dataplane supposed to be updated for this route
        self.mock_dp.setup_dataplane_for_remote_endpoint.assert_called_once()

        self._reset_mocks()

        vpn_nlri_2 = self._generate_route_nlri(IP_ADDR_PREFIX2)
        event2 = self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri_2,
                                       [t.RT3], worker_a, t.NH1, 200,
                                       rtrecords=[RTRecord1])
        # re-advertisement of VPN NLRI2 supposed to happen, to RT4
        self.vpn._advertise_route.assert_called_once()
        self.assertIn(t.RT4, _extract_rt_from_call(self.vpn,
                                                   '_advertise_route'))
        self.assertNotIn(t.RT2, _extract_rt_from_call(self.vpn,
                                                      '_advertise_route'))
        self.assertNotIn(t.RT3, _extract_rt_from_call(self.vpn,
                                                      '_advertise_route'))
        self.assertIn(RTRecord3, _extract_rtrec_from_call(self.vpn,
                                                          '_advertise_route'))
        self.assertIn(RTRecord1, _extract_rtrec_from_call(self.vpn,
                                                          '_advertise_route'))
        # check that event is for re-advertised route vpn_nlri_2 and
        #  contains what we expect
        route_entry = self.vpn._advertise_route.call_args_list[0][0][0]
        self.assertNotEqual(vpn_nlri_2.rd, route_entry.nlri.rd)
        # dataplane *not* supposed to be updated for this route
        self.mock_dp.setup_dataplane_for_remote_endpoint.assert_not_called()

        self._reset_mocks()

        # new interface plugged in
        # route vpn_nlri_2 should be re-advertized with this new next hop as
        #  next-hop
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT2)
        # advertised route count should increment by 2:
        # - vif route itself
        # - re-adv of NLRI1 with this new port as next-hop
        self.assertEqual(2, self.vpn._advertise_route.call_count)
        self.vpn._withdraw_route.assert_not_called()
        self.assertIn(t.RT1, _extract_rt_from_call(self.vpn,
                                                   '_advertise_route', 0))
        self.assertNotIn(t.RT4, _extract_rt_from_call(self.vpn,
                                                      '_advertise_route', 0))
        self.assertIn(t.RT4, _extract_rt_from_call(self.vpn,
                                                   '_advertise_route', 1))
        self.assertNotIn(t.RT1, _extract_rt_from_call(self.vpn,
                                                      '_advertise_route', 1))

        # check that second event is for re-advertised route vpn_nlri_2 and
        #  contains what we expect
        route_entry = self.vpn._advertise_route.call_args_list[1][0][0]
        vpn_nlri_2_readv_rd = route_entry.nlri.rd
        self.assertEqual(vpn_nlri_2.cidr.prefix(),
                         route_entry.nlri.cidr.prefix())
        self.assertNotEqual(vpn_nlri_2.labels, route_entry.nlri.labels)
        self.assertNotEqual(vpn_nlri_2.nexthop, route_entry.nlri.nexthop)
        self.assertNotEqual(vpn_nlri_2.rd, route_entry.nlri.rd)
        self.assertEqual(vpn_nlri_2_readv_rd, route_entry.nlri.rd)

        self._reset_mocks()

        # new route, that, because it contains the redirectRT in RTRecord
        # will not be re-advertized
        vpn_nlri3 = self._generate_route_nlri(IP_ADDR_PREFIX3)
        event3 = self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri3,
                                       [t.RT3], worker_a, t.NH1, 200,
                                       rtrecords=[RTRecord4])
        self.vpn._advertise_route.assert_not_called()
        self.vpn._withdraw_route.assert_not_called()
        self._revert_event(event3)

        self._reset_mocks()

        # vif unplugged, routes VPN NLRI2 with next-hop
        # corresponding to this ports should now be withdrawn
        self.vpn.vif_unplugged(MAC2, IP2)
        self.assertEqual(2, self.vpn._withdraw_route.call_count)
        route_entry = self.vpn._withdraw_route.call_args_list[0][0][0]
        self.assertEqual(vpn_nlri_2.cidr.prefix(),
                         route_entry.nlri.cidr.prefix())
        self.assertNotEqual(vpn_nlri_2.labels, route_entry.nlri.labels)
        self.assertNotEqual(vpn_nlri_2.nexthop, route_entry.nlri.nexthop)
        self.assertNotEqual(vpn_nlri_2.rd, route_entry.nlri.rd)
        self.assertNotEqual(vpn_nlri_2.rd, route_entry.nlri.rd)
        self.assertEqual(vpn_nlri_2_readv_rd, route_entry.nlri.rd)

        self._reset_mocks()

        # RTs of route NLRI1 now include a re-advertiseed RT
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri_1,
                              [t.RT1, t.RT2, t.RT3],
                              worker_a, t.NH1, 200)
        self.vpn._advertise_route.assert_called_once()
        self.assertIn(t.RT4, _extract_rt_from_call(self.vpn,
                                                   '_advertise_route'))
        # dataplane supposed to be updated for this route
        self.mock_dp.setup_dataplane_for_remote_endpoint.assert_called_once()

        self._reset_mocks()

        self._revert_event(event2)
        # withdraw of re-adv route supposed to happen
        self.vpn._withdraw_route.assert_called_once()
        self.vpn._advertise_route.assert_not_called()
        # dataplane *not* supposed to be updated for this route
        self.mock_dp.setup_dataplane_for_remote_endpoint.assert_not_called()

    def test_re_advertisement_last(self):
        self._reset_mocks()

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri_1 = self._generate_route_nlri(IP_ADDR_PREFIX1, t.NH1)
        event1 = self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri_1,
                                       [t.RT3], worker_a, t.NH1, 200,
                                       rtrecords=[RTRecord1])
        # advertised route count increment by 2:
        # - vif route for port
        # - re-advertisement of VPN NLRI1 with port as next-hop
        self.assertEqual(2, self.vpn._advertise_route.call_count)
        self.vpn._withdraw_route.assert_not_called()

        self._reset_mocks()

        vpn_nlri_1bis = self._generate_route_nlri(IP_ADDR_PREFIX1, t.NH1)
        event1bis = self._new_route_event(engine.RouteEvent.ADVERTISE,
                                          vpn_nlri_1bis, [t.RT3], worker_a,
                                          t.NH1, 200, rtrecords=[RTRecord1])
        # second re-advertisement of VPN NLRI1 supposed to happen
        # (must be futher fixed to only append once)
        self.vpn._advertise_route.assert_called_once()
        self.vpn._withdraw_route.assert_not_called()

        self._reset_mocks()

        self._revert_event(event1bis)
        self.vpn._advertise_route.assert_not_called()
        self.vpn._withdraw_route.assert_not_called()

        self._reset_mocks()

        self._revert_event(event1)
        # withdraw of re-adv route supposed to happen
        self.vpn._withdraw_route.assert_called_once()
        self.vpn._advertise_route.assert_not_called()

    # unit test for FlowSpec re-advertisement
    def test_flowspec_re_advertisement_1(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        # FlowSpec route
        flow_nlri1 = self._generate_flow_spec_nlri(TC1)
        self._new_flow_event(engine.RouteEvent.ADVERTISE, flow_nlri1, [t.RT5],
                             [t.RT3], worker_a)

        # re-advertisement of Flow NLRI1 supposed to happen, to RT4
        self.assertEqual(2, self.vpn._advertise_route.call_count)
        self.manager.redirect_traffic_to_vpn.assert_not_called()

        # 1 - re-advertisement of a default route supposed to happen
        # to RT4
        self.assertIn(t.RT4,
                      _extract_rt_from_call(self.vpn, '_advertise_route', 0))

        ipvpn_nlri = _extract_nlri_from_call(self.vpn, '_advertise_route', 0)
        self.assertEqual(ipvpn.DEFAULT_ADDR_PREFIX, ipvpn_nlri.cidr.prefix())

        # 2 - advertisement of FlowSpec NLRI supposed to happen to RT4
        #     for traffic redirection to RT5 on TCP destination port 80
        self.assertIn(t.RT4,
                      _extract_rt_from_call(self.vpn, '_advertise_route', 1))
        self.assertNotIn(t.RT3,
                         _extract_rt_from_call(self.vpn,
                                               '_advertise_route', 1))
        self.assertIn(RTRecord3,
                      _extract_rtrec_from_call(self.vpn,
                                               '_advertise_route', 1))
        self.assertEqual(
            t.RT5,
            _extract_traffic_redirect_from_call(self.vpn,
                                                '_advertise_route', 1))
        # check that second event is for re-advertised route flow_nlri1 and
        #  contains what we expect
        route_entry = self.vpn._advertise_route.call_args_list[1][0][0]
        self.assertNotEqual(flow_nlri1.rd, route_entry.nlri.rd)
        self.assertEqual(self.vpn.instance_rd, route_entry.nlri.rd)
        # dataplane *not* supposed to be updated for this route
        self.mock_dp.setup_dataplane_for_remote_endpoint.assert_not_called()

    def _check_attract_traffic(self, method, redirect_rts,
                               expected_classifiers):
        self.assertEqual(len(expected_classifiers),
                         getattr(self.vpn, method).call_count)

        for index, classifier in enumerate(expected_classifiers):
            if not classifier:
                # Skip advertisement to exported route targets
                if (self.vpn.export_rts == _extract_rt_from_call(
                        self.vpn,
                        method,
                        index)):
                    continue

                # 1 - re-advertisement of a default route supposed to happen
                # to RT4
                self.assertIn(self.vpn.readvertise_to_rts[0],
                              _extract_rt_from_call(self.vpn, method, index))

                ipvpn_nlri = _extract_nlri_from_call(self.vpn, method, index)
                self.assertEqual(ipvpn.DEFAULT_ADDR_PREFIX,
                                 ipvpn_nlri.cidr.prefix())

                if self.vpn.readvertise:
                    self.assertNotIn(self.vpn.readvertise_from_rts[0],
                                     _extract_rt_from_call(self.vpn,
                                                           method, index))
            else:
                # 2 - advertisement of FlowSpec NLRI supposed to happen to RT5
                #     for traffic redirection to RT4 on TCP destination port 80
                flow_nlri = _extract_nlri_from_call(self.vpn, method, index)
                self.assertIsInstance(flow_nlri, exa.Flow)

                self.assertEqual(flow_nlri.rd, self.vpn.instance_rd)
                self.assertIn(redirect_rts[0],
                              _extract_rt_from_call(self.vpn, method, index))
                self.assertEqual(
                    self.vpn.readvertise_to_rts[0],
                    _extract_traffic_redirect_from_call(self.vpn,
                                                        method, index)
                )
                self.assertEqual(
                    classifier,
                    _extract_traffic_classifier_from_call(self.vpn,
                                                          method, index)
                )

    # unit test for IPVPN traffic redirection
    def test_attract_traffic_re_advertisement(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.vpn._advertise_route.assert_called_once()

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        event1 = self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1,
                                       [t.RT3], worker_a, t.NH1, 200)

        # Default and FlowSpec routes are supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)
        self.vpn._withdraw_route.assert_not_called()

        ipvpn_nlri = _extract_nlri_from_call(self.vpn, '_advertise_route', 0)
        self.assertIsInstance(ipvpn_nlri, exa.IPVPN)
        self.assertEqual(ipvpn.DEFAULT_ADDR_PREFIX,
                         ipvpn_nlri.cidr.prefix())

        flow_nlri = _extract_nlri_from_call(self.vpn, '_advertise_route', 1)
        self.assertIsInstance(flow_nlri, exa.Flow)

        self._reset_mocks()

        vpn_nlri2 = self._generate_route_nlri(IP_ADDR_PREFIX2)
        event2 = self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri2,
                                       [t.RT3], worker_a, t.NH1, 200)

        # Only FlowSpec route is supposed to be advertised
        self.vpn._advertise_route.assert_called_once()
        self.vpn._withdraw_route.assert_not_called()

        flow_nlri = _extract_nlri_from_call(self.vpn, '_advertise_route', 0)
        self.assertIsInstance(flow_nlri, exa.Flow)

        self._reset_mocks()

        self._revert_event(event2)

        # Only FlowSpec route is supposed to be withdrawn
        self.vpn._withdraw_route.assert_called_once()
        self.vpn._advertise_route.assert_not_called()

        flow_nlri = _extract_nlri_from_call(self.vpn, '_withdraw_route', 0)
        self.assertIsInstance(flow_nlri, exa.Flow)

        self._reset_mocks()

        self._revert_event(event1)

        # Default and FlowSpec routes are supposed to be withdrawn
        self.assertEqual(2, self.vpn._withdraw_route.call_count)
        self.vpn._advertise_route.assert_not_called()

        ipvpn_nlri = _extract_nlri_from_call(self.vpn, '_withdraw_route', 0)
        self.assertIsInstance(ipvpn_nlri, exa.IPVPN)
        self.assertEqual(ipvpn.DEFAULT_ADDR_PREFIX,
                         ipvpn_nlri.cidr.prefix())

        flow_nlri = _extract_nlri_from_call(self.vpn, '_withdraw_route', 1)
        self.assertIsInstance(flow_nlri, exa.Flow)

    def test_attract_traffic_single_prefix_advertise(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.vpn._advertise_route.assert_called_once()

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1, [t.RT3],
                              worker_a, t.NH1, 200)

        self._check_attract_traffic('_advertise_route',
                                    ATTRACT_TRAFFIC_1['redirect_rts'],
                                    [None, TC1])

    def test_attract_traffic_single_prefix_withdraw(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.vpn._advertise_route.assert_called_once()

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        event1 = self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1,
                                       [t.RT3], worker_a, t.NH1, 200)

        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        self._revert_event(event1)

        self._check_attract_traffic('_withdraw_route',
                                    ATTRACT_TRAFFIC_1['redirect_rts'],
                                    [None, TC1])

    def test_attract_traffic_multiple_prefix_advertise(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.vpn._advertise_route.assert_called_once()

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1, [t.RT3],
                              worker_a, t.NH1, 200)

        vpn_nlri2 = self._generate_route_nlri(IP_ADDR_PREFIX2)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri2, [t.RT3],
                              worker_a, t.NH1, 200)

        self._check_attract_traffic(
            '_advertise_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [None, TC1, TC2])

    def test_attract_traffic_multiple_prefix_withdraw(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.vpn._advertise_route.assert_called_once()

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        event1 = self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1,
                                       [t.RT3], worker_a, t.NH1, 200)

        vpn_nlri2 = self._generate_route_nlri(IP_ADDR_PREFIX2)
        event2 = self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri2,
                                       [t.RT3], worker_a, t.NH1, 200)

        self.assertEqual(3, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        self._revert_event(event2)
        self._revert_event(event1)

        self._check_attract_traffic(
            '_withdraw_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [TC2, None, TC1])

    def test_attract_traffic_static_dest_prefix_no_readvertise_advertise(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier and a static destination prefix, to a specific route
        # target
        self._config_vrf_with_attract_traffic(ATTRACT_STATIC_1,
                                              no_readvertise=True)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        self._check_attract_traffic('_advertise_route',
                                    ATTRACT_STATIC_1['redirect_rts'],
                                    [None, None, TC_STATIC1])

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1, [t.RT3],
                              worker_a, t.NH1, 200)

        self.vpn._advertise_route.assert_not_called()

    def test_attract_traffic_static_dest_prefix_advertise(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier and a static destination prefix, to a specific route
        # target
        self._config_vrf_with_attract_traffic(ATTRACT_STATIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        self._check_attract_traffic('_advertise_route',
                                    ATTRACT_STATIC_1['redirect_rts'],
                                    [None, None, TC_STATIC1])

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1, [t.RT3],
                              worker_a, t.NH1, 200)

        self._check_attract_traffic('_advertise_route',
                                    ATTRACT_STATIC_1['redirect_rts'],
                                    [None, TC1])

    def test_attract_traffic_static_dest_prefix_advertise_multiple(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier and multiple static destination prefixes, to a specific
        # route target
        self._config_vrf_with_attract_traffic(ATTRACT_STATIC_2)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        self._check_attract_traffic('_advertise_route',
                                    ATTRACT_STATIC_1['redirect_rts'],
                                    [None, None, TC_STATIC1, None, TC_STATIC2])

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1, [t.RT3],
                              worker_a, t.NH1, 200)

        self._check_attract_traffic('_advertise_route',
                                    ATTRACT_STATIC_1['redirect_rts'],
                                    [None, TC1])

    def test_redirected_vrf_single_flow_advertised(self):
        self._mock_vpnmanager_for_attract_traffic()

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.vpn._advertise_route.assert_called_once()

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        # FlowSpec route
        flow_nlri1 = self._generate_flow_spec_nlri(TC1)
        self._new_flow_event(engine.RouteEvent.ADVERTISE, flow_nlri1, [t.RT5],
                             [t.RT1], worker_a)

        redirect_rt5 = t._rt_to_string(t.RT5)
        self.manager.redirect_traffic_to_vpn.assert_called_once()
        self.assertIn(TC1,
                      self.vpn.redirect_rt_2_classifiers[redirect_rt5])

    def test_redirected_vrf_multiple_flow_advertised(self):
        self._mock_vpnmanager_for_attract_traffic()

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.vpn._advertise_route.assert_called_once()

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        # FlowSpec route
        flow_nlri1 = self._generate_flow_spec_nlri(TC1)
        self._new_flow_event(engine.RouteEvent.ADVERTISE, flow_nlri1, [t.RT5],
                             [t.RT1], worker_a)
        flow_nlri2 = self._generate_flow_spec_nlri(TC2)
        self._new_flow_event(engine.RouteEvent.ADVERTISE, flow_nlri2, [t.RT5],
                             [t.RT1], worker_a)

        redirect_rt5 = t._rt_to_string(t.RT5)
        self.assertEqual(2, self.manager.redirect_traffic_to_vpn.call_count)
        self.assertIn(TC1,
                      self.vpn.redirect_rt_2_classifiers[redirect_rt5])
        self.assertIn(TC2,
                      self.vpn.redirect_rt_2_classifiers[redirect_rt5])

    def test_redirected_vrf_multiple_flow_withdrawn(self):
        self._mock_vpnmanager_for_attract_traffic()

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.vpn._advertise_route.assert_called_once()

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        # FlowSpec route

        flow_nlri1 = self._generate_flow_spec_nlri(TC1)
        event1 = self._new_flow_event(engine.RouteEvent.ADVERTISE, flow_nlri1,
                                      [t.RT5], [t.RT1], worker_a)
        flow_nlri2 = self._generate_flow_spec_nlri(TC2)
        event2 = self._new_flow_event(engine.RouteEvent.ADVERTISE, flow_nlri2,
                                      [t.RT5], [t.RT1], worker_a)

        self.assertEqual(2, self.manager.redirect_traffic_to_vpn.call_count)

        self._reset_mocks_vpnmanager()

        self._revert_event(event2)

        redirect_rt5 = t._rt_to_string(t.RT5)
        self.assertNotIn(TC2,
                         self.vpn.redirect_rt_2_classifiers[redirect_rt5])

        self._revert_event(event1)

        self.assertTrue(not self.vpn.redirect_rt_2_classifiers)
        self.manager.stop_redirect_to_vpn.assert_called_once()

    def test_load_balancing_single_prefix_advertise(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1, [t.RT3],
                              worker_a, t.NH1, 200)

        self._check_attract_traffic('_advertise_route',
                                    ATTRACT_TRAFFIC_1['redirect_rts'],
                                    [None, None, TC1])

    def test_load_balancing_single_prefix_withdraw(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        event1 = self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1,
                                       [t.RT3], worker_a, t.NH1, 200)

        self.assertEqual(3, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        self._revert_event(event1)

        self._check_attract_traffic('_withdraw_route',
                                    ATTRACT_TRAFFIC_1['redirect_rts'],
                                    [None, None, TC1])

    def test_load_balancing_multiple_prefix_advertise(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1, [t.RT3],
                              worker_a, t.NH1, 200)

        vpn_nlri2 = self._generate_route_nlri(IP_ADDR_PREFIX2)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri2, [t.RT3],
                              worker_a, t.NH1, 200)

        self._check_attract_traffic(
            '_advertise_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [None, None, TC1, TC2])

    def test_load_balancing_multiple_prefix_withdraw(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        event1 = self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1,
                                       [t.RT3], worker_a, t.NH1, 200)

        vpn_nlri2 = self._generate_route_nlri(IP_ADDR_PREFIX2)
        event2 = self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri2,
                                       [t.RT3], worker_a, t.NH1, 200)

        self.assertEqual(4, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        self._revert_event(event2)
        self._revert_event(event1)

        self._check_attract_traffic(
            '_withdraw_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [TC2, None, None, TC1])

    def test_load_balancing_new_plug(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1, [t.RT3],
                              worker_a, t.NH1, 200)

        self.assertEqual(3, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        self.vpn.vif_plugged(MAC3, IP3, LOCAL_PORT1)

        self._check_attract_traffic(
            '_advertise_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [None, None])

    def test_load_balancing_unplug_all(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1, [t.RT3],
                              worker_a, t.NH1, 200)

        self.assertEqual(3, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        self.vpn.vif_unplugged(MAC1, IP1)

        self._check_attract_traffic(
            '_withdraw_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [None, None])

        self._reset_mocks()

        self.vpn.vif_unplugged(MAC2, IP2)

        self._check_attract_traffic(
            '_withdraw_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [None, TC1, None])

    def test_cleanup_assist(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(engine.RouteEvent.ADVERTISE, vpn_nlri1,
                              [t.RT1], worker_a, t.NH1, 200)

        # FlowSpec route
        flow_nlri1 = self._generate_flow_spec_nlri(TC1)
        self._new_flow_event(engine.RouteEvent.ADVERTISE, flow_nlri1,
                             [t.RT5], [t.RT1], worker_a)

        self.mock_dp.needs_cleanup_assist.return_value = False

        with mock.patch.object(self.vpn, 'best_route_removed') as mock_brr:
            self.vpn.stop()
            mock_brr.assert_called_once()
            self.assertIsInstance(mock_brr.call_args[0][1].nlri,
                                  flowspec.Flow)
