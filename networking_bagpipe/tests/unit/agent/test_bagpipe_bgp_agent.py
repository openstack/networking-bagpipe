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

import copy

import mock

from oslo_config import cfg

from oslo_utils import uuidutils

from networking_bagpipe.agent.bagpipe_bgp_agent import BAGPIPE_NOTIFIER
from networking_bagpipe.agent.bagpipe_bgp_agent import BAGPIPE_NOTIFIERS

from networking_bagpipe.agent.bagpipe_bgp_agent import BaGPipeBGPAgent
from networking_bagpipe.agent.bagpipe_bgp_agent import BaGPipeBGPException

from networking_bagpipe.agent.bagpipe_bgp_agent import BGPVPN_L2
from networking_bagpipe.agent.bagpipe_bgp_agent import BGPVPN_L3
from networking_bagpipe.agent.bagpipe_bgp_agent import BGPVPN_NOTIFIER
from networking_bagpipe.agent.bagpipe_bgp_agent import BGPVPN_TYPES
from networking_bagpipe.agent.bagpipe_bgp_agent import BGPVPN_TYPES_MAP
from networking_bagpipe.agent.bagpipe_bgp_agent import EVPN
from networking_bagpipe.agent.bagpipe_bgp_agent import IPVPN
from networking_bagpipe.agent.bagpipe_bgp_agent import VPN_TYPES

from neutron.plugins.ml2.drivers.linuxbridge.agent.linuxbridge_neutron_agent \
    import LinuxBridgeManager
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_agent_extension_api as agent_ext_api

from neutron.tests import base
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent import (
    ovs_test_base)

from neutron_lib import constants as n_const

import logging

LOG = logging.getLogger(__name__)

PATCH_TUN_TO_MPLS_OFPORT = 1
PATCH_TUN_FROM_MPLS_OFPORT = 3
PATCH_TUN_OFPORTS = [PATCH_TUN_TO_MPLS_OFPORT, PATCH_TUN_FROM_MPLS_OFPORT]

PATCH_INT_TO_MPLS_OFPORT = 5
PATCH_INT_OFPORTS = [PATCH_INT_TO_MPLS_OFPORT]

PATCH_MPLS_FROM_TUN_OFPORT = 2
PATCH_MPLS_TO_TUN_OFPORT = 4
PATCH_MPLS_TO_INT_OFPORT = 6
PATCH_MPLS_OFPORTS = [PATCH_MPLS_FROM_TUN_OFPORT, PATCH_MPLS_TO_TUN_OFPORT,
                      PATCH_MPLS_TO_INT_OFPORT]

PORT10 = {'id': uuidutils.generate_uuid(),
          'mac_address': '00:00:de:ad:be:ef',
          'ip_address': '10.0.0.2'}

PORT11 = {'id': uuidutils.generate_uuid(),
          'mac_address': '00:00:de:ad:f0:0d',
          'ip_address': '10.0.0.3'}

NETWORK1 = {'id': uuidutils.generate_uuid(),
            'gateway_ip': '10.0.0.1'}

PORT20 = {'id': uuidutils.generate_uuid(),
          'mac_address': '00:00:de:ad:be:ef',
          'ip_address': '20.0.0.2'}

PORT21 = {'id': uuidutils.generate_uuid(),
          'mac_address': '00:00:de:ad:f0:0d',
          'ip_address': '20.0.0.3'}

NETWORK2 = {'id': uuidutils.generate_uuid(),
            'gateway_ip': '20.0.0.1'}

LOCAL_VLAN_MAP = {}
LOCAL_VLAN_MAP[PORT10['id']] = 31
LOCAL_VLAN_MAP[PORT11['id']] = 31
LOCAL_VLAN_MAP[PORT20['id']] = 52
LOCAL_VLAN_MAP[PORT21['id']] = 52

BAGPIPE_EVPN_RT1 = {'import_rt': ['BAGPIPE_EVPN:1'],
                    'export_rt': ['BAGPIPE_EVPN:1']}

BAGPIPE_EVPN_RT2 = {'import_rt': ['BAGPIPE_EVPN:2'],
                    'export_rt': ['BAGPIPE_EVPN:2']}

BGPVPN_EVPN_RT10 = {'import_rt': ['BGPVPN_EVPN:10'],
                    'export_rt': ['BGPVPN_EVPN:10']}

BGPVPN_EVPN_RT20 = {'import_rt': ['BGPVPN_EVPN:20'],
                    'export_rt': ['BGPVPN_EVPN:20']}

BGPVPN_IPVPN_RT100 = {'import_rt': ['BGPVPN_IPVPN:100'],
                      'export_rt': ['BGPVPN_IPVPN:100']}

BGPVPN_IPVPN_RT200 = {'import_rt': ['BGPVPN_IPVPN:200'],
                      'export_rt': ['BGPVPN_IPVPN:200']}


class DummyPort(object):
    def __init__(self, network, port, evpn=None, ipvpn=None):
        self.id = port['id']
        self.network_id = network['id']
        self.mac_address = port['mac_address']
        self.ip_address = port['ip_address']
        self.gateway_ip = network['gateway_ip']

        if evpn:
            self.evpn = evpn

        if ipvpn:
            self.ipvpn = ipvpn


class DummyVif(object):
    def __init__(self, ofport, port_name):
        self.ofport = ofport
        self.port_name = port_name


class DummyBGPVPN(object):
    def __init__(self, network, evpn=None, ipvpn=None, gateway_mac=None):
        self.network_id = network['id']

        if evpn:
            self.evpn = evpn

        if ipvpn:
            self.ipvpn = ipvpn

        if gateway_mac:
            self.gateway_mac = gateway_mac


class TestBaGPipeBGPAgentMixin(object):

    DUMMY_VIF10 = None
    DUMMY_VIF11 = None
    DUMMY_VIF20 = None
    DUMMY_VIF21 = None

    def _get_expected_local_port(self, network_id, port_id, vif_name):
        raise NotImplementedError

    def _get_expected_route_target(self, vpn_type, port, others_rts,
                                   others_last):
        if others_rts:
            others_import = others_rts.get('import_rt')
            others_export = others_rts.get('export_rt')
        else:
            others_import = []
            others_export = []

        if vpn_type in port:
            import_rt = list(port[vpn_type]['import_rt'])
            export_rt = list(port[vpn_type]['export_rt'])
        else:
            import_rt = []
            export_rt = []

        if others_last:
            import_rt += others_import
            export_rt += others_export
        else:
            import_rt = others_import + import_rt
            export_rt = others_export + export_rt

        return import_rt, export_rt

    def _mock_send_expected_call(self, vpn_type, port, vif, evpn2ipvpn=False,
                                 others_rts=None, others_last=False,
                                 fallback=None):
        network_id = port['network_id']

        vif_name = vif.port_name if vif else None
        local_port, linuxbr = self._get_expected_local_port(network_id,
                                                            port['id'],
                                                            vif_name)
        # Change local port if plugging evpn into ipvpn
        if evpn2ipvpn:
            local_port = dict(evpn=dict(id=network_id + '_evpn'))

        import_rt, export_rt = self._get_expected_route_target(vpn_type,
                                                               port,
                                                               others_rts,
                                                               others_last)

        expected_call = dict(vpn_instance_id=network_id + '_' + vpn_type,
                             vpn_type=vpn_type,
                             local_port=local_port,
                             mac_address=port['mac_address'],
                             ip_address=port['ip_address'],
                             gateway_ip=port['gateway_ip'],
                             import_rt=import_rt,
                             export_rt=export_rt)

        if linuxbr:
            expected_call.update(dict(
                linuxbr=LinuxBridgeManager.get_bridge_name(network_id))
            )
        if fallback:
            expected_call.update({'fallback': fallback})

        return mock.call(expected_call)

    def _check_network_attachments(self, network_id, expected_size,
                                   notifiers=BAGPIPE_NOTIFIERS,
                                   vpn_types=VPN_TYPES):
        if expected_size == 0:
            self.assertNotIn(network_id, self.agent.reg_attachments,
                             "Network %s expected to have no attachments left"
                             % network_id)
        else:
            self.assertIn(network_id, self.agent.reg_attachments)
            attachments = self.agent.reg_attachments[network_id]
            self.assertEqual(len(attachments), expected_size,
                             "Network attachments size not as expected")
            for attachment in attachments:
                for notifier in notifiers:
                    self.assertIn(notifier, attachment,
                                  "No %s details found in attachment %s" %
                                  (notifier, attachment))
                    for vpn_type in vpn_types:
                        self.assertIn(vpn_type, attachment[notifier],
                                      "No %s %s details found in "
                                      "attachment %s" % (notifier,
                                                         vpn_type,
                                                         attachment))

    # ----------------------------
    # BaGPipe RPC notifier tests |
    # ----------------------------
    def test_bagpipe_attach_single_port(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BAGPIPE_EVPN_RT1).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bagpipe_port_attach(None, dummy_port10)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BAGPIPE_NOTIFIER],
                                            [EVPN])

    def test_bagpipe_attach_same_port_different_route_target(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BAGPIPE_EVPN_RT1).__dict__
        dummy_port10bis = DummyPort(NETWORK1, PORT10,
                                    evpn=BAGPIPE_EVPN_RT2).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              dummy_port10bis,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bagpipe_port_attach(None, dummy_port10)
            self.agent.bagpipe_port_attach(None, dummy_port10bis)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BAGPIPE_NOTIFIER],
                                            [EVPN])

    def test_bagpipe_attach_multiple_ports_same_network(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BAGPIPE_EVPN_RT1).__dict__
        dummy_port11 = DummyPort(NETWORK1, PORT11,
                                 evpn=BAGPIPE_EVPN_RT1).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              dummy_port11,
                                              self.DUMMY_VIF11)
            ]

            self.agent.bagpipe_port_attach(None, dummy_port10)
            self.agent.bagpipe_port_attach(None, dummy_port11)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'],
                                            2,
                                            [BAGPIPE_NOTIFIER],
                                            [EVPN])

    def test_bagpipe_attach_multiple_ports_different_networks(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BAGPIPE_EVPN_RT1).__dict__
        dummy_port20 = DummyPort(NETWORK2, PORT20,
                                 evpn=BAGPIPE_EVPN_RT2).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              dummy_port20,
                                              self.DUMMY_VIF20)
            ]

            self.agent.bagpipe_port_attach(None, dummy_port10)
            self.agent.bagpipe_port_attach(None, dummy_port20)

            send_attach_fn.assert_has_calls(expected_calls)

            for network_id in [NETWORK1['id'], NETWORK2['id']]:
                self._check_network_attachments(network_id,
                                                1,
                                                [BAGPIPE_NOTIFIER],
                                                [EVPN])

    def test_bagpipe_detach_single_port(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BAGPIPE_EVPN_RT1).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bagpipe_port_attach(None, dummy_port10)
            self.agent.bagpipe_port_detach(None, dummy_detach10)

            send_detach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'], 0)
            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)

    def test_bagpipe_detach_multiple_ports_same_network(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BAGPIPE_EVPN_RT1).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        dummy_port11 = DummyPort(NETWORK1, PORT11,
                                 evpn=BAGPIPE_EVPN_RT1).__dict__
        dummy_detach11 = dict(id=PORT11['id'], network_id=NETWORK1['id'])

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              dummy_port11,
                                              self.DUMMY_VIF11)
            ]

            # Attach 2 ports on network 1
            self.agent.bagpipe_port_attach(None, dummy_port10)
            self.agent.bagpipe_port_attach(None, dummy_port11)

            # Detach 1 port from network 1
            self.agent.bagpipe_port_detach(None, dummy_detach10)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BAGPIPE_NOTIFIER],
                                            [EVPN])

            # Detach remaining port from network 1
            self.agent.bagpipe_port_detach(None, dummy_detach11)

            # Check if calls on BaGPipe BGP API are as expected
            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'], 0)
            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)

    def test_bagpipe_detach_multiple_ports_different_networks(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BAGPIPE_EVPN_RT1).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        dummy_port11 = DummyPort(NETWORK1, PORT11,
                                 evpn=BAGPIPE_EVPN_RT1).__dict__
        dummy_detach11 = dict(id=PORT11['id'], network_id=NETWORK1['id'])

        dummy_port20 = DummyPort(NETWORK2, PORT20,
                                 evpn=BAGPIPE_EVPN_RT2).__dict__
        dummy_detach20 = dict(id=PORT20['id'], network_id=NETWORK2['id'])

        dummy_port21 = DummyPort(NETWORK2, PORT21,
                                 evpn=BAGPIPE_EVPN_RT2).__dict__
        dummy_detach21 = dict(id=PORT21['id'], network_id=NETWORK2['id'])

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              dummy_port20,
                                              self.DUMMY_VIF20),
                self._mock_send_expected_call(EVPN,
                                              dummy_port11,
                                              self.DUMMY_VIF11),
                self._mock_send_expected_call(EVPN,
                                              dummy_port21,
                                              self.DUMMY_VIF21)
            ]

            # Attach 2 ports on network 1
            self.agent.bagpipe_port_attach(None, dummy_port10)
            self.agent.bagpipe_port_attach(None, dummy_port11)

            # Attach 2 ports on network 2
            self.agent.bagpipe_port_attach(None, dummy_port20)
            self.agent.bagpipe_port_attach(None, dummy_port21)

            # Detach 1 port from each network
            self.agent.bagpipe_port_detach(None, dummy_detach10)
            self.agent.bagpipe_port_detach(None, dummy_detach20)

            # Verify attachments list consistency
            for network_id in [NETWORK1['id'], NETWORK2['id']]:
                self._check_network_attachments(network_id,
                                                1,
                                                [BAGPIPE_NOTIFIER],
                                                [EVPN])

            # Detach remaining port from each network
            self.agent.bagpipe_port_detach(None, dummy_detach11)
            self.agent.bagpipe_port_detach(None, dummy_detach21)

            # Check if calls on BaGPipe BGP API are as expected
            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            for network_id in [NETWORK1['id'], NETWORK2['id']]:
                self._check_network_attachments(network_id, 0)

            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)

    # ----------------------------
    # BGP VPN RPC notifier tests |
    # ----------------------------
    def test_update_bgpvpn_no_plugged_ports(self):
        dummy_bgpvpn1 = DummyBGPVPN(NETWORK1,
                                    evpn=BGPVPN_EVPN_RT10).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            self.agent.update_bgpvpn(None, dummy_bgpvpn1)

            self.assertEqual(0, send_attach_fn.call_count,
                             "Send attach mustn't be called")

    def test_update_bgpvpn_already_plugged_ports(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10).__dict__
        dummy_port11 = DummyPort(NETWORK1, PORT11).__dict__

        dummy_bgpvpn1 = DummyBGPVPN(NETWORK1,
                                    ipvpn=BGPVPN_IPVPN_RT100).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(IPVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=BGPVPN_IPVPN_RT100),
                self._mock_send_expected_call(IPVPN,
                                              dummy_port11,
                                              self.DUMMY_VIF11,
                                              others_rts=BGPVPN_IPVPN_RT100)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port11)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'], 2,
                                            [BGPVPN_NOTIFIER])

            self.agent.update_bgpvpn(None, dummy_bgpvpn1)

            send_attach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'], 2,
                                            [BGPVPN_NOTIFIER])

    def test_update_bgpvpn_same_vpn_types(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BGPVPN_EVPN_RT10).__dict__

        dummy_port10bis = DummyPort(NETWORK1, PORT10,
                                    evpn=BGPVPN_EVPN_RT20).__dict__

        evpn_rts = ({k: BGPVPN_EVPN_RT10[k] + BGPVPN_EVPN_RT20[k]
                    for k in ['import_rt', 'export_rt']})

        dummy_bgpvpn1 = DummyBGPVPN(NETWORK1,
                                    evpn=evpn_rts).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              dummy_port10bis,
                                              self.DUMMY_VIF10,
                                              others_rts=BGPVPN_EVPN_RT10)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)

            self.agent.update_bgpvpn(None, dummy_bgpvpn1)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BGPVPN_NOTIFIER])

    def test_update_bgpvpn_different_vpn_types(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BGPVPN_EVPN_RT10).__dict__

        dummy_port10bis = DummyPort(NETWORK1, PORT10,
                                    evpn=BGPVPN_EVPN_RT10,
                                    ipvpn=BGPVPN_IPVPN_RT100).__dict__

        dummy_bgpvpn1 = DummyBGPVPN(NETWORK1,
                                    evpn=BGPVPN_EVPN_RT10,
                                    ipvpn=BGPVPN_IPVPN_RT100).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              dummy_port10bis,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(IPVPN,
                                              dummy_port10bis,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)

            self.agent.update_bgpvpn(None, dummy_bgpvpn1)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BGPVPN_NOTIFIER])

    def test_delete_bgpvpn_remaining_plugged_ports(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BGPVPN_EVPN_RT10).__dict__
        dummy_port11 = DummyPort(NETWORK1, PORT11,
                                 evpn=BGPVPN_EVPN_RT10).__dict__

        dummy_bgpvpn1 = DummyBGPVPN(NETWORK1,
                                    evpn=BGPVPN_EVPN_RT10).__dict__

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              dummy_port11,
                                              self.DUMMY_VIF11)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port11)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'],
                                            2,
                                            [BGPVPN_NOTIFIER])

            self.agent.delete_bgpvpn(None, dummy_bgpvpn1)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'],
                                            2,
                                            [BGPVPN_NOTIFIER])

    def test_delete_bgpvpn_no_plugged_ports(self):
        dummy_bgpvpn1 = DummyBGPVPN(NETWORK1,
                                    evpn=BGPVPN_EVPN_RT10).__dict__

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:
            self.agent.delete_bgpvpn(None, dummy_bgpvpn1)

            self.assertEqual(0, send_detach_fn.call_count,
                             "Send detach mustn't be called")

    def test_delete_bgpvpn_had_plugged_ports(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 ipvpn=BGPVPN_EVPN_RT10).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        dummy_port11 = DummyPort(NETWORK1, PORT11,
                                 ipvpn=BGPVPN_EVPN_RT10).__dict__
        dummy_detach11 = dict(id=PORT11['id'], network_id=NETWORK1['id'])

        dummy_bgpvpn1 = DummyBGPVPN(NETWORK1,
                                    ipvpn=BGPVPN_EVPN_RT10).__dict__

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port11)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)
            self.agent.bgpvpn_port_detach(None, dummy_detach11)

            self.assertEqual(2, send_detach_fn.call_count,
                             "Send detach must be called twice")

            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)

            send_detach_fn.reset_mock()
            self.agent.delete_bgpvpn(None, dummy_bgpvpn1)

            self.assertEqual(0, send_detach_fn.call_count,
                             "Send detach ustn't be called")

    def _test_bgpvpn_attach_single_port(self, bgpvpn_type, bgpvpn_rts):
        mapped_type = (BGPVPN_TYPES_MAP[bgpvpn_type] if bgpvpn_type in
                       BGPVPN_TYPES else bgpvpn_type)
        bgpvpn_info = {mapped_type: bgpvpn_rts}
        dummy_port10 = DummyPort(NETWORK1, PORT10, **bgpvpn_info).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(mapped_type,
                                              dummy_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BGPVPN_NOTIFIER],
                                            [mapped_type])

    def test_bgpvpn_attach_single_port_l3_bgpvpn1(self):
        self._test_bgpvpn_attach_single_port(BGPVPN_L3, BGPVPN_IPVPN_RT100)

    def test_bgpvpn_attach_single_port_l3_bgpvpn2(self):
        self._test_bgpvpn_attach_single_port(IPVPN, BGPVPN_IPVPN_RT100)

    def test_bgpvpn_attach_single_port_bgpvpn1(self):
        self._test_bgpvpn_attach_single_port(BGPVPN_L2, BGPVPN_EVPN_RT10)

    def test_bgpvpn_attach_single_port_bgpvpn2(self):
        self._test_bgpvpn_attach_single_port(EVPN, BGPVPN_EVPN_RT10)

    def test_bgpvpn_attach_same_port_different_bgpvpn(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BGPVPN_EVPN_RT10).__dict__
        dummy_port10bis = DummyPort(NETWORK1, PORT10,
                                    evpn=BGPVPN_EVPN_RT10,
                                    ipvpn=BGPVPN_IPVPN_RT100).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              dummy_port10bis,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(IPVPN,
                                              dummy_port10bis,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)

            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BGPVPN_NOTIFIER],
                                            [EVPN])

            self.agent.bgpvpn_port_attach(None, dummy_port10bis)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BGPVPN_NOTIFIER])

    def test_bgpvpn_attach_single_port_multiple_bgpvpns(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BGPVPN_EVPN_RT10,
                                 ipvpn=BGPVPN_IPVPN_RT100).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(IPVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BGPVPN_NOTIFIER],
                                            [EVPN, IPVPN])

    def test_bgpvpn_attach_multiple_ports_same_bgpvpn(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 ipvpn=BGPVPN_IPVPN_RT100).__dict__
        dummy_port11 = DummyPort(NETWORK1, PORT11,
                                 ipvpn=BGPVPN_IPVPN_RT100).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(IPVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(IPVPN,
                                              dummy_port11,
                                              self.DUMMY_VIF11)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port11)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'],
                                            2,
                                            [BGPVPN_NOTIFIER],
                                            [IPVPN])

    def test_bgpvpn_attach_multiple_ports_different_bgpvpns(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 ipvpn=BGPVPN_IPVPN_RT100).__dict__
        dummy_port20 = DummyPort(NETWORK2, PORT20,
                                 ipvpn=BGPVPN_IPVPN_RT200).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(IPVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(IPVPN,
                                              dummy_port20,
                                              self.DUMMY_VIF20)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port20)

            send_attach_fn.assert_has_calls(expected_calls)

            for network_id in [NETWORK1['id'], NETWORK2['id']]:
                self._check_network_attachments(network_id,
                                                1,
                                                [BGPVPN_NOTIFIER],
                                                [IPVPN])

    def _test_bgpvpn_detach_single_port(self, bgpvpn_type, bgpvpn_rts):
        bgpvpn_info = {bgpvpn_type: bgpvpn_rts}
        dummy_port10 = DummyPort(NETWORK1, PORT10, **bgpvpn_info).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(bgpvpn_type,
                                              dummy_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_detach(None, dummy_detach10)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)

    def test_bgpvpn_detach_single_port_l3_bgpvpn(self):
        self._test_bgpvpn_detach_single_port(IPVPN, BGPVPN_IPVPN_RT100)

    def test_bgpvpn_detach_single_port_bgpvpn(self):
        self._test_bgpvpn_detach_single_port(EVPN, BGPVPN_EVPN_RT10)

    def test_bgpvpn_detach_single_port_multiple_bgpvpns(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 evpn=BGPVPN_EVPN_RT10,
                                 ipvpn=BGPVPN_IPVPN_RT100).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(IPVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True),
                self._mock_send_expected_call(EVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_detach(None, dummy_detach10)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)

    def test_bgpvpn_detach_multiple_ports_same_bgpvpn(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 ipvpn=BGPVPN_IPVPN_RT100).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        dummy_port11 = DummyPort(NETWORK1, PORT11,
                                 ipvpn=BGPVPN_IPVPN_RT100).__dict__
        dummy_detach11 = dict(id=PORT11['id'], network_id=NETWORK1['id'])

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(IPVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(IPVPN,
                                              dummy_port11,
                                              self.DUMMY_VIF11)
            ]

            # Attach 2 ports on BGP VPN L3 1
            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port11)

            # Detach 1 port from BGP VPN L3 1
            self.agent.bgpvpn_port_detach(None, dummy_detach10)

            # Detach remaining port from BGP VPN L3 1
            self.agent.bgpvpn_port_detach(None, dummy_detach11)

            # Check if calls on BaGPipe BGP API are as expected
            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)

    def test_bgpvpn_detach_multiple_ports_different_bgpvpns(self):
        dummy_port10 = DummyPort(NETWORK1, PORT10,
                                 ipvpn=BGPVPN_IPVPN_RT100).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        dummy_port20 = DummyPort(NETWORK2, PORT20,
                                 ipvpn=BGPVPN_IPVPN_RT200).__dict__
        dummy_detach20 = dict(id=PORT20['id'], network_id=NETWORK2['id'])

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(IPVPN,
                                              dummy_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(IPVPN,
                                              dummy_port20,
                                              self.DUMMY_VIF20)
            ]

            self.agent.bgpvpn_port_attach(None, dummy_port10)
            self.agent.bgpvpn_port_attach(None, dummy_port20)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)
            self.agent.bgpvpn_port_detach(None, dummy_detach20)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            for network_id in [NETWORK1['id'], NETWORK2['id']]:
                self._check_network_attachments(network_id, 0)

            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)

    # -------------------------------------------
    # Multiple simultaneous RPC notifiers tests |
    # -------------------------------------------
    def test_multiple_attach_single_port_evpns(self):
        bagpipe_port10 = DummyPort(NETWORK1, PORT10,
                                   evpn=BAGPIPE_EVPN_RT1).__dict__
        bgpvpn_port10 = DummyPort(NETWORK1, PORT10,
                                  evpn=BGPVPN_EVPN_RT10).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=BAGPIPE_EVPN_RT1)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BAGPIPE_NOTIFIER,
                                             BGPVPN_NOTIFIER],
                                            [EVPN])

    def test_multiple_attach_single_port_different_vpns(self):
        bagpipe_port10 = DummyPort(NETWORK1, PORT10,
                                   evpn=BAGPIPE_EVPN_RT1).__dict__
        bgpvpn_port10 = DummyPort(NETWORK1, PORT10,
                                  ipvpn=BGPVPN_IPVPN_RT100).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(IPVPN,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BAGPIPE_NOTIFIER],
                                            [EVPN])
            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BGPVPN_NOTIFIER],
                                            [IPVPN])

    def test_multiple_attach_multiple_ports_same_evpns(self):
        bagpipe_port10 = DummyPort(NETWORK1, PORT10,
                                   evpn=BAGPIPE_EVPN_RT1).__dict__
        bgpvpn_port10 = DummyPort(NETWORK1, PORT10,
                                  evpn=BGPVPN_EVPN_RT10).__dict__

        bagpipe_port11 = DummyPort(NETWORK1, PORT11,
                                   evpn=BAGPIPE_EVPN_RT1).__dict__
        bgpvpn_port11 = DummyPort(NETWORK1, PORT11,
                                  evpn=BGPVPN_IPVPN_RT100).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=BAGPIPE_EVPN_RT1),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port11,
                                              self.DUMMY_VIF11),
                self._mock_send_expected_call(EVPN,
                                              bgpvpn_port11,
                                              self.DUMMY_VIF11,
                                              others_rts=BAGPIPE_EVPN_RT1)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bagpipe_port_attach(None, bagpipe_port11)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port11)

            send_attach_fn.assert_has_calls(expected_calls)

            self._check_network_attachments(NETWORK1['id'],
                                            2,
                                            BAGPIPE_NOTIFIERS,
                                            [EVPN])

    def test_multiple_attach_multiple_ports_different_evpns(self):
        bagpipe_port10 = DummyPort(NETWORK1, PORT10,
                                   evpn=BAGPIPE_EVPN_RT1).__dict__
        bgpvpn_port10 = DummyPort(NETWORK1, PORT10,
                                  evpn=BGPVPN_EVPN_RT10).__dict__

        bagpipe_port20 = DummyPort(NETWORK2, PORT20,
                                   evpn=BAGPIPE_EVPN_RT2).__dict__
        bgpvpn_port20 = DummyPort(NETWORK2, PORT20,
                                  evpn=BGPVPN_EVPN_RT20).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=BAGPIPE_EVPN_RT1),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port20,
                                              self.DUMMY_VIF20),
                self._mock_send_expected_call(EVPN,
                                              bgpvpn_port20,
                                              self.DUMMY_VIF20,
                                              others_rts=BAGPIPE_EVPN_RT2)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bagpipe_port_attach(None, bagpipe_port20)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port20)

            send_attach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            for network_id in [NETWORK1['id'], NETWORK2['id']]:
                self._check_network_attachments(network_id,
                                                1,
                                                BAGPIPE_NOTIFIERS,
                                                [EVPN])

    def test_multiple_attach_multiple_ports_different_vpns(self):
        bagpipe_port10 = DummyPort(NETWORK1, PORT10,
                                   evpn=BAGPIPE_EVPN_RT1).__dict__
        bgpvpn_port10 = DummyPort(NETWORK1, PORT10,
                                  ipvpn=BGPVPN_IPVPN_RT100).__dict__

        bagpipe_port20 = DummyPort(NETWORK2, PORT20,
                                   evpn=BAGPIPE_EVPN_RT2).__dict__
        bgpvpn_port20 = DummyPort(NETWORK2, PORT20,
                                  ipvpn=BGPVPN_IPVPN_RT200).__dict__

        with mock.patch.object(self.agent,
                               'send_attach_local_port') as send_attach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(IPVPN,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port20,
                                              self.DUMMY_VIF20),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port20,
                                              self.DUMMY_VIF20),
                self._mock_send_expected_call(IPVPN,
                                              bgpvpn_port20,
                                              self.DUMMY_VIF20,
                                              evpn2ipvpn=True)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bagpipe_port_attach(None, bagpipe_port20)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port20)

            send_attach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            for network_id in [NETWORK1['id'], NETWORK2['id']]:
                self._check_network_attachments(network_id,
                                                1,
                                                [BAGPIPE_NOTIFIER],
                                                [EVPN])
                self._check_network_attachments(network_id,
                                                1,
                                                [BGPVPN_NOTIFIER],
                                                [IPVPN])

    def test_multiple_detach_single_port_evpns1(self):
        bagpipe_port10 = DummyPort(NETWORK1, PORT10,
                                   evpn=BAGPIPE_EVPN_RT1).__dict__
        bgpvpn_port10 = DummyPort(NETWORK1, PORT10,
                                  evpn=BGPVPN_EVPN_RT10).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=BAGPIPE_EVPN_RT1),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BAGPIPE_NOTIFIER],
                                            [EVPN])

            self.agent.bagpipe_port_detach(None, dummy_detach10)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)

    def test_multiple_detach_single_port_evpns2(self):
        bagpipe_port10 = DummyPort(NETWORK1, PORT10,
                                   evpn=BAGPIPE_EVPN_RT1).__dict__
        bgpvpn_port10 = DummyPort(NETWORK1, PORT10,
                                  evpn=BGPVPN_EVPN_RT10).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        with mock.patch.object(
            self.agent,
            'send_detach_local_port',
            side_effect=[None, BaGPipeBGPException(reason="Port not plugged")]
        ) as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=BGPVPN_EVPN_RT10,
                                              others_last=True),
                self._mock_send_expected_call(EVPN,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bagpipe_port_detach(None, dummy_detach10)
            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'],
                                            1,
                                            [BGPVPN_NOTIFIER],
                                            [EVPN])

            self.agent.bgpvpn_port_detach(None, dummy_detach10)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)

    def test_multiple_detach_single_port_different_vpns(self):
        bagpipe_port10 = DummyPort(NETWORK1, PORT10,
                                   evpn=BAGPIPE_EVPN_RT1).__dict__
        bgpvpn_port10 = DummyPort(NETWORK1, PORT10,
                                  ipvpn=BGPVPN_IPVPN_RT100).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(IPVPN,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10)
            ]

            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)
            self.agent.bagpipe_port_attach(None, bagpipe_port10)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)
            self.agent.bagpipe_port_detach(None, dummy_detach10)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)

    def test_multiple_detach_multiple_ports_same_evpns(self):
        bagpipe_port10 = DummyPort(NETWORK1, PORT10,
                                   evpn=BAGPIPE_EVPN_RT1).__dict__
        bgpvpn_port10 = DummyPort(NETWORK1, PORT10,
                                  evpn=BGPVPN_EVPN_RT10).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        bagpipe_port11 = DummyPort(NETWORK1, PORT11,
                                   evpn=BAGPIPE_EVPN_RT1).__dict__
        bgpvpn_port11 = DummyPort(NETWORK1, PORT11,
                                  evpn=BGPVPN_EVPN_RT10).__dict__
        dummy_detach11 = dict(id=PORT11['id'], network_id=NETWORK1['id'])

        with mock.patch.object(self.agent,
                               'send_detach_local_port') as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(EVPN,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              others_rts=BAGPIPE_EVPN_RT1),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              bgpvpn_port11,
                                              self.DUMMY_VIF11,
                                              others_rts=BAGPIPE_EVPN_RT1),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port11,
                                              self.DUMMY_VIF11)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bagpipe_port_attach(None, bagpipe_port11)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port11)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)
            self.agent.bagpipe_port_detach(None, dummy_detach10)

            self.agent.bgpvpn_port_detach(None, dummy_detach11)
            self.agent.bagpipe_port_detach(None, dummy_detach11)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            self._check_network_attachments(NETWORK1['id'], 0)

            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)

    def test_multiple_detach_multiple_ports_different_vpns(self):
        bagpipe_port10 = DummyPort(NETWORK1, PORT10,
                                   evpn=BAGPIPE_EVPN_RT1).__dict__
        bgpvpn_port10 = DummyPort(NETWORK1, PORT10,
                                  ipvpn=BGPVPN_IPVPN_RT100).__dict__
        dummy_detach10 = dict(id=PORT10['id'], network_id=NETWORK1['id'])

        bagpipe_port20 = DummyPort(NETWORK2, PORT20,
                                   evpn=BAGPIPE_EVPN_RT2).__dict__
        bgpvpn_port20 = DummyPort(NETWORK2, PORT20,
                                  ipvpn=BGPVPN_IPVPN_RT200).__dict__
        dummy_detach20 = dict(id=PORT20['id'], network_id=NETWORK2['id'])

        with mock.patch.object(
            self.agent,
            'send_detach_local_port',
            side_effect=[None, None,
                         BaGPipeBGPException(reason="Port not plugged"),
                         None, None,
                         BaGPipeBGPException(reason="Port not plugged")]
        ) as send_detach_fn:
            expected_calls = [
                self._mock_send_expected_call(IPVPN,
                                              bgpvpn_port10,
                                              self.DUMMY_VIF10,
                                              evpn2ipvpn=True),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port10,
                                              self.DUMMY_VIF10),
                self._mock_send_expected_call(IPVPN,
                                              bgpvpn_port20,
                                              self.DUMMY_VIF20,
                                              evpn2ipvpn=True),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port20,
                                              self.DUMMY_VIF20),
                self._mock_send_expected_call(EVPN,
                                              bagpipe_port20,
                                              self.DUMMY_VIF20)
            ]

            self.agent.bagpipe_port_attach(None, bagpipe_port10)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port10)

            self.agent.bagpipe_port_attach(None, bagpipe_port20)
            self.agent.bgpvpn_port_attach(None, bgpvpn_port20)

            self.agent.bgpvpn_port_detach(None, dummy_detach10)
            self.agent.bagpipe_port_detach(None, dummy_detach10)

            self.agent.bgpvpn_port_detach(None, dummy_detach20)
            self.agent.bagpipe_port_detach(None, dummy_detach20)

            send_detach_fn.assert_has_calls(expected_calls)

            # Verify attachments list consistency
            for network_id in [NETWORK1['id'], NETWORK2['id']]:
                self._check_network_attachments(network_id, 0)

            self.assertEqual(0, len(self.agent.reg_attachments),
                             "Registered attachments list must be empty: %s" %
                             self.agent.reg_attachments)


class TestBaGPipeBGPAgentLinuxBridge(base.BaseTestCase,
                                     TestBaGPipeBGPAgentMixin):

    def setUp(self):
        cfg.CONF.set_override('enable_vxlan', False, 'VXLAN')
        super(TestBaGPipeBGPAgentLinuxBridge, self).setUp()

        self.bridge_mappings = {}
        self.interface_mappings = {}

        self.agent = BaGPipeBGPAgent(n_const.AGENT_TYPE_LINUXBRIDGE,
                                     mock.Mock())

    def _get_expected_local_port(self, network_id, port_id, vif_name):
        local_port = dict(
            linuxif=LinuxBridgeManager.get_tap_device_name(port_id)
        )
        linuxbr = LinuxBridgeManager.get_bridge_name(network_id)

        return local_port, linuxbr


class TestBaGPipeBGPAgentOVS(ovs_test_base.OVSOFCtlTestBase,
                             TestBaGPipeBGPAgentMixin):

    DUMMY_VIF10 = DummyVif(10, 'VIF10')
    DUMMY_VIF11 = DummyVif(11, 'VIF11')
    DUMMY_VIF20 = DummyVif(20, 'VIF20')
    DUMMY_VIF21 = DummyVif(21, 'VIF21')

    def setUp(self):
        super(TestBaGPipeBGPAgentOVS, self).setUp()

        self.INT_BRIDGE = 'integration_bridge'
        self.TUN_BRIDGE = 'tunnet_bridge'
        self.MPLS_BRIDGE = 'mpls_bridge'

        self.mock_int_br = mock.Mock()
        self.mock_int_br.add_patch_port = mock.Mock()
        self.mock_int_br.add_patch_port.side_effect = PATCH_INT_OFPORTS
        self.mock_int_br.get_vif_port_by_id = mock.Mock()

        self.mock_tun_br = mock.Mock(spec=agent_ext_api.OVSCookieBridge)
        self.mock_tun_br.add_patch_port = mock.Mock()
        self.mock_tun_br.add_patch_port.side_effect = PATCH_TUN_OFPORTS
        self.mock_tun_br.get_port_ofport = mock.Mock()

        with mock.patch('neutron.agent.common.ovs_lib.OVSBridge.'
                        'bridge_exists', return_value=True), \
                mock.patch('neutron.agent.common.ovs_lib.OVSBridge.'
                           'add_patch_port', side_effect=PATCH_MPLS_OFPORTS):
            self.agent = BaGPipeBGPAgent(n_const.AGENT_TYPE_OVS,
                                         mock.Mock(),
                                         int_br=self.mock_int_br,
                                         tun_br=self.mock_tun_br)
            self.agent.get_local_vlan = (
                lambda port: LOCAL_VLAN_MAP.get(port)
            )

    def _get_expected_local_port(self, network_id, port_id, vif_name):
        vlan = self.agent.get_local_vlan(port_id)
        local_port = dict(
            linuxif=vif_name,
            ovs=dict(plugged=True,
                     port_number=PATCH_MPLS_FROM_TUN_OFPORT,
                     to_vm_port_number=PATCH_MPLS_TO_TUN_OFPORT,
                     vlan=vlan)
        )

        return local_port, None

    def test_bagpipe_attach_single_port(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bagpipe_attach_single_port()

    def test_bagpipe_attach_same_port_different_route_target(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bagpipe_attach_same_port_different_route_target()

    def test_bagpipe_attach_multiple_ports_same_network(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bagpipe_attach_multiple_ports_same_network()

    def test_bagpipe_attach_multiple_ports_different_networks(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF20]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bagpipe_attach_multiple_ports_different_networks()

    def test_bagpipe_detach_single_port(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bagpipe_detach_single_port()

    def test_bagpipe_detach_multiple_ports_same_network(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bagpipe_detach_multiple_ports_same_network()

    def test_bagpipe_detach_multiple_ports_different_networks(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11,
                                            self.DUMMY_VIF20,
                                            self.DUMMY_VIF21]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bagpipe_detach_multiple_ports_different_networks()

    # ----------------------------
    # BGP VPN RPC notifier tests |
    # ----------------------------
    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_update_bgpvpn_already_plugged_ports(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_update_bgpvpn_already_plugged_ports()
            self.assertEqual(2, gw_redir_fn.call_count)

    def test_update_bgpvpn_same_vpn_types(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_update_bgpvpn_same_vpn_types()

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_update_bgpvpn_different_vpn_types(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_update_bgpvpn_different_vpn_types()
            self.assertEqual(1, gw_redir_fn.call_count)

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_delete_bgpvpn_remaining_plugged_ports(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_delete_bgpvpn_remaining_plugged_ports()

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_delete_bgpvpn_had_plugged_ports(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_delete_bgpvpn_had_plugged_ports()

            self.assertEqual(2, gw_redir_fn.call_count)

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def _test_bgpvpn_attach_single_port(self, bgpvpn, network,
                                        gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self)._test_bgpvpn_attach_single_port(bgpvpn, network)
            self.assertEqual(1 if (bgpvpn == IPVPN or
                                   bgpvpn == BGPVPN_L3) else 0,
                             gw_redir_fn.call_count)

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_bgpvpn_attach_same_port_different_bgpvpn(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bgpvpn_attach_same_port_different_bgpvpn()
            self.assertEqual(1, gw_redir_fn.call_count)

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_bgpvpn_attach_single_port_multiple_bgpvpns(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bgpvpn_attach_single_port_multiple_bgpvpns()
            self.assertEqual(1, gw_redir_fn.call_count)

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_bgpvpn_attach_multiple_ports_same_bgpvpn(self, gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bgpvpn_attach_multiple_ports_same_bgpvpn()
            self.assertEqual(2, gw_redir_fn.call_count)

    @mock.patch('networking_bagpipe.agent.bagpipe_bgp_agent'
                '.BaGPipeBGPAgent._enable_gw_redirect',
                autospec=True)
    def test_bgpvpn_attach_multiple_ports_different_bgpvpns(self,
                                                            gw_redir_fn):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF20]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bgpvpn_attach_multiple_ports_different_bgpvpns()
            self.assertEqual(2, gw_redir_fn.call_count)

    def _test_bgpvpn_detach_single_port(self, bgpvpn, network):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self)._test_bgpvpn_detach_single_port(bgpvpn, network)

    def test_bgpvpn_detach_single_port_multiple_bgpvpns(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bgpvpn_detach_single_port_multiple_bgpvpns()

    def test_bgpvpn_detach_multiple_ports_same_bgpvpn(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bgpvpn_detach_multiple_ports_same_bgpvpn()

    def test_bgpvpn_detach_multiple_ports_different_bgpvpns(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF20]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_bgpvpn_detach_multiple_ports_different_bgpvpns()

    # Test fallback and ARP gateway voodoo

    def test_fallback(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_update_bgpvpn_already_plugged_ports()

            port10_with_gw_mac = DummyPort(NETWORK1, PORT10).__dict__
            port10_with_gw_mac.update({'gateway_mac': GW_MAC})
            port10_with_gw_mac.update(DummyBGPVPN(NETWORK1,
                                                  ipvpn=BGPVPN_IPVPN_RT100).
                                      __dict__)
            with mock.patch.object(self.agent, 'send_attach_local_port') as\
                    send_attach_fn:
                self.agent.bgpvpn_port_attach(None,
                                              copy.copy(port10_with_gw_mac))

                fallback = {'dst_mac': GW_MAC,
                            'ovs_port_number': PATCH_MPLS_TO_INT_OFPORT,
                            'src_mac': '00:00:5e:2a:10:00'}

                expected_calls = [
                    self._mock_send_expected_call(IPVPN,
                                                  port10_with_gw_mac,
                                                  self.DUMMY_VIF10,
                                                  fallback=fallback),
                ]

                send_attach_fn.assert_has_calls(expected_calls)

    def test_gateway_arp_voodoo(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent.int_br,
                                  'add_flow') as add_flow, \
                mock.patch('neutron.plugins.ml2.drivers.openvswitch.'
                           'agent.ovs_agent_extension_api.OVSCookieBridge'
                           '.delete_flows') as tun_delete_flows,\
                mock.patch.object(self.agent.int_br,
                                  'delete_flows') as int_delete_flows:
            super(TestBaGPipeBGPAgentOVS,
                  self).test_update_bgpvpn_already_plugged_ports()

            port10_with_gw_mac = DummyPort(NETWORK1, PORT10).__dict__
            port10_with_gw_mac.update({'gateway_mac': GW_MAC})
            port10_with_gw_mac.update(DummyBGPVPN(NETWORK1,
                                                  ipvpn=BGPVPN_IPVPN_RT100).
                                      __dict__)

            self.agent.bgpvpn_port_attach(None, copy.copy(port10_with_gw_mac))

            self.assertEqual(2, add_flow.call_count)

            add_flow.assert_has_calls([
                mock.call(table=mock.ANY,
                          priority=2,
                          proto='arp',
                          arp_op=0x2,
                          dl_src=GW_MAC,
                          arp_sha=GW_MAC,
                          arp_spa='10.0.0.1',
                          actions="drop"),
                mock.call(table=mock.ANY,
                          priority=2,
                          proto='arp',
                          arp_op=0x01,
                          dl_src=GW_MAC,
                          arp_spa='10.0.0.1',
                          arp_sha=GW_MAC,
                          actions="load:0x0->NXM_OF_ARP_SPA[],NORMAL"
                          )
            ])

            self.agent.bgpvpn_port_detach(None, DummyPort(NETWORK1,
                                                          PORT10).__dict__)

            self.assertEqual(0, tun_delete_flows.call_count)
            self.assertEqual(0, int_delete_flows.call_count)

            self.agent.bgpvpn_port_detach(None, DummyPort(NETWORK1,
                                                          PORT11).__dict__)

            self.assertEqual(1, tun_delete_flows.call_count)
            self.assertEqual(1, int_delete_flows.call_count)

            tun_delete_flows.assert_has_calls([
                mock.call(self.mock_tun_br,
                          table=mock.ANY,
                          proto='arp',
                          arp_op=0x01,
                          arp_tpa='10.0.0.1',
                          dl_vlan=mock.ANY,
                          )])
            int_delete_flows.assert_has_calls([
                mock.call(table=mock.ANY,
                          proto='arp',
                          dl_src=GW_MAC,
                          arp_sha=GW_MAC),
            ])

    def test_gateway_arp_voodoo_update_bgpvpn_after_plug(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent.int_br,
                                  'add_flow') as add_flow:
            port10 = DummyPort(NETWORK1, PORT10).__dict__
            port10.update({'gateway_mac': GW_MAC})

            self.agent.bgpvpn_port_attach(None, copy.copy(port10))

            dummy_bgpvpn1 = DummyBGPVPN(NETWORK1,
                                        ipvpn=BGPVPN_IPVPN_RT100,
                                        gateway_mac=GW_MAC).__dict__

            with mock.patch.object(self.agent, 'send_attach_local_port') as\
                    send_attach_fn:

                self.agent.update_bgpvpn(None, dummy_bgpvpn1)

                self.assertEqual(2, add_flow.call_count)

                add_flow.assert_has_calls([
                    mock.call(table=mock.ANY,
                              priority=2,
                              proto='arp',
                              arp_op=0x2,
                              dl_src=GW_MAC,
                              arp_sha=GW_MAC,
                              arp_spa='10.0.0.1',
                              actions="drop"),
                    mock.call(table=mock.ANY,
                              priority=2,
                              proto='arp',
                              arp_op=0x01,
                              dl_src=GW_MAC,
                              arp_spa='10.0.0.1',
                              arp_sha=GW_MAC,
                              actions="load:0x0->NXM_OF_ARP_SPA[],NORMAL"
                              )
                ])

                fallback = {'dst_mac': GW_MAC,
                            'ovs_port_number': PATCH_MPLS_TO_INT_OFPORT,
                            'src_mac': '00:00:5e:2a:10:00'}

                expected_calls = [
                    self._mock_send_expected_call(
                        IPVPN,
                        port10,
                        self.DUMMY_VIF10,
                        others_rts=BGPVPN_IPVPN_RT100,
                        fallback=fallback),
                ]

                send_attach_fn.assert_has_calls(expected_calls)

                self.agent.delete_bgpvpn(None, dummy_bgpvpn1)

                add_flow.reset_mock()
                self.assertEqual(0, add_flow.call_count)

                self.agent.update_bgpvpn(None, dummy_bgpvpn1)

                self.assertEqual(2, add_flow.call_count)

    def test_gateway_plug_before_update(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10]), \
                mock.patch.object(self.agent.int_br,
                                  'add_flow') as add_flow:
            port10 = DummyPort(NETWORK1, PORT10).__dict__

            self.agent.bgpvpn_port_attach(None, copy.copy(port10))

            dummy_bgpvpn1 = DummyBGPVPN(NETWORK1,
                                        ipvpn=BGPVPN_IPVPN_RT100,
                                        gateway_mac=GW_MAC).__dict__

            with mock.patch.object(self.agent, 'send_attach_local_port') as\
                    send_attach_fn:

                self.agent.update_bgpvpn(None, dummy_bgpvpn1)

                self.assertEqual(2, add_flow.call_count)

                add_flow.assert_has_calls([
                    mock.call(table=mock.ANY,
                              priority=2,
                              proto='arp',
                              arp_op=0x2,
                              dl_src=GW_MAC,
                              arp_sha=GW_MAC,
                              arp_spa='10.0.0.1',
                              actions="drop"),
                    mock.call(table=mock.ANY,
                              priority=2,
                              proto='arp',
                              arp_op=0x01,
                              dl_src=GW_MAC,
                              arp_spa='10.0.0.1',
                              arp_sha=GW_MAC,
                              actions="load:0x0->NXM_OF_ARP_SPA[],NORMAL"
                              )
                ])

                fallback = {'dst_mac': GW_MAC,
                            'ovs_port_number': PATCH_MPLS_TO_INT_OFPORT,
                            'src_mac': '00:00:5e:2a:10:00'}

                expected_calls = [
                    self._mock_send_expected_call(
                        IPVPN,
                        port10,
                        self.DUMMY_VIF10,
                        others_rts=BGPVPN_IPVPN_RT100,
                        fallback=fallback),
                ]

                send_attach_fn.assert_has_calls(expected_calls)

                self.agent.delete_bgpvpn(None, dummy_bgpvpn1)

                add_flow.reset_mock()
                self.assertEqual(0, add_flow.call_count)

                self.agent.update_bgpvpn(None, dummy_bgpvpn1)

                self.assertEqual(2, add_flow.call_count)

    def test_evpn_no_gateway_arp_voodoo(self):
        GW_MAC = 'aa:bb:cc:dd:ee:ff'

        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]), \
                mock.patch.object(self.agent.int_br,
                                  'add_flow') as add_flow, \
                mock.patch('neutron.plugins.ml2.drivers.openvswitch.'
                           'agent.ovs_agent_extension_api.'
                           'OVSCookieBridge.delete_flows') as delete_flows:

            port10_with_gw_mac = DummyPort(NETWORK1, PORT10).__dict__
            port10_with_gw_mac.update({'gateway_mac': GW_MAC})
            port10_with_gw_mac.update(DummyBGPVPN(NETWORK1,
                                                  evpn=BGPVPN_EVPN_RT10).
                                      __dict__)

            self.agent.bgpvpn_port_attach(None, copy.copy(port10_with_gw_mac))

            self.assertEqual(0, add_flow.call_count)

            self.agent.bgpvpn_port_detach(None, DummyPort(NETWORK1,
                                                          PORT10).__dict__)
            self.assertEqual(0, delete_flows.call_count)

            self.agent.bgpvpn_port_detach(None, DummyPort(NETWORK1,
                                                          PORT11).__dict__)

            self.assertEqual(0, delete_flows.call_count)

    # -------------------------------------------
    # Multiple simultaneous RPC notifiers tests |
    # -------------------------------------------

    def test_multiple_attach_single_port_evpns(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_multiple_attach_single_port_evpns()

    def test_multiple_attach_single_port_different_vpns(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_multiple_attach_single_port_different_vpns()

    def test_multiple_attach_multiple_ports_same_evpns(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_multiple_attach_multiple_ports_same_evpns()

    def test_multiple_attach_multiple_ports_different_evpns(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF20]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_multiple_attach_multiple_ports_different_evpns()

    def test_multiple_attach_multiple_ports_different_vpns(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF20]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_multiple_attach_multiple_ports_different_vpns()

    def test_multiple_detach_single_port_evpns1(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_multiple_detach_single_port_evpns1()

    def test_multiple_detach_single_port_evpns2(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_multiple_detach_single_port_evpns2()

    def test_multiple_detach_single_port_different_vpns(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               return_value=self.DUMMY_VIF10):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_multiple_detach_single_port_different_vpns()

    def test_multiple_detach_multiple_ports_same_evpns(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF11]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_multiple_detach_multiple_ports_same_evpns()

    def test_multiple_detach_multiple_ports_different_vpns(self):
        with mock.patch.object(self.agent.int_br, 'get_vif_port_by_id',
                               side_effect=[self.DUMMY_VIF10,
                                            self.DUMMY_VIF20]):
            super(TestBaGPipeBGPAgentOVS,
                  self).test_multiple_detach_multiple_ports_different_vpns()
