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

from networking_bagpipe.agent.bagpipe_bgp_agent import BaGPipeBGPAgent

from networking_bagpipe.agent.bagpipe_bgp_agent import BGPVPN_TYPES
from networking_bagpipe.agent.bagpipe_bgp_agent import BGPVPN_TYPES_MAP

from neutron.plugins.ml2.drivers.linuxbridge.agent.linuxbridge_neutron_agent \
    import LinuxBridgeManager
from neutron.plugins.ml2.drivers.openvswitch.agent import vlanmanager

from neutron.tests import base
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent import (
    ovs_test_base)

from neutron_lib import constants as n_const

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

LOCAL_VLAN_MAP = {
    NETWORK1['id']: 31,
    NETWORK2['id']: 52
}

BAGPIPE_L2_RT1 = {'import_rt': 'BAGPIPE_L2:1',
                  'export_rt': 'BAGPIPE_L2:1'}

BAGPIPE_L2_RT2 = {'import_rt': 'BAGPIPE_L2:2',
                  'export_rt': 'BAGPIPE_L2:2'}

BGPVPN_L2_RT10 = {'import_rt': ['BGPVPN_L2:10'],
                  'export_rt': ['BGPVPN_L2:10']}

BGPVPN_L2_RT20 = {'import_rt': ['BGPVPN_L2:20'],
                  'export_rt': ['BGPVPN_L2:20']}

BGPVPN_L3_RT100 = {'import_rt': ['BGPVPN_L3:100'],
                   'export_rt': ['BGPVPN_L3:100']}

BGPVPN_L3_RT200 = {'import_rt': ['BGPVPN_L3:200'],
                   'export_rt': ['BGPVPN_L3:200']}


class DummyPort(object):
    def __init__(self, network, port, bgpvpn_port=False,
                 evpn=None, ipvpn=None):
        self.id = port['id']
        self.network_id = network['id']
        self.mac_address = port['mac_address']
        self.ip_address = port['ip_address']
        self.gateway_ip = network['gateway_ip']

        if bgpvpn_port:
            if evpn:
                self.l2vpn = copy.deepcopy(evpn)

            if ipvpn:
                self.l3vpn = copy.deepcopy(ipvpn)
        else:
            if evpn:
                self.evpn = copy.deepcopy(evpn)

            if ipvpn:
                self.ipvpn = copy.deepcopy(ipvpn)


class DummyVif(object):
    def __init__(self, ofport, port_name):
        self.ofport = ofport
        self.port_name = port_name


class DummyBGPVPN(object):
    def __init__(self, network, l2vpn=None, l3vpn=None, gateway_mac=None):
        self.network_id = network['id']

        if l2vpn:
            self.l2vpn = copy.deepcopy(l2vpn)

        if l3vpn:
            self.l3vpn = copy.deepcopy(l3vpn)

        if gateway_mac:
            self.gateway_mac = gateway_mac


class RTList(list):

    def __eq__(self, other):
        return set(self) == set(other)


class BaseTestBaGPipeBGPAgent(object):

    DUMMY_VIF10 = None
    DUMMY_VIF11 = None
    DUMMY_VIF20 = None
    DUMMY_VIF21 = None

    def _get_expected_local_port(self, network_id, port_id, vif_name):
        raise NotImplementedError

    def _format_as_list(self, value):
        return value if isinstance(value, list) else [value]

    def _get_expected_route_target(self, vpn_type, port, others_rts):
        import_rt = RTList()
        export_rt = RTList()

        if vpn_type in port:
            import_rt += self._format_as_list(port[vpn_type]['import_rt'])
            export_rt += self._format_as_list(port[vpn_type]['export_rt'])

        if others_rts:
            import_rt += self._format_as_list(others_rts.get('import_rt'))
            export_rt += self._format_as_list(others_rts.get('export_rt'))

        return import_rt, export_rt

    def _mock_send_expected_call(self, vpn_type, port, vif, evpn2ipvpn=False,
                                 others_rts=None, fallback=None):
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
                                                               others_rts)

        if vpn_type in BGPVPN_TYPES:
            vpn_type = BGPVPN_TYPES_MAP[vpn_type]

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

    def _check_network_info(self, network_id, expected_size,
                            service=None, vpn_type=None, vpn_rts=None):
        if expected_size == 0:
            self.assertNotIn(network_id, self.agent.networks_info,
                             "Network %s expected to have no ports left"
                             % network_id)
        else:
            self.assertIn(network_id, self.agent.networks_info)
            network_info = self.agent.networks_info[network_id]
            self.assertEqual(len(network_info.ports), expected_size,
                             "Network ports size not as expected")

            if service and vpn_type and vpn_rts:
                service_infos = network_info.service_infos
                self.assertIn(service, service_infos,
                              "No %s service details found for network %s" %
                              (service, network_id))

                self.assertIn(vpn_type, service_infos[service],
                              "No %s service %s details found for "
                              "network %s" % (service,
                                              vpn_type,
                                              network_id))

                self.assertEqual(vpn_rts, service_infos[service][vpn_type],
                                 "%s service %s details not matching %s for "
                                 "network %s" % (service,
                                                 vpn_type,
                                                 vpn_rts,
                                                 network_id))


class BaseTestBaGPipeBGPAgentLinuxBridge(base.BaseTestCase,
                                         BaseTestBaGPipeBGPAgent):

    def setUp(self):
        cfg.CONF.set_override('enable_vxlan', False, 'VXLAN')
        super(BaseTestBaGPipeBGPAgentLinuxBridge, self).setUp()

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


class BaseTestBaGPipeBGPAgentOVS(ovs_test_base.OVSOFCtlTestBase,
                                 BaseTestBaGPipeBGPAgent):

    DUMMY_VIF10 = DummyVif(10, 'VIF10')
    DUMMY_VIF11 = DummyVif(11, 'VIF11')
    DUMMY_VIF20 = DummyVif(20, 'VIF20')
    DUMMY_VIF21 = DummyVif(21, 'VIF21')

    def setUp(self):
        super(BaseTestBaGPipeBGPAgentOVS, self).setUp()

        self.mock_int_br = mock.Mock()
        self.mock_int_br.add_patch_port = mock.Mock()
        self.mock_int_br.add_patch_port.side_effect = PATCH_INT_OFPORTS
        self.mock_int_br.get_vif_port_by_id = mock.Mock()

        self.mock_tun_br = mock.Mock()
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

        self.vlan_manager = vlanmanager.LocalVlanManager()
        for net_id, vlan in LOCAL_VLAN_MAP.items():
            try:
                self.vlan_manager.add(net_id, vlan, None, None, None)
            except vlanmanager.MappingAlreadyExists:
                pass

    def _get_expected_local_port(self, network_id, port_id, vif_name):
        vlan = self.vlan_manager.get(network_id).vlan
        local_port = dict(
            linuxif="patch2tun:%s" % vlan,
            ovs=dict(plugged=True,
                     port_number=PATCH_MPLS_FROM_TUN_OFPORT,
                     to_vm_port_number=PATCH_MPLS_TO_TUN_OFPORT,
                     vlan=vlan)
        )

        return local_port, None
