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

import mock

from neutron import context
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron.plugins.ml2 import config
from neutron.plugins.ml2 import managers
from neutron.plugins.ml2 import rpc
from neutron.tests.common import helpers
from neutron.tests.unit.plugins.ml2 import test_plugin

from networking_bagpipe.driver.type_route_target import TYPE_ROUTE_TARGET
import networking_bagpipe.rpc.client as bagpipe_rpc

from neutron_lib import constants as n_consts

HOST = 'bagpipe_host'
HOST_2 = HOST + '_2'
HOST_3 = HOST + '_3'

NOTIFIER = 'networking_bagpipe.rpc.client.BaGPipeAgentNotifyAPI'
DEVICE_OWNER_COMPUTE = 'compute:None'


def _get_linuxbridge_agent_dict(host, agent_type, binary,
                                bridge_mappings=None,
                                interface_mappings=None):
    agent = {
        'binary': binary,
        'host': host,
        'topic': n_consts.L2_AGENT_TOPIC,
        'agent_type': agent_type,
        'start_flag': True}

    if bridge_mappings is not None:
        agent['configurations']['bridge_mappings'] = bridge_mappings
    if interface_mappings is not None:
        agent['configurations']['interface_mappings'] = interface_mappings
    return agent


def register_linuxbridge_agent(host=HOST,
                               agent_type=n_consts.AGENT_TYPE_LINUXBRIDGE,
                               binary='bagpipe-linuxbridge-agent',
                               bridge_mappings=None,
                               interface_mappings=None):
    agent = _get_linuxbridge_agent_dict(host, agent_type, binary,
                                        bridge_mappings,
                                        interface_mappings)
    return helpers._register_agent(agent)


class TestBaGpipeRpcTestCase(test_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = ['bagpipe']

    def setUp(self):
        config.cfg.CONF.set_override('type_drivers',
                                     TYPE_ROUTE_TARGET,
                                     'ml2')
        config.cfg.CONF.set_override('tenant_network_types',
                                     TYPE_ROUTE_TARGET,
                                     'ml2',
                                     enforce_type=True)

        super(TestBaGpipeRpcTestCase, self).setUp()

        self.adminContext = context.get_admin_context()

        self.type_manager = managers.TypeManager()
        self.notifier = bagpipe_rpc.BaGPipeAgentNotifyAPI()
        self.callbacks = rpc.RpcCallbacks(self.notifier, self.type_manager)

        net_arg = {pnet.NETWORK_TYPE: TYPE_ROUTE_TARGET,
                   pnet.SEGMENTATION_ID: '101'}
        self._network = self._make_network(self.fmt, 'net1', True,
                                           arg_list=(pnet.NETWORK_TYPE,
                                                     pnet.SEGMENTATION_ID,),
                                           **net_arg)

        net_arg = {pnet.NETWORK_TYPE: TYPE_ROUTE_TARGET,
                   pnet.SEGMENTATION_ID: '102'}
        self._network2 = self._make_network(self.fmt, 'net2', True,
                                            arg_list=(pnet.NETWORK_TYPE,
                                                      pnet.SEGMENTATION_ID,),
                                            **net_arg)

        cast = ('networking_bagpipe.rpc.client.BaGPipeAgentNotifyAPI.'
                '_notification_host')
        cast_patch = mock.patch(cast)
        self.mock_cast = cast_patch.start()

    def _register_ml2_agents(self):
        register_linuxbridge_agent(host=HOST)
        register_linuxbridge_agent(host=HOST_2)
        register_linuxbridge_agent(host=HOST_3)

    def test_attach_port_on_bagpipe_network_called(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                p1 = port1['port']
                s1 = subnet['subnet']
                device = 'tap' + p1['id']

                p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                s1_cidr = s1['cidr'][s1['cidr'].index('/'):]
                expected = {'id': p1['id'],
                            'network_id': p1['network_id'],
                            'mac_address': p1['mac_address'],
                            'ip_address': p1_ips[0] + s1_cidr,
                            'gateway_ip': s1['gateway_ip'],
                            'evpn': {'import_rt': '64512:101',
                                     'export_rt': '64512:101'
                                     }
                            }

                self.mock_cast.reset_mock()
                self.callbacks.update_device_up(self.adminContext,
                                                agent_id=HOST,
                                                device=device)

                self.mock_cast.assert_called_with(
                    mock.ANY, 'attach_port_on_bagpipe_network', expected,
                    HOST)

    def test_attach_port_on_bagpipe_network_called_two_agents(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST,
                        'admin_state_up': True}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID, 'admin_state_up',),
                           **host_arg) as port1:
                host_arg = {portbindings.HOST_ID: HOST_2,
                            'admin_state_up': True}
                with self.port(subnet=subnet,
                               device_owner=DEVICE_OWNER_COMPUTE,
                               arg_list=(portbindings.HOST_ID,
                                         'admin_state_up',),
                               **host_arg) as port2:
                    p1 = port1['port']
                    s1 = subnet['subnet']
                    device1 = 'tap' + p1['id']

                    p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                    s1_cidr = s1['cidr'][s1['cidr'].index('/'):]
                    expected1 = {'id': p1['id'],
                                 'network_id': p1['network_id'],
                                 'mac_address': p1['mac_address'],
                                 'ip_address': p1_ips[0] + s1_cidr,
                                 'gateway_ip': s1['gateway_ip'],
                                 'evpn': {'import_rt': '64512:101',
                                          'export_rt': '64512:101'
                                          }
                                 }

                    p2 = port2['port']
                    device2 = 'tap' + p2['id']

                    p2_ips = [p['ip_address'] for p in p2['fixed_ips']]
                    expected2 = {'id': p2['id'],
                                 'network_id': p2['network_id'],
                                 'mac_address': p2['mac_address'],
                                 'ip_address': p2_ips[0] + s1_cidr,
                                 'gateway_ip': s1['gateway_ip'],
                                 'evpn': {'import_rt': '64512:101',
                                          'export_rt': '64512:101'
                                          }
                                 }

                    expected_calls = [
                        mock.call(mock.ANY, 'attach_port_on_bagpipe_network',
                                  expected1, HOST),
                        mock.call(mock.ANY, 'attach_port_on_bagpipe_network',
                                  expected2, HOST_2)
                    ]

                    self.mock_cast.reset_mock()
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST,
                                                    device=device1)
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST_2,
                                                    device=device2)

                    self.mock_cast.assert_has_calls(expected_calls)

    def test_attach_port_on_bagpipe_network_called_two_networks(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST_2}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                with self.subnet(network=self._network2,
                                 cidr='10.0.1.0/24') as subnet2:
                    host_arg = {portbindings.HOST_ID: HOST}
                    with self.port(subnet=subnet2,
                                   device_owner=DEVICE_OWNER_COMPUTE,
                                   arg_list=(portbindings.HOST_ID,),
                                   **host_arg) as port2:
                        p1 = port1['port']
                        s1 = subnet['subnet']
                        device1 = 'tap' + p1['id']

                        p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                        s1_cidr = s1['cidr'][s1['cidr'].index('/'):]
                        expected1 = {'id': p1['id'],
                                     'network_id': p1['network_id'],
                                     'mac_address': p1['mac_address'],
                                     'ip_address': p1_ips[0] + s1_cidr,
                                     'gateway_ip': s1['gateway_ip'],
                                     'evpn': {'import_rt': '64512:101',
                                              'export_rt': '64512:101'
                                              }
                                     }

                        p2 = port2['port']
                        s2 = subnet2['subnet']
                        device2 = 'tap' + p2['id']

                        p2_ips = [p['ip_address'] for p in p2['fixed_ips']]
                        s2_cidr = s2['cidr'][s2['cidr'].index('/'):]
                        expected2 = {'id': p2['id'],
                                     'network_id': p2['network_id'],
                                     'mac_address': p2['mac_address'],
                                     'ip_address': p2_ips[0] + s2_cidr,
                                     'gateway_ip': s2['gateway_ip'],
                                     'evpn': {'import_rt': '64512:102',
                                              'export_rt': '64512:102'
                                              }
                                     }

                        expected_calls = [
                            mock.call(mock.ANY,
                                      'attach_port_on_bagpipe_network',
                                      expected1, HOST_2),
                            mock.call(mock.ANY,
                                      'attach_port_on_bagpipe_network',
                                      expected2, HOST)
                        ]

                        self.mock_cast.reset_mock()
                        self.callbacks.update_device_up(self.adminContext,
                                                        agent_id=HOST_2,
                                                        device=device1)
                        self.callbacks.update_device_up(self.adminContext,
                                                        agent_id=HOST,
                                                        device=device2)

                        self.mock_cast.assert_has_calls(expected_calls)

    def test_delete_port(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port:
                p1 = port['port']
                device1 = 'tap' + p1['id']

                self.mock_cast.reset_mock()
                self.callbacks.update_device_up(self.adminContext,
                                                agent_id=HOST,
                                                device=device1)

                with self.port(subnet=subnet,
                               device_owner=DEVICE_OWNER_COMPUTE,
                               arg_list=(portbindings.HOST_ID,),
                               **host_arg) as port2:
                    p2 = port2['port']
                    device2 = 'tap' + p2['id']

                    self.mock_cast.reset_mock()
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST,
                                                    device=device2)

                self._delete('ports', port2['port']['id'])

                expected = {'id': p2['id'],
                            'network_id': p2['network_id'],
                            }

                self.mock_cast.assert_any_call(
                    mock.ANY, 'detach_port_from_bagpipe_network',
                    expected, HOST)

    def _update_and_check_portbinding(self, port_id, host_id):
        data = {'port': {'binding:host_id': host_id}}
        req = self.new_update_request('ports', data, port_id)
        res = self.deserialize(self.fmt,
                               req.get_response(self.api))
        self.assertEqual(host_id, res['port']['binding:host_id'])

    def _test_host_changed(self, twice):
        self._register_ml2_agents()
        helpers.register_dhcp_agent()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                p1 = port1['port']
                s1 = subnet['subnet']
                device1 = 'tap' + p1['id']

                p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                s1_cidr = s1['cidr'][s1['cidr'].index('/'):]
                expected1 = {'id': p1['id'],
                             'network_id': p1['network_id'],
                             'mac_address': p1['mac_address'],
                             'ip_address': p1_ips[0] + s1_cidr,
                             'gateway_ip': s1['gateway_ip'],
                             'evpn': {'import_rt': '64512:101',
                                      'export_rt': '64512:101'
                                      }
                             }

                self.callbacks.update_device_up(self.adminContext,
                                                agent_id=HOST,
                                                device=device1)

                self.mock_cast.assert_called_once_with(
                    mock.ANY, 'attach_port_on_bagpipe_network',
                    expected1, HOST)

                # FIXME(tmorin): migration code need to be updated
                # to follow the changes in Neutron commit
                # c5fa665de3173f3ad82cc3e7624b5968bc52c08d
#                 if twice:
#                     self._update_and_check_portbinding(p1['id'], HOST_3)
#                 self._update_and_check_portbinding(p1['id'], HOST_2)
#
#                 expected1 = {'id': p1['id'],
#                              'network_id': p1['network_id']}
#
#                 self.mock_cast.reset_mock()
#                 self.callbacks.get_device_details(self.adminContext,
#                                                   device=device1,
#                                                   agent_id=HOST_2)
#
#                 self.mock_cast.assert_called_once_with(
#                     mock.ANY, 'attach_port_on_bagpipe_network',
#                     expected1, HOST_2)
#
#                 self.mock_cast.assert_called_once_with(
#                     mock.ANY, 'detach_port_from_bagpipe_network',
#                     expected1, HOST)

    def test_host_changed(self):
        self._test_host_changed(twice=False)

    def test_host_changed_twice(self):
        self._test_host_changed(twice=True)
