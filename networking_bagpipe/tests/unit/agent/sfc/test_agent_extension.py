# Copyright (c) 2017 Orange.
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

from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from networking_bagpipe.agent.sfc import agent_extension as bagpipe_agt_ext
from networking_bagpipe.bagpipe_bgp import constants as bbgp_const
from networking_bagpipe.driver import constants as sfc_const
from networking_bagpipe.objects import sfc as sfc_obj
from networking_bagpipe.tests.unit.agent import base

from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc

from neutron.plugins.ml2.drivers.linuxbridge.agent.common \
    import constants as lb_agt_constants
from neutron.plugins.ml2.drivers.linuxbridge.agent.linuxbridge_neutron_agent \
    import LinuxBridgeManager

CHAIN_HOP_CLASSIFIER = {"protocol": "tcp",
                        "sourcePrefix": "1.2.3.4/32",
                        "destinationPort": "80",
                        "destinationPrefix": "5.6.7.8/32"}

CHAIN_HOP_REVERSE_CLASSIFIER = {"protocol": "tcp",
                                "sourcePrefix": "5.6.7.8/32",
                                "sourcePort": "80",
                                "destinationPrefix": "1.2.3.4/32"}

CHAIN_HOP_RT1000 = ['SFC_L3:1000']
CHAIN_HOP_EGRESS_TO_RT1002 = 'SFC_L3:1002'
CHAIN_HOP_EGRESS_PARAMS1 = {'readv_from_rts': ['SFC_L3:1001'],
                            'readv_to_rt': CHAIN_HOP_EGRESS_TO_RT1002,
                            'redirect_rts': ['SFC_L3:1003']}

CHAIN_HOP_RT2000 = ['SFC_L3:2000']
CHAIN_HOP_EGRESS_TO_RT2002 = 'SFC_L3:2002'
CHAIN_HOP_EGRESS_PARAMS2 = {'readv_from_rts': ['SFC_L3:2001'],
                            'readv_to_rt': CHAIN_HOP_EGRESS_TO_RT2002,
                            'redirect_rts': ['SFC_L3:2003']}

net_ports = {
    base.NETWORK1['id']: [base.PORT10['id'], base.PORT11['id']],
    base.NETWORK2['id']: [base.PORT20['id'], base.PORT21['id']]
}


class TestSfcAgentExtension(base.BaseTestLinuxBridgeAgentExtension):

    agent_extension_class = bagpipe_agt_ext.BagpipeSfcAgentExtension

    def setUp(self):
        super(TestSfcAgentExtension, self).setUp()
        self.mocked_bulk_rpc = mock.patch.object(
            self.agent_ext._pull_rpc, 'bulk_pull').start()

    @mock.patch.object(registry, 'register')
    @mock.patch.object(resources_rpc, 'ResourcesPushRpcCallback')
    def test_initialize_rpcs(self, rpc_mock, subscribe_mock):
        self.agent_ext.initialize(self.connection,
                                  lb_agt_constants.EXTENSION_DRIVER_TYPE)
        self.connection.create_consumer.assert_has_calls(
            [mock.call(
                resources_rpc.resource_type_versioned_topic(resource_type),
                [rpc_mock()],
                fanout=True)
             for resource_type in (
                 sfc_obj.BaGPipeChainHop.obj_name(),
                 sfc_obj.BaGPipePortHops.obj_name())],
            any_order=True
        )
        subscribe_mock.assert_has_calls(
            [
                mock.call(mock.ANY, sfc_obj.BaGPipeChainHop.obj_name()),
                mock.call(mock.ANY, sfc_obj.BaGPipePortHops.obj_name())
            ],
            any_order=True
        )

    def _check_port_sfc_info(self, port_id, sides=None):
        self.assertIn(port_id, self.agent_ext.ports_info)
        port_info = self.agent_ext.ports_info[port_id]

        if sides:
            self.assertTrue(port_info.chain_hops)
            for side in sides:
                self.assertTrue(port_info.chain_hops[side])

                hop_keys = list(sfc_obj.BaGPipeChainHop.fields)
                if side == sfc_const.EGRESS:
                    hop_keys += ['lb_consistent_hash_order']
                self.assertTrue(all(key in hop_keys for
                                    key in list(port_info.chain_hops[side])))
        else:
            self.assertFalse(port_info.chain_hops)

    def _fake_chain_hop(self, portchain_id, rts,
                        ingress_network, egress_network,
                        reverse_hop=False,
                        **chain_hop_params):
        chain_hop = dict(
            id=uuidutils.generate_uuid(),
            portchain_id=portchain_id,
            rts=rts,
            ingress_gw=ingress_network['gateway_ip'],
            egress_gw=egress_network['gateway_ip'],
            ingress_ports=net_ports[ingress_network['id']],
            egress_ports=net_ports[egress_network['id']],
            reverse_hop=reverse_hop,
            **chain_hop_params
        )

        return sfc_obj.BaGPipeChainHop(**chain_hop)

    def _chain_hops_notif(self, chain_hops, event_type):
        self.agent_ext.handle_sfc_chain_hops(
            None, sfc_obj.BaGPipeChainHop.obj_name(),
            chain_hops, event_type)

    def _fake_port_hops(self, port_id, ingress_hops=None, egress_hops=None):
        port_hops = dict(
            port_id=port_id,
            ingress_hops=ingress_hops if ingress_hops else [],
            egress_hops=egress_hops if egress_hops else []
        )

        return sfc_obj.BaGPipePortHops(**port_hops)

    def _port_hops_notif(self, port_hops, event_type):
        self.agent_ext.handle_sfc_port_hops(
            None, sfc_obj.BaGPipePortHops.obj_name(),
            port_hops, event_type)

    def test_chain_hop_before_port_up_ingress_only(self):
        ingress_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2)

        self.mocked_bulk_rpc.return_value = [ingress_hop]

        # Verify build callback attachments
        def check_build_cb(port_id):
            linuxbr1 = LinuxBridgeManager.get_bridge_name(base.NETWORK1['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=dict(linuxif=linuxbr1),
                        import_rt=CHAIN_HOP_RT1000,
                        export_rt=[]
                    )]
                ),
                self.agent_ext.build_sfc_attach_info(base.PORT10['id'])
            )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 1)
        self._check_port_sfc_info(base.PORT10['id'], [sfc_const.INGRESS])

    def test_chain_hop_before_port_up_egress_only(self):
        egress_params = copy.copy(CHAIN_HOP_EGRESS_PARAMS1)
        egress_params.update(
            dict(classifiers=jsonutils.dumps([CHAIN_HOP_CLASSIFIER]))
        )

        egress_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK2,
            egress_network=base.NETWORK1,
            **egress_params)

        self.mocked_bulk_rpc.return_value = [egress_hop]

        # Verify build callback attachments
        def check_build_cb(port_id):
            linuxbr1 = LinuxBridgeManager.get_bridge_name(base.NETWORK1['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=dict(linuxif=linuxbr1),
                        import_rt=[],
                        export_rt=CHAIN_HOP_RT1000,
                        readvertise=dict(
                            from_rt=egress_params['readv_from_rts'],
                            to_rt=[egress_params['readv_to_rt']]
                        ),
                        attract_traffic=dict(
                            redirect_rts=egress_params['redirect_rts'],
                            classifier=CHAIN_HOP_CLASSIFIER
                        ),
                        lb_consistent_hash_order=0
                    )]
                ),
                self.agent_ext.build_sfc_attach_info(base.PORT10['id'])
            )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 1)
        self._check_port_sfc_info(base.PORT10['id'], [sfc_const.EGRESS])

    def test_two_chain_hops_before_port_up(self):
        ingress_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2)

        egress_params = copy.copy(CHAIN_HOP_EGRESS_PARAMS2)
        egress_params.update(
            dict(classifiers=jsonutils.dumps([CHAIN_HOP_REVERSE_CLASSIFIER]))
        )

        egress_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT2000,
            ingress_network=base.NETWORK2,
            egress_network=base.NETWORK1,
            **egress_params)

        self.mocked_bulk_rpc.return_value = [ingress_hop, egress_hop]

        # Verify build callback attachments
        def check_build_cb(port_id):
            linuxbr1 = LinuxBridgeManager.get_bridge_name(base.NETWORK1['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=dict(linuxif=linuxbr1),
                        import_rt=CHAIN_HOP_RT1000,
                        export_rt=CHAIN_HOP_RT2000,
                        readvertise=dict(
                            from_rt=egress_params['readv_from_rts'],
                            to_rt=[egress_params['readv_to_rt']]
                        ),
                        attract_traffic=dict(
                            redirect_rts=egress_params['redirect_rts'],
                            classifier=CHAIN_HOP_REVERSE_CLASSIFIER
                        ),
                        lb_consistent_hash_order=0
                    )]
                ),
                self.agent_ext.build_sfc_attach_info(base.PORT10['id'])
            )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 1)
        self._check_port_sfc_info(base.PORT10['id'],
                                  [sfc_const.INGRESS, sfc_const.EGRESS])

    def test_chain_hop_before_port_delete(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        chain_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2)

        self._chain_hops_notif([chain_hop], rpc_events.CREATED)

        self.agent_ext.delete_port(None, self._port_data(base.PORT10,
                                                         delete=True))

        local_port = self._get_expected_local_port(bbgp_const.IPVPN,
                                                   base.NETWORK1['id'],
                                                   base.PORT10['id'],
                                                   detach=True)
        detach_info = {
            'network_id': base.NETWORK1['id'],
            bbgp_const.IPVPN: {
                'ip_address': base.PORT10['ip_address'],
                'mac_address': base.PORT10['mac_address'],
                'local_port': local_port['local_port']
            }
        }

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info)]
        )

        # Verify attachments list consistency
        self.assertEqual(0, len(self.agent_ext.ports_info),
                         "Registered ports list must be empty: %s" %
                         self.agent_ext.ports_info)
        self.assertEqual(0, len(self.agent_ext.networks_info),
                         "Registered networks list must be empty: %s" %
                         self.agent_ext.networks_info)

    def test_chain_hop_created_no_plugged_ports(self):
        chain_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2)
        self._chain_hops_notif([chain_hop], rpc_events.CREATED)

        self.assertEqual(0, self.mocked_bagpipe_agent.do_port_plug.call_count,
                         "Do port plug mustn't be called")

    def test_chain_hop_created_already_ingress_plugged_ports(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        chain_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2)

        # Verify build callback attachments
        def check_build_cb(port_id):
            linuxbr1 = LinuxBridgeManager.get_bridge_name(base.NETWORK1['id'])
            for port in [base.PORT10, base.PORT11]:
                if port['id'] != port_id:
                    continue

                self.assertDictEqual(
                    dict(
                        network_id=base.NETWORK1['id'],
                        ipvpn=[dict(
                            ip_address=port['ip_address'],
                            mac_address=port['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=dict(linuxif=linuxbr1),
                            import_rt=CHAIN_HOP_RT1000,
                            export_rt=[]
                        )]
                    ),
                    self.agent_ext.build_sfc_attach_info(port['id'])
                )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._chain_hops_notif([chain_hop], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 2)
        for port_id in net_ports[base.NETWORK1['id']]:
            self._check_port_sfc_info(port_id, [sfc_const.INGRESS])

    def test_chain_hop_created_already_egress_plugged_ports(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT20))
        self.agent_ext.handle_port(None, self._port_data(base.PORT21))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        egress_params = copy.copy(CHAIN_HOP_EGRESS_PARAMS1)
        egress_params.update(
            dict(readv_to_rt=CHAIN_HOP_EGRESS_TO_RT1002,
                 classifiers=jsonutils.dumps([CHAIN_HOP_CLASSIFIER]))
        )

        chain_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2,
            **egress_params)

        # Verify build callback attachments
        def check_build_cb(port_id):
            linuxbr2 = LinuxBridgeManager.get_bridge_name(base.NETWORK2['id'])
            for index, port in enumerate([base.PORT20, base.PORT21]):
                if port['id'] != port_id:
                    continue

                self.assertDictEqual(
                    dict(
                        network_id=base.NETWORK2['id'],
                        ipvpn=[dict(
                            ip_address=port['ip_address'],
                            mac_address=port['mac_address'],
                            gateway_ip=base.NETWORK2['gateway_ip'],
                            local_port=dict(linuxif=linuxbr2),
                            import_rt=[],
                            export_rt=CHAIN_HOP_RT1000,
                            readvertise=dict(
                                from_rt=egress_params['readv_from_rts'],
                                to_rt=[egress_params['readv_to_rt']]
                            ),
                            attract_traffic=dict(
                                redirect_rts=egress_params['redirect_rts'],
                                classifier=CHAIN_HOP_CLASSIFIER
                            ),
                            lb_consistent_hash_order=index
                        )]
                    ),
                    self.agent_ext.build_sfc_attach_info(port['id'])
                )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._chain_hops_notif([chain_hop], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT20['id']), mock.call(base.PORT21['id'])],
            any_order=True
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK2['id'], 2)
        for port_id in net_ports[base.NETWORK2['id']]:
            self._check_port_sfc_info(port_id, [sfc_const.EGRESS])

    def test_chain_hop_created_egress_ports_static_prefix_advertise(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT20))
        self.agent_ext.handle_port(None, self._port_data(base.PORT21))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        egress_params = copy.copy(CHAIN_HOP_EGRESS_PARAMS1)
        egress_params.pop('readv_to_rt')
        egress_params.update(
            dict(attract_to_rt=CHAIN_HOP_EGRESS_TO_RT1002,
                 classifiers=jsonutils.dumps([CHAIN_HOP_CLASSIFIER]))
        )

        chain_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2,
            **egress_params)

        # Verify build callback attachments
        def check_build_cb(port_id):
            linuxbr2 = LinuxBridgeManager.get_bridge_name(base.NETWORK2['id'])
            for index, port in enumerate([base.PORT20, base.PORT21]):
                if port['id'] != port_id:
                    continue

                static_prefix = CHAIN_HOP_CLASSIFIER['destinationPrefix']
                self.assertDictEqual(
                    dict(
                        network_id=base.NETWORK2['id'],
                        ipvpn=[dict(
                            ip_address=port['ip_address'],
                            mac_address=port['mac_address'],
                            gateway_ip=base.NETWORK2['gateway_ip'],
                            local_port=dict(linuxif=linuxbr2),
                            import_rt=[],
                            export_rt=CHAIN_HOP_RT1000,
                            attract_traffic=dict(
                                to_rt=[egress_params['attract_to_rt']],
                                redirect_rts=egress_params['redirect_rts'],
                                static_destination_prefixes=[static_prefix],
                                classifier=CHAIN_HOP_CLASSIFIER
                            ),
                            lb_consistent_hash_order=index
                        )]
                    ),
                    self.agent_ext.build_sfc_attach_info(port['id'])
                )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._chain_hops_notif([chain_hop], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT20['id']), mock.call(base.PORT21['id'])],
            any_order=True
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK2['id'], 2)
        for port_id in net_ports[base.NETWORK2['id']]:
            self._check_port_sfc_info(port_id, [sfc_const.EGRESS])

    def test_chain_hop_created_egress_ports_default_prefix_advertise(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT20))
        self.agent_ext.handle_port(None, self._port_data(base.PORT21))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        no_dest_prefix_classifier = copy.copy(CHAIN_HOP_CLASSIFIER)
        no_dest_prefix_classifier.pop('destinationPrefix')

        egress_params = copy.copy(CHAIN_HOP_EGRESS_PARAMS1)
        egress_params.pop('readv_to_rt')
        egress_params.update(
            dict(attract_to_rt=CHAIN_HOP_EGRESS_TO_RT1002,
                 classifiers=jsonutils.dumps([no_dest_prefix_classifier]))
        )

        chain_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2,
            **egress_params)

        # Verify build callback attachments
        def check_build_cb(port_id):
            linuxbr2 = LinuxBridgeManager.get_bridge_name(base.NETWORK2['id'])
            for index, port in enumerate([base.PORT20, base.PORT21]):
                if port['id'] != port_id:
                    continue

                self.assertDictEqual(
                    dict(
                        network_id=base.NETWORK2['id'],
                        ipvpn=[dict(
                            ip_address=port['ip_address'],
                            mac_address=port['mac_address'],
                            gateway_ip=base.NETWORK2['gateway_ip'],
                            local_port=dict(linuxif=linuxbr2),
                            import_rt=[],
                            export_rt=CHAIN_HOP_RT1000,
                            attract_traffic=dict(
                                to_rt=[egress_params['attract_to_rt']],
                                redirect_rts=egress_params['redirect_rts'],
                                static_destination_prefixes=['0.0.0.0/0'],
                                classifier=no_dest_prefix_classifier
                            ),
                            lb_consistent_hash_order=index
                        )]
                    ),
                    self.agent_ext.build_sfc_attach_info(port['id'])
                )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._chain_hops_notif([chain_hop], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT20['id']), mock.call(base.PORT21['id'])],
            any_order=True
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK2['id'], 2)
        for port_id in net_ports[base.NETWORK2['id']]:
            self._check_port_sfc_info(port_id, [sfc_const.EGRESS])

    def test_chain_hop_created_already_plugged_ports(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))

        self.agent_ext.handle_port(None, self._port_data(base.PORT20))
        self.agent_ext.handle_port(None, self._port_data(base.PORT21))

        self.assertEqual(self.mocked_bagpipe_agent.do_port_plug.call_count, 0)

        egress_params = copy.copy(CHAIN_HOP_EGRESS_PARAMS1)
        egress_params.update(
            dict(classifiers=jsonutils.dumps([CHAIN_HOP_CLASSIFIER]))
        )

        chain_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2,
            **egress_params)

        # Verify build callback attachments
        def check_build_cb(port_id):
            linuxbr1 = LinuxBridgeManager.get_bridge_name(base.NETWORK1['id'])
            for index, port in enumerate([base.PORT10, base.PORT11]):
                if port['id'] != port_id:
                    continue

                self.assertDictEqual(
                    dict(
                        network_id=base.NETWORK1['id'],
                        ipvpn=[dict(
                            ip_address=port['ip_address'],
                            mac_address=port['mac_address'],
                            gateway_ip=base.NETWORK1['gateway_ip'],
                            local_port=dict(linuxif=linuxbr1),
                            import_rt=CHAIN_HOP_RT1000,
                            export_rt=[]
                        )]
                    ),
                    self.agent_ext.build_sfc_attach_info(port['id'])
                )

            linuxbr2 = LinuxBridgeManager.get_bridge_name(base.NETWORK2['id'])
            for index, port in enumerate([base.PORT20, base.PORT21]):
                if port['id'] != port_id:
                    continue

                self.assertDictEqual(
                    dict(
                        network_id=base.NETWORK2['id'],
                        ipvpn=[dict(
                            ip_address=port['ip_address'],
                            mac_address=port['mac_address'],
                            gateway_ip=base.NETWORK2['gateway_ip'],
                            local_port=dict(linuxif=linuxbr2),
                            import_rt=[],
                            export_rt=CHAIN_HOP_RT1000,
                            readvertise=dict(
                                from_rt=egress_params['readv_from_rts'],
                                to_rt=[egress_params['readv_to_rt']]
                            ),
                            attract_traffic=dict(
                                redirect_rts=egress_params['redirect_rts'],
                                classifier=CHAIN_HOP_CLASSIFIER
                            ),
                            lb_consistent_hash_order=index
                        )]
                    ),
                    self.agent_ext.build_sfc_attach_info(port['id'])
                )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._chain_hops_notif([chain_hop], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id']),
             mock.call(base.PORT20['id']), mock.call(base.PORT21['id'])],
            any_order=True
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 2)
        for port in [base.PORT10, base.PORT11]:
            self._check_port_sfc_info(port['id'], [sfc_const.INGRESS])

        self._check_network_info(base.NETWORK2['id'], 2)
        for port in [base.PORT20, base.PORT21]:
            self._check_port_sfc_info(port['id'], [sfc_const.EGRESS])

    def test_two_chain_hops_created_same_port(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        egress_params_1 = copy.copy(CHAIN_HOP_EGRESS_PARAMS1)
        egress_params_1.update(
            dict(classifiers=jsonutils.dumps([CHAIN_HOP_CLASSIFIER]))
        )

        chain_hop_1 = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2,
            **egress_params_1)

        egress_params_2 = copy.copy(CHAIN_HOP_EGRESS_PARAMS2)
        egress_params_2.update(
            dict(classifiers=jsonutils.dumps([CHAIN_HOP_REVERSE_CLASSIFIER]))
        )

        chain_hop_2 = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT2000,
            ingress_network=base.NETWORK2,
            egress_network=base.NETWORK1,
            **egress_params_2)

        # Verify build callback attachments
        def check_build_cb(port_id):
            linuxbr1 = LinuxBridgeManager.get_bridge_name(base.NETWORK1['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=dict(linuxif=linuxbr1),
                        import_rt=CHAIN_HOP_RT1000,
                        export_rt=CHAIN_HOP_RT2000,
                        readvertise=dict(
                            from_rt=egress_params_2['readv_from_rts'],
                            to_rt=[egress_params_2['readv_to_rt']]
                        ),
                        attract_traffic=dict(
                            redirect_rts=egress_params_2['redirect_rts'],
                            classifier=CHAIN_HOP_REVERSE_CLASSIFIER
                        ),
                        lb_consistent_hash_order=0
                    )]
                ),
                self.agent_ext.build_sfc_attach_info(base.PORT10['id'])
            )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._chain_hops_notif([chain_hop_1, chain_hop_2], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 1)
        self._check_port_sfc_info(base.PORT10['id'],
                                  [sfc_const.INGRESS, sfc_const.EGRESS])

    def test_one_by_one_chain_hops_created_same_port(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        egress_params_1 = copy.copy(CHAIN_HOP_EGRESS_PARAMS1)
        egress_params_1.update(
            dict(classifiers=jsonutils.dumps([CHAIN_HOP_CLASSIFIER]))
        )

        chain_hop_1 = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2,
            **egress_params_1)

        # Verify build callback attachments
        def check_build_cb_1(port_id):
            linuxbr1 = LinuxBridgeManager.get_bridge_name(base.NETWORK1['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=dict(linuxif=linuxbr1),
                        import_rt=CHAIN_HOP_RT1000,
                        export_rt=[]
                    )]
                ),
                self.agent_ext.build_sfc_attach_info(base.PORT10['id'])
            )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb_1

        self._chain_hops_notif([chain_hop_1], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 1)
        self._check_port_sfc_info(base.PORT10['id'], [sfc_const.INGRESS])

        self.mocked_bagpipe_agent.reset_mock()

        egress_params_2 = copy.copy(CHAIN_HOP_EGRESS_PARAMS2)
        egress_params_2.update(
            dict(classifiers=jsonutils.dumps([CHAIN_HOP_REVERSE_CLASSIFIER]))
        )

        chain_hop_2 = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT2000,
            ingress_network=base.NETWORK2,
            egress_network=base.NETWORK1,
            **egress_params_2)

        # Verify build callback attachments
        def check_build_cb_2(port_id):
            linuxbr1 = LinuxBridgeManager.get_bridge_name(base.NETWORK1['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=dict(linuxif=linuxbr1),
                        import_rt=CHAIN_HOP_RT1000,
                        export_rt=CHAIN_HOP_RT2000,
                        readvertise=dict(
                            from_rt=egress_params_2['readv_from_rts'],
                            to_rt=[egress_params_2['readv_to_rt']]
                        ),
                        attract_traffic=dict(
                            redirect_rts=egress_params_2['redirect_rts'],
                            classifier=CHAIN_HOP_REVERSE_CLASSIFIER
                        ),
                        lb_consistent_hash_order=0
                    )]
                ),
                self.agent_ext.build_sfc_attach_info(base.PORT10['id'])
            )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb_2

        self._chain_hops_notif([chain_hop_2], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 1)
        self._check_port_sfc_info(base.PORT10['id'],
                                  [sfc_const.INGRESS, sfc_const.EGRESS])

    def test_port_hop_created_already_plugged_port_ingress(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))

        chain_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2)

        port10_hops = self._fake_port_hops(base.PORT10['id'],
                                           ingress_hops=[chain_hop])

        # Verify build callback attachments
        def check_build_cb(port_id):
            linuxbr1 = LinuxBridgeManager.get_bridge_name(base.NETWORK1['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK1['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT10['ip_address'],
                        mac_address=base.PORT10['mac_address'],
                        gateway_ip=base.NETWORK1['gateway_ip'],
                        local_port=dict(linuxif=linuxbr1),
                        import_rt=CHAIN_HOP_RT1000,
                        export_rt=[]
                    )]
                ),
                self.agent_ext.build_sfc_attach_info(base.PORT10['id'])
            )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._port_hops_notif([port10_hops], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id'])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 1)
        self._check_port_sfc_info(base.PORT10['id'], [sfc_const.INGRESS])

    def test_port_hop_created_already_plugged_port_egress(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT21))

        chain_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2)

        port21_hops = self._fake_port_hops(base.PORT21['id'],
                                           egress_hops=[chain_hop])

        # Verify build callback attachments
        def check_build_cb(port_id):
            linuxbr2 = LinuxBridgeManager.get_bridge_name(base.NETWORK2['id'])
            self.assertDictEqual(
                dict(
                    network_id=base.NETWORK2['id'],
                    ipvpn=[dict(
                        ip_address=base.PORT21['ip_address'],
                        mac_address=base.PORT21['mac_address'],
                        gateway_ip=base.NETWORK2['gateway_ip'],
                        local_port=dict(linuxif=linuxbr2),
                        import_rt=[],
                        export_rt=CHAIN_HOP_RT1000,
                        lb_consistent_hash_order=1
                    )]
                ),
                self.agent_ext.build_sfc_attach_info(base.PORT21['id'])
            )

        # we need to check what build_sfc_attach_info returns, at the
        # precise time when do_port_plug is called
        self.mocked_bagpipe_agent.do_port_plug.side_effect = check_build_cb

        self._port_hops_notif([port21_hops], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT21['id'])]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK2['id'], 1)
        self._check_port_sfc_info(base.PORT21['id'], [sfc_const.EGRESS])

    def test_chain_hop_deleted_no_plugged_ports(self):
        chain_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2)
        self._chain_hops_notif([chain_hop], rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug.assert_not_called()
        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_not_called()

    def test_chain_hop_deleted_remaining_ingress_ports(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))

        chain_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2)

        self._chain_hops_notif([chain_hop], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

        # Verify attachment list consistency
        self._check_network_info(base.NETWORK1['id'], 2)
        for port_id in net_ports[base.NETWORK1['id']]:
            self._check_port_sfc_info(port_id, [sfc_const.INGRESS])

        self.mocked_bagpipe_agent.reset_mock()

        # Prepare expected information for DELETE
        linuxbr1 = LinuxBridgeManager.get_bridge_name(base.NETWORK1['id'])

        detach_info10 = dict(
            network_id=base.NETWORK1['id'],
            ipvpn=dict(
                ip_address=base.PORT10['ip_address'],
                mac_address=base.PORT10['mac_address'],
                local_port=dict(linuxif=linuxbr1)
            )
        )

        detach_info11 = dict(
            network_id=base.NETWORK1['id'],
            ipvpn=dict(
                ip_address=base.PORT11['ip_address'],
                mac_address=base.PORT11['mac_address'],
                local_port=dict(linuxif=linuxbr1)
            )
        )

        def check_build_cb(port_id, detach_info):
            self.assertDictEqual(
                {},
                self.agent_ext.build_sfc_attach_info(port_id)
                )

        # we need to check that build_sfc_attach_info contains the expected
        # content precisely at the time when do_port_plug_refresh is called
        self.mocked_bagpipe_agent.do_port_plug_refresh.side_effect = (
            check_build_cb
        )

        # Delete chain hop
        self._chain_hops_notif([chain_hop], rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info10),
             mock.call(base.PORT11['id'], detach_info11)],
            any_order=True
        )

        # Verify attachment list consistency
        self._check_network_info(base.NETWORK1['id'], 2)
        for port_id in net_ports[base.NETWORK1['id']]:
            self._check_port_sfc_info(port_id)

    def test_one_by_one_chain_hops_deleted_same_port(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))
        self.agent_ext.handle_port(None, self._port_data(base.PORT20))
        self.agent_ext.handle_port(None, self._port_data(base.PORT21))

        egress_params_1 = copy.copy(CHAIN_HOP_EGRESS_PARAMS1)
        egress_params_1.update(
            dict(classifiers=jsonutils.dumps([CHAIN_HOP_CLASSIFIER]))
        )

        chain_hop_1 = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2,
            **egress_params_1)

        egress_params_2 = copy.copy(CHAIN_HOP_EGRESS_PARAMS2)
        egress_params_2.update(
            dict(classifiers=jsonutils.dumps([CHAIN_HOP_REVERSE_CLASSIFIER]))
        )

        chain_hop_2 = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT2000,
            ingress_network=base.NETWORK2,
            egress_network=base.NETWORK1,
            **egress_params_2)

        self._chain_hops_notif([chain_hop_1, chain_hop_2], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id']),
             mock.call(base.PORT20['id']), mock.call(base.PORT21['id'])],
            any_order=True
        )

        # Verify attachment list consistency
        for network_id in [base.NETWORK1['id'], base.NETWORK2['id']]:
            self._check_network_info(network_id, 2)
            for port_id in net_ports[network_id]:
                self._check_port_sfc_info(port_id,
                                          [sfc_const.INGRESS,
                                           sfc_const.EGRESS])

        self.mocked_bagpipe_agent.reset_mock()

        # Prepare expected information for DELETE
        linuxbr1 = LinuxBridgeManager.get_bridge_name(base.NETWORK1['id'])

        detach_info10 = dict(
            network_id=base.NETWORK1['id'],
            ipvpn=dict(
                ip_address=base.PORT10['ip_address'],
                mac_address=base.PORT10['mac_address'],
                local_port=dict(linuxif=linuxbr1)
            )
        )

        detach_info11 = dict(
            network_id=base.NETWORK1['id'],
            ipvpn=dict(
                ip_address=base.PORT11['ip_address'],
                mac_address=base.PORT11['mac_address'],
                local_port=dict(linuxif=linuxbr1)
            )
        )

        linuxbr2 = LinuxBridgeManager.get_bridge_name(base.NETWORK2['id'])

        detach_info20 = dict(
            network_id=base.NETWORK2['id'],
            ipvpn=dict(
                ip_address=base.PORT20['ip_address'],
                mac_address=base.PORT20['mac_address'],
                local_port=dict(linuxif=linuxbr2)
            )
        )

        detach_info21 = dict(
            network_id=base.NETWORK2['id'],
            ipvpn=dict(
                ip_address=base.PORT21['ip_address'],
                mac_address=base.PORT21['mac_address'],
                local_port=dict(linuxif=linuxbr2)
            )
        )

        self.port2build_attach = {
            base.PORT10['id']: dict(
                network_id=base.NETWORK1['id'],
                ipvpn=[dict(
                    ip_address=base.PORT10['ip_address'],
                    mac_address=base.PORT10['mac_address'],
                    gateway_ip=base.NETWORK1['gateway_ip'],
                    local_port=dict(linuxif=linuxbr1),
                    import_rt=CHAIN_HOP_RT1000,
                    export_rt=[]
                )]
            ),
            base.PORT11['id']: dict(
                network_id=base.NETWORK1['id'],
                ipvpn=[dict(
                    ip_address=base.PORT11['ip_address'],
                    mac_address=base.PORT11['mac_address'],
                    gateway_ip=base.NETWORK1['gateway_ip'],
                    local_port=dict(linuxif=linuxbr1),
                    import_rt=CHAIN_HOP_RT1000,
                    export_rt=[]
                )]
            ),
            base.PORT20['id']: dict(
                network_id=base.NETWORK2['id'],
                ipvpn=[dict(
                    ip_address=base.PORT20['ip_address'],
                    mac_address=base.PORT20['mac_address'],
                    gateway_ip=base.NETWORK2['gateway_ip'],
                    local_port=dict(linuxif=linuxbr2),
                    import_rt=[],
                    export_rt=CHAIN_HOP_RT1000,
                    readvertise=dict(
                        from_rt=egress_params_1['readv_from_rts'],
                        to_rt=[egress_params_1['readv_to_rt']]
                    ),
                    attract_traffic=dict(
                        redirect_rts=egress_params_1['redirect_rts'],
                        classifier=CHAIN_HOP_CLASSIFIER
                    ),
                    lb_consistent_hash_order=0
                )]
            ),
            base.PORT21['id']: dict(
                network_id=base.NETWORK2['id'],
                ipvpn=[dict(
                    ip_address=base.PORT21['ip_address'],
                    mac_address=base.PORT21['mac_address'],
                    gateway_ip=base.NETWORK2['gateway_ip'],
                    local_port=dict(linuxif=linuxbr2),
                    import_rt=[],
                    export_rt=CHAIN_HOP_RT1000,
                    readvertise=dict(
                        from_rt=egress_params_1['readv_from_rts'],
                        to_rt=[egress_params_1['readv_to_rt']]
                    ),
                    attract_traffic=dict(
                        redirect_rts=egress_params_1['redirect_rts'],
                        classifier=CHAIN_HOP_CLASSIFIER
                    ),
                    lb_consistent_hash_order=1
                )]
            )
        }

        def check_build_cb_1(port_id, detach_info):
            self.assertDictEqual(
                self.port2build_attach[port_id],
                self.agent_ext.build_sfc_attach_info(port_id)
            )

        # we need to check that build_sfc_attach_info contains the expected
        # content precisely at the time when do_port_plug_refresh is called
        self.mocked_bagpipe_agent.do_port_plug_refresh.side_effect = (
            check_build_cb_1
        )

        self._chain_hops_notif([chain_hop_2], rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info10),
             mock.call(base.PORT11['id'], detach_info11),
             mock.call(base.PORT20['id'], detach_info20),
             mock.call(base.PORT21['id'], detach_info21)],
            any_order=True
        )

        # Verify attachment list consistency
        self._check_network_info(base.NETWORK1['id'], 2)
        for port in [base.PORT10, base.PORT11]:
            self._check_port_sfc_info(port['id'], [sfc_const.INGRESS])

        self._check_network_info(base.NETWORK2['id'], 2)
        for port in [base.PORT20, base.PORT21]:
            self._check_port_sfc_info(port['id'], [sfc_const.EGRESS])

        self.mocked_bagpipe_agent.reset_mock()

        def check_build_cb_2(port_id, detach_info):
            self.assertDictEqual(
                {},
                self.agent_ext.build_sfc_attach_info(port_id)
                )

        # we need to check that build_sfc_attach_info contains the expected
        # content precisely at the time when do_port_plug_refresh is called
        self.mocked_bagpipe_agent.do_port_plug_refresh.side_effect = (
            check_build_cb_2
        )

        # Delete port hop
        self._chain_hops_notif([chain_hop_1], rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info10),
             mock.call(base.PORT11['id'], detach_info11),
             mock.call(base.PORT20['id'], detach_info20),
             mock.call(base.PORT21['id'], detach_info21)],
            any_order=True
        )

        # Verify attachment list consistency
        for network_id in [base.NETWORK1['id'], base.NETWORK2['id']]:
            self._check_network_info(network_id, 2)
            for port_id in net_ports[network_id]:
                self._check_port_sfc_info(port_id)

    def test_port_hop_deleted_remaining_ingress_ports(self):
        self.agent_ext.handle_port(None, self._port_data(base.PORT10))
        self.agent_ext.handle_port(None, self._port_data(base.PORT11))

        chain_hop = self._fake_chain_hop(
            portchain_id=uuidutils.generate_uuid(),
            rts=CHAIN_HOP_RT1000,
            ingress_network=base.NETWORK1,
            egress_network=base.NETWORK2)

        self._chain_hops_notif([chain_hop], rpc_events.CREATED)

        self.mocked_bagpipe_agent.do_port_plug.assert_has_calls(
            [mock.call(base.PORT10['id']), mock.call(base.PORT11['id'])],
            any_order=True
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 2)
        for port_id in net_ports[base.NETWORK1['id']]:
            self._check_port_sfc_info(port_id, [sfc_const.INGRESS])

        self.mocked_bagpipe_agent.reset_mock()

        # Prepare expected information for DELETE
        linuxbr1 = LinuxBridgeManager.get_bridge_name(base.NETWORK1['id'])

        detach_info10 = dict(
            network_id=base.NETWORK1['id'],
            ipvpn=dict(
                ip_address=base.PORT10['ip_address'],
                mac_address=base.PORT10['mac_address'],
                local_port=dict(linuxif=linuxbr1)
            )
        )

        def check_build_cb(port_id, detach_info):
            self.assertDictEqual(
                {},
                self.agent_ext.build_sfc_attach_info(base.PORT10['id'])
                )

        # we need to check that build_sfc_attach_info contains the expected
        # content precisely at the time when do_port_plug_refresh is called
        self.mocked_bagpipe_agent.do_port_plug_refresh.side_effect = (
            check_build_cb
        )

        # Delete port hop
        port10_hops = self._fake_port_hops(base.PORT10['id'],
                                           ingress_hops=[chain_hop])
        self._port_hops_notif([port10_hops], rpc_events.DELETED)

        self.mocked_bagpipe_agent.do_port_plug_refresh.assert_has_calls(
            [mock.call(base.PORT10['id'], detach_info10)]
        )

        # Verify attachments list consistency
        self._check_network_info(base.NETWORK1['id'], 2)
        self._check_port_sfc_info(base.PORT10['id'])
        self._check_port_sfc_info(base.PORT11['id'], [sfc_const.INGRESS])
