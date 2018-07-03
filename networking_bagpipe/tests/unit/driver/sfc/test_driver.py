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

import mock

from oslo_serialization import jsonutils
from oslo_utils import importutils

from neutron_lib import context

from neutron.api import extensions as api_ext
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.common import config

from networking_bagpipe.driver import sfc as driver
from networking_bagpipe.objects import sfc as sfc_obj
from networking_bagpipe.tests.unit.driver.sfc import base as sfc_base

from networking_sfc.db import flowclassifier_db as fc_db
from networking_sfc.db import sfc_db
from networking_sfc.extensions import flowclassifier
from networking_sfc.extensions import servicegraph
from networking_sfc.extensions import sfc
from networking_sfc.extensions import tap
from networking_sfc.services.sfc.common import context as sfc_ctx
from networking_sfc.services.sfc.common import exceptions as sfc_exc
from networking_sfc.tests.unit.db import test_flowclassifier_db
from networking_sfc.tests.unit.db import test_sfc_db


class BaGPipeSfcDriverTestCase(
    test_sfc_db.SfcDbPluginTestCaseBase,
    test_flowclassifier_db.FlowClassifierDbPluginTestCaseBase,
    sfc_base.NeutronDbPluginV2TestCase
):

    resource_prefix_map = dict([
        (k, sfc.SFC_PREFIX)
        for k in sfc.RESOURCE_ATTRIBUTE_MAP.keys()
    ] + [
        (k, flowclassifier.FLOW_CLASSIFIER_PREFIX)
        for k in flowclassifier.RESOURCE_ATTRIBUTE_MAP.keys()
    ])

    def setUp(self):
        sfc_plugin = test_sfc_db.DB_SFC_PLUGIN_CLASS
        flowclassifier_plugin = (
            test_flowclassifier_db.DB_FLOWCLASSIFIER_PLUGIN_CLASS)

        service_plugins = {
            sfc.SFC_EXT: sfc_plugin,
            flowclassifier.FLOW_CLASSIFIER_EXT: flowclassifier_plugin
        }
        sfc_db.SfcDbPlugin.supported_extension_aliases = [
            sfc.SFC_EXT, servicegraph.SG_EXT, tap.TAP_EXT]
        sfc_db.SfcDbPlugin.path_prefix = sfc.SFC_PREFIX
        fc_db.FlowClassifierDbPlugin.supported_extension_aliases = [
            flowclassifier.FLOW_CLASSIFIER_EXT]
        fc_db.FlowClassifierDbPlugin.path_prefix = (
            flowclassifier.FLOW_CLASSIFIER_PREFIX
        )
        super(BaGPipeSfcDriverTestCase, self).setUp(
            ext_mgr=None,
            plugin=None,
            service_plugins=service_plugins
        )
        self.sfc_plugin = importutils.import_object(sfc_plugin)
        self.flowclassifier_plugin = importutils.import_object(
            flowclassifier_plugin)
        ext_mgr = api_ext.PluginAwareExtensionManager.get_instance()
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)
        self.ctx = context.get_admin_context()

        self.driver = driver.BaGPipeSfcDriver()
        self.driver.initialize()
        self.mocked_push_rpc = self.driver._push_rpc.push = mock.Mock()

    def _validate_chain_hop_rpc_call(self, call_index, rpc_event,
                                     expected_chain_hops):
        rpc_call_args = self.mocked_push_rpc.call_args_list[call_index][0]
        self.assertEqual(len(rpc_call_args[1]), len(expected_chain_hops))
        self.assertEqual(rpc_call_args[2], rpc_event)

        for index, hop in enumerate(rpc_call_args[1]):
            current_hop = hop.to_dict()

            if current_hop.get('classifiers'):
                current_hop['classifiers'] = (
                    jsonutils.loads(current_hop['classifiers'])
                )

            self.assertDictContainsSubset(
                expected_chain_hops[index],
                current_hop)

    def _validate_port_hops_rpc_call(self, call_index, rpc_event,
                                     ingress_port, egress_port):
        rpc_call_args = self.mocked_push_rpc.call_args_list[call_index][0]
        self.assertEqual(len(rpc_call_args[1]), 2)
        self.assertEqual(rpc_call_args[2], rpc_event)

        self.assertEqual(ingress_port, rpc_call_args[1][0].port_id)
        self.assertEqual(len(rpc_call_args[1][0].ingress_hops), 0)
        self.assertEqual(len(rpc_call_args[1][0].egress_hops),
                         int(rpc_event == rpc_events.CREATED))

        if rpc_event == rpc_events.CREATED:
            self.assertIsInstance(rpc_call_args[1][0].egress_hops[0],
                                  sfc_obj.BaGPipeChainHop)

        self.assertEqual(egress_port, rpc_call_args[1][1].port_id)
        self.assertEqual(len(rpc_call_args[1][1].ingress_hops),
                         int(rpc_event == rpc_events.CREATED))
        self.assertEqual(len(rpc_call_args[1][1].egress_hops), 0)

        if rpc_event == rpc_events.CREATED:
            self.assertIsInstance(rpc_call_args[1][1].ingress_hops[0],
                                  sfc_obj.BaGPipeChainHop)

    def test_create_port_chain(self):
        with self.port_pair_group(
            port_pair_group={'name': 'test_ppg'}
        ) as ppg:
            ppg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                ppg['port_pair_group']
            )
            self.driver.create_port_pair_group(ppg_context)
            with self.port_chain(port_chain={
                'name': 'test_chain',
                'port_pair_groups': [
                    ppg['port_pair_group']['id']
                ]
            }) as pc:
                pc_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc['port_chain']
                )
                self.driver.create_port_chain(pc_context)

                self.mocked_push_rpc.assert_not_called()

    def test_create_port_chain_with_port_pairs(self):
        with self.port(
            name='ingress_port',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port, self.port(
            name='egress_port',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port:
            with self.port_pair(port_pair={
                'ingress': ingress_port['port']['id'],
                'egress': egress_port['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [pp['port_pair']['id']]
                }) as ppg:
                    ppg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg_context)
                    with self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg['port_pair_group']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        self.mocked_push_rpc.assert_not_called()

    def test_create_port_chain_with_flow_classifiers(self):
        with self.port_pair_group(
            port_pair_group={'name': 'test_ppg'}
        ) as ppg:
            ppg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                ppg['port_pair_group']
            )
            self.driver.create_port_pair_group(ppg_context)
            with self.flow_classifier(flow_classifier={
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'destination_port_range_min': 300,
                'destination_port_range_max': 400,
                'ethertype': 'IPv4',
                'source_ip_prefix': sfc_base.SRC_CIDR,
                'destination_ip_prefix': sfc_base.DEST_CIDR,
                'l7_parameters': {},
                'protocol': 'tcp'
            }) as fc, self.port_chain(port_chain={
                'name': 'test_chain',
                'port_pair_groups': [
                    ppg['port_pair_group']['id']
                ],
                'flow_classifiers': [
                    fc['flow_classifier']['id']
                ]
            }) as pc:
                pc_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc['port_chain']
                )
                self.driver.create_port_chain(pc_context)

                self.mocked_push_rpc.assert_not_called()

    def test_create_port_chain_with_flow_classifiers_port_pairs(self):
        with self.port(
            name='src_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port, self.port(
            name='ingress_port',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port, self.port(
            name='egress_port',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port, self.port(
            name='dest_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._dest_net['network']['id']
        ) as dest_port:
            with self.port_pair(port_pair={
                'ingress': ingress_port['port']['id'],
                'egress': egress_port['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp['port_pair']['id']
                    ]
                }) as ppg:
                    ppg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg_context)
                    with self.flow_classifier(flow_classifier={
                        'source_port_range_min': 100,
                        'source_port_range_max': 200,
                        'destination_port_range_min': 300,
                        'destination_port_range_max': 400,
                        'ethertype': 'IPv4',
                        'source_ip_prefix': sfc_base.SRC_CIDR,
                        'destination_ip_prefix': sfc_base.DEST_CIDR,
                        'l7_parameters': {},
                        'protocol': 'tcp',
                        'logical_source_port': src_port['port']['id']
                    }) as fc, self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg['port_pair_group']['id']
                        ],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        expected_chain_hops = [dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._dest_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.DEST_GATEWAY,
                            ingress_ports=[egress_port['port']['id']],
                            egress_ports=[dest_port['port']['id']],
                            rts=[self._dest_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg['port_pair_group']['id'],
                            ingress_network=self._src_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.SRC_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[src_port['port']['id']],
                            egress_ports=[ingress_port['port']['id']],
                            rts=['64512:5000'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5000'],
                            attract_to_rt='64512:5001',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        )]

                        self.assertEqual(self.mocked_push_rpc.call_count, 1)
                        self._validate_chain_hop_rpc_call(0,
                                                          rpc_events.CREATED,
                                                          expected_chain_hops)

    def test_create_port_chain_multi_port_pair_groups_port_pairs(self):
        with self.port(
            name='src_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port, self.port(
            name='ingress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port1, self.port(
            name='egress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port1, self.port(
            name='ingress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port2, self.port(
            name='egress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port2, self.port(
            name='ingress_port3',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port3, self.port(
            name='egress_port3',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port3, self.port(
            name='dest_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._dest_net['network']['id']
        ) as dest_port:
            with self.port_pair(port_pair={
                'ingress': ingress_port1['port']['id'],
                'egress': egress_port1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress_port2['port']['id'],
                'egress': egress_port2['port']['id']
            }) as pp2, self.port_pair(port_pair={
                'ingress': ingress_port3['port']['id'],
                'egress': egress_port3['port']['id']
            }) as pp3:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)
                pp3_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp3['port_pair']
                )
                self.driver.create_port_pair(pp3_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id']
                    ]
                }) as ppg1, self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp2['port_pair']['id']
                    ]
                }) as ppg2, self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp3['port_pair']['id']
                    ]
                }) as ppg3:
                    ppg1_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg1['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg1_context)
                    ppg2_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg2['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg2_context)
                    ppg3_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg3['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg3_context)
                    with self.flow_classifier(flow_classifier={
                        'source_port_range_min': 100,
                        'source_port_range_max': 200,
                        'destination_port_range_min': 300,
                        'destination_port_range_max': 400,
                        'ethertype': 'IPv4',
                        'source_ip_prefix': sfc_base.SRC_CIDR,
                        'destination_ip_prefix': sfc_base.DEST_CIDR,
                        'l7_parameters': {},
                        'protocol': 'tcp',
                        'logical_source_port': src_port['port']['id']
                    }) as fc, self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg1['port_pair_group']['id'],
                            ppg2['port_pair_group']['id'],
                            ppg3['port_pair_group']['id']
                        ],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        expected_chain_hops = [dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg3['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._dest_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.DEST_GATEWAY,
                            ingress_ports=[egress_port3['port']['id']],
                            egress_ports=[dest_port['port']['id']],
                            rts=[self._dest_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg2['port_pair_group']['id'],
                            egress_ppg=ppg3['port_pair_group']['id'],
                            ingress_network=None,
                            egress_network=None,
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[egress_port2['port']['id']],
                            egress_ports=[ingress_port3['port']['id']],
                            rts=['64512:5000'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5000'],
                            attract_to_rt='64512:5001',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg1['port_pair_group']['id'],
                            egress_ppg=ppg2['port_pair_group']['id'],
                            ingress_network=None,
                            egress_network=None,
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[egress_port1['port']['id']],
                            egress_ports=[ingress_port2['port']['id']],
                            rts=['64512:5002'],
                            readv_from_rts=['64512:5001'],
                            readv_to_rt='64512:5003',
                            redirect_rts=['64512:5002'],
                            attract_to_rt=None,
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg1['port_pair_group']['id'],
                            ingress_network=self._src_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.SRC_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[src_port['port']['id']],
                            egress_ports=[ingress_port1['port']['id']],
                            rts=['64512:5004'],
                            readv_from_rts=['64512:5003'],
                            readv_to_rt='64512:5005',
                            redirect_rts=['64512:5004'],
                            attract_to_rt=None,
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        )]

                        self.assertEqual(self.mocked_push_rpc.call_count, 1)
                        self._validate_chain_hop_rpc_call(0,
                                                          rpc_events.CREATED,
                                                          expected_chain_hops)

    def test_create_port_chain_multi_port_pair_groups_multi_port_pairs(self):
        with self.port(
            name='src_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port, self.port(
            name='ingress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port1, self.port(
            name='egress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port1, self.port(
            name='ingress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port2, self.port(
            name='egress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port2, self.port(
            name='ingress_port3',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port3, self.port(
            name='egress_port3',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port3, self.port(
            name='ingress_port4',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port4, self.port(
            name='egress_port4',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port4, self.port(
            name='dest_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._dest_net['network']['id']
        ) as dest_port:
            with self.port_pair(port_pair={
                'ingress': ingress_port1['port']['id'],
                'egress': egress_port1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress_port2['port']['id'],
                'egress': egress_port2['port']['id']
            }) as pp2, self.port_pair(port_pair={
                'ingress': ingress_port3['port']['id'],
                'egress': egress_port3['port']['id']
            }) as pp3, self.port_pair(port_pair={
                'ingress': ingress_port4['port']['id'],
                'egress': egress_port4['port']['id']
            }) as pp4:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)
                pp3_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp3['port_pair']
                )
                self.driver.create_port_pair(pp3_context)
                pp4_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp4['port_pair']
                )
                self.driver.create_port_pair(pp4_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id'],
                        pp2['port_pair']['id']
                    ]
                }) as ppg1, self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp3['port_pair']['id'],
                        pp4['port_pair']['id']
                    ]
                }) as ppg2:
                    ppg1_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg1['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg1_context)
                    ppg2_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg2['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg2_context)
                    with self.flow_classifier(flow_classifier={
                        'source_port_range_min': 100,
                        'source_port_range_max': 200,
                        'destination_port_range_min': 300,
                        'destination_port_range_max': 400,
                        'ethertype': 'IPv4',
                        'source_ip_prefix': sfc_base.SRC_CIDR,
                        'destination_ip_prefix': sfc_base.DEST_CIDR,
                        'l7_parameters': {},
                        'protocol': 'tcp',
                        'logical_source_port': src_port['port']['id']
                    }) as fc, self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg1['port_pair_group']['id'],
                            ppg2['port_pair_group']['id']
                        ],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        expected_chain_hops = [dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg2['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._dest_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.DEST_GATEWAY,
                            ingress_ports=[egress_port3['port']['id'],
                                           egress_port4['port']['id']],
                            egress_ports=[dest_port['port']['id']],
                            rts=[self._dest_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg1['port_pair_group']['id'],
                            egress_ppg=ppg2['port_pair_group']['id'],
                            ingress_network=None,
                            egress_network=None,
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[egress_port1['port']['id'],
                                           egress_port2['port']['id']],
                            egress_ports=[ingress_port3['port']['id'],
                                          ingress_port4['port']['id']],
                            rts=['64512:5000'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5000'],
                            attract_to_rt='64512:5001',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg1['port_pair_group']['id'],
                            ingress_network=self._src_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.SRC_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[src_port['port']['id']],
                            egress_ports=[ingress_port1['port']['id'],
                                          ingress_port2['port']['id']],
                            rts=['64512:5002'],
                            readv_from_rts=['64512:5001'],
                            readv_to_rt='64512:5003',
                            redirect_rts=['64512:5002'],
                            attract_to_rt=None,
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        )]

                        self.assertEqual(self.mocked_push_rpc.call_count, 1)
                        self._validate_chain_hop_rpc_call(0,
                                                          rpc_events.CREATED,
                                                          expected_chain_hops)

    def test_create_port_chain_with_symmetric_parameter(self):
        with self.port(
            name='src_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port, self.port(
            name='ingress_port',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port, self.port(
            name='egress_port',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port, self.port(
            name='dest_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._dest_net['network']['id']
        ) as dest_port:
            with self.port_pair(port_pair={
                'ingress': ingress_port['port']['id'],
                'egress': egress_port['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp['port_pair']['id']
                    ]
                }) as ppg:
                    ppg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg_context)
                    with self.flow_classifier(flow_classifier={
                        'source_port_range_min': 100,
                        'source_port_range_max': 200,
                        'destination_port_range_min': 300,
                        'destination_port_range_max': 400,
                        'ethertype': 'IPv4',
                        'source_ip_prefix': sfc_base.SRC_CIDR,
                        'destination_ip_prefix': sfc_base.DEST_CIDR,
                        'l7_parameters': {},
                        'protocol': 'tcp',
                        'logical_source_port': src_port['port']['id']
                    }) as fc, self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg['port_pair_group']['id']
                        ],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ],
                        'chain_parameters': {'symmetric': True}
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        expected_chain_hops = [dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._dest_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.DEST_GATEWAY,
                            ingress_ports=[egress_port['port']['id']],
                            egress_ports=[dest_port['port']['id']],
                            rts=[self._dest_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg['port_pair_group']['id'],
                            ingress_network=self._src_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.SRC_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[src_port['port']['id']],
                            egress_ports=[ingress_port['port']['id']],
                            rts=['64512:5000'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5000'],
                            attract_to_rt='64512:5001',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._src_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.SRC_GATEWAY,
                            ingress_ports=[ingress_port['port']['id']],
                            egress_ports=[src_port['port']['id']],
                            rts=[self._src_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=True
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg['port_pair_group']['id'],
                            ingress_network=self._dest_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.DEST_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[dest_port['port']['id']],
                            egress_ports=[egress_port['port']['id']],
                            rts=['64512:5002'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5002'],
                            attract_to_rt='64512:5003',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.DEST_CIDR,
                                     sourcePort='300:400',
                                     destinationPrefix=sfc_base.SRC_CIDR,
                                     destinationPort='100:200')],
                            reverse_hop=True
                        )]

                        self.assertEqual(self.mocked_push_rpc.call_count, 1)
                        self._validate_chain_hop_rpc_call(0,
                                                          rpc_events.CREATED,
                                                          expected_chain_hops)

    def test_update_port_chain_add_port_pair(self):
        with self.port(
            name='src_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port, self.port(
            name='ingress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port1, self.port(
            name='egress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port1, self.port(
            name='ingress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port2, self.port(
            name='egress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port2:
            with self.port_pair(port_pair={
                'ingress': ingress_port1['port']['id'],
                'egress': egress_port1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress_port2['port']['id'],
                'egress': egress_port2['port']['id']
            }) as pp2:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)

                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id']
                    ]
                }) as ppg:
                    ppg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg_context)

                    with self.flow_classifier(flow_classifier={
                        'logical_source_port': src_port['port']['id'],
                        'destination_ip_prefix': sfc_base.DEST_CIDR,
                    }) as fc, self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg['port_pair_group']['id']
                        ],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        self.mocked_push_rpc.reset_mock()

                        updates = {
                            'port_pairs': [
                                pp1['port_pair']['id'],
                                pp2['port_pair']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_pair_groups', {'port_pair_group': updates},
                            ppg['port_pair_group']['id']
                        )
                        res = req.get_response(self.ext_api)
                        ppgbis = self.deserialize(
                            self.fmt, res
                        )
                        ppgbis['port_pair_group']['port_chains'] = [
                            pc['port_chain']['id']
                        ]
                        ppgbis_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            ppgbis['port_pair_group'],
                            original_portpairgroup=ppg['port_pair_group']
                        )
                        self.driver.update_port_pair_group(ppgbis_context)

                        self.assertEqual(self.mocked_push_rpc.call_count, 1)
                        self._validate_port_hops_rpc_call(
                            0,
                            rpc_events.CREATED,
                            ingress_port2['port']['id'],
                            egress_port2['port']['id']
                        )

    def test_update_port_chain_delete_port_pair(self):
        with self.port(
            name='src_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port, self.port(
            name='ingress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port1, self.port(
            name='egress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port1, self.port(
            name='ingress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port2, self.port(
            name='egress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port2:
            with self.port_pair(port_pair={
                'ingress': ingress_port1['port']['id'],
                'egress': egress_port1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress_port2['port']['id'],
                'egress': egress_port2['port']['id']
            }) as pp2:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)

                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id'],
                        pp2['port_pair']['id']
                    ]
                }) as ppg:
                    ppg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg_context)

                    with self.flow_classifier(flow_classifier={
                        'logical_source_port': src_port['port']['id'],
                        'destination_ip_prefix': sfc_base.DEST_CIDR,
                    }) as fc, self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg['port_pair_group']['id']
                        ],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        self.mocked_push_rpc.reset_mock()

                        updates = {
                            'port_pairs': [
                                pp1['port_pair']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_pair_groups', {'port_pair_group': updates},
                            ppg['port_pair_group']['id']
                        )
                        res = req.get_response(self.ext_api)
                        ppgbis = self.deserialize(
                            self.fmt, res
                        )
                        ppgbis['port_pair_group']['port_chains'] = [
                            pc['port_chain']['id']
                        ]
                        ppgbis_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            ppgbis['port_pair_group'],
                            original_portpairgroup=ppg['port_pair_group']
                        )
                        self.driver.update_port_pair_group(ppgbis_context)

                        self.assertEqual(self.mocked_push_rpc.call_count, 1)
                        self._validate_port_hops_rpc_call(
                            0,
                            rpc_events.DELETED,
                            ingress_port2['port']['id'],
                            egress_port2['port']['id']
                        )

    def test_update_port_chain_replace_port_pair(self):
        with self.port(
            name='src_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port, self.port(
            name='ingress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port1, self.port(
            name='egress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port1, self.port(
            name='ingress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port2, self.port(
            name='egress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port2:
            with self.port_pair(port_pair={
                'ingress': ingress_port1['port']['id'],
                'egress': egress_port1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress_port2['port']['id'],
                'egress': egress_port2['port']['id']
            }) as pp2:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)

                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id']
                    ]
                }) as ppg:
                    ppg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg_context)

                    with self.flow_classifier(flow_classifier={
                        'logical_source_port': src_port['port']['id'],
                        'destination_ip_prefix': sfc_base.DEST_CIDR
                    }) as fc, self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg['port_pair_group']['id']
                        ],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        self.mocked_push_rpc.reset_mock()

                        updates = {
                            'port_pairs': [
                                pp2['port_pair']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_pair_groups', {'port_pair_group': updates},
                            ppg['port_pair_group']['id']
                        )
                        res = req.get_response(self.ext_api)
                        ppgbis = self.deserialize(
                            self.fmt, res
                        )
                        ppgbis['port_pair_group']['port_chains'] = [
                            pc['port_chain']['id']
                        ]
                        ppgbis_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            ppgbis['port_pair_group'],
                            original_portpairgroup=ppg['port_pair_group']
                        )
                        self.driver.update_port_pair_group(ppgbis_context)

                        self.assertEqual(self.mocked_push_rpc.call_count, 2)
                        self._validate_port_hops_rpc_call(
                            0,
                            rpc_events.CREATED,
                            ingress_port2['port']['id'],
                            egress_port2['port']['id']
                        )

                        self._validate_port_hops_rpc_call(
                            1,
                            rpc_events.DELETED,
                            ingress_port1['port']['id'],
                            egress_port1['port']['id']
                        )

    def test_update_port_chain_delete_flow_classifier(self):
        with self.port(
            name='src_port1',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port, self.port(
            name='ingress_port',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port, self.port(
            name='egress_port',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port, self.port(
            name='dest_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._dest_net['network']['id']
        ) as dest_port:
            with self.port_pair(port_pair={
                'ingress': ingress_port['port']['id'],
                'egress': egress_port['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)

                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp['port_pair']['id']
                    ]
                }) as ppg:
                    ppg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg_context)

                    with self.flow_classifier(flow_classifier={
                        'source_port_range_min': 100,
                        'source_port_range_max': 200,
                        'destination_port_range_min': 300,
                        'destination_port_range_max': 400,
                        'ethertype': 'IPv4',
                        'source_ip_prefix': sfc_base.SRC_CIDR,
                        'destination_ip_prefix': sfc_base.DEST_CIDR,
                        'l7_parameters': {},
                        'protocol': 'tcp',
                        'logical_source_port': src_port['port']['id']
                    }) as fc, self.port_chain(port_chain={
                        'port_pair_groups': [ppg['port_pair_group']['id']],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        updates = {
                            'flow_classifiers': []
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = req.get_response(self.ext_api)
                        pc2 = self.deserialize(
                            self.fmt, res
                        )
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc2['port_chain'],
                            original_portchain=pc['port_chain']
                        )

                        self.mocked_push_rpc.reset_mock()
                        self.driver.update_port_chain(pc_context)

                        expected_chain_hops = [dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._dest_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.DEST_GATEWAY,
                            ingress_ports=[egress_port['port']['id']],
                            egress_ports=[dest_port['port']['id']],
                            rts=[self._dest_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg['port_pair_group']['id'],
                            ingress_network=self._src_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.SRC_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[src_port['port']['id']],
                            egress_ports=[ingress_port['port']['id']],
                            rts=['64512:5000'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5000'],
                            attract_to_rt='64512:5001',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        )]

                        self.assertEqual(self.mocked_push_rpc.call_count, 1)
                        self._validate_chain_hop_rpc_call(0,
                                                          rpc_events.DELETED,
                                                          expected_chain_hops)

    def test_update_port_chain_replace_flow_classifier(self):
        with self.port(
            name='src_port1',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port1, self.port(
            name='src_port2',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port2, self.port(
            name='ingress_port',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port, self.port(
            name='egress_port',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port:
            with self.port_pair(port_pair={
                'ingress': ingress_port['port']['id'],
                'egress': egress_port['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)

                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp['port_pair']['id']
                    ]
                }) as ppg:
                    ppg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg_context)

                    with self.flow_classifier(flow_classifier={
                        'logical_source_port': src_port1['port']['id'],
                        'destination_ip_prefix': sfc_base.DEST_CIDR
                    }) as fc1, self.flow_classifier(flow_classifier={
                        'logical_source_port': src_port2['port']['id'],
                        'destination_ip_prefix': sfc_base.DEST_CIDR
                    }) as fc2, self.port_chain(port_chain={
                        'port_pair_groups': [ppg['port_pair_group']['id']],
                        'flow_classifiers': [
                            fc1['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        updates = {
                            'flow_classifiers': [
                                fc2['flow_classifier']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = req.get_response(self.ext_api)
                        pc2 = self.deserialize(
                            self.fmt, res
                        )
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc2['port_chain'],
                            original_portchain=pc['port_chain']
                        )
                        self.assertRaises(sfc_exc.SfcDriverError,
                                          self.driver.update_port_chain,
                                          pc_context)

    def test_update_port_chain_add_port_pair_group(self):
        with self.port(
            name='src_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port, self.port(
            name='ingress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port1, self.port(
            name='egress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port1, self.port(
            name='ingress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port2, self.port(
            name='egress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port2, self.port(
            name='dest_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._dest_net['network']['id']
        ) as dest_port:
            with self.port_pair(port_pair={
                'ingress': ingress_port1['port']['id'],
                'egress': egress_port1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress_port2['port']['id'],
                'egress': egress_port2['port']['id']
            }) as pp2:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)

                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id']
                    ]
                }) as ppg1, self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp2['port_pair']['id']
                    ]
                }) as ppg2:
                    ppg1_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg1['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg1_context)
                    ppg2_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg2['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg2_context)

                    with self.flow_classifier(flow_classifier={
                        'source_port_range_min': 100,
                        'source_port_range_max': 200,
                        'destination_port_range_min': 300,
                        'destination_port_range_max': 400,
                        'ethertype': 'IPv4',
                        'source_ip_prefix': sfc_base.SRC_CIDR,
                        'destination_ip_prefix': sfc_base.DEST_CIDR,
                        'l7_parameters': {},
                        'protocol': 'tcp',
                        'logical_source_port': src_port['port']['id']
                    }) as fc, self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg1['port_pair_group']['id']
                        ],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        updates = {
                            'port_pair_groups': [
                                ppg1['port_pair_group']['id'],
                                ppg2['port_pair_group']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = req.get_response(self.ext_api)
                        pc2 = self.deserialize(
                            self.fmt, res
                        )
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc2['port_chain'],
                            original_portchain=pc['port_chain']
                        )

                        self.mocked_push_rpc.reset_mock()
                        self.driver.update_port_chain(pc_context)

                        expected_deleted_hops = [dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg1['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._dest_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.DEST_GATEWAY,
                            ingress_ports=[egress_port1['port']['id']],
                            egress_ports=[dest_port['port']['id']],
                            rts=[self._dest_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg1['port_pair_group']['id'],
                            ingress_network=self._src_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.SRC_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[src_port['port']['id']],
                            egress_ports=[ingress_port1['port']['id']],
                            rts=['64512:5000'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5000'],
                            attract_to_rt='64512:5001',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        )]

                        expected_created_hops = [dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg2['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._dest_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.DEST_GATEWAY,
                            ingress_ports=[egress_port2['port']['id']],
                            egress_ports=[dest_port['port']['id']],
                            rts=[self._dest_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg1['port_pair_group']['id'],
                            egress_ppg=ppg2['port_pair_group']['id'],
                            ingress_network=None,
                            egress_network=None,
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[egress_port1['port']['id']],
                            egress_ports=[ingress_port2['port']['id']],
                            rts=['64512:5000'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5000'],
                            attract_to_rt='64512:5001',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg1['port_pair_group']['id'],
                            ingress_network=self._src_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.SRC_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[src_port['port']['id']],
                            egress_ports=[ingress_port1['port']['id']],
                            rts=['64512:5002'],
                            readv_from_rts=['64512:5001'],
                            readv_to_rt='64512:5003',
                            redirect_rts=['64512:5002'],
                            attract_to_rt=None,
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        )]

                        self.assertEqual(self.mocked_push_rpc.call_count, 2)
                        self._validate_chain_hop_rpc_call(
                            0,
                            rpc_events.DELETED,
                            expected_deleted_hops
                        )

                        self._validate_chain_hop_rpc_call(
                            1,
                            rpc_events.CREATED,
                            expected_created_hops
                        )

    def test_update_port_chain_delete_port_pair_group(self):
        with self.port(
            name='src_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port, self.port(
            name='ingress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port1, self.port(
            name='egress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port1, self.port(
            name='ingress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port2, self.port(
            name='egress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port2, self.port(
            name='dest_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._dest_net['network']['id']
        ) as dest_port:
            with self.port_pair(port_pair={
                'ingress': ingress_port1['port']['id'],
                'egress': egress_port1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress_port2['port']['id'],
                'egress': egress_port2['port']['id']
            }) as pp2:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)

                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id']
                    ]
                }) as ppg1, self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp2['port_pair']['id']
                    ]
                }) as ppg2:
                    ppg1_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg1['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg1_context)
                    ppg2_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg2['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg2_context)

                    with self.flow_classifier(flow_classifier={
                        'source_port_range_min': 100,
                        'source_port_range_max': 200,
                        'destination_port_range_min': 300,
                        'destination_port_range_max': 400,
                        'ethertype': 'IPv4',
                        'source_ip_prefix': sfc_base.SRC_CIDR,
                        'destination_ip_prefix': sfc_base.DEST_CIDR,
                        'l7_parameters': {},
                        'protocol': 'tcp',
                        'logical_source_port': src_port['port']['id']
                    }) as fc, self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg1['port_pair_group']['id'],
                            ppg2['port_pair_group']['id']
                        ],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        updates = {
                            'port_pair_groups': [
                                ppg1['port_pair_group']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = req.get_response(self.ext_api)
                        pc2 = self.deserialize(
                            self.fmt, res
                        )
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc2['port_chain'],
                            original_portchain=pc['port_chain']
                        )

                        self.mocked_push_rpc.reset_mock()
                        self.driver.update_port_chain(pc_context)

                        expected_deleted_hops = [dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg2['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._dest_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.DEST_GATEWAY,
                            ingress_ports=[egress_port2['port']['id']],
                            egress_ports=[dest_port['port']['id']],
                            rts=[self._dest_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg1['port_pair_group']['id'],
                            egress_ppg=ppg2['port_pair_group']['id'],
                            ingress_network=None,
                            egress_network=None,
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[egress_port1['port']['id']],
                            egress_ports=[ingress_port2['port']['id']],
                            rts=['64512:5000'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5000'],
                            attract_to_rt='64512:5001',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg1['port_pair_group']['id'],
                            ingress_network=self._src_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.SRC_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[src_port['port']['id']],
                            egress_ports=[ingress_port1['port']['id']],
                            rts=['64512:5002'],
                            readv_from_rts=['64512:5001'],
                            readv_to_rt='64512:5003',
                            redirect_rts=['64512:5002'],
                            attract_to_rt=None,
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        )]

                        expected_created_hops = [dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg1['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._dest_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.DEST_GATEWAY,
                            ingress_ports=[egress_port1['port']['id']],
                            egress_ports=[dest_port['port']['id']],
                            rts=[self._dest_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg1['port_pair_group']['id'],
                            ingress_network=self._src_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.SRC_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[src_port['port']['id']],
                            egress_ports=[ingress_port1['port']['id']],
                            rts=['64512:5002'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5002'],
                            attract_to_rt='64512:5003',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        )]

                        self.assertEqual(self.mocked_push_rpc.call_count, 2)
                        self._validate_chain_hop_rpc_call(
                            0,
                            rpc_events.DELETED,
                            expected_deleted_hops
                        )

                        self._validate_chain_hop_rpc_call(
                            1,
                            rpc_events.CREATED,
                            expected_created_hops
                        )

    def test_update_port_chain_replace_port_pair_group(self):
        with self.port(
            name='src_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port, self.port(
            name='ingress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port1, self.port(
            name='egress_port1',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port1, self.port(
            name='ingress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port2, self.port(
            name='egress_port2',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port2, self.port(
            name='dest_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._dest_net['network']['id']
        ) as dest_port:
            with self.port_pair(port_pair={
                'ingress': ingress_port1['port']['id'],
                'egress': egress_port1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress_port2['port']['id'],
                'egress': egress_port2['port']['id']
            }) as pp2:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)

                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id']
                    ]
                }) as ppg1, self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp2['port_pair']['id']
                    ]
                }) as ppg2:
                    ppg1_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg1['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg1_context)
                    ppg2_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg2['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg2_context)

                    with self.flow_classifier(flow_classifier={
                        'source_port_range_min': 100,
                        'source_port_range_max': 200,
                        'destination_port_range_min': 300,
                        'destination_port_range_max': 400,
                        'ethertype': 'IPv4',
                        'source_ip_prefix': sfc_base.SRC_CIDR,
                        'destination_ip_prefix': sfc_base.DEST_CIDR,
                        'l7_parameters': {},
                        'protocol': 'tcp',
                        'logical_source_port': src_port['port']['id']
                    }) as fc, self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg1['port_pair_group']['id']
                        ],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        updates = {
                            'port_pair_groups': [
                                ppg2['port_pair_group']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = req.get_response(self.ext_api)
                        pc2 = self.deserialize(
                            self.fmt, res
                        )
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc2['port_chain'],
                            original_portchain=pc['port_chain']
                        )

                        self.mocked_push_rpc.reset_mock()
                        self.driver.update_port_chain(pc_context)

                        expected_deleted_hops = [dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg1['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._dest_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.DEST_GATEWAY,
                            ingress_ports=[egress_port1['port']['id']],
                            egress_ports=[dest_port['port']['id']],
                            rts=[self._dest_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg1['port_pair_group']['id'],
                            ingress_network=self._src_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.SRC_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[src_port['port']['id']],
                            egress_ports=[ingress_port1['port']['id']],
                            rts=['64512:5000'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5000'],
                            attract_to_rt='64512:5001',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        )]

                        expected_created_hops = [dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg2['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._dest_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.DEST_GATEWAY,
                            ingress_ports=[egress_port2['port']['id']],
                            egress_ports=[dest_port['port']['id']],
                            rts=[self._dest_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg2['port_pair_group']['id'],
                            ingress_network=self._src_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.SRC_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[src_port['port']['id']],
                            egress_ports=[ingress_port2['port']['id']],
                            rts=['64512:5002'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5002'],
                            attract_to_rt='64512:5003',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        )]

                        self.assertEqual(self.mocked_push_rpc.call_count, 2)
                        self._validate_chain_hop_rpc_call(
                            0,
                            rpc_events.DELETED,
                            expected_deleted_hops
                        )

                        self._validate_chain_hop_rpc_call(
                            1,
                            rpc_events.CREATED,
                            expected_created_hops
                        )

    def test_delete_port_chain(self):
        with self.port_pair_group(
            port_pair_group={'name': 'test_ppg'}
        ) as ppg:
            ppg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                ppg['port_pair_group']
            )
            self.driver.create_port_pair_group(ppg_context)
            with self.port_chain(port_chain={
                'name': 'test_chain',
                'port_pair_groups': [
                    ppg['port_pair_group']['id']
                ]
            }) as pc:
                pc_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc['port_chain']
                )
                self.driver.create_port_chain(pc_context)

                self.mocked_push_rpc.reset_mock()
                self.driver.delete_port_chain(pc_context)

                self.mocked_push_rpc.assert_not_called()

    def test_delete_port_chain_with_port_pairs(self):
        with self.port(
            name='ingress_port',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port, self.port(
            name='egress_port',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port:
            with self.port_pair(port_pair={
                'ingress': ingress_port['port']['id'],
                'egress': egress_port['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [pp['port_pair']['id']]
                }) as ppg:
                    ppg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg_context)
                    with self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg['port_pair_group']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        self.mocked_push_rpc.reset_mock()
                        self.driver.delete_port_chain(pc_context)

                        self.mocked_push_rpc.assert_not_called()

    def test_delete_port_chain_with_flow_classifiers(self):
        with self.port_pair_group(
            port_pair_group={'name': 'test_ppg'}
        ) as ppg:
            ppg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                ppg['port_pair_group']
            )
            self.driver.create_port_pair_group(ppg_context)
            with self.flow_classifier(flow_classifier={
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'destination_port_range_min': 300,
                'destination_port_range_max': 400,
                'ethertype': 'IPv4',
                'source_ip_prefix': sfc_base.SRC_CIDR,
                'destination_ip_prefix': sfc_base.DEST_CIDR,
                'l7_parameters': {},
                'protocol': 'tcp'
            }) as fc, self.port_chain(port_chain={
                'name': 'test_chain',
                'port_pair_groups': [
                    ppg['port_pair_group']['id']
                ],
                'flow_classifiers': [
                    fc['flow_classifier']['id']
                ]
            }) as pc:
                pc_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc['port_chain']
                )
                self.driver.create_port_chain(pc_context)

                self.mocked_push_rpc.reset_mock()
                self.driver.delete_port_chain(pc_context)

                self.mocked_push_rpc.assert_not_called()

    def test_delete_port_chain_with_flow_classifiers_port_pairs(self):
        with self.port(
            name='src_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._src_net['network']['id']
        ) as src_port, self.port(
            name='ingress_port',
            device_owner='compute:None',
            device_id='test'
        ) as ingress_port, self.port(
            name='egress_port',
            device_owner='compute:None',
            device_id='test'
        ) as egress_port, self.port(
            name='dest_port',
            device_owner='compute:None',
            device_id='test',
            network_id=self._dest_net['network']['id']
        ) as dest_port:
            with self.port_pair(port_pair={
                'ingress': ingress_port['port']['id'],
                'egress': egress_port['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp['port_pair']['id']
                    ]
                }) as ppg:
                    ppg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        ppg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(ppg_context)
                    with self.flow_classifier(flow_classifier={
                        'source_port_range_min': 100,
                        'source_port_range_max': 200,
                        'destination_port_range_min': 300,
                        'destination_port_range_max': 400,
                        'ethertype': 'IPv4',
                        'source_ip_prefix': sfc_base.SRC_CIDR,
                        'destination_ip_prefix': sfc_base.DEST_CIDR,
                        'l7_parameters': {},
                        'protocol': 'tcp',
                        'logical_source_port': src_port['port']['id']
                    }) as fc, self.port_chain(port_chain={
                        'name': 'test_chain',
                        'port_pair_groups': [
                            ppg['port_pair_group']['id']
                        ],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)

                        self.mocked_push_rpc.reset_mock()
                        self.driver.delete_port_chain(pc_context)

                        expected_chain_hops = [dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=ppg['port_pair_group']['id'],
                            egress_ppg=None,
                            ingress_network=None,
                            egress_network=self._dest_net['network']['id'],
                            ingress_gw=self._subnet['subnet']['gateway_ip'],
                            egress_gw=sfc_base.DEST_GATEWAY,
                            ingress_ports=[egress_port['port']['id']],
                            egress_ports=[dest_port['port']['id']],
                            rts=[self._dest_rt],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=[],
                            classifiers=None,
                            reverse_hop=False
                        ), dict(
                            project_id=self._tenant_id,
                            portchain_id=pc['port_chain']['id'],
                            ingress_ppg=None,
                            egress_ppg=ppg['port_pair_group']['id'],
                            ingress_network=self._src_net['network']['id'],
                            egress_network=None,
                            ingress_gw=sfc_base.SRC_GATEWAY,
                            egress_gw=self._subnet['subnet']['gateway_ip'],
                            ingress_ports=[src_port['port']['id']],
                            egress_ports=[ingress_port['port']['id']],
                            rts=['64512:5000'],
                            readv_from_rts=[],
                            readv_to_rt=None,
                            redirect_rts=['64512:5000'],
                            attract_to_rt='64512:5001',
                            classifiers=[
                                dict(protocol='tcp',
                                     sourcePrefix=sfc_base.SRC_CIDR,
                                     sourcePort='100:200',
                                     destinationPrefix=sfc_base.DEST_CIDR,
                                     destinationPort='300:400')],
                            reverse_hop=False
                        )]

                        self.assertEqual(self.mocked_push_rpc.call_count, 1)
                        self._validate_chain_hop_rpc_call(0,
                                                          rpc_events.DELETED,
                                                          expected_chain_hops)
