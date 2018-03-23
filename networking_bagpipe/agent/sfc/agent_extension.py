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

"""
L2 Agent extension to support bagpipe networking-sfc driver RPCs in the
Linux Bridge agent
"""
from copy import deepcopy

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_serialization import jsonutils

from oslo_concurrency import lockutils

from neutron_lib.agent import l2_extension
from neutron_lib import constants as n_const

from networking_bagpipe.agent import agent_base_info
from networking_bagpipe.agent import bagpipe_bgp_agent
from networking_bagpipe.bagpipe_bgp import constants as bbgp_const
from networking_bagpipe.driver import constants as sfc_const
from networking_bagpipe.objects import sfc as sfc_obj

from neutron.api.rpc.callbacks.consumer import registry as cons_registry
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc

from neutron.plugins.ml2.drivers.linuxbridge.agent.common \
    import constants as lb_agt_constants
from neutron.plugins.ml2.drivers.linuxbridge.agent.linuxbridge_neutron_agent \
    import LinuxBridgeManager

LOG = logging.getLogger(__name__)

SFC_SERVICE = 'sfc'


class BagpipeSfcAgentExtension(l2_extension.L2AgentExtension,
                               agent_base_info.BaseInfoManager):

    def initialize(self, connection, driver_type):

        if driver_type != lb_agt_constants.EXTENSION_DRIVER_TYPE:
            raise Exception("This extension is currently working only with the"
                            " Linux Bridge Agent")

        self.bagpipe_bgp_agent = (
            bagpipe_bgp_agent.BaGPipeBGPAgent.get_instance(
                n_const.AGENT_TYPE_LINUXBRIDGE)
        )

        self.bagpipe_bgp_agent.register_build_callback(
            SFC_SERVICE,
            self.build_sfc_attach_info)

        self.ports = set()
        self.bagpipe_bgp_agent.register_port_list(SFC_SERVICE,
                                                  self.ports)

        self._setup_rpc(connection)

    def _setup_rpc(self, connection):
        self._pull_rpc = resources_rpc.ResourcesPullRpcApi()
        self._register_rpc_consumers(connection)

    def _register_rpc_consumers(self, connection):
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]

        # Consume BaGPipeChainHop OVO RPC
        cons_registry.register(self.handle_sfc_chain_hops,
                               sfc_obj.BaGPipeChainHop.obj_name())
        topic_chain_hop = resources_rpc.resource_type_versioned_topic(
            sfc_obj.BaGPipeChainHop.obj_name())
        connection.create_consumer(topic_chain_hop, endpoints, fanout=True)

        # Consume BaGPipePortHops OVO RPC
        cons_registry.register(self.handle_sfc_port_hops,
                               sfc_obj.BaGPipePortHops.obj_name())
        topic_port_hops = resources_rpc.resource_type_versioned_topic(
            sfc_obj.BaGPipePortHops.obj_name())
        connection.create_consumer(topic_port_hops, endpoints, fanout=True)

    def _add_sfc_chain_hop_helper_for_port(self, port_id, chain_hop, side,
                                           lb_consistent_hash_order):
        orig_info = deepcopy(chain_hop)
        port_info = self.ports_info[port_id]

        # Set gateway IP address in NetworkInfo if necessary
        net_info = port_info.network
        if net_info.gateway_info == agent_base_info.NO_GW_INFO:
            gateway_info = (
                agent_base_info.GatewayInfo(None,
                                            chain_hop[side + '_gw'])
            )
            net_info.set_gateway_info(gateway_info)

        # FIXME: We could use subset bytes of port pair id to avoid hash
        # polarization
        # Chain hop ingress, respectively egress, port corresponds to SFC port
        # pair egress, respectively ingress, port side.
        if side == sfc_const.EGRESS:
            orig_info['lb_consistent_hash_order'] = (
                lb_consistent_hash_order
            )

        port_info.add_chain_hop({side: orig_info})

    def _add_sfc_chain_hop_helper(self, port_ids, chain_hop, side):
        for index, port_id in enumerate(port_ids):
            if port_id not in self.ports_info:
                continue

            self._add_sfc_chain_hop_helper_for_port(port_id, chain_hop, side,
                                                    index)

    def _remove_sfc_chain_hop_helper(self, port_info, chain_hop, side):
        sfc_info = port_info.chain_hops
        if side in sfc_info:
            if side == sfc_const.EGRESS:
                sfc_info[side].pop('lb_consistent_hash_order')

            if chain_hop != sfc_info[side]:
                LOG.warning("%s service inconsistent %s informations for "
                            "port %s", SFC_SERVICE, side, port_info.id)
                return

            sfc_info.pop(side)

    def build_sfc_attach_info(self, port_id):
        if port_id not in self.ports_info:
            LOG.warning("%s service has no PortInfo for port %s",
                        SFC_SERVICE, port_id)
            return {}

        port_info = self.ports_info[port_id]

        ipvpn_attachment = self._build_attachment(port_info)

        attachments = {}

        if ipvpn_attachment:
            attachments[bbgp_const.IPVPN] = [ipvpn_attachment]
            attachments['network_id'] = port_info.network.id

        return attachments

    def _build_attachment(self, port_info):
        if not port_info.chain_hops:
            return {}

        linuxbr = LinuxBridgeManager.get_bridge_name(port_info.network.id)
        chain_hop = port_info.chain_hops

        attachment = {
            'ip_address': port_info.ip_address,
            'mac_address': port_info.mac_address,
            'gateway_ip': port_info.network.gateway_info.ip,
            'local_port': {'linuxif': linuxbr},
            bbgp_const.RT_IMPORT: (chain_hop[sfc_const.INGRESS]['rts']
                                   if chain_hop.get(sfc_const.INGRESS)
                                   else []),
            bbgp_const.RT_EXPORT: (chain_hop[sfc_const.EGRESS]['rts']
                                   if chain_hop.get(sfc_const.EGRESS)
                                   else [])
        }

        egress_info = chain_hop.get(sfc_const.EGRESS)
        if egress_info:
            if egress_info.get('readv_to_rt'):
                attachment.update({
                    'readvertise': dict(
                        from_rt=egress_info.get('readv_from_rts', []),
                        to_rt=[egress_info['readv_to_rt']]
                    )
                })

            if (egress_info.get('redirect_rts') and
                    egress_info.get('classifiers')):
                classifier = jsonutils.loads(egress_info['classifiers'])[0]

                attract_traffic = dict(
                    redirect_rts=egress_info['redirect_rts'],
                    classifier=classifier
                )

                if egress_info.get('attract_to_rt'):
                    destination_prefix = classifier.get('destinationPrefix',
                                                        '0.0.0.0/0')

                    attract_traffic.update(dict(
                        to_rt=[egress_info['attract_to_rt']],
                        static_destination_prefixes=[destination_prefix])
                    )

                attachment.update(
                    dict(attract_traffic=attract_traffic)
                )

            attachment.update(dict(
                lb_consistent_hash_order=egress_info[
                    'lb_consistent_hash_order'])
            )

        return attachment

    def _build_sfc_detach_info(self, port_info):
        linuxbr = LinuxBridgeManager.get_bridge_name(port_info.network.id)

        detach_info = {
            'network_id': port_info.network.id,
            bbgp_const.IPVPN: {
                'ip_address': port_info.ip_address,
                'mac_address': port_info.mac_address,
                'local_port': {'linuxif': linuxbr}
            }
        }

        return detach_info

    def handle_sfc_chain_hops(self, context, resource_type, chain_hops,
                              event_type):
        LOG.debug("handle_sfc_chain_hops called with: {resource_type: %s, "
                  "chain_hops: %s, event_type: %s",
                  resource_type, chain_hops, event_type)
        if event_type == rpc_events.CREATED:
            self.sfc_ports_attach(chain_hops)
        elif event_type == rpc_events.DELETED:
            self.sfc_ports_detach(chain_hops)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-sfc')
    def sfc_ports_attach(self, chain_hops):
        attach_ids = set()

        for hop in chain_hops:
            hop_dict = hop.to_dict()

            ingress_ids = hop_dict.pop('ingress_ports')
            egress_ids = hop_dict.pop('egress_ports')

            if ingress_ids:
                self._add_sfc_chain_hop_helper(ingress_ids, hop_dict,
                                               sfc_const.INGRESS)
                attach_ids.update(ingress_ids)

            if egress_ids:
                self._add_sfc_chain_hop_helper(egress_ids, hop_dict,
                                               sfc_const.EGRESS)
                attach_ids.update(egress_ids)

        port_ids = [p_id for p_id in attach_ids if p_id in self.ports_info]
        for port_id in port_ids:
            self.bagpipe_bgp_agent.do_port_plug(port_id)

    def _remove_sfc_info_for_port(self, port_id, side, chain_hop,
                                  ports_to_detach):
        port_info = self.ports_info.get(port_id)
        if not port_info:
            LOG.warning("%s service inconsistent for port %s",
                        SFC_SERVICE, port_id)
            return

        if port_id not in ports_to_detach:
            detach_info = self._build_sfc_detach_info(port_info)

            ports_to_detach[port_id] = detach_info

        self._remove_sfc_chain_hop_helper(port_info, chain_hop, side)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-sfc')
    def sfc_ports_detach(self, chain_hops):
        ports_to_detach = dict()

        for hop in chain_hops:
            hop_dict = hop.to_dict()

            ingress_ids = hop_dict.pop('ingress_ports')
            egress_ids = hop_dict.pop('egress_ports')

            if ingress_ids:
                for port_id in ingress_ids:
                    self._remove_sfc_info_for_port(port_id,
                                                   sfc_const.INGRESS,
                                                   hop_dict,
                                                   ports_to_detach)

            if egress_ids:
                for port_id in egress_ids:
                    self._remove_sfc_info_for_port(port_id,
                                                   sfc_const.EGRESS,
                                                   hop_dict,
                                                   ports_to_detach)

        for port_id, detach_info in ports_to_detach.items():
            self.bagpipe_bgp_agent.do_port_plug_refresh(port_id, detach_info)

    def handle_sfc_port_hops(self, context, resource_type, port_hops,
                             event_type):
        LOG.debug("handle_sfc_port_hops called with: {resource_type: %s, "
                  "port_hops: %s, event_type: %s",
                  (resource_type, port_hops, event_type))
        if event_type == rpc_events.CREATED:
            self.sfc_add_port_hops(port_hops)
        elif event_type == rpc_events.DELETED:
            self.sfc_remove_port_hops(port_hops)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-sfc')
    def sfc_add_port_hops(self, port_hops):
        for port_hop in port_hops:
            port_id = port_hop.port_id
            for side in [sfc_const.INGRESS, sfc_const.EGRESS]:
                for hop in getattr(port_hop, side + '_hops'):
                    hop_dict = hop.to_dict()

                    lb_consistent_hash_order = (
                        hop_dict[side + '_ports'].index(port_id)
                    )

                    del hop_dict['ingress_ports']
                    del hop_dict['egress_ports']

                    self._add_sfc_chain_hop_helper_for_port(
                        port_id, hop_dict, side, lb_consistent_hash_order
                    )

            self.bagpipe_bgp_agent.do_port_plug(port_id)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-sfc')
    def sfc_remove_port_hops(self, port_hops):
        for port_hop in port_hops:
            port_id = port_hop.port_id
            port_info = self.ports_info.get(port_id)

            if not port_info:
                LOG.warning("%s service inconsistent for port %s",
                            SFC_SERVICE, port_id)
                continue

            detach_info = self._build_sfc_detach_info(port_info)
            self.ports_info[port_id].chain_hops = {}

            self.bagpipe_bgp_agent.do_port_plug_refresh(port_id, detach_info)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-sfc')
    def handle_port(self, context, port):
        port_id = port['port_id']
        net_id = port['network_id']

        self.ports.add(port_id)

        net_info, port_info = (
            self._get_network_port_infos(net_id, port_id)
        )

        port_info.mac_address = port['mac_address']
        port_info.ip_address = port['fixed_ips'][0]['ip_address']

        port_hops = self._pull_rpc.bulk_pull(
            context,
            sfc_obj.BaGPipeChainHop.obj_name(),
            filter_kwargs=dict(port_id=port_id))

        for port_hop in port_hops:
            hop_dict = port_hop.to_dict()
            ingress_ports = hop_dict.pop('ingress_ports')
            egress_ports = hop_dict.pop('egress_ports')

            if port_id in ingress_ports:
                self._add_sfc_chain_hop_helper_for_port(
                    port_id, hop_dict, sfc_const.INGRESS,
                    ingress_ports.index(port_id)
                )

            if port_id in egress_ports:
                self._add_sfc_chain_hop_helper_for_port(
                    port_id, hop_dict, sfc_const.EGRESS,
                    egress_ports.index(port_id)
                )

        if port_info.chain_hops:
            self.bagpipe_bgp_agent.do_port_plug(port_id)

    @log_helpers.log_method_call
    @lockutils.synchronized('bagpipe-sfc')
    def delete_port(self, context, port):
        port_id = port['port_id']
        port_info = self.ports_info.get(port_id)

        if port_info and port_info.chain_hops:
            detach_info = self._build_sfc_detach_info(port_info)

            self._remove_network_port_infos(port_info.network.id, port_id)
            self.ports.remove(port_id)

            self.bagpipe_bgp_agent.do_port_plug_refresh(port_id,
                                                        detach_info)
