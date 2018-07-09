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

from netaddr.core import AddrFormatError
from netaddr.ip import IPNetwork

from neutron_lib.api.definitions import bgpvpn as bgpvpn_def
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.plugins import directory

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc

from neutron.db import models_v2

from networking_bagpipe.db import sfc_db
from networking_bagpipe.driver import constants
from networking_bagpipe.objects import sfc as sfc_obj

from networking_sfc.extensions import flowclassifier
from networking_sfc.services.sfc.common import exceptions as exc
from networking_sfc.services.sfc.drivers import base as driver_base

LOG = logging.getLogger(__name__)


class BaGPipeSfcDriver(driver_base.SfcDriverBase,
                       sfc_db.BaGPipeSfcDriverDB):
    """BaGPipe Sfc Driver Base Class."""

    def initialize(self):
        super(BaGPipeSfcDriver, self).initialize()
        self.rt_allocator = sfc_db.RTAllocator()
        self._push_rpc = resources_rpc.ResourcesPushRpcApi()

    def _parse_ipaddress_prefix(self, cidr):
        try:
            net = IPNetwork(cidr)
            return (str(net.ip), net.prefixlen)
        except AddrFormatError:
            raise exc.SfcDriverError(message=(
                "Malformed IP prefix: %s" % cidr))

    def _get_subnet_by_port(self, port_id):
        core_plugin = directory.get_plugin()
        port = core_plugin.get_port(self.admin_context, port_id)
        subnet = None
        for ip in port['fixed_ips']:
            subnet = core_plugin.get_subnet(self.admin_context,
                                            ip["subnet_id"])

            # currently only support one IPv4 subnet for a port
            if subnet['ip_version'] == 4:
                return subnet

    def _get_subnet_by_prefix(self, cidr):
        core_plugin = directory.get_plugin()

        # Parse address/mask
        (ip_address, mask) = self._parse_ipaddress_prefix(cidr)
        if mask == 32:
            port = core_plugin.get_ports(
                self.admin_context,
                filters={'fixed_ips': {'ip_address': [ip_address]}}
            )

            for fixed_ip in port[0]['fixed_ips']:
                # currently only support one subnet for a port, return first
                # one found
                return core_plugin.get_subnet(self.admin_context,
                                              fixed_ip["subnet_id"])
        else:
            return core_plugin.get_subnets(self.admin_context,
                                           filters={'cidr': [cidr]})[0]

    def _get_ports_by_network(self, network_id):
        core_plugin = directory.get_plugin()
        ports = core_plugin.get_ports(self.admin_context,
                                      filters={'network_id': [network_id]})

        return [port['id'] for port in ports]

    def _get_bgpvpns_by_network(self, context, network_id):
        """Retrieve BGP VPNs associated to network.

        Depends on BGP VPN service plugin activation.
        """
        bgpvpns = []
        if not network_id:
            return bgpvpns

        bgpvpn_plugin = (
            directory.get_plugin(bgpvpn_def.ALIAS)
        )
        if not bgpvpn_plugin:
            LOG.warning("BGPVPN service not found")
            return bgpvpns

        tenant_bgpvpns = bgpvpn_plugin.get_bgpvpns(
            self.admin_context,
            filters=dict(tenant_id=[context.current['tenant_id']]))

        if tenant_bgpvpns:
            for bgpvpn in tenant_bgpvpns:
                if network_id in bgpvpn['networks']:
                    bgpvpns.append(bgpvpn)

        LOG.debug("BGPVPNs associated to network %s: %s", network_id, bgpvpns)

        return bgpvpns

    def _get_network_rt(self, network_id):
        core_plugin = directory.get_plugin()
        network = core_plugin.get_network(self.admin_context, network_id)

        return (
            self.rt_allocator._get_rt_from_rtnn(network[pnet.SEGMENTATION_ID])
        )

    def _get_bgpvpn_rts(self, bgpvpn_list):
        import_rts = set()
        export_rts = set()
        for bgpvpn in bgpvpn_list:
            if 'route_targets' in bgpvpn:
                import_rts.add(bgpvpn['route_targets'])
                export_rts.add(bgpvpn['route_targets'])
            if 'import_targets' in bgpvpn:
                import_rts.add(bgpvpn['import_targets'])
            if 'export_targets' in bgpvpn:
                import_rts.add(bgpvpn['export_targets'])

        return (import_rts, export_rts)

    def _get_fcs_by_ids(self, fc_ids):
        flow_classifiers = []
        if not fc_ids:
            return flow_classifiers

        # Get the portchain flow classifiers
        fc_plugin = (
            directory.get_plugin(flowclassifier.FLOW_CLASSIFIER_EXT)
        )
        if not fc_plugin:
            LOG.warning("Not found the flow classifier service plugin")
            return flow_classifiers

        return [fc_plugin.get_flow_classifier(self.admin_context, fc_id)
                for fc_id in fc_ids]

    def _build_bagpipe_classifier_from_fc(self, fc, reverse, source_bgpvpns):
        classifier = {}
        classifier['protocol'] = fc['protocol']

        for side in (constants.SOURCE, constants.DESTINATION):
            flow_side = constants.REVERSE_FLOW_SIDE[side] if reverse else side

            port_range_min = fc[side + '_port_range_min']
            port_range_max = fc[side + '_port_range_max']
            if port_range_min is not None:
                if (port_range_max is not None and
                        port_range_min != port_range_max):
                    classifier[flow_side + 'Port'] = ':'.join(
                        [str(port_range_min), str(port_range_max)]
                    )
                else:
                    classifier[flow_side + 'Port'] = str(port_range_min)

            if flow_side == constants.SOURCE and source_bgpvpns:
                continue

            logical_port = fc['logical_' + side + '_port']
            if logical_port is not None:
                port = self._get_by_id(
                    self.admin_context, models_v2.Port, logical_port
                )
                if fc[side + '_ip_prefix'] is None:
                    ips = port['fixed_ips']
                    # For now, only handle when the port has a single IP
                    if len(ips) == 1:
                        classifier[flow_side + 'Prefix'] = (
                            ips[0]['ip_address'] + '/32'
                        )
                else:
                    classifier[flow_side + 'Prefix'] = (
                        fc[side + '_ip_prefix']
                    )
            else:
                if fc[side + '_ip_prefix'] is not None:
                    classifier[flow_side + 'Prefix'] = (
                        fc[side + '_ip_prefix']
                    )

        return classifier

    def _get_ports_by_portpairs_side(self, pps, side):
        # Sort port pairs list ordering ports for load balancing
        sorted_pps = sorted(pps, key=lambda k: k['id'])

        ports = list()
        for pp in sorted_pps:
            ports.append(pp[side])

        return ports

    def _has_valid_port_pair_groups(self, context, ppg_ids):
        for ppg_id in ppg_ids:
            ppg = context._plugin._get_port_pair_group(context._plugin_context,
                                                       ppg_id)

            if not ppg['port_pairs']:
                return False

        return True

    def _is_valid_port_chain(self, context, port_chain):
        """Verify Port Chain consistency for BaGPipe

        Check if Port Chain contains:
        - At least one Port Pair per Port Pair Group,
        - Only one Flow Classifier
        """
        if not port_chain['flow_classifiers']:
            LOG.warning('Port Chain is inconsistent for BaGPipe, missing Flow '
                        'Classifier')
            return False
        elif len(port_chain['flow_classifiers']) > 1:
            LOG.warning('BaGPipe only support one Flow Classifier per Port '
                        'Chain')
            return False

        if not self._has_valid_port_pair_groups(
                context, port_chain['port_pair_groups']):
            LOG.warning('Port Chain is inconsistent for BaGPipe, missing '
                        'Port Pair in Port Pair Group')
            return False

        return True

    @log_helpers.log_method_call
    def _create_portchain_hop_details(self, context, port_chain,
                                      reverse=False):
        project_id = port_chain['tenant_id']
        hop_details = []
        port_pair_groups = port_chain['port_pair_groups']

        fcs = self._get_fcs_by_ids(port_chain['flow_classifiers'])

        classifiers = []
        src_rts = []
        src_ports = []
        dest_rts = []
        dest_ports = []
        for fc in fcs:
            if fc.get('logical_source_port'):
                src_subnet = self._get_subnet_by_port(
                    fc['logical_source_port'])
                src_ports.append(fc['logical_source_port'])
            else:
                src_subnet = self._get_subnet_by_prefix(
                    fc['source_ip_prefix'])
                src_ports.extend(
                    self._get_ports_by_network(src_subnet['network_id'])
                )

            # Check if network is associated to BGPVPNs
            src_bgpvpns = (
                self._get_bgpvpns_by_network(context,
                                             src_subnet['network_id'])
            )
            if src_bgpvpns:
                src_rts.extend(self._get_bgpvpn_rts(src_bgpvpns)[0])
            else:
                src_rts.append(self._get_network_rt(src_subnet['network_id']))

            if fc.get('logical_destination_port'):
                dest_subnet = self._get_subnet_by_port(
                    fc['logical_destination_port'])
                dest_ports.append(fc['logical_destination_port'])
            else:
                dest_subnet = self._get_subnet_by_prefix(
                    fc['destination_ip_prefix'])
                dest_ports.extend(
                    self._get_ports_by_network(dest_subnet['network_id'])
                )

            # Check if network is associated to BGPVPNs
            dest_bgpvpns = (
                self._get_bgpvpns_by_network(context,
                                             dest_subnet['network_id'])
                )
            if dest_bgpvpns:
                dest_rts.extend(self._get_bgpvpn_rts(dest_bgpvpns)[0])
            else:
                dest_rts.append(
                    self._get_network_rt(dest_subnet['network_id'])
                )

            (ingress_bgpvpns, egress_bgpvpns) = (
                (dest_bgpvpns, src_bgpvpns) if reverse
                else (src_bgpvpns, dest_bgpvpns)
            )

            classifiers.append(
                self._build_bagpipe_classifier_from_fc(fc, reverse,
                                                       ingress_bgpvpns)
            )

            # bagpipe-bgp only support one flow classifier for the moment
            break

        reversed_ppg = port_pair_groups[::-1] if reverse else port_pair_groups
        reversed_ingress = (constants.REVERSE_PORT_SIDE[constants.INGRESS]
                            if reverse else constants.INGRESS)
        reversed_egress = (constants.REVERSE_PORT_SIDE[constants.EGRESS]
                           if reverse else constants.EGRESS)
        # Iterate in reversed order to propagate default route from last
        # ingress VRF
        for position, ppg_id in reversed(list(enumerate(reversed_ppg))):
            # Last Hop:
            # - Between last SF egress and Destination ports
            # - Between first SF ingress and Source ports if symmetric reverse
            #   traffic
            if position == len(reversed_ppg)-1:
                last_ppg = context._plugin._get_port_pair_group(
                    context._plugin_context, ppg_id)

                last_eports = self._get_ports_by_portpairs_side(
                    last_ppg['port_pairs'], reversed_egress)

                last_subnet = self._get_subnet_by_port(last_eports[0])

                hop_detail_obj = sfc_obj.BaGPipeChainHop(
                    context._plugin_context,
                    id=uuidutils.generate_uuid(),
                    project_id=project_id,
                    portchain_id=port_chain['id'],
                    rts=(src_rts if reverse else dest_rts),
                    ingress_gw=last_subnet['gateway_ip'],
                    egress_gw=(src_subnet['gateway_ip'] if reverse
                               else dest_subnet['gateway_ip']),
                    reverse_hop=reverse,
                    ingress_ppg=last_ppg['id'],
                    egress_network=(src_subnet['network_id'] if reverse
                                    else dest_subnet['network_id'])
                )
                hop_detail_obj.create()
                hop_details.append(hop_detail_obj)

            # Intermediate Hop: Between one SF ingress and previous (reversed
            # order) SF egress ports
            if (position < len(reversed_ppg)-1 and
                    len(reversed_ppg) > 1):
                prev_ppg_id = reversed_ppg[position+1]

                current_ppg = context._plugin._get_port_pair_group(
                    context._plugin_context, ppg_id)

                current_eports = self._get_ports_by_portpairs_side(
                    current_ppg['port_pairs'], reversed_egress)

                current_subnet = self._get_subnet_by_port(current_eports[0])

                prev_ppg = context._plugin._get_port_pair_group(
                    context._plugin_context,
                    prev_ppg_id)

                prev_iports = self._get_ports_by_portpairs_side(
                    prev_ppg['port_pairs'], reversed_ingress)

                prev_subnet = self._get_subnet_by_port(prev_iports[0])

                prev_ppg_rt = self.rt_allocator.allocate_rt(
                    prev_ppg_id,
                    reverse=reverse)

                prev_redirect_rt = self.rt_allocator.allocate_rt(
                    prev_ppg_id,
                    is_redirect=True,
                    reverse=reverse)

                if position+1 == len(reversed_ppg)-1:
                    # Advertise FlowSpec routes from last intermediate hop
                    prev_readv_from_rts = ((src_rts if reverse else dest_rts)
                                           if egress_bgpvpns else None)
                    prev_readv_to_rt = (prev_redirect_rt
                                        if egress_bgpvpns else None)
                    prev_attract_to_rt = (prev_redirect_rt
                                          if not egress_bgpvpns else None)

                    hop_detail_obj = sfc_obj.BaGPipeChainHop(
                        context._plugin_context,
                        id=uuidutils.generate_uuid(),
                        project_id=project_id,
                        portchain_id=port_chain['id'],
                        rts=[prev_ppg_rt],
                        ingress_gw=current_subnet['gateway_ip'],
                        egress_gw=prev_subnet['gateway_ip'],
                        reverse_hop=reverse,
                        ingress_ppg=current_ppg['id'],
                        egress_ppg=prev_ppg['id'],
                        readv_from_rts=prev_readv_from_rts,
                        readv_to_rt=prev_readv_to_rt,
                        attract_to_rt=prev_attract_to_rt,
                        redirect_rts=[prev_ppg_rt],
                        classifiers=jsonutils.dumps(classifiers)
                    )
                else:
                    # Readvertise FlowSpec routes between intermediate hops
                    from_redirect_rt = (
                        self.rt_allocator.get_redirect_rt_by_ppg(
                            reversed_ppg[position+2]))

                    hop_detail_obj = sfc_obj.BaGPipeChainHop(
                        context._plugin_context,
                        id=uuidutils.generate_uuid(),
                        project_id=project_id,
                        portchain_id=port_chain['id'],
                        rts=[prev_ppg_rt],
                        ingress_gw=current_subnet['gateway_ip'],
                        egress_gw=prev_subnet['gateway_ip'],
                        reverse_hop=reverse,
                        ingress_ppg=current_ppg['id'],
                        egress_ppg=prev_ppg['id'],
                        readv_from_rts=[from_redirect_rt],
                        readv_to_rt=prev_redirect_rt,
                        redirect_rts=[prev_ppg_rt],
                        classifiers=jsonutils.dumps(classifiers)
                    )
                hop_detail_obj.create()
                hop_details.append(hop_detail_obj)

            # First Hop:
            # - Between Source and first SF ingress ports
            # - Between Destination and last SF egress ports if symmetric
            #   reverse traffic
            if position == 0:
                first_ppg = context._plugin._get_port_pair_group(
                    context._plugin_context, ppg_id)

                first_iports = self._get_ports_by_portpairs_side(
                    first_ppg['port_pairs'], reversed_ingress)

                first_subnet = self._get_subnet_by_port(first_iports[0])

                first_ppg_rt = self.rt_allocator.allocate_rt(
                    ppg_id,
                    reverse=reverse)

                first_redirect_rt = self.rt_allocator.allocate_rt(
                    ppg_id,
                    is_redirect=True,
                    reverse=reverse)

                first_rts = ((dest_rts if reverse else src_rts)
                             if ingress_bgpvpns else [first_ppg_rt])

                if len(reversed_ppg) == 1:
                    first_readv_from_rts = ((src_rts if reverse else dest_rts)
                                            if egress_bgpvpns else None)
                    first_readv_to_rt = (first_redirect_rt
                                         if egress_bgpvpns else None)
                    first_attract_to_rt = (first_redirect_rt
                                           if not egress_bgpvpns else None)
                    first_rts = ((dest_rts if reverse else src_rts)
                                 if ingress_bgpvpns else [first_ppg_rt])

                    hop_detail_obj = sfc_obj.BaGPipeChainHop(
                        context._plugin_context,
                        id=uuidutils.generate_uuid(),
                        project_id=project_id,
                        portchain_id=port_chain['id'],
                        rts=first_rts,
                        ingress_gw=(dest_subnet['gateway_ip'] if reverse
                                    else src_subnet['gateway_ip']),
                        egress_gw=first_subnet['gateway_ip'],
                        reverse_hop=reverse,
                        ingress_network=(dest_subnet['network_id'] if reverse
                                         else src_subnet['network_id']),
                        egress_ppg=first_ppg['id'],
                        readv_from_rts=first_readv_from_rts,
                        readv_to_rt=first_readv_to_rt,
                        attract_to_rt=first_attract_to_rt,
                        redirect_rts=first_rts,
                        classifiers=jsonutils.dumps(classifiers)
                    )
                else:
                    from_redirect_rt = (
                        self.rt_allocator.get_redirect_rt_by_ppg(
                            reversed_ppg[position+1]))

                    hop_detail_obj = sfc_obj.BaGPipeChainHop(
                        context._plugin_context,
                        id=uuidutils.generate_uuid(),
                        project_id=project_id,
                        portchain_id=port_chain['id'],
                        rts=first_rts,
                        ingress_gw=(dest_subnet['gateway_ip'] if reverse
                                    else src_subnet['gateway_ip']),
                        egress_gw=first_subnet['gateway_ip'],
                        reverse_hop=reverse,
                        ingress_network=(dest_subnet['network_id'] if reverse
                                         else src_subnet['network_id']),
                        egress_ppg=first_ppg['id'],
                        readv_from_rts=[from_redirect_rt],
                        readv_to_rt=first_redirect_rt,
                        redirect_rts=first_rts,
                        classifiers=jsonutils.dumps(classifiers)
                    )
                hop_detail_obj.create()
                hop_details.append(hop_detail_obj)

        LOG.debug("BaGPipe SFC driver Chain Hop details: %s", hop_details)

        return hop_details

    def _create_portchain_hops(self, context, port_chain):
        symmetric = port_chain['chain_parameters'].get('symmetric')

        hop_objs = self._create_portchain_hop_details(context,
                                                      port_chain)

        if symmetric:
            hop_objs.extend(self._create_portchain_hop_details(context,
                                                               port_chain,
                                                               reverse=True))

        if hop_objs:
            self._push_rpc.push(context._plugin_context, hop_objs,
                                rpc_events.CREATED)

    @log_helpers.log_method_call
    def create_port_chain(self, context):
        port_chain = context.current

        if not self._is_valid_port_chain(context, port_chain):
            return

        self._create_portchain_hops(context, port_chain)

    def _delete_portchain_hops(self, context, port_chain):
        # Release PPG route targets
        for ppg_id in port_chain['port_pair_groups']:
            ppg_rtnns = self.rt_allocator.get_rts_by_ppg(ppg_id)

            if ppg_rtnns:
                for rtnn in ppg_rtnns:
                    self.rt_allocator.release_rt(rtnn)

        hop_objs = sfc_obj.BaGPipeChainHop.get_objects(
            context._plugin_context,
            portchain_id=port_chain['id'])

        if hop_objs:
            for hop_obj in hop_objs:
                hop_obj.delete()

            self._push_rpc.push(context._plugin_context, hop_objs,
                                rpc_events.DELETED)

    @log_helpers.log_method_call
    def delete_port_chain(self, context):
        port_chain = context.current

        self._delete_portchain_hops(context, port_chain)

    @log_helpers.log_method_call
    def update_port_chain(self, context):
        current = context.current
        original = context.original

        # Delete existing BaGPipeChainHop objects if not valid PortChain
        if not self._is_valid_port_chain(context, current):
            self._delete_portchain_hops(context, current)

            return

        # Create BaGPipeChainHop objects
        if (not original['flow_classifiers'] or
            (original['port_pair_groups'] == current['port_pair_groups'] and
             not sfc_obj.BaGPipeChainHop.get_objects(
                context._plugin_context,
                portchain_id=current['id']))):
            self._create_portchain_hops(context, current)

            return

        # If Flow Classifier has been modified, raise not supported exception
        if current['flow_classifiers'] != original['flow_classifiers']:
            LOG.error('BaGPipe driver not supporting Flow Classifiers update')
            raise exc.SfcDriverError(method='update_port_chain')

        # Delete and re-create BaGPipeChainHop objects (Better to update
        # BaGPipeChainHop objects
        if current['port_pair_groups'] != original['port_pair_groups']:
            self._delete_portchain_hops(context, current)

            self._create_portchain_hops(context, current)

    def _has_valid_port_pairs(self, context):
        port_pair_group = context._plugin._get_port_pair_group(
            context._plugin_context,
            context.current['id'])
        port_pairs = port_pair_group['port_pairs']

        if not port_pairs:
            return

        for side in [constants.INGRESS, constants.EGRESS]:
            port_ids = self._get_ports_by_portpairs_side(port_pairs, side)

            network_ids = set()
            for port_id in port_ids:
                subnet = self._get_subnet_by_port(port_id)
                network_ids.add(subnet['network_id'])

            if len(network_ids) > 1:
                raise exc.SfcBadRequest(message=(
                    'PortPairGroup %s %s ports must be on same network'
                    % (port_pair_group['id'], side)))

    @log_helpers.log_method_call
    def create_port_pair_group_precommit(self, context):
        self._has_valid_port_pairs(context)

    @log_helpers.log_method_call
    def update_port_pair_group_precommit(self, context):
        self._has_valid_port_pairs(context)

    @log_helpers.log_method_call
    def create_port_pair_group(self, context):
        pass

    @log_helpers.log_method_call
    def delete_port_pair_group(self, context):
        pass

    @log_helpers.log_method_call
    def update_port_pair_group(self, context):
        current = context.current
        original = context.original

        # Check if PortPairGroup is associated to any PortChain
        ppg = context._plugin._get_port_pair_group(context._plugin_context,
                                                   current['id'])

        if not ppg.chain_group_associations:
            return

        # Check if PortPairs have been modified
        if set(current['port_pairs']) == set(original['port_pairs']):
            return

        current_pps = current['port_pairs']
        orig_pps = original['port_pairs']
        added_pps = set(current_pps).difference(set(orig_pps))
        removed_pps = set(orig_pps).difference(set(current_pps))

        # Create BaGPipePortHops OVO for each port added in port chains
        # containing this port pair group
        if added_pps:
            port_objs = []
            for pp_id in added_pps:
                pp = context._plugin._get_port_pair(context._plugin_context,
                                                    pp_id)

                for side in [constants.INGRESS, constants.EGRESS]:
                    port_objs.append(
                        sfc_obj.BaGPipePortHops.get_object(
                            context._plugin_context,
                            port_id=getattr(pp, side)
                        )
                    )

            if port_objs:
                self._push_rpc.push(context._plugin_context, port_objs,
                                    rpc_events.CREATED)

        # Delete BaGPipePortHops OVO for each port added in port chains
        # containing this port pair group
        if removed_pps:
            port_objs = []
            for pp_id in removed_pps:
                pp = context._plugin._get_port_pair(context._plugin_context,
                                                    pp_id)

                for side in [constants.INGRESS, constants.EGRESS]:
                    port_objs.append(
                        sfc_obj.BaGPipePortHops.get_object(
                            context._plugin_context,
                            port_id=getattr(pp, side)
                        )
                    )

            if port_objs:
                self._push_rpc.push(context._plugin_context, port_objs,
                                    rpc_events.DELETED)

    @log_helpers.log_method_call
    def create_port_pair(self, context):
        pass

    @log_helpers.log_method_call
    def update_port_pair(self, context):
        pass

    @log_helpers.log_method_call
    def delete_port_pair(self, context):
        pass
