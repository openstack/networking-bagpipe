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

from oslo_config import cfg

from oslo_log import log

from neutron.agent import securitygroups_rpc
from neutron import context as n_context
from neutron.db import api as db_api
from neutron.db import models_v2
from neutron.extensions import portbindings

from neutron.plugins.common import constants as p_constants

from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent

from neutron_lib import constants as n_const

from networking_bagpipe.driver.type_route_target import TYPE_ROUTE_TARGET
from networking_bagpipe.rpc import client as bagpipe_rpc_client

from sqlalchemy.orm import exc


LOG = log.getLogger(__name__)

ml2_bagpipe_opts = [
    cfg.IntOpt('as_number', default=64512,
               help="Autonomous System number"),
]

cfg.CONF.register_opts(ml2_bagpipe_opts, "ml2_bagpipe")


class NoNetworkInfoForPort(Exception):
    pass


def get_network_info_for_port(session, port_id):
    """Get Port network informations from DB

    Get network informations (MAC, IP and gateway addresses and
    subnet mask) from database associated to a port
    """
    LOG.debug("get_network_info_for_port() called for port %s" % port_id)

    with session.begin(subtransactions=True):
        try:
            net_info = (session.
                        query(models_v2.Port.mac_address,
                              models_v2.IPAllocation.ip_address,
                              models_v2.Subnet.cidr,
                              models_v2.Subnet.gateway_ip).
                        join(models_v2.IPAllocation).
                        join(models_v2.Subnet,
                             models_v2.IPAllocation.subnet_id ==
                             models_v2.Subnet.id).
                        filter(models_v2.Subnet.ip_version == 4).
                        filter(models_v2.Port.id == port_id).one())
            return net_info
        except exc.NoResultFound:
            raise NoNetworkInfoForPort(port_id)


class BaGPipeMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """ML2 Mechanism driver for bagpipe-bgp

    This mechanism driver uses RPCs toward compute node agents to trigger
    the attachment of VM ports in E-VPN VPN instances.
    """

    def __init__(self):
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        super(BaGPipeMechanismDriver, self).__init__(
            n_const.AGENT_TYPE_LINUXBRIDGE,
            portbindings.VIF_TYPE_BRIDGE,
            {portbindings.CAP_PORT_FILTER: sg_enabled})
        self.agent_notify = bagpipe_rpc_client.BaGPipeAgentNotifyAPI()

    def initialize(self):
        self.rpc_ctx = n_context.get_admin_context_without_session()
        self.migrated_ports = {}

    def get_allowed_network_types(self, agent):
        return (agent['configurations'].get('tunnel_types', []) +
                [p_constants.TYPE_LOCAL, p_constants.TYPE_FLAT,
                 p_constants.TYPE_VLAN])

    def get_mappings(self, agent):
        return agent['configurations'].get('interface_mappings', {})

    def _get_route_target(self, segment):
        if (segment and segment[api.NETWORK_TYPE] == TYPE_ROUTE_TARGET):
            return "%s:%s" % (cfg.CONF.ml2_bagpipe.as_number,
                              segment.get(api.SEGMENTATION_ID))
        else:
            LOG.warning("no RT for segment %s", segment)

    def check_segment_for_agent(self, segment, agent):
        mappings = agent['configurations'].get('bridge_mappings', {})
        tunnel_types = agent['configurations'].get('tunnel_types', [])
        LOG.debug("Checking segment: %(segment)s "
                  "for mappings: %(mappings)s "
                  "with tunnel_types: %(tunnel_types)s",
                  {'segment': segment, 'mappings': mappings,
                   'tunnel_types': tunnel_types})
        return (segment[api.NETWORK_TYPE] == TYPE_ROUTE_TARGET)

    def _get_network_info_for_port(self, port_id):
        """Get MAC, IP and Gw IP addresses informations for a specific port"""
        session = db_api.get_session()
        (mac_address, ip_address, cidr, gateway_ip) = (
            get_network_info_for_port(session, port_id)
        )

        return {'mac_address': mac_address,
                'ip_address': ip_address + cidr[cidr.index('/'):],
                'gateway_ip': gateway_ip}

    def _retrieve_bagpipe_net_info_for_port(self, port_id, segment):
        """Retrieve BaGPipe network informations for a specific port

        {
            'network_id': <UUID>,
            'mac_address': '00:00:de:ad:be:ef',
            'ip_address': '10.0.0.2',
            'gateway_ip': '10.0.0.1',
            'evpn' : {
                'import_rt': ['12345:1', '12345:2', '12345:3'],
                'export_rt': ['12345:1', '12345:2', '12345:4']
            }
        }
        """
        bagpipe_network_info = {}

        # Check if port is connected on a BaGPipe network
        bagpipe_rt = self._get_route_target(segment)
        if bagpipe_rt:
            bagpipe_network_info.update(
                {'evpn': {
                    'import_rt': bagpipe_rt,
                    'export_rt': bagpipe_rt}}
            )
        else:
            LOG.debug("No E-VPN RT info for port %s", port_id)

        LOG.debug("Getting port %s network details", port_id)
        bagpipe_network_info.update(self._get_network_info_for_port(port_id))

        return bagpipe_network_info

    def delete_port_postcommit(self, context):
        port = context.current
        agent_host = context.host

        port_bagpipe_info = {'id': port['id'],
                             'network_id': port['network_id']}

        self.agent_notify.detach_port_from_bagpipe_network(
            self.rpc_ctx,
            port_bagpipe_info, agent_host
        )

    def update_port_postcommit(self, context):
        port = context.current
        orig = context.original
        agent_host = context.host

        if (context.host != context.original_host and
                context.status == n_const.PORT_STATUS_ACTIVE and
                not self.migrated_ports.get(orig['id'])):
            # Port has been migrated. We need to store the original
            # binding to send bagpipe informations for port to the
            # appropriate host
            self.migrated_ports[orig['id']] = (
                (orig, context.original_host))
        elif context.status != context.original_status:
            port_bagpipe_info = {'id': port['id'],
                                 'network_id': port['network_id']}

            if context.status == n_const.PORT_STATUS_ACTIVE:
                segment = context.bottom_bound_segment
                if not segment:
                    LOG.debug(("Port %(port)s updated by agent %(agent)s "
                               "isn't bound to any segment"),
                              {'port': port['id'], 'agent': agent_host})
                    return

                try:
                    bagpipe_network_info = (
                        self._retrieve_bagpipe_net_info_for_port(port['id'],
                                                                 segment)
                    )
                    port_bagpipe_info.update(bagpipe_network_info)
                    self.agent_notify.attach_port_on_bagpipe_network(
                        self.rpc_ctx,
                        port_bagpipe_info, agent_host
                    )
                except NoNetworkInfoForPort:
                    LOG.warning("No network info for port %s (v6 only?),"
                                " not attached!", port['id'])
            elif context.status == n_const.PORT_STATUS_DOWN:
                self.agent_notify.detach_port_from_bagpipe_network(
                    self.rpc_ctx,
                    port_bagpipe_info,
                    agent_host
                )
            elif context.status == n_const.PORT_STATUS_BUILD:
                orig = self.migrated_ports.pop(port['id'], None)
                if orig:
                    # this port has been migrated: Detach from BaGPipe
                    # network ? automatically handled by BGP ?
                    original_port = orig[0]
                    original_host = orig[1]
                    port_bagpipe_info.update({'id': original_port['id']})
                    self.agent_notify.detach_port_from_bagpipe_network(
                        self.rpc_ctx,
                        port_bagpipe_info,
                        original_host
                    )
