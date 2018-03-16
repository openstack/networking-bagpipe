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

import sys

import eventlet
eventlet.monkey_patch()

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_config import types
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from networking_bagpipe.agent import agent_base_info
from networking_bagpipe.agent import bagpipe_bgp_agent
from networking_bagpipe.bagpipe_bgp import constants as bbgp_const

from neutron.agent.linux import ip_lib
from neutron.common import config as common_config
from neutron.plugins.ml2.drivers.linuxbridge.agent import \
    linuxbridge_neutron_agent as lnx_agt

from neutron_lib.agent import l2_extension
from neutron_lib import constants as n_const


LOG = logging.getLogger(__name__)

BAGPIPE_L2_SERVICE = 'bagpipe_l2'

opts = [
    cfg.ListOpt('as_number', default=[64512],
                item_type=types.Integer(min=1, max=2**32),
                help=("Autonomous System number used to generate BGP RTs for"
                      "E-VPNs used by bagpipe ML2 (more than one is possible,"
                      "to allow a deployment to do a 2-step transition "
                      "to change the AS number used)")
                )
]
cfg.CONF.register_opts(opts, "ml2_bagpipe_extension")


class BagpipeML2AgentExtension(l2_extension.L2AgentExtension,
                               agent_base_info.BaseInfoManager):

    def initialize(self, connection, driver_type):

        self.bagpipe_bgp_agent = (
            bagpipe_bgp_agent.BaGPipeBGPAgent.get_instance(
                n_const.AGENT_TYPE_LINUXBRIDGE)
        )

        self.bagpipe_bgp_agent.register_build_callback(
            BAGPIPE_L2_SERVICE,
            self.build_bagpipe_l2_attach_info)

        self.ports = set()
        self.bagpipe_bgp_agent.register_port_list(BAGPIPE_L2_SERVICE,
                                                  self.ports)

    @log_helpers.log_method_call
    def build_bagpipe_l2_attach_info(self, port_id):
        port_info = self.ports_info.get(port_id)

        if not port_info:
            LOG.debug("no info for port %s", port_id)
            return {}

        LOG.debug("segmentation id: %s", port_info.network.segmentation_id)

        as_numbers = cfg.CONF.ml2_bagpipe_extension.as_number
        bagpipe_rts = [
            "%s:%s" % (as_number, port_info.network.segmentation_id)
            for as_number in as_numbers
        ]

        attach_info = self._base_attach_info(port_info)
        attach_info.update({
            'linuxbr': lnx_agt.LinuxBridgeManager.get_bridge_name(
                port_info.network.id
            ),
            'vni': port_info.network.segmentation_id,
            bbgp_const.RT_IMPORT: bagpipe_rts,
            bbgp_const.RT_EXPORT: bagpipe_rts
        })

        return {
            'network_id': port_info.network.id,
            bbgp_const.EVPN: [
                attach_info
            ]
        }

    def _base_attach_info(self, port_info):
        info = {
            'mac_address': port_info.mac_address,
            'local_port': {
                'linuxif': lnx_agt.LinuxBridgeManager.get_tap_device_name(
                    port_info.id)
            }
        }
        if port_info.ip_address:
            info.update({'ip_address': port_info.ip_address})
        return info

    @lockutils.synchronized('bagpipe-ml2')
    @log_helpers.log_method_call
    def handle_port(self, context, data):
        if data.get('network_type') != n_const.TYPE_VXLAN:
            LOG.debug("network is not of type vxlan, not handled by this "
                      "extension")
            return

        port_id = data['port_id']

        tap_device_name = lnx_agt.LinuxBridgeManager.get_tap_device_name(
            port_id)
        if not ip_lib.device_exists(tap_device_name):
            LOG.debug('skip non-existing port %s', port_id)
            return

        net_id = data['network_id']
        net_info, port_info = (
            self._get_network_port_infos(net_id, port_id)
        )

        def delete_hook():
            self._delete_port(context, {'port_id': port_info.id})

        port_info.update_admin_state(data, delete_hook)
        if not port_info.admin_state_up:
            return

        port_info.mac_address = data['mac_address']

        # take the first IPv4 (error if none, warning if many)
        ip_address = None
        for alloc in data.get('fixed_ips'):
            if '.' in alloc['ip_address']:
                if not ip_address:
                    ip_address = alloc['ip_address']
                else:
                    LOG.warning("multiple IPv4 addresses for %s, ignoring %s",
                                port_id, alloc['ip_address'])
        if ip_address is None:
            LOG.debug("no IP address for port %s", port_id)

        port_info.ip_address = ip_address

        net_info.segmentation_id = data['segmentation_id']

        self.bagpipe_bgp_agent.do_port_plug(port_id)

        self.ports.add(port_id)

    @lockutils.synchronized('bagpipe-ml2')
    def delete_port(self, context, data):
        self._delete_port(context, data)

    # un-synchronized version, to be called indirectly from handle_port
    @log_helpers.log_method_call
    def _delete_port(self, context, data):
        port_id = data['port_id']
        port_info = self.ports_info.get(port_id)

        if port_info:
            detach_info = {
                'network_id': port_info.network.id,
                bbgp_const.EVPN: self._base_attach_info(port_info)
            }

            self._remove_network_port_infos(port_info.network.id, port_id)
            self.ports.remove(port_id)

            self.bagpipe_bgp_agent.do_port_plug_refresh(port_id,
                                                        detach_info)


def main():
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    LOG.warning('This modified agent is not needed anymore. The normal '
                'neutron linuxbridge agent should be used instead, along with'
                'networks of type VXLAN, rather than RT.')
