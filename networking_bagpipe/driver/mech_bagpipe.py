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

from neutron_lib import constants as n_constants
from oslo_config import cfg
from oslo_log import log

from neutron.agent import securitygroups_rpc

from neutron.plugins.ml2.drivers import mech_agent

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_const


LOG = log.getLogger(__name__)


ml2_bagpipe_opts = [
    cfg.IntOpt('as_number', default=-1,
               help=("not used: bagpipe AS configuration for generation of "
                     "EVPN RTs must be done on neutron l2 agents"))
]

cfg.CONF.register_opts(ml2_bagpipe_opts, "ml2_bagpipe")


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

        if cfg.CONF.ml2_bagpipe.as_number != -1:
            raise Exception(
                "bagpipe AS configuration must be done on neutron l2 agents, "
                "in [ml2_bagpipe_extension]")

    def get_allowed_network_types(self, agent):
        return (agent['configurations'].get('tunnel_types', []) +
                [n_constants.TYPE_LOCAL, n_constants.TYPE_FLAT,
                 n_constants.TYPE_VLAN, n_constants.TYPE_VXLAN])

    def get_mappings(self, agent):
        return agent['configurations'].get('interface_mappings', {})
