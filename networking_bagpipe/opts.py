#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from networking_bagpipe.agent.bagpipe_ml2 import agent_extension as ml2_agt_ext
from networking_bagpipe.agent.bgpvpn import agent_extension as bgpvpn_agt_ext
from networking_bagpipe.bagpipe_bgp.api import config as api_config
from networking_bagpipe.bagpipe_bgp.common import config
from networking_bagpipe.bagpipe_bgp.common import run_command
from networking_bagpipe.bagpipe_bgp import constants
from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers
from networking_bagpipe.bagpipe_bgp.vpn.evpn import linux_vxlan
from networking_bagpipe.bagpipe_bgp.vpn.ipvpn import mpls_linux_dataplane
from networking_bagpipe.bagpipe_bgp.vpn.ipvpn import mpls_ovs_dataplane
from networking_bagpipe.db import sfc_db


# NOTE(amotoki): oslo.config suggests to use lower case as group name.
# If a group name is registered with upper case names,
# oslo.config looks up both upper case and lower case versions of names
# in configuration files, so using lower case in sample files is safe enough.


def list_bagpipe_bgp_agent_opts():
    return [
        ('bagpipe_ml2_extension', ml2_agt_ext.opts),
        ('bagpipe', bgpvpn_agt_ext.bagpipe_bgpvpn_opts),
    ]


def list_api_opts():
    return [
        ('api', api_config.common_opts),
    ]


def list_bgp_common_opts():
    return [
        ('bgp', config.bgp_opts),
    ]


def list_run_command_opts():
    return [
        ('common', run_command.common_opts),
    ]


def list_dataplane_driver_ipvpn_opts():
    return [
        (constants.config_group(constants.IPVPN).lower(),
         dataplane_drivers.dataplane_common_opts),
    ]


def list_dataplane_driver_evpn_opts():
    return [
        (constants.config_group(constants.EVPN).lower(),
         dataplane_drivers.dataplane_common_opts),
    ]


def list_dataplane_driver_evpn_linux_vxlan_opts():
    return [
        (constants.config_group(constants.EVPN).lower(),
         linux_vxlan.LinuxVXLANDataplaneDriver.driver_opts),
    ]


def list_dataplane_driver_ipvpn_mpls_linux_opts():
    return [
        (constants.config_group(constants.IPVPN).lower(),
         mpls_linux_dataplane.MPLSLinuxDataplaneDriver.driver_opts),
    ]


def list_dataplane_driver_ipvpn_mpls_ovs_opts():
    return [
        (constants.config_group(constants.IPVPN).lower(),
         mpls_ovs_dataplane.MPLSOVSDataplaneDriver.driver_opts),
    ]


def list_neutron_sfc_opts():
    return [
        ('sfc_bagpipe', sfc_db.sfc_bagpipe_opts)
    ]
