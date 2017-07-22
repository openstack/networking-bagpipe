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

from networking_bagpipe.agent import bagpipe_bgp_agent
from networking_bagpipe.bagpipe_bgp.api import api
from networking_bagpipe.bagpipe_bgp.common import config
from networking_bagpipe.bagpipe_bgp.common import run_command
from networking_bagpipe.bagpipe_bgp import constants
from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers
from networking_bagpipe.bagpipe_bgp.vpn.evpn import linux_vxlan
from networking_bagpipe.bagpipe_bgp.vpn.ipvpn import mpls_linux_dataplane
from networking_bagpipe.bagpipe_bgp.vpn.ipvpn import mpls_ovs_dataplane
from networking_bagpipe.driver import mech_bagpipe
from networking_bagpipe.driver import type_route_target


# NOTE(amotoki): oslo.config suggests to use lower case as group name.
# If a group name is registered with upper case names,
# oslo.config looks up both upper case and lower case versions of names
# in configuration files, so using lower case in sample files is safe enough.


def list_bagpipe_bgp_agent_opts():
    return [
        ('bagpipe', bagpipe_bgp_agent.bagpipe_bgp_opts),
    ]


def list_api_opts():
    return [
        ('api', api.common_opts),
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


def list_ml2_mech_bagpipe_opts():
    return [
        ('ml2_bagpipe', mech_bagpipe.ml2_bagpipe_opts),
    ]


def list_ml2_type_route_target_opts():
    return [
        ('ml2_type_route_target', type_route_target.route_target_opts),
    ]
