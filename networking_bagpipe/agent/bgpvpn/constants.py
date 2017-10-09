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

from networking_bagpipe.agent.common import constants as b_const

from neutron_lib.api.definitions import bgpvpn

BGPVPN_SERVICE = 'bgpvpn'

DEFAULT_GATEWAY_MAC = "00:00:5e:00:43:64"
FALLBACK_SRC_MAC = "00:00:5e:2a:10:00"

# BGPVPN service VPN types
BGPVPN_L3 = bgpvpn.BGPVPN_L3 + 'vpn'
BGPVPN_L2 = bgpvpn.BGPVPN_L2 + 'vpn'
BGPVPN_TYPES = [BGPVPN_L2, BGPVPN_L3]

# Map from BGPVPN service VPN types to bagpipe-bgp VPN types
BGPVPN_TYPES_MAP = {BGPVPN_L2: b_const.EVPN, BGPVPN_L3: b_const.IPVPN}

LINUXIF_PREFIX = "patch2tun"
