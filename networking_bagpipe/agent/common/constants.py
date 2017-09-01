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

from collections import namedtuple

DEFAULT_GATEWAY_MAC = "00:00:5e:00:43:64"
FALLBACK_SRC_MAC = "00:00:5e:2a:10:00"

BAGPIPE_L2_SERVICE = 'bagpipe_l2'
BGPVPN_SERVICE = 'bgpvpn'
BAGPIPE_SERVICES = [BAGPIPE_L2_SERVICE, BGPVPN_SERVICE]

# bagpipe-bgp VPN types
EVPN = 'evpn'
IPVPN = 'ipvpn'
VPN_TYPES = [EVPN, IPVPN]

# BGPVPN service VPN types
BGPVPN_L2 = 'l2vpn'
BGPVPN_L3 = 'l3vpn'
BGPVPN_TYPES = [BGPVPN_L2, BGPVPN_L3]
# Map from BGPVPN service VPN types to bagpipe-bgp VPN types
BGPVPN_TYPES_MAP = {BGPVPN_L2: EVPN, BGPVPN_L3: IPVPN}

RT_IMPORT = 'import_rt'
RT_EXPORT = 'export_rt'
RT_TYPES = [RT_IMPORT, RT_EXPORT]

LINUXIF_PREFIX = "patch2tun"

GatewayInfo = namedtuple('GatewayInfo', ['mac', 'ip'])
NO_GW_INFO = GatewayInfo(None, None)
