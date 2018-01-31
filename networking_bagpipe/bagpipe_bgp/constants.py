# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

# Copyright 2014 Orange
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

IPVPN = "ipvpn"
EVPN = "evpn"

VPN_TYPES = [EVPN, IPVPN]

RT_IMPORT = 'import_rt'
RT_EXPORT = 'export_rt'
RT_TYPES = [RT_IMPORT, RT_EXPORT]

# port directions
TO_PORT = 'to-port'
FROM_PORT = 'from-port'
BOTH = 'both'
ALL_DIRECTIONS = (BOTH, TO_PORT, FROM_PORT)


def config_group(vpn_type):
    return "DATAPLANE_DRIVER_%s" % vpn_type.upper()

# maximum length for a linux network device name
#  grep 'define.*IFNAMSIZ' /usr/src/linux/include/uapi/linux/if.h
# define    IFNAMSIZ    16
# (minus 1 for trailing null)
LINUX_DEV_LEN = 15
