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

from oslo_utils import uuidutils

EVPN_RT1 = {'import_rt': ['EVPN:1'],
            'export_rt': ['EVPN:1']}

EVPN_RT2 = {'import_rt': ['EVPN:2'],
            'export_rt': ['EVPN:2']}

IPVPN_RT100 = {'import_rt': ['IPVPN:100'],
               'export_rt': ['IPVPN:100']}

IPVPN_RT200 = {'import_rt': ['IPVPN:200'],
               'export_rt': ['IPVPN:200']}

NETWORK_INFO1 = {'network_id': uuidutils.generate_uuid(),
                 'gateway_ip': '10.0.0.1'
                 }

PORT_INFO1 = {'mac_address': '00:00:de:ad:be:ef',
              'ip_address': '10.0.0.2',
              'local_port': {'linuxif': 'port1'},
              }

UPDATED_LOCAL_PORT1 = {'linuxif': 'updated_port1'}

GW_MAC_PORT1 = '00:00:ca:fe:ba:be'

STATIC_ROUTE1 = '1.1.1.1/24'
