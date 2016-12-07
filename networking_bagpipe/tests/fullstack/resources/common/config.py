# Copyright (c) 2016 Orange.
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

import os

from networking_bagpipe.tests.common import json_fixtures

from neutron.common import utils
from neutron.tests.fullstack.resources import config as neutron_cfg


ROOTWRAP_DAEMON_CMD_DFLT = ("sudo /usr/local/bin/oslo-rootwrap-daemon "
                            "/etc/bagpipe-bgp/rootwrap.conf")


class JsonFixture(neutron_cfg.ConfigFixture):
    """A fixture that holds a JSON configuration."""
    def _setUp(self):
        cfg_fixture = json_fixtures.JsonFileFixture(
            self.base_filename, self.config, self.temp_dir)
        self.useFixture(cfg_fixture)
        self.filename = cfg_fixture.filename


class BagpipeBGPConfigFixture(neutron_cfg.ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir, local_ip, bgp_peer,
                 bgp_port, mpls_bridge, mpls_interface):
        super(BagpipeBGPConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir,
            base_filename='bgp.conf')

        self.config.update({
            'COMMON': {
                'root_helper_daemon': os.environ.get('OS_ROOTWRAP_DAEMON_CMD',
                                                     ROOTWRAP_DAEMON_CMD_DFLT)
            },
            'BGP': {
                'local_address': local_ip,
                'peers': bgp_peer,
                'my_as': '64512',
                'bgp_port': bgp_port,
            },
            'API': {
                'host': local_ip,
                'port': '8082'
            },
            'DATAPLANE_DRIVER_IPVPN': {
                'dataplane_driver': self.env_desc.ipvpn_driver,
                'ovs_bridge': mpls_bridge,
                'proxy_arp': 'False'
            },
            'DATAPLANE_DRIVER_EVPN': {
                'dataplane_driver': self.env_desc.evpn_driver
            }
        })

        if self.env_desc.ipvpn_driver != 'dummy':
            if self.env_desc.ipvpn_encap == 'vxlan':
                self.config['DATAPLANE_DRIVER_IPVPN'].update({
                    'vxlan_encap': 'True',
                    'mpls_interface': ''
                })
            if self.env_desc.ipvpn_encap == 'mpls-gre':
                self.config['DATAPLANE_DRIVER_IPVPN'].update({
                    'mpls_interface': '*gre*',
                    'gre_tunnel': self._generate_gre_tunnel()
                })
            if self.env_desc.ipvpn_encap == 'bare-mpls':
                self.config['DATAPLANE_DRIVER_IPVPN'].update({
                    'mpls_interface': mpls_interface
                })

    def _generate_gre_tunnel(self):
        return utils.get_rand_device_name(prefix='mpls-gre')


class GoBGPConfigFixture(JsonFixture):

    def __init__(self, env_desc, host_desc, temp_dir,
                 bgp_peer, bgp_port, host_ips):
        super(GoBGPConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir,
            base_filename='gobgp.conf')

        self.config.update({
            'global': {
                'config': {
                    'as': '64512',
                    'router-id': bgp_peer,
                    'port': bgp_port
                }
            }
        })

        neighbors = list()
        for host_ip in host_ips:
            neighbor = {
                'config': {
                    'neighbor-address': host_ip,
                    'peer-as': '64512'
                },
                'transport': {
                    'config': {
                        'passive-mode': 'true'
                    }
                },
                'route-reflector': {
                    'config': {
                        'route-reflector-client': 'true',
                        'route-reflector-cluster-id': '1.2.3.4'
                    }
                }
            }

            afi_safis = list()
            for afi_safi in ('rtc', 'l2vpn-evpn', 'l3vpn-ipv4-unicast',
                             'l3vpn-ipv4-flowspec'):
                afi_safis.append({
                    'config': {
                        'afi-safi-name': afi_safi
                    }
                })

            neighbor.update({'afi-safis': afi_safis})
            neighbors.append(neighbor)

        self.config.update({'neighbors': neighbors})
