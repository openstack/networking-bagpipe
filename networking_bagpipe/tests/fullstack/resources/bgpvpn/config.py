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

import networking_bgpvpn

from neutron.tests.fullstack.resources import config as neutron_cfg

BGPVPN_SERVICE = 'bgpvpn'

BGPVPN_PROVIDER = ('BGPVPN:BaGPipe:networking_bgpvpn.neutron.services.'
                   'service_drivers.bagpipe.bagpipe.BaGPipeBGPVPNDriver:'
                   'default')


class NeutronConfigFixture(neutron_cfg.NeutronConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir,
                 connection, rabbitmq_environment):
        super(NeutronConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir, connection, rabbitmq_environment)

        if env_desc.bgpvpn:
            self.config['oslo_policy']['policy_dirs'] = (
                os.path.join(networking_bgpvpn.__path__[0],
                             '..', 'etc', 'neutron', 'policy.d')
            )

            # for L2 BGPVPN tests, we need multiple subnet resources using
            # a common IP subnet
            self.config['DEFAULT'].update({
                'allow_overlapping_ips': True
            })


class BGPVPNProviderConfigFixture(neutron_cfg.ConfigFixture):
    def __init__(self, env_desc, host_desc, temp_dir):
        super(BGPVPNProviderConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir,
            base_filename='networking_bgpvpn.conf')

        self.config.update({
            'service_providers': {
                'service_provider': BGPVPN_PROVIDER
            }
        })
