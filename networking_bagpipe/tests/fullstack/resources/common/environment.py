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

import fixtures
from oslo_config import cfg
import random

from networking_bagpipe.tests.fullstack.resources.bagpipe_ml2 \
    import config as bagpipe_ml2_cfg
from networking_bagpipe.tests.fullstack.resources.bgpvpn \
    import config as bgpvpn_cfg
from networking_bagpipe.tests.fullstack.resources.common \
    import config
from networking_bagpipe.tests.fullstack.resources.common \
    import config as common_cfg
from networking_bagpipe.tests.fullstack.resources.common \
    import process as common_proc

from neutron_lib import constants

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as a_utils
from neutron.common import utils
from neutron.tests.common.exclusive_resources import ip_network
from neutron.tests.common import net_helpers
from neutron.tests.fullstack.resources import environment as neutron_env
from neutron.tests.fullstack.resources import process as neutron_proc


class BaGPipeEnvironmentDescription(neutron_env.EnvironmentDescription):

    def __init__(self, bagpipe_ml2=False, evpn_driver='linux', bgpvpn=False,
                 ipvpn_driver='ovs', ipvpn_encap='gre',
                 network_type='vxlan', mech_drivers='openvswitch,linuxbridge',
                 service_plugins=None):
        super(BaGPipeEnvironmentDescription, self).__init__(
            network_type=network_type,
            l2_pop=not bagpipe_ml2 and bgpvpn,
            mech_drivers=mech_drivers,
            service_plugins=service_plugins,
            arp_responder=not bagpipe_ml2 and bgpvpn
        )

        self.bagpipe_ml2 = bagpipe_ml2
        self.bgpvpn = bgpvpn
        self.evpn_driver = evpn_driver
        self.ipvpn_driver = ipvpn_driver
        self.ipvpn_encap = ipvpn_encap


class BaGPipeHost(neutron_env.Host):

    def __init__(self, env_desc, host_desc,
                 test_name, neutron_config,
                 central_data_bridge, central_external_bridge,
                 bgp_peer, bgp_port):
        super(BaGPipeHost, self).__init__(env_desc, host_desc,
                                          test_name, neutron_config,
                                          central_data_bridge,
                                          central_external_bridge)
        self.bgp_peer = bgp_peer
        self.bgp_port = bgp_port

    def _setUp(self):
        if (self.env_desc.bgpvpn and
                self.host_desc.l2_agent_type == constants.AGENT_TYPE_OVS):
            self.mpls_bridge = self.useFixture(
                net_helpers.OVSBridgeFixture(self.generate_mpls_bridge())
            ).bridge
            self.mpls_bridge.set_secure_mode()

        super(BaGPipeHost, self)._setUp()

        self.setup_host_with_bagpipe_bgp()

    def generate_mpls_bridge(self):
        return utils.get_rand_device_name(prefix='br-mpls')

    def setup_host_with_ovs_agent(self):
        agent_cfg_fixture = config.OVSConfigFixture(
            self.env_desc, self.host_desc, self.neutron_config.temp_dir,
            self.local_ip, self.mpls_bridge.br_name)
        self.useFixture(agent_cfg_fixture)

        self.useFixture(
            net_helpers.OVSBridgeFixture(
                agent_cfg_fixture.get_br_tun_name())).bridge

        self.ovs_agent = self.useFixture(
            neutron_proc.OVSAgentFixture(
                self.env_desc, self.host_desc,
                self.test_name, self.neutron_config, agent_cfg_fixture))

    def setup_host_with_linuxbridge_agent(self):
        self.host_namespace = self.useFixture(
            net_helpers.NamespaceFixture(prefix="host-")
        ).name

        self.connect_namespace_to_control_network()

        agent_cfg_fixture = config.LinuxBridgeConfigFixture(
            self.env_desc, self.host_desc,
            self.neutron_config.temp_dir,
            self.local_ip,
            physical_device_name=self.host_port.name
        )
        self.useFixture(agent_cfg_fixture)

        agent_fixture_cls = neutron_proc.LinuxBridgeAgentFixture

        self.linuxbridge_agent = self.useFixture(
            agent_fixture_cls(
                self.env_desc, self.host_desc,
                self.test_name, self.neutron_config, agent_cfg_fixture,
                namespace=self.host_namespace
            )
        )

    def setup_host_with_bagpipe_bgp(self):
        if self.host_desc.l2_agent_type == constants.AGENT_TYPE_OVS:
            mpls_bridge = (self.mpls_bridge.br_name
                           if self.env_desc.bgpvpn
                           else '')
            mpls_interface = ''
            if self.env_desc.bgpvpn:
                self.connect_to_internal_network_via_tunneling()

                if self.env_desc.ipvpn_encap == 'bare-mpls':
                    self.connect_to_internal_network_via_mpls_bridge()
                    mpls_interface = filter(
                        lambda port: net_helpers.VETH0_PREFIX
                        in port, self.mpls_bridge.get_port_name_list())[0]
        elif self.host_desc.l2_agent_type == constants.AGENT_TYPE_LINUXBRIDGE:
            mpls_bridge = None
            mpls_interface = self.host_port.name

        bgp_cfg_fixture = common_cfg.BagpipeBGPConfigFixture(
            self.env_desc, self.host_desc, self.neutron_config.temp_dir,
            self.local_ip, self.bgp_peer, self.bgp_port,
            mpls_bridge, mpls_interface)
        self.useFixture(bgp_cfg_fixture)

        self.bagpipe_bgp = self.useFixture(
            common_proc.BagpipeBGPFixture(
                self.env_desc, self.host_desc,
                self.test_name, bgp_cfg_fixture,
                namespace=self.host_namespace))

    def connect_to_internal_network_via_mpls_bridge(self):
        veth_1, veth_2 = self.useFixture(
            net_helpers.VethFixture()).ports

        veth_1.link.set_up()
        veth_2.link.set_up()

        self.mpls_bridge.add_port(veth_1.name)
        self.central_data_bridge.add_port(veth_2.name)

        mpls_device = ip_lib.IPDevice(self.mpls_bridge.br_name)
        mpls_device.addr.add(utils.ip_to_cidr(self.local_ip, 24))
        mpls_device.link.set_up()

        self.mpls_bridge.remove_all_flows()
        self.mpls_bridge.add_flow(in_port='LOCAL', actions='output:1')
        self.mpls_bridge.add_flow(in_port='1', actions='output:LOCAL')


class GoBGPHost(neutron_env.Host):

    def __init__(self, bgp_address, *args, **kwargs):
        super(GoBGPHost, self).__init__(*args, **kwargs)

        self.bgp_address = bgp_address

        # the right thing would be to use a fixture, but we can't in
        # __init__, so let's gamble :)
        self.bgp_port = random.randint(10000, 60000)

    def _setUp(self):
        gobgp_cfg_fixture = self.useFixture(
            common_cfg.GoBGPConfigFixture(
                self.env_desc, "gobgp",
                self.useFixture(fixtures.TempDir()).path,
                self.bgp_address,
                self.bgp_port,
                [host.local_ip for host in self.hosts]))

        self.useFixture(
            common_proc.GoBGPFixture(self.env_desc, None,
                                     self.test_name, gobgp_cfg_fixture))


class BaGPipeEnvironment(neutron_env.Environment):

    def _bagpipe_host_fixture(self, host_desc, bgp_peer, bgp_port):
        temp_dir = self.useFixture(fixtures.TempDir()).path
        neutron_config = bgpvpn_cfg.NeutronConfigFixture(
            self.env_desc, host_desc, temp_dir,
            cfg.CONF.database.connection, self.rabbitmq_environment)
        self.useFixture(neutron_config)

        return self.useFixture(
            BaGPipeHost(self.env_desc,
                        host_desc,
                        self.test_name,
                        neutron_config,
                        self.central_data_bridge,
                        self.central_external_bridge,
                        bgp_peer, bgp_port))

    def _create_gobgp_host(self, bgp_address):
        return GoBGPHost(bgp_address,
                         self.env_desc,
                         "gobgp",
                         self.test_name,
                         None,
                         self.central_data_bridge,
                         self.central_external_bridge)

    def _dont_be_paranoid(self):
        # we will have many br-mplsXXXXX or host-xxx interfaces on the
        # same subnet (the one for self.env_desc.network_range)
        # and we don't want the IP stack to drop the packets received
        # on these because they are from "us" but coming from "the outside"
        a_utils.execute(['sudo', 'sysctl', '-w',
                         'net.ipv4.conf.default.accept_local=1'])
        a_utils.execute(['sudo', 'sysctl', '-w',
                         'net.ipv4.conf.all.rp_filter=0'])
        a_utils.execute(['sudo', 'sysctl', '-w',
                         'net.ipv4.conf.default.rp_filter=0'])

    def _get_network_range(self):
        # for bare MPLS all compute nodes must be in the same subnet
        if self.env_desc.ipvpn_encap == 'bare-mpls':
            self._dont_be_paranoid()
            return self.useFixture(
                ip_network.ExclusiveIPNetwork(
                    "240.0.0.0", "240.255.255.255", "24")).network

        r = super(BaGPipeEnvironment, self)._get_network_range()
        if r:
            self._dont_be_paranoid()
            return r

    def _setUp(self):
        self.temp_dir = self.useFixture(fixtures.TempDir()).path

        # We need this bridge before rabbit and neutron service will start
        self.central_data_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture('cnt-data')).bridge
        self.central_external_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture('cnt-ex')).bridge

        # Get rabbitmq address (and cnt-data network)
        rabbitmq_ip_address = self._configure_port_for_rabbitmq()
        self.rabbitmq_environment = self.useFixture(
            neutron_proc.RabbitmqEnvironmentFixture(host=rabbitmq_ip_address)
        )

        plugin_cfg_fixture = self.useFixture(
            bagpipe_ml2_cfg.ML2ConfigFixture(
                self.env_desc, self.hosts_desc, self.temp_dir,
                self.env_desc.network_type))
        neutron_cfg_fixture = self.useFixture(
            bgpvpn_cfg.NeutronConfigFixture(
                self.env_desc, None, self.temp_dir,
                cfg.CONF.database.connection, self.rabbitmq_environment))

        service_cfg_fixtures = list()
        if self.env_desc.bgpvpn:
            service_cfg_fixtures.append(self.useFixture(
                bgpvpn_cfg.BGPVPNProviderConfigFixture(
                    self.env_desc, self.hosts_desc, self.temp_dir)))

        self.neutron_server = self.useFixture(
            neutron_proc.NeutronServerFixture(
                self.env_desc, None,
                self.test_name, neutron_cfg_fixture, plugin_cfg_fixture,
                service_cfg_fixtures))

        gobgp_host = self._create_gobgp_host(rabbitmq_ip_address)

        self.hosts = [self._bagpipe_host_fixture(desc,
                                                 rabbitmq_ip_address,
                                                 gobgp_host.bgp_port)
                      for desc in self.hosts_desc]

        gobgp_host.hosts = self.hosts

        self.useFixture(gobgp_host)

        self.wait_until_env_is_up()
