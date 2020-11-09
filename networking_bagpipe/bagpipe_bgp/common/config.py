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

import shlex
import socket

from oslo_config import cfg
from oslo_config import types
from oslo_privsep import priv_context
from pyroute2 import IPDB  # pylint: disable=no-name-in-module


class InterfaceAddress(types.ConfigType):
    # Option type for a config entry accepting whether an IP address
    # or an interface from which to derive the IP address

    # convert from IP version (4 or 6) to family number
    FAMILY_MAP = {
        4: socket.AF_INET,
        6: socket.AF_INET6,
    }

    def __init__(self, type_name="interface address value", version=4):
        super(InterfaceAddress, self).__init__(type_name=type_name)
        self.version = version
        self.family = self.FAMILY_MAP[version]
        self.ip_address = types.IPAddress(version)

    def __call__(self, value):
        try:
            return self.ip_address(value)
        except ValueError:
            # pyroute2 call to take the first address of this interface having
            # the right IP version (family)
            with IPDB(plugins=("interfaces",)) as ipdb:
                try:
                    interface = ipdb.interfaces[value]
                except KeyError:
                    raise ValueError("interface %s does not exist" % value)

                # we can't use an iterator if we want to access dictionaries
                # inside ipaddr
                for i in range(0, len(interface.ipaddr)):
                    addr = interface.ipaddr[i]
                    if addr['family'] == self.family:
                        return self.ip_address(addr['address'])

                raise ValueError("no IPv%s address found on interface %s",
                                 self.version, value)

    def _formatter(self, value):
        address = self(value)
        return "%s(%s)" % (address, value)

    def __repr__(self):
        return "InterfaceAddress"

    def __eq__(self, other):
        return self.__class__ == other.__class__


bgp_opts = [
    cfg.Opt('local_address', required=True,
            type=InterfaceAddress(),
            help="IP address used for BGP peerings"),
    cfg.ListOpt('peers', default=[],
                item_type=types.HostAddress(version=4),
                help="IP addresses of BGP peers"),
    cfg.IntOpt('my_as', min=1, max=2**16-1, required=True,
               help="Our BGP Autonomous System"),
    cfg.BoolOpt('enable_rtc', default=True,
                help="Enable RT Constraint (RFC4684)"),
    cfg.PortOpt('bgp_port', default=179,
                help="TCP port of connections to BGP peers")
]


def register():
    cfg.CONF.register_opts(bgp_opts, "BGP")


def set_default_root_helper():
    # copy bagpipe-bgp root helper configuration into neutron's config, so
    # that neutron classes find the right configuration to execute commands
    cfg.CONF.set_default('root_helper',
                         cfg.CONF.COMMON.root_helper,
                         group="AGENT")
    cfg.CONF.set_default('root_helper_daemon',
                         cfg.CONF.COMMON.root_helper_daemon,
                         group="AGENT")


def setup_privsep():
    priv_context.init(root_helper=shlex.split(cfg.CONF.COMMON.root_helper))
