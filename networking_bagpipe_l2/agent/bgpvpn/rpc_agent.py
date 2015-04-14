# Copyright (c) 2015 Orange.
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

import abc

from oslo.config import cfg
import six


@six.add_metaclass(abc.ABCMeta)
class BGPVPNAgentRpcCallBackMixin(object):
    """
    Mix-in to support BGP VPN notifications in agent implementations.
    """
    @abc.abstractmethod
    def create_bgpvpn_connection(self, context, bgpvpn_connection):
        """
        Handle RPC fanout cast from service plugin to create a BGP VPN
        connection.
        """
        pass

    @abc.abstractmethod
    def update_bgpvpn_connection(self, context, bgpvpn_connection):
        """
        Handle RPC fanout cast from service plugin to update a BGP VPN
        connection.
        """
        pass

    @abc.abstractmethod
    def delete_bgpvpn_connection(self, context, bgpvpn_connection):
        """
        Handle RPC fanout cast from service plugin to delete a BGP VPN
        connection.
        """
        pass

    def attach_port_on_bgpvpn_network(self, context, port_bgpvpn_info,
                                      host=None):
        """
        Handle RPC cast from service plugin to attach port on BGP VPN network.
        """
        if not host or host == cfg.CONF.host:
            self.bgpvpn_port_attach(context, port_bgpvpn_info)

    def detach_port_from_bgpvpn_network(self, context, port_bgpvpn_info,
                                        host=None):
        """
        Handle RPC cast from service plugin to detach port from BGP VPN
        network.
        """
        if not host or host == cfg.CONF.host:
            self.bgpvpn_port_detach(context, port_bgpvpn_info)

    @abc.abstractmethod
    def bgpvpn_port_attach(self, context, port_bgpvpn_info):
        pass

    @abc.abstractmethod
    def bgpvpn_port_detach(self, context, port_bgpvpn_info):
        pass
