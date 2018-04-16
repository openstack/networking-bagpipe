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

import itertools

from collections import defaultdict
from collections import namedtuple

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class keydefaultdict(defaultdict):
    """Inherit defaultdict class to customize default_factory.

    Override __missing__ method to construct custom object as default_factory
    passing an argument.

    For example:
    class C(object):
        def __init__(self, value):
            self.value = value

    d = keydefaultdict(C)
    d[key] returns C(key)
    """
    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        else:
            # pylint: disable=not-callable
            ret = self[key] = getattr(self, 'default_factory')(key)
            return ret


class CommonInfo(object):

    def __init__(self, id):
        self.id = id
        self._associations = dict()

    @property
    def associations(self):
        return self._associations.values()

    def add_association(self, association):
        self._associations[association.id] = association

    def remove_association(self, association):
        del self._associations[association.id]

    def has_association(self, association_id):
        return association_id in self._associations

    def get_association(self, association_id):
        return self._associations.get(association_id)


class PortInfo(CommonInfo):

    def __init__(self, port_id):
        super(PortInfo, self).__init__(port_id)

        self.ip_address = None
        self.mac_address = None
        self.network = None
        self.chain_hops = dict()
        self.admin_state_up = False

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.id == other.id)

    def __hash__(self):
        return hash(self.id)

    @property
    def all_associations(self):
        return itertools.chain(
            self.associations,
            self.network.associations if self.network else [])

    def has_any_association(self):
        return any(True for _ in self.all_associations)

    def add_chain_hop(self, chain_hop):
        if not chain_hop:
            return

        if not all(item in self.chain_hops.items()
                   for item in chain_hop.items()):
            self.chain_hops.update(chain_hop)

    def update_admin_state(self, port_data, transition_to_down_hook=None):
        if port_data['admin_state_up']:
            self.admin_state_up = True
        else:
            previous_admin_state_up = self.admin_state_up
            if previous_admin_state_up:
                if callable(transition_to_down_hook):
                    transition_to_down_hook()
                self.admin_state_up = False
            else:
                self.admin_state_up = False
        LOG.debug("port %s, admin_state_up is now: %s",
                  self.id, self.admin_state_up)

    def __repr__(self):
        return "PortInfo(%s,%s)" % (self.id, self.admin_state_up)


GatewayInfo = namedtuple('GatewayInfo', ['mac', 'ip'])
NO_GW_INFO = GatewayInfo(None, None)


class NetworkInfo(CommonInfo):

    def __init__(self, network_id):
        super(NetworkInfo, self).__init__(network_id)

        self.gateway_info = NO_GW_INFO
        self.ports = set()
        self.segmentation_id = None

    def set_gateway_info(self, gateway_info):
        self.gateway_info = gateway_info

    def __repr__(self):
        return "NetInfo: %s (segmentation id:%s, gw:%s), " % (
            self.id, self.segmentation_id, self.gateway_info)


class BaseInfoManager(object):

    def __init__(self):
        # Store all ports level network and service informations
        self.ports_info = keydefaultdict(PortInfo)
        # Store all networks level network and service informations
        self.networks_info = keydefaultdict(NetworkInfo)

    def _get_network_port_infos(self, net_id, port_id):
        net_info = self.networks_info[net_id]
        port_info = self.ports_info[port_id]
        net_info.ports.add(port_info)
        port_info.network = net_info

        return net_info, port_info

    def _remove_network_port_infos(self, net_id, port_id):
        port_info = self.ports_info.get(port_id)
        net_info = self.networks_info.get(net_id)

        if port_info:
            del self.ports_info[port_id]

        if net_info:
            net_info.ports.discard(port_info)
            if not net_info.ports:
                del self.networks_info[net_id]
