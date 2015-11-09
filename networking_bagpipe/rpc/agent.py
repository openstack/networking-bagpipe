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

from oslo_config import cfg
import six

from oslo_log.helpers import log_method_call as log


@six.add_metaclass(abc.ABCMeta)
class BaGPipeAgentRpcCallBackMixin(object):
    """Mix-in to support BaGPipe notifications in agent implementations"""

    @log
    def attach_port_on_bagpipe_network(self, context, port_bagpipe_info,
                                       host=None):
        """Attach port RPC

        Handle RPC cast from BaGPipe ML2 mechanism driver to attach port on
        BaGPipe network.
        """
        if not host or host == cfg.CONF.host:
            self.bagpipe_port_attach(context, port_bagpipe_info)

    @log
    def detach_port_from_bagpipe_network(self, context, port_bagpipe_info,
                                         host=None):
        """Detach Port RPC

        Handle RPC cast from BaGPipe ML2 mechanism driver to detach port from
        BaGPipe network.
        """
        if not host or host == cfg.CONF.host:
            self.bagpipe_port_detach(context, port_bagpipe_info)

    @abc.abstractmethod
    def bagpipe_port_attach(self, context, port_bagpipe_info):
        pass

    @abc.abstractmethod
    def bagpipe_port_detach(self, context, port_bagpipe_info):
        pass
