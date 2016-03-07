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

from oslo_log import log as logging

import oslo_messaging

from neutron.common import rpc as n_rpc
from neutron.common import topics

LOG = logging.getLogger(__name__)

# until we have a better way to add something in the topic namespace
# from a python package external to Neutron...
topics_BAGPIPE = "bagpipe-l2"


class BaGPipeAgentNotifyAPI(object):
    """Base class for BaGPipe ML2 mech driver notification to agent RPC API"""

    def __init__(self):
        self.topic_bagpipe_update = topics.get_topic_name(topics.AGENT,
                                                          topics_BAGPIPE,
                                                          topics.UPDATE)

        target = oslo_messaging.Target(topic=topics.AGENT, version='1.0')
        self.client = n_rpc.get_client(target)

    def _notification_host(self, context, method, port_bagpipe_info, host):
        LOG.debug('Notify BaGPipe ML2 plugin agent %(host)s at %(topic)s '
                  'the message %(method)s with %(port_bagpipe_info)s',
                  {'host': host,
                   'topic': self.topic_bagpipe_update,
                   'method': method,
                   'port_bagpipe_info': port_bagpipe_info})

        cctxt = self.client.prepare(topic=self.topic_bagpipe_update,
                                    server=host)
        cctxt.cast(context, method, port_bagpipe_info=port_bagpipe_info)

    def attach_port_on_bagpipe_network(self, context, port_bagpipe_info,
                                       host=None):
        if host:
            self._notification_host(context,
                                    'attach_port_on_bagpipe_network',
                                    port_bagpipe_info,
                                    host)
        else:
            LOG.warning("attach_port_on_bagpipe_network called without"
                        " a host")

    def detach_port_from_bagpipe_network(self, context, port_bagpipe_info,
                                         host=None):
        if host:
            self._notification_host(context,
                                    'detach_port_from_bagpipe_network',
                                    port_bagpipe_info,
                                    host)
        else:
            LOG.warning("detach_port_from_bagpipe_network called without"
                        " a host")
