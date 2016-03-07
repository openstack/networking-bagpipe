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

import oslo_messaging

from neutron.common import rpc as n_rpc
from neutron.common import topics
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

# until we have a better way to add something in the topic namespace
# from a python package external to Neutron...
topics_BAGPIPE_BGPVPN = "bagpipe-bgpvpn"


class BGPVPNAgentNotifyApi(object):
    """Base class for BGP VPN Service Plugin notification to agent RPC API."""

    def __init__(self, topic=topics.AGENT):
        self.topic = topic

        self.topic_bgpvpn_update = topics.get_topic_name(self.topic,
                                                         topics_BAGPIPE_BGPVPN,
                                                         topics.UPDATE)

        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    # BGP VPN CRUD notifications
    # --------------------------------------
    def _notification_fanout(self, context, method, bgpvpn):
        LOG.debug(_('Fanout notify BGP VPN agents at %(topic)s '
                    'the message %(method)s with %(bgpvpn)s'),
                  {'topic': self.topic_bgpvpn_update,
                   'method': method,
                   'bgpvpn': bgpvpn})

        cctxt = self.client.prepare(topic=self.topic_bgpvpn_update,
                                    fanout=True)
        cctxt.cast(context, method, bgpvpn=bgpvpn)

    def create_bgpvpn(self, context, bgpvpn):
        return self._notification_fanout(context,
                                         'create_bgpvpn',
                                         bgpvpn)

    def update_bgpvpn(self, context, bgpvpn):
        return self._notification_fanout(context,
                                         'update_bgpvpn',
                                         bgpvpn)

    def delete_bgpvpn(self, context, bgpvpn):
        return self._notification_fanout(context,
                                         'delete_bgpvpn',
                                         bgpvpn)

    # Port attach/detach on/from BGP VPN notifications
    # ---------------------------------------------------------
    def _notification_host(self, context, method, port_bgpvpn_info, host):
        LOG.debug(_('Notify BGP VPN agent %(host)s at %(topic)s '
                    'the message %(method)s with %(port_bgpvpn_info)s'),
                  {'host': host,
                   'topic': self.topic_bgpvpn_update,
                   'method': method,
                   'port_bgpvpn_info': port_bgpvpn_info})

        cctxt = self.client.prepare(topic=self.topic_bgpvpn_update,
                                    server=host)
        cctxt.cast(context, method, port_bgpvpn_info=port_bgpvpn_info)

    def attach_port_on_bgpvpn(self, context, port_bgpvpn_info, host=None):
        if port_bgpvpn_info:
            self._notification_host(context, 'attach_port_on_bgpvpn',
                                    port_bgpvpn_info, host)

    def detach_port_from_bgpvpn(self, context, port_bgpvpn_info, host=None):
        self._notification_host(context, 'detach_port_from_bgpvpn',
                                port_bgpvpn_info, host)
