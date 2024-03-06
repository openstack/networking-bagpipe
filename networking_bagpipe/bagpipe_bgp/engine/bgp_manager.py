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

from functools import reduce

from oslo_config import cfg
from oslo_log import log as logging

from networking_bagpipe.bagpipe_bgp.common import log_decorator
from networking_bagpipe.bagpipe_bgp.common import looking_glass as lg
from networking_bagpipe.bagpipe_bgp.common import utils
from networking_bagpipe.bagpipe_bgp import engine
from networking_bagpipe.bagpipe_bgp.engine import bgp_peer_worker
from networking_bagpipe.bagpipe_bgp.engine import exa
from networking_bagpipe.bagpipe_bgp.engine import exabgp_peer_worker
from networking_bagpipe.bagpipe_bgp.engine import route_table_manager as rtm


LOG = logging.getLogger(__name__)

# SAFIs for which RFC4684 is effective
RTC_SAFIS = (exa.SAFI.mpls_vpn, exa.SAFI.evpn)


class Manager(engine.EventSource, lg.LookingGlassMixin, utils.ClassReprMixin):

    _instance = None

    def __init__(self):

        LOG.debug("Instantiating BGPManager")

        if cfg.CONF.BGP.enable_rtc:
            first_local_subscriber_callback = self.rtc_advertisement_for_sub
            last_local_subscriber_callback = self.rtc_withdrawal_for_sub
        else:
            first_local_subscriber_callback = None
            last_local_subscriber_callback = None

        self.rtm = rtm.RouteTableManager(first_local_subscriber_callback,
                                         last_local_subscriber_callback)

        self.rtm.start()

        self.peers = {}
        if cfg.CONF.BGP.peers:
            for peer_address in cfg.CONF.BGP.peers:
                LOG.debug("Creating a peer worker for %s", peer_address)
                peer_worker = exabgp_peer_worker.ExaBGPPeerWorker(self,
                                                                  peer_address)
                self.peers[peer_address] = peer_worker
                peer_worker.start()

        # we need a .name since we'll masquerade as a route_entry source
        self.name = "BGPManager"

        engine.EventSource.__init__(self, self.rtm)

    def __repr__(self):
        return self.__class__.__name__

    @log_decorator.log
    def stop(self):
        for peer in self.peers.values():
            peer.stop()
        self.rtm.stop()
        for peer in self.peers.values():
            peer.join()
        self.rtm.join()

    def get_local_address(self):
        return cfg.CONF.BGP.local_address

    @log_decorator.log
    def rtc_advertisement_for_sub(self, sub):
        if sub.safi in RTC_SAFIS:
            event = engine.RouteEvent(
                engine.RouteEvent.ADVERTISE,
                self._subscription_2_rtc_route_entry(sub),
                self)
            LOG.debug("Based on subscription => synthesized RTC %s", event)
            self.rtm.enqueue(event)

    @log_decorator.log
    def rtc_withdrawal_for_sub(self, sub):
        if sub.safi in RTC_SAFIS:
            event = engine.RouteEvent(
                engine.RouteEvent.WITHDRAW,
                self._subscription_2_rtc_route_entry(sub),
                self)
            LOG.debug("Based on unsubscription => synthesized withdraw"
                      " for RTC %s", event)
            self.rtm.enqueue(event)

    def _subscription_2_rtc_route_entry(self, subscription):

        nlri = exa.RTC.new(exa.AFI.ipv4,
                           exa.SAFI.rtc,
                           cfg.CONF.BGP.my_as,
                           subscription.route_target,
                           exa.IP.create(self.get_local_address()))

        route_entry = engine.RouteEntry(nlri)

        return route_entry

    # Looking Glass Functions ###################

    def get_lg_map(self):
        return {"peers": (lg.COLLECTION, (self.get_lg_peer_list,
                                          self.get_lg_peer_path_item)),
                "routes": (lg.FORWARD, self.rtm),
                "workers": (lg.FORWARD, self.rtm),
                "route_counts": (lg.SUBITEM, self.get_lg_route_counts)}

    def get_established_peers_count(self):
        return reduce(lambda count, peer: count +
                      (isinstance(peer, bgp_peer_worker.BGPPeerWorker) and
                       peer.is_established()),
                      self.peers.values(), 0)

    def get_lg_peer_list(self):
        return [{"id": peer.peer_address,
                 "state": peer.fsm.state} for peer in self.peers.values()]

    def get_lg_peer_path_item(self, path_item):
        return self.peers[path_item]

    def get_lg_route_counts(self):
        return {"local_routes_count": self.rtm.get_local_routes_count(),
                "received_routes_count": self.rtm.get_received_routes_count()}
