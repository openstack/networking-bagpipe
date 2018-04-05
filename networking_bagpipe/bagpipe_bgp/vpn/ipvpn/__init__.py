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

import abc
import itertools
import six

from networking_bagpipe.bagpipe_bgp.common import exceptions as exc
from networking_bagpipe.bagpipe_bgp.common import log_decorator
from networking_bagpipe.bagpipe_bgp.common import looking_glass as lg
from networking_bagpipe.bagpipe_bgp.common import utils
from networking_bagpipe.bagpipe_bgp import constants
from networking_bagpipe.bagpipe_bgp import engine
from networking_bagpipe.bagpipe_bgp.engine import exa
from networking_bagpipe.bagpipe_bgp.engine import flowspec
from networking_bagpipe.bagpipe_bgp.engine import ipvpn as ipvpn_routes
from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers as dp_drivers
from networking_bagpipe.bagpipe_bgp.vpn import vpn_instance

DEFAULT_ADDR_PREFIX = '0.0.0.0/0'


@six.add_metaclass(abc.ABCMeta)
class VPNInstanceDataplane(dp_drivers.VPNInstanceDataplane):

    @abc.abstractmethod
    def add_dataplane_for_traffic_classifier(self, classifier,
                                             redirect_to_instance_id):
        pass

    @abc.abstractmethod
    def remove_dataplane_for_traffic_classifier(self, classifier):
        pass


class DummyVPNInstanceDataplane(dp_drivers.DummyVPNInstanceDataplane,
                                VPNInstanceDataplane):

    def add_dataplane_for_traffic_classifier(self, *args, **kwargs):
        raise Exception("not implemented")

    def remove_dataplane_for_traffic_classifier(self, *args, **kwargs):
        raise Exception("not implemented")


class DummyDataplaneDriver(dp_drivers.DummyDataplaneDriver):
    type = constants.IPVPN
    dataplane_instance_class = DummyVPNInstanceDataplane


class VRF(vpn_instance.VPNInstance, lg.LookingGlassMixin):
    # component managing a VRF:
    # - calling a driver to instantiate the dataplane
    # - registering to receive routes for the needed route targets
    # - calling the driver to setup/update/remove routes in the dataplane
    # - cleanup: calling the driver, unregistering for BGP routes

    type = constants.IPVPN
    afi = exa.AFI.ipv4
    safi = exa.SAFI.mpls_vpn

    @log_decorator.log
    def __init__(self, *args, **kwargs):
        vpn_instance.VPNInstance.__init__(self, *args, **kwargs)
        self.readvertised = set()

    def needs_cleanup_assist(self, afi, safi):
        if (afi, safi) == (self.afi, exa.SAFI.flow_vpn):
            return True
        else:
            return self.dataplane.needs_cleanup_assist()

    @classmethod
    def validate_convert_params(cls, params, also_mandatory=()):
        return super(VRF, cls).validate_convert_params(
            params,
            also_mandatory=tuple(set(also_mandatory) | set(['ip_address'])))

    @classmethod
    def validate_convert_attach_params(cls, params):
        super(VRF, cls).validate_convert_attach_params(params)
        if 'gateway_ip' not in params:
            raise exc.APIMissingParameterException('gateway_ip')

    def _nlri_from(self, prefix, label, rd):
        assert rd is not None

        return ipvpn_routes.IPVPNRouteFactory(
            self.afi, prefix, label, rd,
            self.dp_driver.get_local_address())

    def generate_vif_bgp_route(self, mac_address, ip_prefix, plen, label, rd):
        # Generate BGP route and advertise it...
        nlri = self._nlri_from("%s/%s" % (ip_prefix, plen), label, rd)

        return engine.RouteEntry(nlri)

    def _get_local_labels(self):
        for port_data in self.mac_2_localport_data.values():
            yield port_data['label']

    def _get_route_params_for_endpoint(self, endpoint):
        port_data = self.mac_2_localport_data[endpoint[0]]
        label = port_data['label']
        lb_consistent_hash_order = port_data[
            'lb_consistent_hash_order']
        rd = self.endpoint_2_rd[endpoint]

        return (label, rd, lb_consistent_hash_order)

    def _imported(self, route):
        return len(set(route.route_targets).intersection(set(self.import_rts))
                   ) > 0

    def _to_readvertise(self, route):
        rt_records = route.ecoms(exa.RTRecord)
        self.log.debug("RTRecords: %s (readvertise_to_rts:%s)",
                       rt_records,
                       self.readvertise_to_rts)

        readvertise_targets_as_records = [exa.RTRecord.from_rt(rt)
                                          for rt in self.readvertise_to_rts]

        if self.attract_traffic:
            readvertise_targets_as_records += [exa.RTRecord.from_rt(rt)
                                               for rt in self.attract_rts]

        if set(readvertise_targets_as_records).intersection(set(rt_records)):
            self.log.debug("not to re-advertise because one of the readvertise"
                           " or attract-redirect RTs is in RTRecords: %s",
                           set(readvertise_targets_as_records)
                           .intersection(set(rt_records)))
            return False

        return len(set(route.route_targets).intersection(
            set(self.readvertise_from_rts)
            )) > 0

    def _gen_rtrecords_extended_community(self, ecoms):
        # new RTRecord = original RTRecord (if any) + orig RTs converted into
        # RTRecord attributes
        orig_rtrecords = ecoms(exa.RTRecord)
        rts = ecoms(exa.RTExtCom)
        add_rtrecords = [exa.RTRecord.from_rt(rt) for rt in rts]

        return list(set(orig_rtrecords) | set(add_rtrecords))

    def _route_for_readvertisement(self, route, endpoint):
        label, rd, lb_consistent_hash_order = (
            self._get_route_params_for_endpoint(endpoint)
        )
        self.log.debug("Prefix %s (re-)advertisement with label %s and route "
                       "distinguisher %s", route.nlri.cidr.prefix(), label, rd)
        nlri = self._nlri_from(route.nlri.cidr.prefix(), label, rd)

        attributes = exa.Attributes()

        ecoms = self._gen_encap_extended_communities()
        ecoms.communities += (
            self._gen_rtrecords_extended_community(route.ecoms)
        )
        ecoms.communities.append(
            exa.ConsistentHashSortOrder(lb_consistent_hash_order))
        attributes.add(ecoms)

        entry = engine.RouteEntry(nlri, self.readvertise_to_rts, attributes)
        self.log.debug("RouteEntry for (re-)advertisement: %s", entry)
        return entry

    def _default_route_for_advertisement(self, endpoint):
        label, rd, lb_consistent_hash_order = (
            self._get_route_params_for_endpoint(endpoint)
        )
        self.log.debug("Default route (re-)advertisement with label %s and "
                       "route distinguisher %s", label, rd)
        nlri = self._nlri_from(DEFAULT_ADDR_PREFIX, label, rd)

        attributes = exa.Attributes()

        ecoms = self._gen_encap_extended_communities()
        ecoms.communities.append(
            exa.ConsistentHashSortOrder(lb_consistent_hash_order))
        attributes.add(ecoms)

        entry = engine.RouteEntry(nlri, self.readvertise_to_rts, attributes)
        self.log.debug("RouteEntry for default prefix advertisement: %s",
                       entry)
        return entry

    @log_decorator.log
    def _routes_for_attract_static_dest_prefixes(self, endpoint):
        if not self.attract_static_dest_prefixes:
            return

        label, rd, _ = self._get_route_params_for_endpoint(endpoint)

        for prefix in self.attract_static_dest_prefixes:
            nlri = self._nlri_from(prefix, label, rd)

            entry = engine.RouteEntry(nlri, self.readvertise_to_rts)
            self.log.debug("RouteEntry for attract static destination prefix: "
                           "%s", entry)
            yield entry

    @log_decorator.log
    def _route_for_redirect_prefix(self, prefix):
        prefix_classifier = utils.dict_camelcase_to_underscore(
            self.attract_classifier)
        prefix_classifier['destination_prefix'] = prefix

        traffic_classifier = vpn_instance.TrafficClassifier(
            **prefix_classifier)
        self.log.debug("Advertising prefix %s for redirection based on "
                       "traffic classifier %s", prefix, traffic_classifier)
        rules = traffic_classifier.map_traffic_classifier_2_redirect_rules()

        return self.synthesize_redirect_bgp_route(rules)

    def _redirect_route_for_readvertisement(self, route):
        # Create a FlowSpec NLRI with distinct RD and a copy of rules from
        # FlowSpec route to readvertise
        nlri = flowspec.FlowRouteFactory(self.afi, self.instance_rd)
        nlri.rules = route.nlri.rules

        attributes = exa.Attributes()

        ecoms = exa.ExtendedCommunities()
        ecoms.communities += (
            self._gen_rtrecords_extended_community(route.ecoms)
        )
        assert len(self.attract_rts) == 1
        rt = self.attract_rts[0]
        ecoms.communities.append(
            exa.TrafficRedirect(exa.ASN(int(rt.asn)), int(rt.number))
        )
        attributes.add(ecoms)

        entry = engine.RouteEntry(nlri, self.readvertise_to_rts, attributes)
        self.log.debug("RouteEntry for redirect (re-)advertisement: %s", entry)
        return entry

    @log_decorator.log
    def _readvertise(self, route):
        nlri = route.nlri

        self.log.debug("Start re-advertising %s from VRF", nlri)
        if self.attract_traffic:
            # Start advertising default route only when the first route to
            # readvertise appears
            if not self.readvertised:
                for endpoint in self.all_endpoints():
                    self.log.debug("Start advertising default route from VRF "
                                   "%d to redirection VRF", self.instance_id)
                    self._advertise_route(
                        self._default_route_for_advertisement(endpoint)
                    )

            if isinstance(nlri, flowspec.Flow):
                # Readvertise FlowSpec route
                self._advertise_route(
                    self._redirect_route_for_readvertisement(route)
                )
            else:
                # Advertise FlowSpec route for prefix
                self._advertise_route(
                    self._route_for_redirect_prefix(nlri.cidr.prefix())
                )

        else:
            for endpoint in self.all_endpoints():
                self.log.debug("Start re-advertising %s from endpoint %s",
                               nlri.cidr.prefix(), endpoint)
                self._advertise_route(
                    self._route_for_readvertisement(route, endpoint)
                )

        self.readvertised.add(route)

    @log_decorator.log
    def _readvertise_stop(self, route, last):
        nlri = route.nlri

        if last:
            self.log.debug("Stop re-advertising %s from VRF", nlri)
            if self.attract_traffic:
                # Stop advertising default route only if the withdrawn route is
                # the last of the routes to readvertise
                if len(self.readvertised) == 1:
                    for endpoint in self.all_endpoints():
                        self.log.debug("Stop advertising default route from "
                                       "VRF to redirection VRF")
                        self._withdraw_route(
                            self._default_route_for_advertisement(endpoint)
                        )

                if isinstance(nlri, flowspec.Flow):
                    # Withdraw readvertised FlowSpec route
                    self._withdraw_route(
                        self._redirect_route_for_readvertisement(route)
                    )
                else:
                    # Withdraw FlowSpec route for prefix
                    self._withdraw_route(
                        self._route_for_redirect_prefix(nlri.cidr.prefix())
                    )
            else:
                for endpoint in self.all_endpoints():
                    self.log.debug("Stop re-advertising %s from endpoint %s",
                                   nlri.cidr.prefix(), endpoint)
                    route_entry = (
                        self._route_for_readvertisement(route, endpoint)
                    )
                    self._withdraw_route(route_entry)

        self.readvertised.remove(route)

    @log_decorator.log_info
    def vif_plugged(self, mac_address, ip_address_prefix, localport,
                    advertise_subnet=False, lb_consistent_hash_order=0,
                    local_pref=None, **kwargs):
        super(VRF, self).vif_plugged(mac_address, ip_address_prefix,
                                     localport, advertise_subnet,
                                     lb_consistent_hash_order, local_pref,
                                     **kwargs)

        if vpn_instance.forward_to_port(kwargs.get('direction')):
            endpoint = (mac_address, ip_address_prefix)
            for route in itertools.chain(
                    self.readvertised,
                    self._routes_for_attract_static_dest_prefixes(endpoint)):
                self.log.debug("Re-advertising %s with this port as next hop",
                               route.nlri)
                if self.attract_traffic:
                    self._advertise_route(
                        self._default_route_for_advertisement(endpoint)
                    )

                    if self.has_only_one_endpoint():
                        self._advertise_route(self._route_for_redirect_prefix(
                            route.nlri.cidr.prefix()))
                else:
                    self._advertise_route(
                        self._route_for_readvertisement(route, endpoint)
                    )

    @log_decorator.log_info
    def vif_unplugged(self, mac_address, ip_address_prefix):
        endpoint = (mac_address, ip_address_prefix)
        direction = self.endpoint_2_direction[endpoint]
        if vpn_instance.forward_to_port(direction):
            for route in itertools.chain(
                    self.readvertised,
                    self._routes_for_attract_static_dest_prefixes(endpoint)):
                self.log.debug("Stop re-advertising %s", route.nlri)
                if self.attract_traffic:
                    self._withdraw_route(
                        self._default_route_for_advertisement(endpoint)
                    )

                    if self.has_only_one_endpoint():
                        self._withdraw_route(self._route_for_redirect_prefix(
                            route.nlri.cidr.prefix()))
                else:
                    self._withdraw_route(
                        self._route_for_readvertisement(route, endpoint)
                    )

        super(VRF, self).vif_unplugged(mac_address, ip_address_prefix)

    # Callbacks for BGP route updates (TrackerWorker) ########################

    def route_to_tracked_entry(self, route):
        if isinstance(route.nlri, ipvpn_routes.IPVPN):
            return route.nlri.cidr.prefix()
        elif isinstance(route.nlri, flowspec.Flow):
            return (flowspec.Flow, route.nlri._rules())
        else:
            self.log.error("We should not receive routes of type %s",
                           type(route.nlri))
            return None

    @utils.synchronized
    @log_decorator.log
    def new_best_route(self, entry, new_route):

        if self.readvertise:
            # check if this is a route we need to re-advertise
            self.log.debug("route RTs: %s", new_route.route_targets)
            self.log.debug("readv from RTs: %s", self.readvertise_from_rts)
            if self._to_readvertise(new_route):
                self.log.debug("Need to re-advertise %s", entry)
                self._readvertise(new_route)

        if not self._imported(new_route):
            self.log.debug("No need to setup dataplane for:%s", entry)
            return

        if isinstance(new_route.nlri, flowspec.Flow):
            if len(new_route.ecoms(exa.TrafficRedirect)) == 1:
                traffic_redirect = new_route.ecoms(exa.TrafficRedirect)
                redirect_rt = "%s:%s" % (traffic_redirect[0].asn,
                                         traffic_redirect[0].target)

                self.start_redirect_traffic(redirect_rt,
                                            new_route.nlri.rules)
            else:
                self.log.warning("FlowSpec action or multiple traffic "
                                 "redirect actions not supported: %s",
                                 new_route.ecoms())
        else:
            prefix = entry

            encaps = self._check_encaps(new_route)
            if not encaps:
                return

            assert len(new_route.nlri.labels.labels) == 1

            lb_consistent_hash_order = 0
            if new_route.ecoms(exa.ConsistentHashSortOrder):
                lb_consistent_hash_order = new_route.ecoms(
                    exa.ConsistentHashSortOrder)[0].order

            self.dataplane.setup_dataplane_for_remote_endpoint(
                prefix, new_route.nexthop,
                new_route.nlri.labels.labels[0], new_route.nlri, encaps,
                lb_consistent_hash_order)

    @utils.synchronized
    @log_decorator.log
    def best_route_removed(self, entry, old_route, last):

        if self.readvertise:
            # check if this is a route we were re-advertising
            if self._to_readvertise(old_route):
                self.log.debug("Need to stop re-advertising %s", entry)
                self._readvertise_stop(old_route, last)

        if isinstance(old_route.nlri, flowspec.Flow):
            if self._imported(old_route):
                if len(old_route.ecoms(exa.TrafficRedirect)) == 1:
                    if last:
                        traffic_redirect = old_route.ecoms(
                            exa.TrafficRedirect)
                        redirect_rt = "%s:%s" % (traffic_redirect[0].asn,
                                                 traffic_redirect[0].target)

                        self.stop_redirect_traffic(redirect_rt,
                                                   old_route.nlri.rules)
                else:
                    self.log.warning("FlowSpec action or multiple traffic "
                                     "redirect actions not supported: %s",
                                     old_route.ecoms())
        else:
            prefix = entry

            # NOTE(tmorin): On new best routes, we only trigger dataplane
            # update events after checking with self._imported(...) that the
            # route was imported (and not a route that we receive because the
            # VRF should readvertise ir). On best_route_removed, we can't do
            # that because we could end up in a situation where:
            # - initially import_rts contains RT X
            # - we receive a route for RT X and install dataplane state
            # - the import_rts list is later updated and RT X is not anymore
            # part of the imported RTs, and the VRF unsubscribes from RT X
            # - we receive the best_route_removed callbacks corresponding to
            # the unsubscribe, but since the route is for no RT that is in
            # import_rts, we don't update the dataplane
            # The result would be to fail to remove dataplane state for this
            # route, so we're better not optimizing this case and remove
            # dataplane state, including possibly for routes that we did
            # not install in it.

            if self._skip_route_removal(last):
                self.log.debug("Skipping removal of non-last route because "
                               "dataplane does not want it")
                return

            # if we still have a route with same dataplane properties in
            # best routes, then we don't want to clear the dataplane entry
            if self.equivalent_route_in_best_routes(
                    old_route,
                    lambda r: (r.nexthop, r.nlri.labels.labels[0])):
                self.log.debug("Route for same dataplane is still in best "
                               "routes, skipping removal")
                return

            encaps = self._check_encaps(old_route)
            if not encaps:
                return

            assert len(old_route.nlri.labels.labels) == 1

            lb_consistent_hash_order = 0
            if old_route.ecoms(exa.ConsistentHashSortOrder):
                lb_consistent_hash_order = old_route.ecoms(
                    exa.ConsistentHashSortOrder)[0].order

            self.dataplane.remove_dataplane_for_remote_endpoint(
                prefix, old_route.nexthop,
                old_route.nlri.labels.labels[0], old_route.nlri, encaps,
                lb_consistent_hash_order)

    # Looking glass ###

    def get_lg_map(self):
        return {
            "readvertised": (lg.SUBTREE, self.get_lg_readvertised_routes),
        }

    def get_lg_readvertised_routes(self, path_prefix):
        return [route.get_lg_local_info(path_prefix)
                for route in self.readvertised]
