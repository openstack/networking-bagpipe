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

import six

from networking_bagpipe.bagpipe_bgp.common import log_decorator
from networking_bagpipe.bagpipe_bgp.common import looking_glass as lg
from networking_bagpipe.bagpipe_bgp.common import utils
from networking_bagpipe.bagpipe_bgp import constants
from networking_bagpipe.bagpipe_bgp import engine
from networking_bagpipe.bagpipe_bgp.engine import exa
from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers as dp_drivers
from networking_bagpipe.bagpipe_bgp.vpn import vpn_instance


@six.add_metaclass(abc.ABCMeta)
class VPNInstanceDataplane(dp_drivers.VPNInstanceDataplane):

    @abc.abstractmethod
    def add_dataplane_for_bum_endpoint(self, remote_pe, dpid, nlri, encaps):
        pass

    @abc.abstractmethod
    def remove_dataplane_for_bum_endpoint(self, remote_pe, dpid, nlri):
        pass

    @abc.abstractmethod
    def set_gateway_port(self, linuxif, gateway_ip):
        '''Set the IP gateway port

        Used to determine a port to which traffic at the destination of the
        IP gateway should be sent.  This is used to plug an EVI into an IP VPN
        VRF.
        '''
        pass

    @abc.abstractmethod
    def gateway_port_down(self, linuxif):
        '''Unset the IP gateway port

        Used to revert the action done when set_gateway_port was called.
        Relevant only when an EVI had been plugged into an IP VPN VRF.
        '''
        pass


class DummyVPNInstanceDataplane(dp_drivers.DummyVPNInstanceDataplane,
                                VPNInstanceDataplane):
    '''Dummy, do-nothing dataplane driver'''

    @log_decorator.log_info
    def add_dataplane_for_bum_endpoint(self, *args, **kwargs):
        pass

    @log_decorator.log_info
    def remove_dataplane_for_bum_endpoint(self, *args, **kwargs):
        pass

    @log_decorator.log_info
    def set_gateway_port(self, *args, **kwargs):
        pass

    @log_decorator.log_info
    def gateway_port_down(self, *args, **kwargs):
        pass


class DummyDataplaneDriver(dp_drivers.DummyDataplaneDriver):

    type = constants.EVPN

    dataplane_instance_class = DummyVPNInstanceDataplane
    encaps = [exa.Encapsulation(exa.Encapsulation.Type.VXLAN)]

    def __init__(self, *args, **kwargs):
        dp_drivers.DummyDataplaneDriver.__init__(self, *args, **kwargs)


class EVI(vpn_instance.VPNInstance, lg.LookingGlassMixin):
    '''Implementation an E-VPN MAC-VRF instance (EVI)

    based on RFC7432 and draft-ietf-bess-evpn-overlay.
    '''

    type = constants.EVPN
    afi = exa.AFI.l2vpn
    safi = exa.SAFI.evpn

    @log_decorator.log
    def __init__(self, *args, **kwargs):

        vpn_instance.VPNInstance.__init__(self, *args, **kwargs)

        self.gw_port = None

        encaps = self.dp_driver.supported_encaps()
        if (exa.Encapsulation(exa.Encapsulation.Type.VXLAN) in encaps
                and any([
                exa.Encapsulation(exa.Encapsulation.Type.MPLS) in encaps,
                exa.Encapsulation(exa.Encapsulation.Type.GRE) in encaps,
                exa.Encapsulation(exa.Encapsulation.Type.MPLS_UDP) in encaps
                ])):
            raise Exception("The dataplane can't support both an MPLS encap "
                            "and a VXLAN encapsulation")

        # Advertise route to receive multi-destination traffic
        self.log.info("Generating BGP route for broadcast/multicast traffic")

        nlri = exa.EVPNMulticast(
            self.instance_rd,
            exa.EthernetTag(),
            exa.IP.create(self.bgp_manager.get_local_address()),
            None,
            exa.IP.create(self.bgp_manager.get_local_address()))

        attributes = exa.Attributes()

        attributes.add(self._gen_encap_extended_communities())

        # add PMSI Tunnel Attribute route
        attributes.add(
            exa.PMSIIngressReplication(self.dp_driver.get_local_address(),
                                       raw_label=self.instance_label))

        self.multicast_route_entry = engine.RouteEntry(nlri, self.export_rts,
                                                       attributes)

        self._advertise_route(self.multicast_route_entry)

    def _vxlan_dp_driver(self):
        return (exa.Encapsulation(exa.Encapsulation.Type.VXLAN) in
                self.dp_driver.supported_encaps())

    def generate_vif_bgp_route(self, mac_address, ip_prefix, plen, label, rd):
        # Generate BGP route and advertise it...

        if ip_prefix:
            assert(plen == 32)

        if self._vxlan_dp_driver():
            mpls_label_field = exa.Labels([], raw_labels=[self.instance_label])
        else:
            mpls_label_field = exa.Labels([self.instance_label])

        # label parameter ignored, we need to use instance label
        nlri = exa.EVPNMAC(
            rd, exa.ESI(), exa.EthernetTag(), exa.MAC(mac_address), 6*8,
            mpls_label_field,
            exa.IP.create(ip_prefix) if ip_prefix else None, None,
            exa.IP.create(self.dp_driver.get_local_address()))

        return engine.RouteEntry(nlri)

    @log_decorator.log
    def set_gateway_port(self, linuxif, ipvpn):
        self.dataplane.set_gateway_port(linuxif, ipvpn.gateway_ip)
        self.gw_port = (linuxif, ipvpn)

    @log_decorator.log
    def gateway_port_down(self, linuxif):
        self.dataplane.gateway_port_down(linuxif)
        self.gw_port = None

    def has_gateway_port(self):
        return (self.gw_port is not None)

    def _interpret_nlri_mpls_field(self, label_field):
        # interpret the MPLS field of an EVPN MAroute, based on
        # whether we assume this is a VXLAN VNI or not
        if self._vxlan_dp_driver():
            return label_field.raw_labels[0]
        else:
            return label_field.labels[0]

    def _interpret_pta_label_field(self, pmsi_tunnel):
        # interpret the MPLS field of a PMSI tunnel attribute, based on
        # whether we assume this is a VXLAN VNI or not
        if self._vxlan_dp_driver():
            return pmsi_tunnel.raw_label
        else:
            return pmsi_tunnel.label

    # TrackerWorker callbacks for BGP route updates ##########################

    def route_to_tracked_entry(self, route):
        if isinstance(route.nlri, exa.EVPNMAC):
            return (exa.EVPNMAC, route.nlri.mac)
        elif isinstance(route.nlri, exa.EVPNMulticast):
            return (exa.EVPNMulticast, (route.nlri.ip, route.nlri.rd))
        elif isinstance(route.nlri, exa.EVPN):
            self.log.warning("Received EVPN route of unsupported subtype: %s",
                             route.nlri.CODE)
            return None
        else:
            raise Exception("EVI %d should not receive routes of type %s" %
                            (self.instance_id, type(route.nlri)))

    @utils.synchronized
    @log_decorator.log
    def new_best_route(self, entry, new_route):
        (entry_class, info) = entry

        encaps = self._check_encaps(new_route)
        if not encaps:
            return

        if entry_class == exa.EVPNMAC:
            prefix = info

            remote_pe = new_route.nexthop

            dataplane_id = self._interpret_nlri_mpls_field(
                new_route.nlri.label)

            self.dataplane.setup_dataplane_for_remote_endpoint(
                prefix, remote_pe, dataplane_id, new_route.nlri, encaps)

        elif entry_class == exa.EVPNMulticast:
            remote_endpoint = info

            # check that the route is actually carrying an PMSITunnel of type
            # ingress replication
            pmsi_tunnel = new_route.attributes.get(exa.PMSI.ID)
            if not isinstance(pmsi_tunnel, exa.PMSIIngressReplication):
                self.log.warning("Received PMSITunnel of unsupported type: %s",
                                 type(pmsi_tunnel))
            else:
                remote_endpoint = pmsi_tunnel.ip
                dataplane_id = self._interpret_pta_label_field(pmsi_tunnel)

                self.log.info("Setting up dataplane for new ingress "
                              "replication destination %s", remote_endpoint)
                self.dataplane.add_dataplane_for_bum_endpoint(
                    remote_endpoint, dataplane_id, new_route.nlri, encaps)
        else:
            self.log.warning("unsupported entry_class: %s",
                             entry_class.__name__)

    @utils.synchronized
    @log_decorator.log
    def best_route_removed(self, entry, old_route, last):
        (entry_class, info) = entry

        if entry_class == exa.EVPNMAC:

            if self._skip_route_removal(last):
                self.log.debug("Skipping removal of non-last route because "
                               "dataplane does not want it")
                return

            def ip_dpid_from_route(route):
                return (route.nexthop,
                        self._interpret_nlri_mpls_field(route.nlri.label))

            if self.equivalent_route_in_best_routes(old_route,
                                                    ip_dpid_from_route):
                self.log.debug("Route for same dataplane is still in best "
                               "routes, skipping removal")
                return

            prefix = info

            remote_pe, dataplane_id = ip_dpid_from_route(old_route)

            self.dataplane.remove_dataplane_for_remote_endpoint(
                prefix, remote_pe, dataplane_id, old_route.nlri)

        elif entry_class == exa.EVPNMulticast:
            remote_endpoint = info

            def ip_dpid_from_route(route):
                pmsi_tunnel = route.attributes.get(exa.PMSI.ID)
                remote_endpoint = pmsi_tunnel.ip
                dataplane_id = self._interpret_pta_label_field(pmsi_tunnel)
                return (remote_endpoint, dataplane_id)

            # check that the route is actually carrying an PMSITunnel of type
            # ingress replication
            pmsi_tunnel = old_route.attributes.get(exa.PMSI.ID)
            if not isinstance(pmsi_tunnel, exa.PMSIIngressReplication):
                self.log.warning("PMSITunnel of suppressed route is of"
                                 " unsupported type")
                return

            if self.equivalent_route_in_best_routes(old_route,
                                                    ip_dpid_from_route):
                self.log.debug("Route for same dataplane is still in best "
                               "routes, skipping removal")
                return

            remote_endpoint, dataplane_id = ip_dpid_from_route(old_route)
            self.log.info("Cleaning up dataplane for ingress replication "
                          "destination %s", remote_endpoint)

            self.dataplane.remove_dataplane_for_bum_endpoint(
                remote_endpoint, dataplane_id, old_route.nlri)
        else:
            self.log.warning("unsupported entry_class: %s",
                             entry_class.__name__)

    # Looking Glass ####

    def get_lg_local_info(self, path_prefix):
        if not self.gw_port:
            return {"gateway_port": None}
        else:
            (linuxif, ipvpn) = self.gw_port
            return {"gateway_port": {
                    "interface": repr(linuxif),
                    "ipvpn": {"href":
                              lg.get_absolute_path(
                                  "VPN_INSTANCES", path_prefix,
                                  [ipvpn.external_instance_id]),
                              "id": ipvpn.name,
                              "external_instance_id":
                                  ipvpn.external_instance_id
                              },
                    }}
