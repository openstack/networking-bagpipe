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

import threading

from oslo_log import log as logging
import six

from networking_bagpipe.bagpipe_bgp.common import exceptions as exc
from networking_bagpipe.bagpipe_bgp.common import log_decorator
from networking_bagpipe.bagpipe_bgp.common import looking_glass as lg
from networking_bagpipe.bagpipe_bgp.common import run_command
from networking_bagpipe.bagpipe_bgp.common import utils
from networking_bagpipe.bagpipe_bgp import constants
from networking_bagpipe.bagpipe_bgp.engine import bgp_manager
from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers as dp_drivers
from networking_bagpipe.bagpipe_bgp.vpn import evpn
from networking_bagpipe.bagpipe_bgp.vpn import identifier_allocators
from networking_bagpipe.bagpipe_bgp.vpn import ipvpn

from neutron_lib import exceptions


LOG = logging.getLogger(__name__)

INSTANCE_ID_MAX = 2**32-1


def redirect_instance_extid(instance_type, rt):
    '''generate the ext intance id of a redirection VPN instance'''
    return "redirect-to-%s-%s" % (instance_type, rt.replace(":", "_"))


class MaxInstanceIDReached(exceptions.NeutronException):
    _message = "Could not create VPN instance: max instance id was reached"


class VPNManager(lg.LookingGlassMixin, utils.ClassReprMixin):
    """VPN Manager

    Creates, and keeps track of, VPN instances (VRFs and EVIs) and passes
    plug/unplug calls to the right VPN instance.
    """

    _instance = None

    type2class = {constants.IPVPN: ipvpn.VRF,
                  constants.EVPN: evpn.EVI
                  }

    @log_decorator.log
    def __init__(self):
        LOG.debug("Instantiating VPN Manager...")

        self.bgp_manager = bgp_manager.Manager()

        self.dataplane_drivers = dp_drivers.instantiate_dataplane_drivers()

        # VPN instance dict
        self.vpn_instances = {}
        self.next_vpn_instance_id = 1

        LOG.debug("Creating label allocator")
        self.label_allocator = identifier_allocators.LabelAllocator()

        LOG.debug("Creating route distinguisher allocator")
        self.rd_allocator = identifier_allocators.RDAllocator(
            self.bgp_manager.get_local_address())

        # dict containing info how an ipvpn is plugged
        # from an evpn  (keys: ipvpn instances)
        self._evpn_ipvpn_ifs = {}

        # keys: vni
        # value: VPNInstance
        self.vpn_instance_by_vni = {}

        self.lock = threading.RLock()

    def _run_command(self, *args, **kwargs):
        run_command.run_command(LOG, *args, run_as_root=True, **kwargs)

    @log_decorator.log_info
    def _attach_evpn_2_ipvpn(self, localport, ipvpn_instance):
        # Assuming localport indicates no real interface but only
        # an EVPN, this method will create a pair of twin interfaces, one
        # to plug in the EVPN, the other to plug in the IPVPN.
        #
        # The localport dict will be modified so that the 'linuxif' indicates
        # the name of the interface to plug in the IPVPN.
        #
        # The EVPN instance will be notified so that it forwards traffic
        # destinated to the gateway on the interface toward the IPVPN.

        assert 'evpn' in localport

        if 'id' not in localport['evpn']:
            raise Exception("Missing parameter 'id' :an external EVPN "
                            "instance id must be specified for an EVPN "
                            "attachment")

        try:
            evpn = self.vpn_instances[localport['evpn']['id']]
        except Exception:
            raise Exception("The specified evpn instance does not exist (%s)"
                            % localport['evpn'])

        if evpn.type != constants.EVPN:
            raise Exception("The specified instance to plug is not an evpn"
                            "instance (is %s instead)" % evpn.type)

        if ipvpn_instance in self._evpn_ipvpn_ifs:
            (evpn_if, ipvpn_if, evpn, managed) = \
                self._evpn_ipvpn_ifs[ipvpn_instance]

            if localport['evpn']['id'] != evpn.external_instance_id:
                raise Exception('Trying to plug into an IPVPN a new E-VPN '
                                'while one is already plugged in')
            else:
                # do nothing
                LOG.warning('Trying to plug an E-VPN into an IPVPN, but it was'
                            ' already done')
                localport['linuxif'] = ipvpn_if
                return

        #  detect if this evpn is already plugged into an IPVPN
        if evpn.has_gateway_port():
            raise Exception("Trying to plug E-VPN into an IPVPN, but this EVPN"
                            " is already plugged into an IPVPN")

        if 'linuxif' in localport and localport['linuxif']:
            raise Exception("Cannot specify an attachment with both a linuxif "
                            "and an evpn")

        if 'ovs_port_name' in localport['evpn']:
            try:
                assert localport['ovs']['plugged']
                assert(localport['ovs']['port_name'] or
                       localport['ovs']['port_number'])
            except Exception:
                raise Exception("Using ovs_port_name in EVPN/IPVPN attachment"
                                " requires specifying the corresponding OVS"
                                " port, which must also be pre-plugged")

            evpn_if = localport['evpn']['ovs_port_name']

            # we assume in this case that the E-VPN interface is already
            # plugged into the E-VPN bridge
            managed = False
        else:
            evpn_if = "evpn%d-ipvpn%d" % (
                evpn.instance_id, ipvpn_instance.instance_id)
            ipvpn_if = "ipvpn%d-evpn%d" % (
                ipvpn_instance.instance_id, evpn.instance_id)

            # FIXME: do it only if not existing already...
            LOG.info("Creating veth pair %s %s ", evpn_if, ipvpn_if)

            # delete the interfaces if they exist already
            self._run_command("ip link delete %s" % evpn_if,
                              acceptable_return_codes=[0, 1])
            self._run_command("ip link delete %s" % ipvpn_if,
                              acceptable_return_codes=[0, 1])

            self._run_command("ip link add %s type veth peer name %s"
                              " mtu 65535" % (evpn_if, ipvpn_if))

            self._run_command("ip link set %s up" % evpn_if)
            self._run_command("ip link set %s up" % ipvpn_if)
            managed = True

        localport['linuxif'] = ipvpn_if

        evpn.set_gateway_port(evpn_if, ipvpn_instance)

        self._evpn_ipvpn_ifs[ipvpn_instance] = (
            evpn_if, ipvpn_if, evpn, managed)

    @log_decorator.log_info
    def _detach_evpn_2_ipvpn(self, ipvpn):
        # Symmetric to _attach_evpn_2_ipvpn

        (evpn_if, ipvpn_if, evpn_instance,
         managed) = self._evpn_ipvpn_ifs[ipvpn]

        if not ipvpn.has_enpoint(ipvpn_if):
            # TODO(tmorin): check that this evpn instance is still up and
            # running ?
            evpn_instance.gateway_port_down(evpn_if)

            # cleanup veth pair
            if managed:
                self._run_command("ip link delete %s" % evpn_if)

            del self._evpn_ipvpn_ifs[ipvpn]

    def _cleanup_evpn2ipvpn(self, ipvpn):
        (_, ipvpn_if, _, managed) = self._evpn_ipvpn_ifs[ipvpn]

        # cleanup veth pair
        if managed:
            self._run_command("ovs-vsctl del-port %s" % ipvpn_if)
            self._run_command("ip link delete %s" % ipvpn_if)

    @utils.synchronized
    @log_decorator.log_info
    def _get_vpn_instance(self, external_instance_id, instance_type,
                          import_rts, export_rts, gateway_ip, mask,
                          readvertise, attract_traffic, fallback=None,
                          **kwargs):
        # Get an vpn_instance with this external_instance_id,
        # if one already exists, check matching instance_type
        # else create one with provided parameters and start it
        #   (unless create_if_none is False --> raise exc.VPNNotFound)
        # returns True if an already started instance was found
        # False if a new instance was created without starting it

        LOG.info("Finding %s for external vpn_instance identifier %s",
                 instance_type, external_instance_id)

        vpn_instance = self.vpn_instances.get(external_instance_id)

        if vpn_instance:
            if vpn_instance.type != instance_type:
                raise Exception("Found an existing vpn_instance with "
                                "external id %s but a different type "
                                "(asked %s vs. already having %s)"
                                % (external_instance_id,
                                   instance_type, vpn_instance.type))
            return vpn_instance, True

        if not kwargs.pop('create_if_none', True):
            raise exc.VPNNotFound(external_instance_id)

        # if a vni is specified, check that no VPN instance with same VNI
        # already exists...
        if 'vni' in kwargs and kwargs['vni'] in self.vpn_instance_by_vni:
            raise exc.APIAlreadyUsedVNI(kwargs['vni'])

        vpn_instance_class = VPNManager.type2class[instance_type]
        dataplane_driver = self.dataplane_drivers[instance_type]

        # unique internal vpn instance id
        instance_id = self.next_vpn_instance_id
        if instance_id > INSTANCE_ID_MAX:
            raise MaxInstanceIDReached()

        self.next_vpn_instance_id += 1

        vpn_instance = vpn_instance_class(self, dataplane_driver,
                                          external_instance_id, instance_id,
                                          import_rts, export_rts,
                                          gateway_ip, mask,
                                          readvertise, attract_traffic,
                                          fallback, **kwargs)

        self.register_vpn_instance(vpn_instance)

        return vpn_instance, False

    @utils.synchronized
    @log_decorator.log_info
    def register_vpn_instance(self, vpn_instance):
        self.vpn_instances[vpn_instance.external_instance_id] = vpn_instance
        if vpn_instance.forced_vni:
            self.vpn_instance_by_vni[
                vpn_instance.instance_label] = vpn_instance

    @utils.synchronized
    @log_decorator.log_info
    def unregister_vpn_instance(self, vpn_instance):
        del self.vpn_instances[vpn_instance.external_instance_id]
        if vpn_instance.forced_vni:
            del self.vpn_instance_by_vni[vpn_instance.instance_label]

    def _check_instance_type(self, params):
        if 'vpn_type' not in params:
            raise exc.APIException("missing instance_type")

        instance_type = params['vpn_type']
        if instance_type not in self.type2class:
            raise exc.APIException("unknown vpn_type: %s" % instance_type)

        if instance_type not in self.dataplane_drivers:
            LOG.error("No dataplane driver for VPN type %s", instance_type)
            raise exc.APIException("No dataplane driver for VPN type %s" %
                                   instance_type)

        return instance_type

    @log_decorator.log_info
    def plug_vif_to_vpn(self, **params):

        instance_type = self._check_instance_type(params)

        vpn_instance_class = VPNManager.type2class[instance_type]
        vpn_instance_class.validate_convert_attach_params(params)

        external_instance_id = params.get('external_instance_id')
        import_rts = params.get('import_rts')
        export_rts = params.get('export_rts')
        mac_address = params.get('mac_address')
        gateway_ip = params.get('gateway_ip')
        localport = params.get('localport')
        linuxbr = params.get('linuxbr')
        advertise_subnet = params.get('advertise_subnet')
        readvertise = params.get('readvertise')
        attract_traffic = params.get('attract_traffic')
        lb_consistent_hash_order = params.get('lb_consistent_hash_order')
        local_pref = params.get('local_pref')
        fallback = params.get('fallback')
        vni = params.get('vni')

        ip_address_prefix = params.get('ip_address_prefix')
        ip_address_plen = params.get('ip_address_plen')

        # Convert route target string to RouteTarget dictionary
        import_rts = utils.convert_route_targets(import_rts)
        export_rts = utils.convert_route_targets(export_rts)

        if readvertise:
            try:
                readvertise = {k: utils.convert_route_targets(readvertise[k])
                               for k in ['from_rt', 'to_rt']}
            except KeyError as e:
                raise Exception("Wrong 'readvertise' parameters: %s" % e)

        if attract_traffic:
            try:
                attract_traffic['redirect_rts'] = (
                    utils.convert_route_targets(
                        attract_traffic['redirect_rts'])
                )
            except KeyError as e:
                raise Exception("Wrong 'attract_traffic' parameters: %s" % e)

        kwargs = {}
        if vni:
            kwargs['vni'] = vni
        if instance_type == constants.EVPN and linuxbr:
            kwargs['linuxbr'] = linuxbr

        vpn_instance, started = self._get_vpn_instance(
            external_instance_id, instance_type, import_rts, export_rts,
            gateway_ip, ip_address_plen, readvertise, attract_traffic,
            fallback, **kwargs)

        vpn_instance.description = params.get('instance_description')

        vpn_instance.update_route_targets(import_rts, export_rts)
        vpn_instance.update_fallback(fallback)

        if instance_type == constants.IPVPN and 'evpn' in localport:
            # special processing for the case where what we plug into
            # the ipvpn is not an existing interface but an interface
            # to create, connected to an existing evpn instance
            self._attach_evpn_2_ipvpn(localport, vpn_instance)

        plug_kwargs = {}
        plug_kwargs['description'] = params.get('description')
        plug_kwargs['direction'] = params.get('direction')

        # Plug VIF to VPN instance
        vpn_instance.vif_plugged(mac_address, ip_address_prefix, localport,
                                 advertise_subnet, lb_consistent_hash_order,
                                 local_pref, **plug_kwargs)

        # delaying the start after the first vif_plugged allows to handle
        # dataplane driver for which the first vif_plugged needs to happen
        # before route advertisements can be processed
        if not started:
            vpn_instance.start()

    @log_decorator.log_info
    def unplug_vif_from_vpn(self, **params):

        instance_type = self._check_instance_type(params)

        vpn_instance_class = VPNManager.type2class[instance_type]
        vpn_instance_class.validate_convert_detach_params(params)

        external_instance_id = params.get('external_instance_id')
        mac_address = params.get('mac_address')
        localport = params.get('localport')
        ip_address_prefix = params.get('ip_address_prefix')

        # Retrieve VPN instance or raise exception if does not exist
        try:
            vpn_instance = self.vpn_instances[external_instance_id]
        except KeyError:
            LOG.error("Try to unplug VIF from non existing VPN instance %s",
                      external_instance_id)
            raise exc.VPNNotFound(external_instance_id)

        # Unplug VIF from VPN instance
        vpn_instance.vif_unplugged(mac_address, ip_address_prefix)

        if vpn_instance.type == constants.IPVPN and 'evpn' in localport:
            self._detach_evpn_2_ipvpn(vpn_instance)

        if vpn_instance.stop_if_empty():
            self.unregister_vpn_instance(vpn_instance)

    def redirect_instance_for_rt(self, redirected_type, redirect_rt,
                                 stop=False):
        external_instance_id = redirect_instance_extid(redirected_type,
                                                       redirect_rt)
        LOG.info("Need VPN instance %s for traffic redirection to RT %s",
                 external_instance_id, redirect_rt)

        # Convert route target string to RouteTarget dictionary
        import_rts = utils.convert_route_targets([redirect_rt])

        # Retrieve a redirect VPN instance or create a new one if none exists
        # yet
        try:
            i, s = self._get_vpn_instance(external_instance_id,
                                          redirected_type,
                                          import_rts, [],
                                          "127.0.0.1",
                                          "24", None, None,
                                          create_if_none=(not stop))
            if not s:
                i.start()
            return i
        except exc.VPNNotFound:
            # (reached only in the 'stop' case)
            LOG.error("Try to stop traffic redirection for an RT for which"
                      " no VPN instance exists (%s)", external_instance_id)
            raise

    @log_decorator.log_info
    def redirect_traffic_to_vpn(self, redirected_id,
                                redirected_type, redirect_rt):
        redirect_instance = self.redirect_instance_for_rt(redirected_type,
                                                          redirect_rt)
        redirect_instance.register_redirected_instance(redirected_id)
        return redirect_instance

    @log_decorator.log_info
    def stop_redirect_to_vpn(self, redirected_id,
                             redirected_type, redirect_rt):
        redirect_instance = self.redirect_instance_for_rt(redirected_type,
                                                          redirect_rt,
                                                          stop=True)
        redirect_instance.unregister_redirected_instance(redirected_id)
        if redirect_instance.stop_if_no_redirected_instance():
            self.unregister_vpn_instance(redirect_instance)

    @log_decorator.log_info
    def stop(self):
        self.bgp_manager.stop()
        for vpn_instance in six.itervalues(self.vpn_instances):
            vpn_instance.stop()
            # Cleanup veth pair
            if (vpn_instance.type == constants.IPVPN and
                    self._evpn_ipvpn_ifs.get(vpn_instance)):
                self._cleanup_evpn2ipvpn(vpn_instance)
        for vpn_instance in six.itervalues(self.vpn_instances):
            vpn_instance.join()
        self.vpn_instances.clear()

    @classmethod
    @utils.oslo_synchronized('VPNManager')
    def _create_instance(cls):
        if not cls.has_instance():
            cls._instance = cls()

    @classmethod
    def has_instance(cls):
        return cls._instance is not None

    @classmethod
    def clear_instance(cls):
        cls._instance = None

    @classmethod
    def get_instance(cls):
        # double checked locking
        if not cls.has_instance():
            cls._create_instance()
        return cls._instance

    # Looking Glass hooks ####

    def get_lg_map(self):
        class DataplaneLGHook(lg.LookingGlassMixin):

            def __init__(self, vpn_manager):
                self.manager = vpn_manager

            def get_lg_map(self):
                return {
                    "drivers": (lg.COLLECTION, (
                        self.manager.get_lg_dataplanes_list,
                        self.manager.get_lg_dataplane_from_path_item)),
                    "ids": (lg.DELEGATE, self.manager.label_allocator)
                }
        dataplane_hook = DataplaneLGHook(self)
        return {
            "instances": (lg.COLLECTION, (self.get_lg_vpn_list,
                                          self.get_lg_vpn_from_path_item)),
            "dataplane": (lg.DELEGATE, dataplane_hook),
            "instances_per_vni": (lg.SUBITEM, self.get_lg_instances_per_vni)
        }

    def get_lg_vpn_list(self):
        return [instance.get_lg_summary()
                for instance in list(self.vpn_instances.values())]

    def get_lg_vpn_from_path_item(self, path_item):
        return self.vpn_instances[path_item]

    def get_vpn_instances_count(self):
        return len(self.vpn_instances)

    def get_lg_instances_per_vni(self):
        return {vni: {'name': str(instance),
                      'external_instance_id': instance.external_instance_id
                      }
                for vni, instance in self.vpn_instance_by_vni.items()}

    def get_lg_dataplanes_list(self):
        return [{"id": i} for i in self.dataplane_drivers.keys()]

    def get_lg_dataplane_from_path_item(self, path_item):
        return self.dataplane_drivers[path_item]
