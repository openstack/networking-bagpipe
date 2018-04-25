# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

# Copyright 2017 Orange
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

import logging as python_logging
import time
import uuid

from oslo_config import cfg
from oslo_log import log as logging
import pbr.version
import pecan
from pecan import request

from networking_bagpipe.bagpipe_bgp.common import exceptions as exc
from networking_bagpipe.bagpipe_bgp.common import looking_glass as lg
from networking_bagpipe.bagpipe_bgp.common import utils
from networking_bagpipe.bagpipe_bgp.vpn import manager as vpn_manager


LOG = logging.getLogger(__name__)

LOOKING_GLASS_BASE = "looking-glass"


def expose(*args, **kwargs):
    """Helper function so we don't have to specify json for everything."""
    kwargs.setdefault('content_type', 'application/json')
    kwargs.setdefault('template', 'json')
    return pecan.expose(*args, **kwargs)


def when(index, *args, **kwargs):
    """Helper function so we don't have to specify json for everything."""
    kwargs.setdefault('content_type', 'application/json')
    kwargs.setdefault('template', 'json')
    return index.when(*args, **kwargs)


class PingController(object):

    def __init__(self):
        # Random generated sequence number
        self.sequence = int(uuid.uuid4())

    @expose(generic=True)
    def index(self):
        return self.sequence


class VPNManagerController(object):

    def __init__(self):
        self.manager = vpn_manager.VPNManager.get_instance()

    @staticmethod
    def stop():
        vpn_manager.VPNManager.get_instance().stop()


class AttachController(VPNManagerController):
    """attach_localport parameters:

    'vpn_instance_id': external VPN instance identifier (all ports with same
                     vpn_instance_id will be plugged in the same VPN
                     instance
    'instance_description': free form description of VPN instance
    'description': free form description of attachment
    'vpn_type': type of the VPN instance ('ipvpn' or 'evpn')
    'import_rt': list of import Route Targets (or comma-separated string)
    'export_rt': list of export Route Targets (or comma-separated string)
    'gateway_ip': IP address of gateway for this VPN instance
    'mac_address': MAC address of endpoint to connect to the VPN instance
    'ip_address': IP/mask of endpoint to connect to the VPN instance
    'advertise_subnet': optional, if set to True then VRF will advertise
                        the whole subnet (defaults to False, readvertise
                        ip_address as a singleton (/32)
    'linuxbr': Name of a linux bridge to which the linuxif is already
             plugged-in (optional)
    'vni': VXLAN VNI to use (optional)
    'local_pref': BGP LOCAL_PREF for the route to this vif (optional)
    'direction': 'to-port' | 'from-port' | 'both'
        # specify local port traffic direction in VPN instance
        # (route advertisements are not done with from-port only)
        # to-port: only forward traffic to the VIF
        # from-port: only forward traffic to the VIF
    'local_port': local port to plug to the VPN instance
        should be a dict containing any of the following key,value pairs
        {
            'linuxif': 'tap456abc', # name of a linux interface
                                    # - if OVS information is provided it
                                    #   does not have to be an existing
                                    #   interface
                                    # - not needed/not used if 'evpn' plug
                                    #   is used
            'ovs': {  # optional
                # whether or not interface is already plugged into the
                # OVS bridge:
                'plugged': True,
                # name of a linux interface to be plugged into the OVS
                # bridge (optional and ignored if port_number is
                # provided):
                'port_name': 'qvo456abc',
                # OVS port number (optional if 'port_name' provided):
                'port_number': '7',
                # the VLAN id for VM traffic (optional)
                'vlan': '42',
                # optional specification of a distinct port to send
                # traffic to the VM(only applies if a vlan is
                # specified) :
                'to_vm_port_number'
                'to_vm_port_name'
               },
            'evpn': {  # for an ipvpn attachment...
                 'id': 'xyz'  # specifies the vpn_instance_id of an evpn
                              # that will be attached to the ipvpn
                 'ovs_port_name': 'qvb456abc' # optional, if provided,
                                              # and if ovs/port_name is
                                              # also provided, then the
                                              # interface name will be
                                              # assumed as already plugged
                                              # into the evpn
                }
        }
        if local_port is not a list, it is assumed to be a name of a linux
        interface (string)
    'readvertise': {  # optional, used to re-advertise addresses...
        'from_rt': [list of RTs]  # ...received on these RTs
        'to_rt': [list of RTs] # ...toward these RTs
    }
    'attract_traffic': { # optional, will result in the generation of FlowSpec
                         # routes, based on the specified classifier,
                         # advertised to the readvertise:to_rt RTs, redirecting
                         # traffic toward the "attract_to_rts" RT using a
                         # redirect-to-VRF action action.
                         # The prefixes for which FlowSpec routes are
                         # advertised are:
                         # - prefixes carrying one of the readvertise:from_rt
                         #   RTs,
                         # - prefixes in static_destination_prefixes.
                         #
                         # When this is used, the routes that are advertised to
                         # the readvertise:to_rt route targets are, instead of
                         # the prefixes of the routes carrying an RT in
                         # readvertise:from_rt, the prefix in
                         # static_destination_prefixes if any, or else a
                         # default0.0.0.0 route. These routes are advertised
                         # for each locally attached interface, each time with
                         # a distinct RD
        'classifier': {
            'sourcePrefix': IP/mask,
            'sourcePort': Port number or port range,
            'destinationPort': Port number or port range,
            'protocol': IP protocol
        },
        'redirect_rts': [list of RTs] # RTs of generated FlowSpec routes
        'attract_to_rts': [list of RTs] # RTs of the redirect-to-VRF action of
                                        # the generated FlowSpec routes
        'static_destination_prefixes': [list of IP/mask] # When present,
                                                         # FlowSpec routes will
                                                         # be generated from
                                                         # these prefixes (as
                                                         # destination prefix);
                                                         # this is done
                                                         # additionally to
                                                         # FlowSpec routes
                                                         # generated from
                                                         # routes carrying
                                                         # readvertise:from_rt
    }
    'fallback': # (optional) if provided, on a VRF lookup miss,
                # the MAC destination address will be
                # rewritten to this MAC before being
                # sent back where it came from
                {
                'src_mac': 'aa:bb:cc:dd:ee:ff'  # new source MAC
                'dst_mac': 'aa:bb:cc:dd:ee:00'  # new destination MAC
                'ovs_port_name': 'patch_foo'
                'ovs_port_number': 4               # (unsupported yet)
                'ovs_resubmit': '(<port>,<table>)' # (unsupported yet)
    }
    """

    @expose(generic=True)
    def index(self):
        return {}

    @when(index, method='PUT')
    @when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)

    @when(index, method='POST')
    def process(self):
        try:
            attach_params = request.json
        except Exception:
            LOG.error('attach_localport: No local port details received')
            pecan.abort(400, 'No local port details received')

        try:
            LOG.info('Local port attach received: %s', attach_params)

            self.manager.plug_vif_to_vpn(**attach_params)
        except exc.APIException as e:
            LOG.warning('attach_localport: API error: %s', e)
            pecan.abort(400, "API error: %s" % e)
        except Exception:
            LOG.exception('attach_localport: An error occurred during local '
                          'port plug to VPN')
            pecan.abort(500, 'An error occurred during local port plug to VPN')


class DetachController(VPNManagerController):

    @expose(generic=True)
    def index(self):
        return {}

    @when(index, method='PUT')
    @when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)

    @when(index, method='POST')
    def process(self):
        try:
            detach_params = request.json
        except Exception:
            LOG.error('detach_localport: No local port details received')
            pecan.abort(400, 'No local port details received')

        try:
            LOG.info('Local port detach received: %s', detach_params)
            self.manager.unplug_vif_from_vpn(**detach_params)
        except exc.APIException as e:
            LOG.warning('detach_localport: API error: %s', e)
            pecan.abort(400, "API error: %s" % e)
        except Exception:
            LOG.exception('detach_localport: An error occurred during local '
                          'port unplug from VPN')
            pecan.abort(500, 'An error occurred during local port unplug from '
                        'VPN')


class LookingGlassController(VPNManagerController,
                             lg.LookingGlassMixin):

    def __init__(self):
        super(LookingGlassController, self).__init__()

        self.start_time = time.time()

        lg.set_references_root(LOOKING_GLASS_BASE)
        lg.set_reference_path("BGP_WORKERS", ["bgp", "workers"])
        lg.set_reference_path("VPN_INSTANCES", ["vpns", "instances"])
        lg.set_reference_path("DATAPLANE_DRIVERS",
                              ["vpns", "dataplane", "drivers"])

        self.catchall_lg_log_handler = lg.LookingGlassLogHandler()
        python_logging.getLogger().addHandler(self.catchall_lg_log_handler)

    @expose(generic=True)
    def index(self):
        return {}

    @when(index, method='GET')
    def process(self, *url_path_elements):

        path_prefix = "%s://%s/%s" % (
            request.scheme,  # http
            request.host,
            LOOKING_GLASS_BASE,
        )

        try:
            lg_info = self.get_looking_glass_info(path_prefix,
                                                  url_path_elements)
            if lg_info is None:
                raise lg.NoSuchLookingGlassObject(path_prefix,
                                                  url_path_elements[0])
            return lg_info
        except lg.NoSuchLookingGlassObject as e:
            LOG.info('looking_glass: %s', repr(e))
            pecan.abort(404, repr(e))
        except Exception:
            LOG.exception('looking_glass: an error occurred')
            pecan.abort(500, 'Server error')

    @when(index, method='DELETE')
    @when(index, method='POST')
    @when(index, method='PUT')
    def not_supported(self):
        pecan.abort(405)

    # Looking glass hooks #################

    def get_lg_map(self):
        return {
            "summary":  (lg.SUBITEM, self.get_lg_summary),
            "config":   (lg.SUBTREE, self.get_lg_config),
            "bgp":      (lg.DELEGATE, self.manager.bgp_manager),
            "vpns":     (lg.DELEGATE, self.manager),
            "logs":     (lg.SUBTREE, self.get_logs)
        }

    def get_lg_config(self, path_prefix):
        return {section: utils.osloconfig_json_serialize(cfg.CONF[section])
                for section in ('COMMON', 'API', 'BGP',
                                'DATAPLANE_DRIVER_IPVPN',
                                'DATAPLANE_DRIVER_EVPN')
                }

    def get_lg_summary(self):
        return {
            "BGP_established_peers":
                self.manager.bgp_manager.get_established_peers_count(),
            "route_counts": self.manager.bgp_manager.get_lg_route_counts(),
            "vpn_instances_count": self.manager.get_vpn_instances_count(),
            "warnings_and_errors": len(self.catchall_lg_log_handler),
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(self.start_time)),
            "version":  (pbr.version.VersionInfo('networking-bagpipe')
                         .release_string())
        }

    def get_logs(self, path_prefix):
        return [{'level': record.levelname,
                 'time':
                 self.catchall_lg_log_handler.formatter.formatTime(record),
                 'name': record.name,
                 'message': record.msg}
                for record in self.catchall_lg_log_handler.get_records()]


class RootController(object):

    @expose(generic=True)
    def index(self):
        return {}

    @when(index, method='POST')
    @when(index, method='PUT')
    @when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)

    ping = PingController()
    attach_localport = AttachController()
    detach_localport = DetachController()

    def stop(self):
        VPNManagerController.stop()


# there is a '-' in the LOOKING_GLASS_BASE name, so we have to use pecan.route
pecan.route(RootController, LOOKING_GLASS_BASE, LookingGlassController())
