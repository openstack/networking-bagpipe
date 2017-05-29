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
import traceback
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
            LOG.debug('Local port attach received: %s', attach_params)

            self.manager.plug_vif_to_vpn(**attach_params)
        except exc.APIException as e:
            LOG.warning('attach_localport: API error: %s', e)
            pecan.abort(400, "API error: %s" % e)
        except Exception as e:
            LOG.error('attach_localport: An error occurred during local port'
                      ' plug to VPN: %s', e)
            LOG.info(traceback.format_exc())
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
            LOG.debug('Local port detach received: %s', detach_params)
            self.manager.unplug_vif_from_vpn(**detach_params)
        except exc.APIException as e:
            LOG.warning('detach_localport: API error: %s', e)
            pecan.abort(400, "API error: %s" % e)
        except Exception as e:
            LOG.error('detach_localport: An error occurred during local port'
                      ' unplug from VPN: %s', e)
            LOG.info(traceback.format_exc())
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
        except Exception as e:
            LOG.error('looking_glass: An error occurred: %s', e)
            LOG.error(traceback.format_exc())
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
            "local_routes_count":
                self.manager.bgp_manager.rtm.
                get_local_routes_count(),
            "received_routes_count":
                self.manager.bgp_manager.rtm.
                get_received_routes_count(),
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
