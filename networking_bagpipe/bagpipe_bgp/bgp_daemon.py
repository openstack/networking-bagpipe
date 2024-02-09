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

import logging as python_logging
import signal
import sys

from oslo_config import cfg
from oslo_log import log as logging
import pbr.version

from neutron.common import config as n_config  # noqa

from networking_bagpipe.bagpipe_bgp.api import api
from networking_bagpipe.bagpipe_bgp.api import config as api_config
from networking_bagpipe.bagpipe_bgp.common import config
from networking_bagpipe.bagpipe_bgp.engine import exabgp_peer_worker
from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers as drivers


LOG = logging.getLogger(__name__)


def setup_config():
    api_config.register_config()
    config.register()
    cfg.CONF(args=sys.argv[1:],
             project='bagpipe-bgp',
             default_config_files=['/etc/bagpipe-bgp/bgp.conf'],
             version=('%%(prog)s %s' %
                      pbr.version.VersionInfo('networking-bagpipe')
                      .release_string()))


BAGPIPE_BGP_MODULE = "networking_bagpipe.bagpipe_bgp"


def setup_logging():
    # even in debug mode we don't want to much talk from these
    extra_log_level_defaults = [
        '%s.engine.exabgp_peer_worker.exabgp=INFO' % BAGPIPE_BGP_MODULE,
        '%s.common.looking_glass=WARNING' % BAGPIPE_BGP_MODULE,
        '%s.engine.route_table_manager=INFO' % BAGPIPE_BGP_MODULE,
        'ovsdbapp.backend.ovs_idl.vlog=INFO',
    ]

    logging.set_defaults(default_log_levels=(logging.get_default_log_levels() +
                                             extra_log_level_defaults))

    logging.setup(cfg.CONF, "bagpipe-bgp")


def fix_log_file():
    # assist transition from past bagpipe-bgp version which were
    # using --log-file to specify the location of a file to configure logging
    if (cfg.CONF.log_file and cfg.CONF.log_file.endswith('.conf')):
        cfg.CONF.log_file = None
        return ("now using oslo.log, specifying a log configuration file "
                "should be done with --log-config-append")


def daemon_main():
    logging.register_options(cfg.CONF)

    setup_config()

    log_file_warn = fix_log_file()

    setup_logging()

    if log_file_warn:
        LOG.warning(log_file_warn)

    exabgp_peer_worker.setup_exabgp_env()

    try:
        LOG.info("Starting bagpipe-bgp...")
        pecan_api = api.PecanAPI()

        cfg.CONF.log_opt_values(LOG, logging.INFO)

        def stop(signum, _):
            LOG.info("Received signal %d, stopping...", signum)
            pecan_api.stop()
            LOG.info("All threads now stopped...")
            sys.exit(0)

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)

        pecan_api.run()
    except Exception:
        LOG.exception("Error while starting BGP daemon")


def cleanup_main():
    logging.register_options(cfg.CONF)

    setup_config()

    fix_log_file()

    setup_logging()

    python_logging.root.name = "[BgpDataplaneCleaner]"

    for vpn_type, dataplane_driver in (
            drivers.instantiate_dataplane_drivers().items()):
        LOG.info("Cleaning dataplane for %s...", vpn_type)
        dataplane_driver.reset_state()

    LOG.info("BGP component dataplanes have been cleaned up.")


if __name__ == '__main__':
    daemon_main()
