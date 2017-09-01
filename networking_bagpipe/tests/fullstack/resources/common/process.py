# Copyright (c) 2016 Orange.
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

import datetime
from distutils import spawn
import os
import random
import signal

import fixtures
from oslo_utils import fileutils

from neutron.agent.linux import async_process
from neutron.tests import base
from neutron.tests.fullstack import base as neutron_base
from neutron.tests.fullstack.resources import process as neutron_proc


class BagpipeBGPFixture(fixtures.Fixture):

    BAGPIPE_BGP = "bagpipe-bgp"

    def __init__(self, env_desc, host_desc, test_name,
                 bgp_cfg_fixture, namespace=None):
        super(BagpipeBGPFixture, self).__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.bgp_cfg_fixture = bgp_cfg_fixture
        self.namespace = namespace

    def _setUp(self):
        self.process_fixture = self.useFixture(neutron_proc.ProcessFixture(
            test_name=self.test_name,
            process_name=self.BAGPIPE_BGP,
            exec_name=self.BAGPIPE_BGP,
            config_filenames=[self.bgp_cfg_fixture.filename],
            namespace=self.namespace,
            kill_signal=signal.SIGTERM))


class BagpipeFakeRRProcessFixture(neutron_proc.ProcessFixture):

    def start(self):
        cmd = [spawn.find_executable(self.exec_name)]
        self.process = async_process.AsyncProcess(
            cmd, run_as_root=True, namespace=self.namespace
        )
        self.process.start()


class BagpipeFakeRRFixture(fixtures.Fixture):

    BAGPIPE_FAKERR = "bagpipe-fakerr"

    def __init__(self, env_desc, host_desc, test_name):
        super(BagpipeFakeRRFixture, self).__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name

    def _setUp(self):
        self.process_fixture = self.useFixture(BagpipeFakeRRProcessFixture(
            test_name=self.test_name,
            process_name=self.BAGPIPE_FAKERR,
            exec_name=self.BAGPIPE_FAKERR,
            config_filenames=None,
            kill_signal=signal.SIGTERM))


class GoBGPProcessFixture(neutron_proc.ProcessFixture):

    # NOTE(tmorin): stopping the process does not work yet for
    # GOBGPD_LOG = True, because get_root_helper_child_pid is not designed to
    # find the right child pid when things when an intermediate shell
    # is used
    # (using 'sh -c "exec gobgpd ..."' does not work either, gobgpd silently
    # stops right after startup for a reason I did not identify)
    GOBGPD_LOG = False

    def start(self):
        test_name = base.sanitize_log_path(self.test_name)

        log_dir = os.path.join(neutron_base.DEFAULT_LOG_DIR, test_name)
        fileutils.ensure_tree(log_dir, mode=0o755)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d--%H-%M-%S-%f")
        log_file = "%s/%s--%s.log" % (log_dir, self.process_name,
                                      timestamp)

        gobgpd_exec = spawn.find_executable(self.exec_name)
        if not gobgpd_exec:
            raise Exception("can't find gobgpd executable in PATH (%s, %s)" %
                            (self.exec_name,
                             os.environ['PATH']))

        cmd = [
            gobgpd_exec,
            '-t', 'json',
            '-f', self.config_filenames[0],
            '--log-level=debug',
            # we don't need this management API:
            '--api-hosts=0.0.0.0:%s' % random.randint(20000, 30000)
        ]

        if self.GOBGPD_LOG:
            cmd = ['sh', '-c', ('%s > %s 2>&1') % (' '.join(cmd), log_file)]

        self.process = async_process.AsyncProcess(
            cmd, namespace=self.namespace
        )
        self.process.start()


class GoBGPFixture(fixtures.Fixture):

    GOBGPD = "gobgpd"

    def __init__(self, env_desc, host_desc, test_name, gobgp_cfg_fixture):
        super(GoBGPFixture, self).__init__()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.test_name = test_name
        self.gobgp_cfg_fixture = gobgp_cfg_fixture

    def _setUp(self):
        config_filenames = [self.gobgp_cfg_fixture.filename]

        self.process_fixture = self.useFixture(GoBGPProcessFixture(
            test_name=self.test_name,
            process_name=self.GOBGPD,
            exec_name=self.GOBGPD,
            config_filenames=config_filenames,
            kill_signal=signal.SIGTERM))
