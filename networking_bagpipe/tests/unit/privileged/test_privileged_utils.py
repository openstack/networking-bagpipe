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

from unittest import mock

from oslo_concurrency import processutils

from neutron.tests import base

from networking_bagpipe.privileged import privileged_utils
from networking_bagpipe.tests.unit.privileged import privsep_fixtures


class TestPrivilegedSysctl(base.BaseTestCase):

    def setUp(self):
        super(TestPrivilegedSysctl, self).setUp()
        self.useFixture(privsep_fixtures.PrivelegedFixture())

    @mock.patch('oslo_concurrency.processutils.execute')
    def test_sysctl_simple(self, mock_execute):
        mock_execute.return_value = ['', '']
        ret = privileged_utils.sysctl('a.b.c', 0)
        mock_execute.assert_called_with('sysctl', '-w', 'a.b.c=0',
                                        check_exit_code=True)
        self.assertEqual(ret, 0)

    @mock.patch('oslo_concurrency.processutils.execute')
    def test_sysctl_failed(self, mock_execute):
        mock_execute.return_value = ['', 'error']
        ret = privileged_utils.sysctl('a.b.c', 1)
        self.assertEqual(ret, 1)

    @mock.patch('oslo_concurrency.processutils.execute')
    def test_sysctl_failed_raise_exception(self, mock_execute):
        mock_execute.side_effect = processutils.ProcessExecutionError(
            'Unexpected error')
        self.assertRaises(processutils.ProcessExecutionError,
                          privileged_utils.sysctl, 'a.b.c', 1)

    @mock.patch('oslo_concurrency.processutils.execute')
    def test_modprobe_simple(self, mock_execute):
        mock_execute.return_value = ['', '']
        privileged_utils.modprobe('foo_module')
        mock_execute.assert_called_once_with(
            'modprobe', 'foo_module', check_exit_code=True)

    @mock.patch('oslo_concurrency.processutils.execute')
    def test_modprobe_failed(self, mock_execute):
        mock_execute.side_effect = processutils.ProcessExecutionError(
            'Unexpected error')
        self.assertRaises(
            processutils.ProcessExecutionError,
            privileged_utils.modprobe, 'foo_module')
