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

from oslo_concurrency import processutils

from networking_bagpipe import privileged


@privileged.default_cmd.entrypoint
def sysctl(knob, value):
    """Run sysctl command

    :param knob: (string) sysctl knob name, a path under /proc/sys, see:
                 https://review.opendev.org/665155
    :param value: (int) value to be set in the knob
    :return: 0 if the command succeeded, 1 otherwise
    """
    cmd = ['sysctl']
    cmd += ['-w', '%s=%s' % (knob, value)]
    result = processutils.execute(*cmd, check_exit_code=True)
    return 1 if result[1] else 0


@privileged.default_cmd.entrypoint
def modprobe(module_name):
    """run modprobe command

    :param module_name: the name of the module to check with modprobe
    """
    cmd = ['modprobe', module_name]
    processutils.execute(*cmd, check_exit_code=True)


# TODO(lajoskatona): use pyroute2.IPDB()
@privileged.default_cmd.entrypoint
def brctl(params, check_exit=True):
    """run brctl command

    :param params: parameters for brctl
    :param check_exit: boolean or list of allowed exit codes, see
                       https://opendev.org/openstack/oslo.concurrency/src/
                       branch/master/oslo_concurrency/processutils.py#L207
    :return: tupple of stdout, stderr
    """
    cmd = ['brctl'] + params.split()
    return processutils.execute(*cmd, check_exit_code=check_exit,
                                run_as_root=True)


# TODO(lajoskatona): use pyroute2.IPRoute() fdb
@privileged.default_cmd.entrypoint
def bridge(params):
    """Run bridge command

    :param params: parameters for bridge
    """
    cmd = ['bridge'] + params.split()
    return processutils.execute(*cmd, run_as_root=True)
