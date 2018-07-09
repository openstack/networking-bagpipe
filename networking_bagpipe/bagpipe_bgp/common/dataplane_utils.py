# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

# Copyright 2018 Orange
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
import collections

from oslo_log import log as logging

from networking_bagpipe._i18n import _
from networking_bagpipe.bagpipe_bgp.common import log_decorator

from neutron.agent.common import ovs_lib
from neutron.plugins.ml2.drivers.openvswitch.agent.common import \
    constants as ovs_const

from neutron_lib import exceptions

LOG = logging.getLogger(__name__)


# largely copied from networking_sfc.services.sfc.common.ovs_ext_lib
class OVSBridgeWithGroups(object):

    def __init__(self, ovs_bridge):
        self.bridge = ovs_bridge

        # OpenFlow 1.1 is needed to manipulate groups
        self.bridge.use_at_least_protocol(ovs_const.OPENFLOW11)

    # proxy most methods to self.bridge
    def __getattr__(self, name):
        return getattr(self.bridge, name)

    def do_action_groups(self, action, kwargs_list):
        group_strs = [_build_group_expr_str(kw, action) for kw in kwargs_list]
        options = ['-']
        if action == 'add' or action == 'del':
            cmd = '%s-groups' % action
        elif action == 'mod':
            cmd = '%s-group' % action
            options.insert(0, '--may-create')
        elif action == 'insert-buckets' or action == 'remove-buckets':
            cmd = action
        else:
            msg = _("Action is illegal")
            raise exceptions.InvalidInput(error_message=msg)

        if action == 'del' and {} in kwargs_list:
            self.run_ofctl(cmd, [])
        else:
            self.run_ofctl(cmd, options, '\n'.join(group_strs))

    @log_decorator.log_info
    def add_group(self, **kwargs):
        self.do_action_groups('add', [kwargs])

    @log_decorator.log_info
    def mod_group(self, **kwargs):
        self.do_action_groups('mod', [kwargs])

    @log_decorator.log_info
    def delete_group(self, **kwargs):
        self.do_action_groups('del', [kwargs])

    @log_decorator.log_info
    def insert_bucket(self, **kwargs):
        self.do_action_groups('insert-buckets', [kwargs])

    @log_decorator.log_info
    def remove_bucket(self, **kwargs):
        self.do_action_groups('remove-buckets', [kwargs])

    def dump_group_for_id(self, group_id):
        retval = None
        group_str = "%d" % group_id
        group = self.run_ofctl("dump-groups", [group_str])
        if group:
            retval = '\n'.join(item for item in group.splitlines()
                               if ovs_lib.is_a_flow_line(item))
        return retval

    def get_bridge_ports(self):
        port_name_list = self.bridge.get_port_name_list()
        of_portno_list = list()
        for port_name in port_name_list:
            of_portno_list.append(self.bridge.get_port_ofport(port_name))
        return of_portno_list


def _build_group_expr_str(group_dict, cmd):
    group_expr_arr = []
    buckets = None
    group_id = None

    if cmd != 'del':
        if "group_id" not in group_dict:
            msg = _("Must specify one group Id on group addition"
                    " or modification")
            raise exceptions.InvalidInput(error_message=msg)
        group_id = "group_id=%s" % group_dict.pop('group_id')

        if cmd != 'remove-buckets':
            if "buckets" not in group_dict:
                msg = _("Must specify one or more buckets on group addition/"
                        "modification or buckets insertion/deletion")
                raise exceptions.InvalidInput(error_message=msg)
            buckets = "%s" % group_dict.pop('buckets')

    if group_id:
        group_expr_arr.append(group_id)

    for key, value in group_dict.items():
        group_expr_arr.append("%s=%s" % (key, value))

    if buckets:
        group_expr_arr.append(buckets)

    return ','.join(group_expr_arr)


class OVSExtendedBridge(ovs_lib.OVSBridge):

    def add_flow_extended(self, flow_matches=[], actions=[]):
        flow_args = {}
        for match in flow_matches:
            flow_args.update(match)

        if actions:
            flow_args["actions"] = join_s(*actions)

        self.add_flow(**flow_args)

    def delete_flows_extended(self, flow_matches=[]):
        flow_args = {}
        for match in flow_matches:
            flow_args.update(match)

        self.delete_flows(**flow_args)


def join_s(*args):
    return ','.join([_f for _f in args if _f])


class ObjectLifecycleManager(object):

    def __init__(self):
        self.objects = dict()
        self.object_used_for = collections.defaultdict(set)

    @log_decorator.log_info
    def is_object_user(self, object_key, user_key):
        return (object_key in self.objects and
                user_key in self.object_used_for[object_key])

    @abc.abstractmethod
    def create_object(self, object_key, *args, **kwargs):
        pass

    @abc.abstractmethod
    def delete_object(self, object):
        pass

    @log_decorator.log_info
    def get_object(self, object_key, user_key, *args, **kwargs):
        obj = self.find_object(object_key)
        if obj is None:
            obj = self.create_object(object_key, *args, **kwargs)
            self.objects[object_key] = obj
            LOG.debug("object for %s: %s", object_key, obj)

        first = not self.object_used_for[object_key]
        self.object_used_for[object_key].add(user_key)

        if first:
            LOG.debug("%s is first user for %s", user_key, object_key)

        return (obj, first)

    @log_decorator.log_info
    def find_object(self, object_key):
        obj = self.objects.get(object_key)
        if obj is not None:
            LOG.debug("existing object for %s: %s", object_key, obj)

        return obj

    @log_decorator.log_info
    def free_object(self, object_key, user_key):
        if object_key not in self.object_used_for:
            LOG.debug("no object to free for %s", object_key)
            return

        self.object_used_for[object_key].discard(user_key)

        last = not self.object_used_for[object_key]
        if last:
            obj = self.objects[object_key]

            LOG.debug("%s was last user for %s, clearing", user_key,
                      object_key)
            self.delete_object(obj)

            del self.objects[object_key]
            del self.object_used_for[object_key]
        else:
            LOG.debug("remaining users for object %s: %s", object_key,
                      self.object_used_for[object_key])

        return last

    @log_decorator.log_info
    def clear_objects(self, filter_method):
        for object_key, users in self.object_used_for.items():
            for user in users:
                if filter_method(object_key, user):
                    self.delete_object(self.objects[object_key])
                    del self.objects[object_key]
                    del self.object_used_for[object_key]
                    break

    def infos(self):
        return self.objects


class ObjectLifecycleManagerProxy(object):

    def __init__(self, manager, parent_user):
        self.manager = manager
        self.parent_user = parent_user

    def _object_key(self, object_key):
        return (self.parent_user, object_key)

    def is_object_user(self, object_key, user_key):
        return self.manager.is_object_user(self._object_key(object_key),
                                           (self.parent_user, user_key))

    def get_object(self, object_key, user_key, *args, **kwargs):
        return self.manager.get_object(self._object_key(object_key),
                                       (self.parent_user, user_key),
                                       *args, **kwargs)

    def find_object(self, object_key):
        return self.manager.find_object(self._object_key(object_key))

    def free_object(self, object_key, user_key):
        if user_key:
            return self.manager.free_object(self._object_key(object_key),
                                            (self.parent_user, user_key))

    def clear_objects(self, filter_method=lambda obj_key, user_key: True):
        self.manager.clear_objects(
            lambda obj_key, user_key: (user_key[0] == self.parent_user and
                                       filter_method(obj_key, user_key[1]))
        )

    def infos(self):
        return self.manager.infos()


class SharedObjectLifecycleManagerProxy(ObjectLifecycleManagerProxy):

    def _object_key(self, object_key):
        return object_key
