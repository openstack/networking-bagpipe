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

import itertools
import threading

from oslo_log import log as logging

from networking_bagpipe.bagpipe_bgp.common import looking_glass as lg
from networking_bagpipe.bagpipe_bgp.common import utils
from networking_bagpipe.bagpipe_bgp.engine import exa

from neutron_lib import exceptions

LOG = logging.getLogger(__name__)


class MaxIDReached(exceptions.NeutronException):
    message = "Could not allocate identifier, maximum (%(max)d) was reached"


class IDAllocator(lg.LookingGlassMixin):

    MIN = 0
    MAX = 2**32-1  # no id > MAX will be allocated

    def __init__(self):
        self.allocated_ids = dict()
        self.released_ids = list()
        self.current_id = self.MIN

        self.lock = threading.Lock()

    def _allocate(self, id, description, update_current=False):
        self.allocated_ids[id] = description

        # Update current_id to the next free id
        if update_current and id == self.current_id:
            for next_id in itertools.count(self.current_id+1):
                if next_id not in self.allocated_ids:
                    self.current_id = next_id
                    break

        LOG.debug("Allocated id %d for '%s'", id, description)
        return id

    @utils.synchronized
    def get_new_id(self, description=None, hint_value=None):

        if hint_value is not None and hint_value > self.MAX:
            LOG.warning("Allocator hint value cannot be beyond MAX")

        if hint_value is not None and hint_value not in self.allocated_ids:
            return self._allocate(hint_value, description, update_current=True)
        elif self.current_id > self.MAX:
            if len(self.released_ids) > 0:
                # FIFO (pop the id that was released the earliest)
                return self._allocate(self.released_ids.pop(0), description)
            else:
                raise MaxIDReached(max=self.MAX)
        else:
            return self._allocate(self.current_id, description,
                                  update_current=True)

    @utils.synchronized
    def release(self, id):
        if id in self.allocated_ids:
            LOG.debug("Released id %d ('%s')", id, self.allocated_ids[id])
            del self.allocated_ids[id]
            self.released_ids.append(id)
        else:
            raise Exception("Asked to release a non-allocated id: %d" % id)

    def get_lg_local_info(self, prefix):
        return self.allocated_ids


class RDAllocator(IDAllocator):

    MAX = 2**16-1

    def __init__(self, prefix):
        super(RDAllocator, self).__init__()
        self.prefix = prefix

    def get_new_rd(self, description):
        new_id = self.get_new_id(description)

        return exa.RouteDistinguisher.fromElements(self.prefix, new_id)

    def release(self, rd):
        super(RDAllocator, self).release(int(str(rd).split(':')[1]))


class LabelAllocator(IDAllocator):

    MIN = 16
    MAX = 2**20-1

    def get_new_label(self, description):
        return self.get_new_id(description)
