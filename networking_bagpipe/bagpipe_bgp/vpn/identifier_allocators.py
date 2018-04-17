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
    MAX = None

    def __init__(self):
        self.allocated_ids = dict()
        self.released_ids = set()
        self.current_id = self.MIN

        self.lock = threading.Lock()

    @utils.synchronized
    def get_new_id(self, description):
        if len(self.released_ids) > 0:
            new_id = self.released_ids.pop()
        else:
            if self.current_id > self.MAX:
                LOG.error("All the %d possible identifiers have been "
                          "allocated.", self.MAX)
                raise MaxIDReached(max=self.MAX)

            new_id = self.current_id
            self.current_id += 1
        self.allocated_ids[new_id] = description

        LOG.debug("Allocated identifier %d for '%s'", new_id, description)

        return new_id

    @utils.synchronized
    def release(self, id):
        if id in self.allocated_ids:
            LOG.debug("Released identifier %d ('%s')", id,
                      self.allocated_ids[id])
            del self.allocated_ids[id]
            self.released_ids.add(id)
        else:
            LOG.warn("Asked to release a non registered identifier: %d", id)

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
