# Copyright (c) 2015 Orange.
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

from oslo.config import cfg

from oslo_log import log

import sqlalchemy as sa
from sqlalchemy.orm import exc as sa_exc

from neutron.common import exceptions as exc
from neutron.db import api as db_api
from neutron.db import model_base

from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import helpers

LOG = log.getLogger(__name__)

MIN_RT_NN = 1
MAX_RT_NN = 65535

route_target_opts = [
    cfg.IntOpt('rt_asn', default=64512,
               help=_("Route Target Autonomous System number.")),
    cfg.ListOpt('rt_nn_ranges',
                default=[],
                help=_("Comma-separated list of <rt_nn_min>:<rt_nn_max> tuples"
                       " enumerating ranges of Route Target number that are "
                       "available for tenant network allocation")),
]

cfg.CONF.register_opts(route_target_opts, "ml2_type_route_target")

# TODO: find a clean way to not collide in the segment type namespace
TYPE_ROUTE_TARGET = 'route_target'


class RouteTargetInUse(exc.InUse):
    message = _("Unable to create the network. "
                "The route target %(rt_nn)s is in use.")


class RouteTargetAllocation(model_base.BASEV2):

    __tablename__ = 'ml2_route_target_allocations'

    rt_nn = sa.Column(sa.Integer, nullable=False, primary_key=True,
                      autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False)


class RouteTargetTypeDriver(helpers.SegmentTypeDriver):

    def __init__(self):
        super(RouteTargetTypeDriver, self).__init__(RouteTargetAllocation)

    def get_type(self):
        return TYPE_ROUTE_TARGET

    def initialize(self):
        self.rt_nn_ranges = []
        self._parse_route_target_number_ranges(
            cfg.CONF.ml2_type_route_target.rt_nn_ranges, self.rt_nn_ranges)
        self._sync_route_target_allocations()

    def _parse_route_target_number_ranges(self, rt_nn_ranges, current_range):
        for entry in rt_nn_ranges:
            entry = entry.strip()
            try:
                rt_nn_min, rt_nn_max = entry.split(':')
                rt_nn_min = rt_nn_min.strip()
                rt_nn_max = rt_nn_max.strip()
                current_range.append((int(rt_nn_min), int(rt_nn_max)))
            except ValueError as ex:
                LOG.error(_("Invalid Route Target number range: '%(range)s' "
                            "- %(e)s. Agent terminated!"),
                          {'range': rt_nn_ranges, 'e': ex})

        LOG.info(_("Route Target number ranges: %(range)s"),
                 {'range': current_range})

    def _is_valid_route_target_number(self, rt_nn):
        return MIN_RT_NN <= rt_nn <= MAX_RT_NN

    def is_partial_segment(self, segment):
        return segment.get(api.SEGMENTATION_ID) is None

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if physical_network:
            msg = _("provider:physical_network specified for %s "
                    "network") % segment.get(api.NETWORK_TYPE)
            raise exc.InvalidInput(error_message=msg)

        segmentation_id = segment.get(api.SEGMENTATION_ID)
        if segmentation_id is None:
            msg = _("segmentation_id required for Route Target provider"
                    " network")
            raise exc.InvalidInput(error_message=msg)
        if not self._is_valid_route_target_number(segmentation_id):
            msg = (_("segmentation_id out of range (%(min)s through "
                     "%(max)s)") %
                   {'min': MIN_RT_NN,
                    'max': MAX_RT_NN})
            raise exc.InvalidInput(error_message=msg)

        for key, value in segment.items():
            if value and key not in [api.NETWORK_TYPE,
                                     api.PHYSICAL_NETWORK,
                                     api.SEGMENTATION_ID]:
                msg = _("%s prohibited for Route Target provider "
                        "network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        segmentation_id = segment.get(api.SEGMENTATION_ID)
        with session.begin(subtransactions=True):
            try:
                alloc = (session.query(RouteTargetAllocation).
                         filter_by(rt_nn=segmentation_id).
                         with_lockmode('update').
                         one())
                if alloc.allocated:
                    raise RouteTargetInUse(rt_nn=segmentation_id)
                LOG.debug(_("Reserving specific route target %s from pool"),
                          segmentation_id)
                alloc.allocated = True
            except sa_exc.NoResultFound:
                LOG.debug(_("Reserving specific route target %s outside pool"),
                          segmentation_id)
                alloc = RouteTargetAllocation(rt_nn=segmentation_id)
                alloc.allocated = True
                session.add(alloc)

    def allocate_tenant_segment(self, session):
        with session.begin(subtransactions=True):
            alloc = (session.query(RouteTargetAllocation).
                     filter_by(allocated=False).
                     with_lockmode('update').
                     first())
            if alloc:
                LOG.debug(_("Allocating Route Target number: %(rt_nn)s"),
                          {'rt_nn': alloc.rt_nn})
                alloc.allocated = True
                return {api.NETWORK_TYPE: TYPE_ROUTE_TARGET,
                        api.PHYSICAL_NETWORK: None,
                        api.SEGMENTATION_ID: alloc.rt_nn}

    def release_segment(self, session, segment):
        rt_nn = segment[api.SEGMENTATION_ID]
        with session.begin(subtransactions=True):
            try:
                alloc = (session.query(RouteTargetAllocation).
                         filter_by(rt_nn=rt_nn).
                         with_lockmode('update').
                         one())
                alloc.allocated = False
                for lo, hi in self.rt_nn_ranges:
                    if lo <= rt_nn <= hi:
                        LOG.debug(_("Releasing Route Target number %s to "
                                    "pool"), rt_nn)
                        break
                else:
                    session.delete(alloc)
                    LOG.debug(_("Releasing Route Target number %s outside "
                                "pool"), rt_nn)
            except sa_exc.NoResultFound:
                LOG.warning(_("Route Target number %s not found"), rt_nn)

    def _sync_route_target_allocations(self):
        """Synchronize route_target_allocations table with configured tunnel
        ranges."""

        # Determine current configured allocatable route targets
        rt_nns = set()
        for rt_nn_range in self.rt_nn_ranges:
            rt_nn_min, rt_nn_max = rt_nn_range
            if rt_nn_max + 1 - rt_nn_min > MAX_RT_NN:
                LOG.error(_("Skipping unreasonable route target range "
                            "%(rt_nn_min)s:%(rt_nn_max)s"),
                          {'rt_nn_min': rt_nn_min, 'rt_nn_max': rt_nn_max})
            else:
                rt_nns |= set(xrange(rt_nn_min, rt_nn_max + 1))

        session = db_api.get_session()
        with session.begin(subtransactions=True):
            # Remove from table unallocated route target not currently
            # allocatable
            allocs = session.query(RouteTargetAllocation
                                   ).with_lockmode("update")
            for alloc in allocs:
                try:
                    # See if route target is allocatable
                    rt_nns.remove(alloc.rt_nn)
                except KeyError:
                    # Route target not allocatable, so check if its allocated
                    if not alloc.allocated:
                        # Not allocated, so remove it from table
                        LOG.debug(_("Removing route target %s from pool"),
                                  alloc.rt_nn)
                        session.delete(alloc)

            # Add missing allocatable route targets to table
            for rt_nn in sorted(rt_nns):
                alloc = RouteTargetAllocation(rt_nn=rt_nn)
                session.add(alloc)
