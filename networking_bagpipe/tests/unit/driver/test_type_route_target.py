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

import mock
import testtools
from testtools import matchers

from neutron.common import exceptions as exc
import neutron.db.api as db
from neutron.plugins.ml2 import driver_api as api
from neutron.tests.unit import testlib_api

from networking_bagpipe.driver import type_route_target

RT_NN_MIN = 100
RT_NN_MAX = 109
RT_NN_RANGES = [(RT_NN_MIN, RT_NN_MAX)]
UPDATED_RT_NN_RANGES = [(RT_NN_MIN + 5, RT_NN_MAX + 5)]


class RouteTargetTypeTest(testlib_api.SqlTestCase):

    def setUp(self):
        super(RouteTargetTypeTest, self).setUp()
        self.driver = type_route_target.RouteTargetTypeDriver()
        self.driver.rt_nn_ranges = RT_NN_RANGES
        self.driver._sync_route_target_allocations()
        self.session = db.get_session()

    def _get_allocation(self, session, segment):
        return (session.query(type_route_target.RouteTargetAllocation).
                filter_by(rt_nn=segment[api.SEGMENTATION_ID]).
                first())

    def test_sync_rt_nn_allocations(self):
        def check_in_ranges(rt_nn_ranges):
            rt_nn_min, rt_nn_max = rt_nn_ranges[0]
            segment = {api.NETWORK_TYPE: type_route_target.TYPE_ROUTE_TARGET,
                       api.PHYSICAL_NETWORK: None}

            segment[api.SEGMENTATION_ID] = rt_nn_min - 1
            self.assertIsNone(
                self._get_allocation(self.session, segment))
            segment[api.SEGMENTATION_ID] = rt_nn_max + 1
            self.assertIsNone(
                self._get_allocation(self.session, segment))

            segment[api.SEGMENTATION_ID] = rt_nn_min
            self.assertFalse(
                self._get_allocation(self.session, segment).allocated)
            segment[api.SEGMENTATION_ID] = rt_nn_min + 1
            self.assertFalse(
                self._get_allocation(self.session, segment).allocated)
            segment[api.SEGMENTATION_ID] = rt_nn_max - 1
            self.assertFalse(
                self._get_allocation(self.session, segment).allocated)
            segment[api.SEGMENTATION_ID] = rt_nn_max
            self.assertFalse(
                self._get_allocation(self.session, segment).allocated)

        check_in_ranges(RT_NN_RANGES)
        self.driver.rt_nn_ranges = UPDATED_RT_NN_RANGES
        self.driver._sync_route_target_allocations()
        check_in_ranges(UPDATED_RT_NN_RANGES)

    def _test_sync_allocations_and_allocated(self, rt_nn):
        segment = {api.NETWORK_TYPE: type_route_target.TYPE_ROUTE_TARGET,
                   api.PHYSICAL_NETWORK: None,
                   api.SEGMENTATION_ID: rt_nn}
        self.driver.reserve_provider_segment(self.session, segment)

        self.driver.rt_nn_ranges = UPDATED_RT_NN_RANGES
        self.driver._sync_route_target_allocations()

        self.assertTrue(
            self._get_allocation(self.session, segment).allocated)

    def test_sync_allocations_and_allocated_in_initial_range(self):
        self._test_sync_allocations_and_allocated(RT_NN_MIN + 2)

    def test_sync_allocations_and_allocated_in_final_range(self):
        self._test_sync_allocations_and_allocated(RT_NN_MAX + 2)

    def test_partial_segment_is_partial_segment(self):
        segment = {api.NETWORK_TYPE: type_route_target.TYPE_ROUTE_TARGET,
                   api.PHYSICAL_NETWORK: None,
                   api.SEGMENTATION_ID: None}
        self.assertTrue(self.driver.is_partial_segment(segment))

    def test_validate_provider_segment(self):
        segment = {api.NETWORK_TYPE: type_route_target.TYPE_ROUTE_TARGET,
                   api.PHYSICAL_NETWORK: 'test_net1',
                   api.SEGMENTATION_ID: None}

        with testtools.ExpectedException(exc.InvalidInput):
            self.driver.validate_provider_segment(segment)

        segment[api.PHYSICAL_NETWORK] = None
        self.driver.validate_provider_segment(segment)

        segment[api.SEGMENTATION_ID] = 1
        self.driver.validate_provider_segment(segment)

    def test_reserve_provider_segment(self):
        segment = {api.NETWORK_TYPE: type_route_target.TYPE_ROUTE_TARGET,
                   api.PHYSICAL_NETWORK: None,
                   api.SEGMENTATION_ID: 201}
        alloc = self._get_allocation(self.session, segment)
        self.assertIsNone(alloc)
        observed = self.driver.reserve_provider_segment(self.session, segment)
        alloc = self._get_allocation(self.session, observed)
        self.assertTrue(alloc.allocated)

    def test_reserve_provider_segment_already_allocated(self):
        segment = {api.NETWORK_TYPE: type_route_target.TYPE_ROUTE_TARGET,
                   api.PHYSICAL_NETWORK: None,
                   api.SEGMENTATION_ID: 201}
        observed = self.driver.reserve_provider_segment(self.session, segment)
        self.assertRaises(type_route_target.RouteTargetInUse,
                          self.driver.reserve_provider_segment,
                          self.session,
                          observed)

    def test_allocate_tenant_segment(self):
        for __ in range(RT_NN_MIN, RT_NN_MAX + 1):
            segment = self.driver.allocate_tenant_segment(self.session)
            alloc = self._get_allocation(self.session, segment)
            self.assertTrue(alloc.allocated)
            rt_nn = segment[api.SEGMENTATION_ID]
            self.assertThat(rt_nn, matchers.GreaterThan(RT_NN_MIN - 1))
            self.assertThat(rt_nn, matchers.LessThan(RT_NN_MAX + 1))

    def test_allocate_tenant_segment_not_available(self):
        for __ in range(RT_NN_MIN, RT_NN_MAX + 1):
            self.driver.allocate_tenant_segment(self.session)
        segment = self.driver.allocate_tenant_segment(self.session)
        self.assertIsNone(segment)

    def test_release_segment(self):
        segment = self.driver.allocate_tenant_segment(self.session)
        self.driver.release_segment(self.session, segment)
        alloc = self._get_allocation(self.session, segment)
        self.assertFalse(alloc.allocated)

    def test_release_segment_unallocated(self):
        segment = {api.NETWORK_TYPE: type_route_target.TYPE_ROUTE_TARGET,
                   api.PHYSICAL_NETWORK: None,
                   api.SEGMENTATION_ID: 201}
        with mock.patch.object(type_route_target.LOG, 'warning') as log_warn:
            self.driver.release_segment(self.session, segment)
            log_warn.assert_called_once_with(
                "Route Target number %(rt_nn)s not found",
                {'rt_nn': 201})
