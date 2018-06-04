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

import testtools

from networking_bagpipe.bagpipe_bgp.vpn import identifier_allocators


class TestIDAllocator(testtools.TestCase):

    min_id = 100
    alloc_id_count = 5
    remove_index = 2

    def setUp(self):
        super(TestIDAllocator, self).setUp()

        self.test_allocator = identifier_allocators.IDAllocator()
        self.test_allocator.current_id = self.min_id
        self.test_allocator.MAX = (self.min_id + self.alloc_id_count) - 1

        self.allocated_ids = set()
        for i in range(self.alloc_id_count):
            self.allocated_ids.add(
                self.test_allocator.get_new_id("Test identifier %d" % i)
            )

    def test_allocated_id_uniqueness(self):
        self.assertEqual(self.allocated_ids,
                         set(self.test_allocator.allocated_ids.keys()))
        self.assertEqual(self.test_allocator.MAX + 1,
                         self.test_allocator.current_id)

    def test_reuse_released_id(self):
        # Check identifier reused after having been released
        remove_id = self.min_id + self.remove_index
        self.test_allocator.release(remove_id)

        reused_id = self.test_allocator.get_new_id("Test reused identifier")
        self.assertEqual(remove_id, reused_id)
        self.assertEqual(self.test_allocator.MAX + 1,
                         self.test_allocator.current_id)

    def test_allocated_id_max(self):
        # Check no identifiers left exception
        self.assertRaises(identifier_allocators.MaxIDReached,
                          self.test_allocator.get_new_id,
                          "Test max reached identifier")


class TestIDAllocatorReUse(testtools.TestCase):

    def setUp(self):
        testtools.TestCase.setUp(self)

    def test_do_not_reuse_at_once(self):
        test_allocator = identifier_allocators.IDAllocator()

        x = test_allocator.get_new_id()
        test_allocator.release(x)
        y = test_allocator.get_new_id()

        self.assertTrue(x != y)

    def test_reuse_as_late_as_possible(self):
        # create an allocator for 4 values
        test_allocator = identifier_allocators.IDAllocator()
        test_allocator.MAX = 3

        # allocate one value, and release it at once
        x = test_allocator.get_new_id()
        test_allocator.release(x)

        # allocate 3 values, check that none is x
        intermediate_ids = [test_allocator.get_new_id(desc)
                            for desc in ('one', 'two', 'three')]
        for y in intermediate_ids:
            self.assertTrue(x != y)

        # allocate one more, this can't be anything else than x
        z1 = test_allocator.get_new_id()
        self.assertEqual(x, z1)

        # we reached MAX, we are now allocating from released_ids()
        # free x
        test_allocator.release(x)
        # free the intermediate ids
        for y in intermediate_ids:
            test_allocator.release(y)

        # check that the next id given to us is x
        z2 = test_allocator.get_new_id()
        self.assertEqual(x, z2)


class TestIDAllocatorRequestValue(testtools.TestCase):

    def setUp(self):
        testtools.TestCase.setUp(self)

    def test_request_not_allocated(self):
        test_allocator = identifier_allocators.IDAllocator()

        x = test_allocator.get_new_id()
        # Request to allocate id greater than current_id value
        y = test_allocator.get_new_id(hint_value=x+3)

        self.assertEqual(y, x+3)
        self.assertEqual(test_allocator.current_id, x+1)

    def test_request_allocated(self):
        test_allocator = identifier_allocators.IDAllocator()

        x = test_allocator.get_new_id()
        y = test_allocator.get_new_id(hint_value=x)

        self.assertTrue(y != x)
        self.assertEqual(y, x+1)
        self.assertEqual(test_allocator.current_id, x+2)

    def test_request_next_already_allocated(self):
        test_allocator = identifier_allocators.IDAllocator()

        x = test_allocator.get_new_id()
        # Request to allocate id equal to current_id value
        y = test_allocator.get_new_id(hint_value=x+1)
        z = test_allocator.get_new_id()

        self.assertTrue(z != y)
        self.assertEqual(z, x+2)
        self.assertEqual(test_allocator.current_id, x+3)
