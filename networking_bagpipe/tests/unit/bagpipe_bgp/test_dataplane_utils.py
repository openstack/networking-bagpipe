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

import mock
import testtools

from networking_bagpipe.bagpipe_bgp.common import dataplane_utils


class TestObjectLifecycleManager(testtools.TestCase):

    def setUp(self):
        super(TestObjectLifecycleManager, self).setUp()

        self.test_object_mgr = dataplane_utils.ObjectLifecycleManager()
        self.test_object_mgr.create_object = mock.Mock(return_value=1)
        self.test_object_mgr.delete_object = mock.Mock()

    def test_get_object_first_user(self):
        _, first1 = self.test_object_mgr.get_object("OBJ1", "USER_A")
        self.assertTrue(first1)

        self.test_object_mgr.create_object.assert_called_once()
        self.assertTrue(len(self.test_object_mgr.objects) == 1)
        self.assertTrue(len(self.test_object_mgr.object_used_for["OBJ1"]) == 1)

    def test_get_object_multiple_users(self):
        self.test_object_mgr.get_object("OBJ1", "USER_A")

        _, first2 = self.test_object_mgr.get_object("OBJ1", "USER_B")
        self.assertFalse(first2)

        self.test_object_mgr.create_object.assert_called_once()
        self.assertTrue(len(self.test_object_mgr.objects) == 1)
        self.assertTrue(len(self.test_object_mgr.object_used_for["OBJ1"]) == 2)

    def test_find_object_already_exist(self):
        self.test_object_mgr.get_object("OBJ1", "USER_A")

        obj1 = self.test_object_mgr.find_object("OBJ1")
        self.assertIsNotNone(obj1)

    def test_find_object_empty(self):
        obj1 = self.test_object_mgr.find_object("OBJ1")
        self.assertIsNone(obj1)

    def test_free_object_last_user(self):
        self.test_object_mgr.get_object("OBJ1", "USER_A")

        last1 = self.test_object_mgr.free_object("OBJ1", "USER_A")
        self.assertTrue(last1)

        self.test_object_mgr.delete_object.assert_called_once()
        self.assertTrue(not self.test_object_mgr.objects)
        self.assertTrue(not self.test_object_mgr.object_used_for)

    def test_free_object_multiple_users(self):
        self.test_object_mgr.get_object("OBJ1", "USER_A")
        self.test_object_mgr.get_object("OBJ1", "USER_B")

        last1 = self.test_object_mgr.free_object("OBJ1", "USER_A")
        self.assertFalse(last1)

        self.test_object_mgr.delete_object.assert_not_called()
        self.assertTrue(len(self.test_object_mgr.objects) == 1)
        self.assertTrue(len(self.test_object_mgr.object_used_for["OBJ1"]) == 1)

        last2 = self.test_object_mgr.free_object("OBJ1", "USER_B")
        self.assertTrue(last2)

        self.test_object_mgr.delete_object.assert_called_once()
        self.assertTrue(not self.test_object_mgr.objects)
        self.assertTrue(not self.test_object_mgr.object_used_for)
