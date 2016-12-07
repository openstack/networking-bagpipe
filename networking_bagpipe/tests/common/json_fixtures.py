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

import os.path

import fixtures
from oslo_serialization import jsonutils


class JsonFileFixture(fixtures.Fixture):
    """A fixture that knows how to translate configuration to JSON file.

    :param base_filename: the filename to use on disk.
    :param config: a dictionary.
    :param temp_dir: an existing temporary directory to use for storage.
    """

    def __init__(self, base_filename, config, temp_dir):
        super(JsonFileFixture, self).__init__()
        self.base_filename = base_filename
        self.config = config
        self.temp_dir = temp_dir

    def _setUp(self):
        # Need to randomly generate a unique folder to put the file in
        self.filename = os.path.join(self.temp_dir, self.base_filename)
        with open(self.filename, 'w') as f:
            jsonutils.dump(self.config, f, indent=4)
            f.flush()
