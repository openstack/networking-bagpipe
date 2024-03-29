# Copyright 2017 Orange
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

from oslo_config import cfg

DEFAULT_PORT = 8082

common_opts = [
    cfg.HostAddressOpt("host", default="127.0.0.1",
                       help="IP address on which the API server should listen",
                       deprecated_name="api_host"),
    cfg.PortOpt("port", default=DEFAULT_PORT,
                help="Port on which the API server should listen",
                deprecated_name="api_port")
]


def register_config():
    cfg.CONF.register_opts(common_opts, "API")
