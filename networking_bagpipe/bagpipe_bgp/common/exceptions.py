# Copyright 2014 Orange
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


class RemotePEMACAddressNotFound(Exception):

    def __init__(self, ip_address):
        super().__init__(
            "MAC address for %s could not be found. CAUTION:"
            " Need direct MPLS/Eth connection" % ip_address)


class APIException(Exception):
    pass


class VPNNotFound(APIException):

    def __init__(self, vrf_id):
        super().__init__("VPN %s could not be found" % vrf_id)


class MalformedMACAddress(APIException):

    def __init__(self, address):
        super().__init__(
            "MAC address %s is not valid" % address)


class MalformedIPAddress(APIException):

    def __init__(self, address):
        super().__init__(
            "IP address %s is not valid" % address)


class OVSBridgeNotFound(APIException):

    def __init__(self, bridge):
        super().__init__(
            "OVS bridge '%s' doesn't exist" % bridge)


class OVSBridgePortNotFound(APIException):

    def __init__(self, interface, bridge):
        super().__init__(
            "OVS Port {} doesn't exist on OVS Bridge {}".format(interface,
                                                                bridge))


class APIMissingParameterException(APIException):
    def __init__(self, parameter):
        super().__init__(
            "Missing parameter: '%s'" % parameter)


class APIAlreadyUsedVNI(APIException):
    def __init__(self, vni):
        super().__init__(
            "A VPN instance using vni %d already exists." % vni)


class APINotPluggedYet(APIException):
    def __init__(self, endpoint):
        super().__init__(
            "Endpoint {} not plugged yet, can't unplug".format(endpoint))
