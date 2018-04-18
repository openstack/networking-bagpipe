# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

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

from oslo_config import cfg
from oslo_log import log as logging
import pyroute2

from networking_bagpipe.bagpipe_bgp.common import log_decorator
from networking_bagpipe.bagpipe_bgp import constants as consts
from networking_bagpipe.bagpipe_bgp.engine import exa
from networking_bagpipe.bagpipe_bgp.vpn import dataplane_drivers as dp_drivers
from networking_bagpipe.bagpipe_bgp.vpn import evpn


BRIDGE_NAME_PREFIX = "evpn---"
VXLAN_INTERFACE_PREFIX = "vxlan--"


class LinuxVXLANEVIDataplane(evpn.VPNInstanceDataplane):

    def __init__(self, *args, **kwargs):
        super(LinuxVXLANEVIDataplane, self).__init__(*args, **kwargs)

        if 'linuxbr' in kwargs:
            self.bridge_name = kwargs.get('linuxbr')
        else:
            self.bridge_name = (
                BRIDGE_NAME_PREFIX +
                self.external_instance_id)[:consts.LINUX_DEV_LEN]

        if not self._interface_exists(self.bridge_name):
            self.log.debug("Starting bridge %s", self.bridge_name)

            # Create bridge
            self._run_command("brctl addbr %s" % self.bridge_name,
                              run_as_root=True)
            self._run_command("brctl setfd %s 0" % self.bridge_name,
                              run_as_root=True)
            self._run_command("brctl stp %s off" % self.bridge_name,
                              run_as_root=True)
            self._run_command("ip link set %s up" % self.bridge_name,
                              run_as_root=True)

            self.log.debug("Bridge %s created", self.bridge_name)

        self._create_and_plug_vxlan_if()

        self.log.debug("VXLAN interface %s plugged on bridge %s",
                       self.vxlan_if_name, self.bridge_name)

        self._cleaning_up = False

    @log_decorator.log_info
    def cleanup(self):
        self.log.info("Cleaning EVI bridge and VXLAN interface %s",
                      self.bridge_name)

        self._cleaning_up = True

        # removing the vxlan interface removes our routes,
        # but if we don't remove the vxlan if (if it was reused) then
        # cleanup will not happen, which is why we use cleanup assist
        # (see needs cleanup assist below)
        self._cleanup_vxlan_if()

        # Delete only EVPN Bridge (Created by dataplane driver)
        if BRIDGE_NAME_PREFIX in self.bridge_name:
            self._run_command("ip link set %s down" % self.bridge_name,
                              run_as_root=True,
                              raise_on_error=False)
            self._run_command("brctl delbr %s" % self.bridge_name,
                              run_as_root=True,
                              raise_on_error=False)

    def needs_cleanup_assist(self):
        # If we reused a vxlan interface we won't cleanup fdb entries
        # in cleanup(), so we need to have remove_dataplane_for_x
        # be called for reach state via cleanup assist
        return VXLAN_INTERFACE_PREFIX not in self.vxlan_if_name

    def _create_and_plug_vxlan_if(self):
        # if a VXLAN interface, with the VNI we want to use, is already plugged
        # in the bridge, we want to reuse it
        with pyroute2.IPDB(plugins=('interfaces',)) as ipdb:
            for port_id in ipdb.interfaces[self.bridge_name].ports:
                port = ipdb.interfaces[port_id]
                if (port.kind == "vxlan" and
                        port.vxlan_id == self.instance_label):
                    self.log.info("reuse vxlan interface %s for VXLAN VNI %s",
                                  port.ifname, self.instance_label)
                    self.vxlan_if_name = port.ifname
                    return

        self.vxlan_if_name = (VXLAN_INTERFACE_PREFIX +
                              self.external_instance_id)[:consts.LINUX_DEV_LEN]

        self.log.debug("Creating and plugging VXLAN interface %s",
                       self.vxlan_if_name)

        if self._interface_exists(self.vxlan_if_name):
            self._remove_vxlan_if()

        dst_port_spec = ""
        if self.driver.config.vxlan_dst_port:
            dst_port_spec = ("dstport %d" %
                             self.driver.config.vxlan_dst_port)

        # Create VXLAN interface
        self._run_command(
            "ip link add %s type vxlan id %d local %s nolearning proxy %s" %
            (self.vxlan_if_name, self.instance_label,
             self.driver.get_local_address(), dst_port_spec),
            run_as_root=True
        )

        self._run_command("ip link set %s up" % self.vxlan_if_name,
                          run_as_root=True)

        # Plug VXLAN interface into bridge
        self._run_command("brctl addif %s %s" % (self.bridge_name,
                                                 self.vxlan_if_name),
                          run_as_root=True)

    def _cleanup_vxlan_if(self):
        if VXLAN_INTERFACE_PREFIX not in self.vxlan_if_name:
            self.log.debug("we reused the VXLAN interface, don't cleanup")
            return

        if self._is_vxlan_if_on_bridge():
            # Unplug VXLAN interface from Linux bridge
            self._unplug_from_bridge(self.vxlan_if_name)

        self._remove_vxlan_if()

    def _remove_vxlan_if(self):
        if not VXLAN_INTERFACE_PREFIX not in self.vxlan_if_name:
            self.log.debug("we reused the VXLAN interface, don't remove")
            return

        # Remove VXLAN interface
        self._run_command("ip link set %s down" % self.vxlan_if_name,
                          run_as_root=True)
        self._run_command("ip link del %s" % self.vxlan_if_name,
                          run_as_root=True)

    def _is_if_on_bridge(self, ifname):
        with pyroute2.IPDB(plugins=('interfaces',)) as ipdb:
            try:
                for port_id in ipdb.interfaces[self.bridge_name].ports:
                    port = ipdb.interfaces[port_id]
                    if port.ifname == ifname:
                        return True
            except KeyError:
                return False
        return False

    def _is_vxlan_if_on_bridge(self):
        return self._is_if_on_bridge(self.vxlan_if_name)

    def _interface_exists(self, interface):
        """Check if interface exists."""
        (_, exit_code) = self._run_command("ip link show dev %s" % interface,
                                           raise_on_error=False,
                                           acceptable_return_codes=[-1])
        return (exit_code == 0)

    def _unplug_from_bridge(self, interface):
        if self._interface_exists(self.bridge_name):
            self._run_command("brctl delif %s %s" %
                              (self.bridge_name, interface),
                              run_as_root=True,
                              acceptable_return_codes=[0, 1])

    def set_gateway_port(self, linuxif, gw_ip):
        self._run_command("brctl addif %s %s" %
                          (self.bridge_name, linuxif),
                          run_as_root=True,
                          raise_on_error=False)

        self._fdb_dump()

    def gateway_port_down(self, linuxif):
        self._run_command("brctl delif %s %s" %
                          (self.bridge_name, linuxif),
                          run_as_root=True,
                          raise_on_error=False)
        # TODO(tmorin): need to cleanup bridge fdb and ip neigh ?

    def set_bridge_name(self, linuxbr):
        self.bridge_name = linuxbr

    @log_decorator.log_info
    def vif_plugged(self, mac_address, ip_address, localport, dpid, direction):
        # Plug localport only if bridge was created by us
        if BRIDGE_NAME_PREFIX in self.bridge_name:
            self.log.debug("Plugging localport %s into EVPN bridge %s",
                           localport['linuxif'], self.bridge_name)
            self._run_command("brctl addif %s %s" %
                              (self.bridge_name, localport['linuxif']),
                              run_as_root=True,
                              raise_on_error=False)

        self._run_command("bridge fdb replace %s dev %s" %
                          (mac_address, localport['linuxif']),
                          run_as_root=True)

        self._fdb_dump()

    @log_decorator.log_info
    def vif_unplugged(self, mac_address, ip_address, localport, dpid,
                      direction, last_endpoint=True):

        # remove local fdb entry, but only if tap interface is still here
        if self._is_if_on_bridge(localport['linuxif']):
            self._run_command("bridge fdb delete %s dev %s" %
                              (mac_address, localport['linuxif']),
                              run_as_root=True)

        # unplug localport only if bridge was created by us
        if BRIDGE_NAME_PREFIX in self.bridge_name:
            self.log.debug("Unplugging localport %s from EVPN bridge %s",
                           localport['linuxif'], self.bridge_name)
            self._unplug_from_bridge(localport['linuxif'])

        self._fdb_dump()

    @log_decorator.log
    def setup_dataplane_for_remote_endpoint(self, prefix, remote_pe, dpid,
                                            nlri, encaps):
        if self._cleaning_up:
            self.log.debug("setup_dataplane_for_remote_endpoint: instance"
                           " cleaning up, do nothing")
            return

        mac = prefix
        ip = nlri.ip
        vni = dpid

        # populate bridge forwarding db
        self._run_command("bridge fdb replace %s dev %s dst %s vni %s" %
                          (mac, self.vxlan_if_name, remote_pe, vni),
                          run_as_root=True)

        # populate ARP cache
        if ip is not None:
            self._run_command("ip neighbor replace %s lladdr %s dev %s nud "
                              "permanent" % (ip, mac, self.vxlan_if_name),
                              run_as_root=True)
        else:
            self.log.trace("No IP in E-VPN route, no ARP proxy for %s" % mac)

        self._fdb_dump()

    @log_decorator.log
    def remove_dataplane_for_remote_endpoint(self, prefix, remote_pe, dpid,
                                             nlri):
        if self._cleaning_up:
            self.log.debug("setup_dataplane_for_remote_endpoint: instance"
                           " cleaning up, do nothing")
            return

        mac = prefix
        ip = nlri.ip
        vni = dpid

        self._fdb_dump()

        # clear ARP proxy
        if ip is not None:
            self._run_command("ip neighbor del %s lladdr %s dev %s nud "
                              "permanent" % (ip, mac, self.vxlan_if_name),
                              run_as_root=True)

        self._run_command("bridge fdb del %s dev %s dst %s vni %s" %
                          (mac, self.vxlan_if_name, remote_pe, vni),
                          run_as_root=True)

        self._fdb_dump()

    @log_decorator.log
    def add_dataplane_for_bum_endpoint(self, remote_pe, dpid, nlri, encaps):
        if self._cleaning_up:
            self.log.debug("setup_dataplane_for_remote_endpoint: instance"
                           " cleaning up, do nothing")
            return

        vni = dpid

        # 00:00:00:00:00 usable as default since kernel commit
        # 58e4c767046a35f11a55af6ce946054ddf4a8580 (2013-06-25)
        self._run_command("bridge fdb append 00:00:00:00:00:00 dev %s dst %s "
                          "vni %s" % (self.vxlan_if_name, remote_pe, vni),
                          run_as_root=True)

        self._fdb_dump()

    @log_decorator.log
    def remove_dataplane_for_bum_endpoint(self, remote_pe, dpid, nlri):
        if self._cleaning_up:
            self.log.debug("setup_dataplane_for_remote_endpoint: instance"
                           " cleaning up, do nothing")
            return

        vni = dpid

        self._fdb_dump()

        self._run_command("bridge fdb delete 00:00:00:00:00:00 dev %s dst %s "
                          "vni %s" % (self.vxlan_if_name, remote_pe, vni),
                          run_as_root=True)

        self._fdb_dump()

    def _fdb_dump(self):
        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug("bridge fdb dump: %s", self._run_command(
                "bridge fdb show br %s" % self.bridge_name,
                acceptable_return_codes=[0, 255],
                run_as_root=True)[0])

    # Looking glass ####

    def get_lg_local_info(self, path_prefix):
        return {
            "linux_bridge": self.bridge_name,
            "vxlan_if": self.vxlan_if_name
        }


class LinuxVXLANDataplaneDriver(dp_drivers.DataplaneDriver):

    """E-VPN Dataplane driver relying on Linux kernel linuxbridge VXLAN"""

    dataplane_instance_class = LinuxVXLANEVIDataplane
    type = consts.EVPN
    required_kernel = "3.11.0"
    encaps = [exa.Encapsulation(exa.Encapsulation.Type.VXLAN)]

    driver_opts = [
        cfg.IntOpt("vxlan_dst_port", default="4789",
                   help=("UDP port toward which send VXLAN traffic (defaults "
                         "to standard IANA-allocated port)")),
    ]

    def __init__(self):
        super(LinuxVXLANDataplaneDriver, self).__init__()

        self._run_command("modprobe vxlan", run_as_root=True)

    @log_decorator.log_info
    def reset_state(self):
        # delete all EVPN bridges
        cmd = "brctl show | tail -n +2 | awk '{print $1}'| grep '%s'"
        for bridge in self._run_command(cmd % BRIDGE_NAME_PREFIX,
                                        run_as_root=True,
                                        raise_on_error=False,
                                        acceptable_return_codes=[0, 1],
                                        shell=True)[0]:
            self._run_command("ip link set %s down" % bridge,
                              run_as_root=True)
            self._run_command("brctl delbr %s" % bridge,
                              run_as_root=True)

        # delete all VXLAN interfaces
        cmd = "ip link show | awk '{print $2}' | tr -d ':' | grep '%s'"
        for interface in self._run_command(cmd % VXLAN_INTERFACE_PREFIX,
                                           run_as_root=True,
                                           raise_on_error=False,
                                           acceptable_return_codes=[0, 1],
                                           shell=True)[0]:
            self._run_command("ip link set %s down" % interface,
                              run_as_root=True)
            self._run_command("ip link delete %s" % interface,
                              run_as_root=True)
