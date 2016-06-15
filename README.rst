=====================
networking-bagpipe
=====================

Driver and agent code to use bagpipe-bgp lightweight implementation
of BGP-based VPNs as a backend, for Neutron-BGPVPN Interconnection
or Neutron ML2.

* Free software: Apache license
* Source: http://git.openstack.org/cgit/openstack/networking-bagpipe
* Bugs: http://bugs.launchpad.net/bagpipe

Overview
--------

This package includes:

* a Neutron ML2 mechanism driver ('bagpipe')
* compute node agent code for::
    * the `bagpipe` ML2 driver
    * the `bagpipe` driver of networking-bgpvpn_

BGP-based VPNs
--------------

BGP-based VPNs rely on extensions to the BGP routing protocol and
typically MPLS or VXLAN encapsulation to provide multi-site isolated
networks. The specification for BGP/MPLS IPVPNs is RFC4364_ and
the specification for E-VPN is RFC7432_.

Neutron ML2 mechanism driver
----------------------------

The `bagpipe` mechanism driver allocates a BGP VPN identifier (called "route target")
for each Neutron network, and will setup an E-VPN instance for each network.

When a Neutron port goes up, the agent on the corresponding compute node provides
this VPN identifier to the locally running `bagpipe-bgp`, to trigger the attachement
of the VM tap interface to the E-VPN instance.

Once E-VPN routes are exchanged, `bagpipe-bgp` setups VXLAN forwarding state in the
linuxbridge.

Neutron BGPVPN Interconnection
------------------------------

The compute node agent code extends the OVS agent of the OVS ML2 driver.

It allows the establishment of interconnections between Neutron networks and
BGP/MPLS IP VPNs, using the BGPVPN Interconnection service plugin
(networking-bgpvpn_) with its bagpipe driver.

How to use ?
------------

How to use the ML2 driver in devstack?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* install devstack (whether stable/kilo or master)

* enable the devstack plugin by adding this to ``local.conf``:

    * to use branch ``stable/X`` (e.g. `stable/mitaka`)::

        enable_plugin networking-bagpipe https://git.openstack.org/openstack/networking-bagpipe.git stable/X

    * to use the development branch::

        enable_plugin networking-bagpipe https://git.openstack.org/openstack/networking-bagpipe.git master

* use the following options in devstack ``local.conf``: ::

    Q_PLUGIN=ml2
    Q_AGENT=bagpipe-linuxbridge
    Q_ML2_PLUGIN_TYPE_DRIVERS=flat,vlan,vxlan,route_target
    Q_ML2_PLUGIN_MECHANISM_DRIVERS=bagpipe

    [[post-config|/$Q_PLUGIN_CONF_FILE]]
    [ml2]
    tenant_network_types=route_target

    [ml2_type_route_target]
    # E-VPN route target ranges
    rt_nn_ranges = 100:119,500:519

    [ml2_bagpipe]
    # Data Center AS number
    as_number = 64512

* configure bagpipe-bgp_ on each compute node

  * (note that with devstack, bagpipe-bgp_ is installed automatically as a git submodule of networking-bagpipe)

  * the following is needed in `local.conf` to configure bagpipe-bgp_ and start it in devstack::

        BAGPIPE_DATAPLANE_DRIVER_EVPN=linux_vxlan.LinuxVXLANDataplaneDriver

        enable_service b-bgp

  * you also need each bagpipe_bgp_ to peer with a BGP Route Reflector:

     * in `local.conf`::

        # IP of your route reflector or BGP router, or fakeRR:
        BAGPIPE_BGP_PEERS=1.2.3.4

     * for two compute nodes, you can use the FakeRR provided in bagpipe-bgp_

     * for more than two compute nodes, you can use GoBGP_ (`sample configuration`_) or a commercial E-VPN implementation (e.g. vendors participating in `EANTC interop testing on E-VPN <http://www.eantc.de/fileadmin/eantc/downloads/events/2011-2015/MPLSSDN2015/EANTC-MPLSSDN2015-WhitePaper_online.pdf>`_)

How to use the networking-bgpvpn_ driver in devstack ?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Information on how to use `bagpipe` driver for networking-bgpvpn_ is provided in
`BGPVPN documentation`_.

.. _bagpipe-bgp: https://github.com/Orange-OpenSource/bagpipe-bgp
.. _networking-bgpvpn: https://github.com/openstack/networking-bgpvpn
.. _RFC4364: http://tools.ietf.org/html/rfc4364
.. _RFC7432: http://tools.ietf.org/html/rfc7432
.. _GoBGP: http://osrg.github.io/gobgp
.. _sample configuration: https://github.com/Orange-OpenSource/bagpipe-bgp/blob/master/samples/gobgp.conf
.. _BGPVPN documentation: http://docs.openstack.org/developer/networking-bgpvpn/bagpipe

