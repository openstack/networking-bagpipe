Applications
============

----------------------
Neutron networks (ML2)
----------------------

.. Note:: This application is distinct from the use of BaGPipe to create
   IPVPN or E-VPN interconnections in the context of the BGPVPN Interconnection
   API (see below).

The ``bagpipe`` mechanism driver for Neutron's ML2 core plugin, when enabled
along with the corresponding compute node agent extension, will result in
Neutron tenant networks to be realized with E-VPN/VXLAN.

How it works is that a BGP VPN identifier (called a BGP "Route
Target") will be defined for each Neutron tenant network, derived from the
VXLAN VNI a.k.a segmentation ID, and the ``bagpipe`` agent extension on compute
nodes will setup a corresponding E-VPN instance with
this identifier on the local :ref:`bagpipe-bgp` instance on the compute node and
attach VM ports to this instance as needed.

.. blockdiag:: ml2.blockdiag

This solution is currently supported with the linux networking stack (i.e. with
the ``linuxbridge`` agent enabled with bagpipe extension, and :ref:`bagpipe-bgp` driver
for the linux bridge VXLAN implementation).  The approach would be easily
extended to support OpenVSwitch as well.

Another way to understand this approach for someone coming with a Neutron ML2
background is that it is similar to the l2population mechanism except that the
bridge forwarding entries are populated based on BGP VPN routes rather than based on
information distributed in RPCs. This similarity comes with a difference:
while l2population announces the information on one messaging topic, each
compute node receiving information about all Neutron networks even the ones
not present on its vswitch, the behavior with BaGPipe ML2 is that a compute
node will only receive the mappings that it needs.

------------------------------
Neutron BGPVPN Interconnection
------------------------------

.. Note:: This application is distinct from the use of BaGPipe to realize
   Neutron networks with BGP E-VPNs. ``bagpipe`` driver for
   networking-bgpvpn_ supports both IPVPNs and E-VPNs, but does not rely on
   ``bagpipe`` ML2 mechanism driver to do so.

In this application, ``networking-bagpipe`` aims at proposing a lightweight
implementation of the BGPVPN Interconnection service, designed to work with
the ML2 ``openvswitch`` or ``linuxbridge`` mechanism drivers (or as an
alternative with the ``bagpipe`` ML2 mechanism driver).

When used along with the ``openvswitch`` or ``linuxbridge`` ML2 mechanism
driver, it involves the use of:

* ``bagpipe`` driver for the BGPVPN service plugin (in networking-bgpvpn_ package)

* ``bagpipe_bgpvpn`` extension for the Neutron compute node agent
  (in this package)

* :ref:`bagpipe-bgp` lightweight BGP VPN implementation (in this package)

Example with OVS agent:

.. blockdiag:: bgpvpn.blockdiag

----------------------
Service Chaining (SFC)
----------------------

For this application, ``networking-bagpipe`` provides a ``bagpipe`` driver
for the ``networking-sfc`` that will result in service chains defined via the
networking-sfc API, being realized with BGP VPN stiching, BGP VPN route
redistribution and BGP Flowspec routes.

The components involved are:

* ``bagpipe`` driver for the ``networking-sfc`` service plugin (in this package)

* ``bagpipe_sfc`` extension for the Neutron compute node agent
  (in this package)

* :ref:`bagpipe-bgp` lightweight BGP VPN implementation (in this package)

.. Note:: This driver is still quite experimental, and still currently
   relies on using the ``linuxbrige`` agent along with the OVS dataplane
   driver for IPVPN in ``bagpipe-bgp``.

----------------------------------------
Work in progress and future applications
----------------------------------------

Work in progress:

* BaGPipe ML2 with openvswitch agent

Considered:

* networking-l2gw driver leveraging bagpipe-bgp running on a ToR

* L3 plugin for inter-subnet distributed routing

.. _networking-bgpvpn: https://github.com/openstack/networking-bgpvpn
.. _BGPVPN documentation: https://docs.openstack.org/networking-bgpvpn/latest/user/drivers/bagpipe/index.html
.. _draft-ietf-bess-service-chaining: https://tools.ietf.org/html/draft-ietf-bess-service-chaining
