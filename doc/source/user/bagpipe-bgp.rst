.. _bagpipe-bgp:

BaGPipe-BGP
===========

BaGPipe-BGP is a component of networking-bagpipe, used on compute nodes
along the Neutron agent and bagpipe agent extension of this agent.

It is a lightweight implementation of BGP VPNs (IP VPNs and
E-VPNs), targeting deployments on compute nodes hosting VMs, in particular for
Openstack/KVM platforms.

The goal of BaGPipe-BGP is *not* to fully implement BGP specifications,
but only the subset of specifications required to implement IP VPN VRFs
and E-VPN EVIs (`RFC4364 <http://tools.ietf.org/html/rfc4364>`__ 
a.k.a RFC2547bis, `RFC7432 <http://tools.ietf.org/html/rfc7432>`__/`draft-ietf-bess-evpn-overlay <http://tools.ietf.org/html/draft-ietf-bess-evpn-overlay>`__,
and `RFC4684 <http://tools.ietf.org/html/RFC4684>`__).

BaGPipe-BGP is designed to use encapsulations over IP (such as
MPLS-over-GRE or VXLAN), and thus does not require the use of LDP. Bare
MPLS over Ethernet is also supported and can be used if compute nodes/routers
have direct Ethernet connectivity.

Typical Use/deployment
----------------------

BaGPipe-BGP has been designed to provide VPN (IP VPN or E-VPN)
connectivity to local VMs running on an Openstack compute node.

BaGPipe-BGP is typically driven via its HTTP REST interface, by
Openstack Neutron agent extensions found in this package.

Moreover, BaGPipe-BGP can also be used standalone (in particular for testing
purposes), with for instance VMs tap interfaces or with veth interfaces to
network namespaces (see `below <#netns-example>`__).

BGP and Route Reflection
------------------------

If you only want to test how to interconnect one compute node running
bagpipe-bgp and an IP/MPLS router, you don't need to setup a BGP Route
Reflector.

However, using BaGPipe-BGP between compute nodes currently requires setting
up a BGP Route Reflector (see :ref:`bgp_implementation` and
`Caveats <#caveats>`__). Typically, passive mode will have to be used
for BGP peerings.

The term "BGP Route Reflector" refers to a BGP implementation that
redistributes routes between iBGP peers
`RFC4456 <http://tools.ietf.org/html/RFC4456>`__.

When using bagpipe-bgp on more than one compute node, we thus need each
instance of BaGPipe-BGP to be configured to peer with at least one route
reflector (see `Configuration <#config>`__).

We provide a tool that can be used to emulate a route reflector to
interconnect **2** BaGPipe-BGP implementations, typically for test
purposes (see `Fake RR <#fakerr>`__).

For more than 2 compute nodes running BaGPipe-BGP, you will need a real BGP
implementation supporting RFC4364 and BGP route reflection (and ideally
also RFC4684), different options can be considered:

*  BGP implementations in other opensource projects would possibly be
   suitable, but we did not explore these exhaustively:

   -  `GoBGP <http://osrg.github.io/gobgp/>`__ , see `sample configuration`_
      and `GoBGP as a RR for bagpipe-bgp PE
      implementations, with
      E-VPN <https://github.com/osrg/gobgp/blob/master/docs/sources/evpn.md>`__

   -  we have successfully used OpenBSD BGPd as an IP VPN RR for
      bagpipe-bgp

   - FRRouting

   - Quagga

*  A commercial router from for instance, Alcatel-Lucent, Cisco or Juniper can
   be used; some of these vendors also provide their OSes as virtual
   machines


.. _bagpipe-bgp-config:

Configuration
-------------

The bagpipe-bgp config file default location is:
``/etc/bagpipe-bgp/bgp.conf``.

It needs to be customized, at least for the following:

*  ``local_address``: the local address to use for BGP sessions and traffic
   encapsulation (can also be specified as an interface, e.g. "eth0", in which
   the IPv4 address of this interface will be used)

*  ``peers``: the list of BGP peers, it depends on the BGP setup that you
   have chosen (see above `BGP Route Reflection <#bgprr>`__)

*  dataplane configuration, if you really want packets to get through
   (see `Dataplane configuration <#dpconfig>`__)

Example with two compute nodes and relying on bagpipe fake route reflector:

*  On compute node A (local\_address=10.0.0.1):

   -  run bagpipe-fakerr

   -  run bagpipe-bgp with peers=127.0.0.1 (compute node A will thus connect to the locally running fake route-reflector)

*  On compute node B (local\_address=10.0.0.2):

   -  run bagpipe-bgp with peers=10.0.0.1

Dataplane driver configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Note well that the dataplane drivers proposed in the sample config file
are *dummy* drivers that will **not** actually drive any dataplane
state. To have traffic really forwarded into IP VPNs or E-VPNs, you need
to select real dataplane drivers.

For instance, you can use the ``ovs`` dataplane driver for IP VPN, and the ``linux``
driver for E-VPN.

**Note well** that there are specific constraints or dependencies applying to
dataplane drivers for IP VPNs:

*  the ``ovs`` driver can be used on most recent Linux kernels,
   but requires an OpenVSwitch with suitable MPLS code (OVS 2.4 to 2.6 was
   tested); this driver can do bare-MPLS or MPLS-over-GRE (but see
   `Caveats <#caveats>`__ for MPLS-over-GRE); for bare MPLS, this driver
   requires the OVS bridge to be associated with an IP address, and that
   VRF interfaces be plugged into OVS prior to calling BaGPipe-BGP API
   to attach them

* the ``linux`` driver relies on the native MPLS stack of the Linux kernel,
  it currently requires a kernel 4.4+ and uses the pyroute2 module that allows
  defining all states via Netlink rather than by executing 'ip' commands

For E-VPN, the ``linux`` driver is supported without any particular additional
configuration being required, and simply requires a Linux kernel >=3.10
(`linux\_vxlan.py <networking_bagpipe/bagpipe_bgp/vpn/evpn/linux_vxlan.py#L269>`__).

Usage
-----

BaGPipe-BGP local service
~~~~~~~~~~~~~~~~~~~~~~~~~

If systemd init scripts are installed (see ``samples/systemd``), ``bagpipe-bgp``
is typically started with: ``systemctl start bagpipe-bgp``

It can also be started directly with the ``bagpipe-bgp`` command
(``--help`` to see what parameters can be used).

By default, it outputs logs on stdin (captured by systemd if run under
systemd).

BaGPipe Fake BGP Route Reflector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you choose to use our fake BGP Route Reflector (see `BGP Route
Reflection <#bgprr>`__), you can start it whether with the
``bagpipe-fakerr`` command, or if you have startup scripts installed,
with ``service bagpipe-fakerr start``.  Note that this tool requires
the additional installation of the ``twisted`` python package.

There isn't anything to configure, logs will be in syslog.

This tool is not a BGP implementation and simply plugs together two TCP
connections face to face.

REST API tool for interface attachments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``bagpipe-rest-attach`` tool allows to exercise the REST API through
the command line to attach and detach interfaces from IP VPN VRFs and
E-VPN EVIs.

See ``bagpipe-rest-attach --help``.

IP VPN example with a VM tap interface
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This example assumes that there is a pre-existing tap interface 'tap42'.

*  on compute node A, plug tap interface tap42, MAC de:ad:00:00:be:ef, IP
   11.11.11.1 into an IP VPN VRF with route-target 64512:77:

   .. code-block:: console

       bagpipe-rest-attach --attach --port tap42 --mac de:ad:00:00:be:ef --ip 11.11.11.1 --gateway-ip 11.11.11.254 --network-type ipvpn --rt 64512:77

*  on compute node B, plug tap interface tap56, MAC ba:d0:00:00:ca:fe, IP
   11.11.11.2 into an IP VPN VRF with route-target 64512:77:

   .. code-block:: console

       bagpipe-rest-attach --attach --port tap56 --mac ba:d0:00:00:ca:fe --ip 11.11.11.2 --gateway-ip 11.11.11.254 --network-type ipvpn --rt 64512:77

Note that this example is a schoolbook example only, but does not
actually work unless you try to use one of the two MPLS Linux dataplane
drivers.

Note also that, assuming that VMs are behind these tap interfaces, these
VMs will need to have proper IP configuration. When BaGPipe-BGP is use
standalone, no DHCP service is provided, and the IP configuration will
have to be static.

Another IP VPN example...
^^^^^^^^^^^^^^^^^^^^^^^^^

In this example, the bagpipe-rest-attach tool will build for you a
network namespace and a properly configured pair of veth interfaces, and
will plug one of the veth to the VRF:

*  on compute node A, plug a netns interface with IP 12.11.11.1 into a new IP
   VPN VRF named "test", with route-target 64512:78

   .. code-block:: console

       bagpipe-rest-attach --attach --port netns --ip 12.11.11.1 --network-type ipvpn --vpn-instance-id test --rt 64512:78

*  on compute node B, plug a netns interface with IP 12.11.11.2 into a new IP
   VPN VRF named "test", with route-target 64512:78

   .. code-block:: console

       bagpipe-rest-attach --attach --port netns --ip 12.11.11.2 --network-type ipvpn --vpn-instance-id test --rt 64512:78

For this last example, assuming that you have configured bagpipe-bgp to
use the ``ovs`` dataplane driver for IP VPN, you will actually be able
to have traffic exchanged between the network namespaces:

.. code-block:: console

    ip netns exec test ping 12.11.11.2
    PING 12.11.11.2 (12.11.11.2) 56(84) bytes of data.
    64 bytes from 12.11.11.2: icmp_req=6 ttl=64 time=1.08 ms
    64 bytes from 12.11.11.2: icmp_req=7 ttl=64 time=0.652 ms

An E-VPN example
^^^^^^^^^^^^^^^^

In this example, similarly as the previous one, the bagpipe-rest-attach
tool will build for you a network namespace and a properly configured
pair of veth interfaces, and will plug one of the veth to the E-VPN
instance:

*  on compute node A, plug a netns interface with IP 12.11.11.1 into a new
   E-VPN named "test2", with route-target 64512:79

   .. code-block:: console

       bagpipe-rest-attach --attach --port netns --ip 12.11.11.1 --network-type evpn --vpn-instance-id test2 --rt 64512:79

*  on compute node B, plug a netns interface with IP 12.11.11.2 into a new
   E-VPN named "test2", with route-target 64512:79

   .. code-block:: console

       bagpipe-rest-attach --attach --port netns --ip 12.11.11.2 --network-type evpn --vpn-instance-id test2 --rt 64512:79

For this last example, assuming that you have configured bagpipe-bgp to
use the ``linux`` dataplane driver for E-VPN, you will
actually be able to have traffic exchanged between the network
namespaces:

.. code-block:: console

    ip netns exec test2 ping 12.11.11.2
    PING 12.11.11.2 (12.11.11.2) 56(84) bytes of data.
    64 bytes from 12.11.11.2: icmp_req=1 ttl=64 time=1.71 ms
    64 bytes from 12.11.11.2: icmp_req=2 ttl=64 time=1.06 ms

Looking glass
~~~~~~~~~~~~~

The REST API (default port 8082) provide troubleshooting information, in
read-only, through the /looking-glass URL.

It can be accessed with a browser: e.g.
http://10.0.0.1:8082/looking-glass or
http://127.0.0.1:8082/looking-glass (a browser extension to nicely
display JSON data is recommended).

It can also be accessed with the ``bagpipe-looking-glass`` utility:

.. code-block:: console

    # bagpipe-looking-glass
    bgp:  (...)
    vpns:  (...)
    config:  (...)
    logs:  (...)
    summary:
      warnings_and_errors: 2
      start_time: 2014-06-11 14:52:32
      local_routes_count: 1
      BGP_established_peers: 0
      vpn_instances_count: 1
      received_routes_count: 0

.. code-block:: console

    # bagpipe-looking-glass bgp peers
    * 192.168.122.1 (...)
      state: Idle

.. code-block:: console

    # bagpipe-looking-glass bgp routes
    match:IPv4/mpls-vpn,*:
      * RD:192.168.122.101:1 12.11.11.1/32 MPLS:[129-B]:
          attributes:
            next_hop: 192.168.122.101
            extended_community: target:64512:78
          afi-safi: IPv4/mpls-vpn
          source: VRF 1 (...)
          route_targets:
            * target:64512:78
    match:IPv4/rtc,*:
      * RTC<64512>:target:64512:78:
          attributes:
            next_hop: 192.168.122.101
          afi-safi: IPv4/rtc
          source: BGPManager (...)
    match:L2VPN/evpn,*: -

Design overview
---------------

The main components of BaGPipe-BGP are:

* the engine dispatching events related to BGP routes between workers
* a worker for each BGP peers
* a VPN manager managing the life-cycle of VRFs, EVIs
* a worker for each IP VPN VRF, or E-VPN EVI
* a REST API:

  - to attach/detach interfaces to VRFs and control the parameters for said VRFs

  - to access internal information useful for troubleshooting (/looking-glass/ URL sub-tree)

Publish/Subscribe design
~~~~~~~~~~~~~~~~~~~~~~~~

The engine dispatching events related to BGP routes is designed with a
publish/subscribe pattern based on the principles in
`RFC4684 <http://tools.ietf.org/html/rfc4684>`__. Workers (a worker can
be a BGP peer or a local worker responsible for an IP VPN VRF) publish
BGP VPN routes with specified Route Targets, and subscribe to the Route
Targets that they need to receive. The engine takes care of propagating
advertisement and withdrawal events between the workers, based on
subscriptions and BGP semantics (e.g. no redistribution between BGP
peers sessions).

Best path selection
~~~~~~~~~~~~~~~~~~~

The core engine does not do any BGP best path selection. For routes
received from external BGP peers, best path selection happens in the VRF
workers. For routes that local workers advertise, no best path selection
is done because two distinct workers will never advertise a route of
same BGP NLRI.

Multi-threading
~~~~~~~~~~~~~~~

For implementation convenience, the design choice was made to use Python
native threads and python Queues to manage the API, local workers, and
BGP peers workloads:

*  the engine (RouteTableManager) is running as a single thread
*  each local VPN worker has its own thread to process route events
*  each BGP peer worker has two threads to process outgoing route
   events, and receive socket data, plus a few timers.
*  VPN port attachment actions are done in the main thread handling
   initial setup and API calls, these calls are protected by Python
   locks

Non-persistency of VPN and port attachments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The BaGPipe-BGP service, as currently designed, does not persist
information on VPNs (VRFs or EVIs) and the ports attached to them. On a
restart, the component responsible triggering the attachment of
interfaces to VPNs, can detect the restart of the BGP and
re-trigger these attachments.

.. _bgp_implementation:

BGP Implementation
~~~~~~~~~~~~~~~~~~

The BGP protocol implementation reuses BGP code from
`ExaBGP <http://code.google.com/p/exabgp>`__. BaGPipe-BGP
only reuses the low-level classes for message encodings and connection setup.

Non-goals for this BGP implementation:

* full-fledged BGP implementation
* redistribution of routes between BGP peers (hence, no route reflection, no eBGP)
* accepting incoming BGP connections
* scaling to a number of routes beyond the number of routes required to
  route traffic in/out of VMs hosted on a compute node running BaGPipe-BGP

Dataplanes
~~~~~~~~~~

BaGPipe-BGP was designed to allow for a modular dataplane
implementation. For each type of VPN (IP VPN, E-VPN) a dataplane driver
is chosen through configuration. A dataplane driver is responsible for
setting up forwarding state for incoming and outgoing traffic based on
port attachment information and BGP routes.

(see `Dataplane driver configuration <#dpconfig>`__)

Caveats
-------

* BGP implementation not written for compliancy

  - the BaGPipe-BGP service does not listen for incoming BGP connections
    (using a BGP route reflector is required to interconnect bagpipe-bgp
    instance together, typically using passive mode for BGP peerings)

  - the state machine, in particular retry timers is possibly not fully compliant

  - however, interop testing has been done with a fair amount of implementations

* standard MPLS-over-GRE, interoperating with routers, requires
  OVS >= 2.8 (previous OpenVSwitch releases do MPLS-o-Ethernet-o-GRE
  and not MPLS-o-GRE)

.. _sample configuration: http://git.openstack.org/cgit/openstack/networking-bagpipe/tree/samples/gobgp.conf
