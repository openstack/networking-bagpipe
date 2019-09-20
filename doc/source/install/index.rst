============
Installation
============

.. _n8g_bagpipe_installation:

Networking-bagpipe installation
-------------------------------

The details related to how a package should be installed may depend on your
environment.

If possible, you should rely on packages provided by your Linux and/or
OpenStack distribution.

If you use ``pip``, follow these steps to install networking-bagpipe:

* identify the version of the networking-bagpipe package that matches
  your Openstack version:

  * Liberty: most recent of 3.0.x
  * Mitaka: most recent of 4.0.x
  * Newton: most recent of 5.0.x
  * Ocata: most recent of 6.0.x
  * Pike: most recent of 7.0.x
  * Queens: most recent of 8.0.x
  * (see https://releases.openstack.org/index.html)

* indicate pip to (a) install precisely this version and (b) take into
  account Openstack upper constraints on package versions for dependencies
  (example for Queens):

  .. code-block:: console

     $ pip install -c https://releases.openstack.org/constraints/upper/queens

BaGPipe for Neutron L2
----------------------

Installation in a devstack test/development environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* install devstack (whether stable/**x** or master)

* enable the devstack plugin by adding this to ``local.conf``:

  * to use branch ``stable/x`` (e.g. `stable/queens`):

    .. code-block:: ini

       enable_plugin networking-bagpipe https://git.openstack.org/openstack/networking-bagpipe.git stable/X

  * to use the development branch:

    .. code-block:: ini

       enable_plugin networking-bagpipe https://git.openstack.org/openstack/networking-bagpipe.git master

* enable bagpipe ML2 by adding this to ``local.conf``:

  .. code-block:: ini

    ENABLE_BAGPIPE_L2=True

* for multinode setups, configure :ref:`bagpipe-bgp` on each compute node, i.e.
  you need each :ref:`bagpipe-bgp` to peer with a BGP Route Reflector:

  * in ``local.conf``:

    .. code-block:: ini

       # IP of your route reflector or BGP router, or fakeRR:
       BAGPIPE_BGP_PEERS=1.2.3.4

  * for two compute nodes, you can use the FakeRR provided in :ref:`bagpipe-bgp`

  * for more than two compute nodes, you can use GoBGP_
    (`sample configuration`_) or a commercial E-VPN implementation (e.g.
    vendors participating in `EANTC interop testing on E-VPN <http://www.eantc.de/fileadmin/eantc/downloads/events/2011-2015/MPLSSDN2015/EANTC-MPLSSDN2015-WhitePaper_online.pdf>`_)

Deployment
~~~~~~~~~~

On Neutron servers, the following needs to be done, *based on an
ML2/linuxbridge or ML2/openvswitch configuration* as a starting point:

* installing ``networking-bagpipe`` python package (see
  :ref:`n8g_bagpipe_installation`)

* in ML2 configuration (``/etc/neutron/plugins/ml2.ini``):

  * adding the ``bagpipe`` mechanism driver (additionally to the
    ``linuxbridge`` or ``openvswitch`` driver which will still handle
    ``flat`` and ``vlan``    networks)

  * *before Queens release* (i.e. if networking-bagpipe < 8) use the
    ``route_target`` type driver as default

  * result:

    .. code-block:: ini

       [ml2]
       # tenant_network_types = route_target  # before queens only!
       mechanism_drivers = openvswitch,linuxbridge,bagpipe


You need to deploy a BGP Route Reflector, that will distribute BGP VPN routes
among compute and network nodes. This route reflector will need to support
E-VPN and, optionally, RT Constraints. One option, among others is to use
GoBGP_ (`sample configuration`_).

On compute node (and network nodes if any) the following needs to be done,
*based on an ML2/linuxbridge or ML2/openvswitch configuration* as a
starting point:

* installing ``networking-bagpipe`` python package (see
  :ref:`n8g_bagpipe_installation`)

* configuring Neutron linuxbridge or OpenvSwitch agent for bagpipe
  ``/etc/neutron/plugins/ml2.ini``:

  * enabling ``bagpipe`` agent extension

  * *before Queens release* (i.e. if networking-bagpipe < 8), disable VXLAN:

  * configuring the AS number and range to use to allocate BGP Route Targets
    for tenant networks

  * result:

    .. code-block:: ini

       [agent]
       extensions = bagpipe

       [vxlan]
       # for a release strictly before OpenStack Queens (networking-bagpipe < 8)
       # enable_vxlan = False

       [ml2_bagpipe_extension]
       as_number = 64512

* configuring :ref:`bagpipe-bgp`:

  * setting ``local_address`` to the compute node address (or the name of one
    of its interfaces e.g. 'eth0')

  * adding the Route Reflector IP to ``peers``

  * selecting the EVPN dataplane driver corresponding to your agent in
    (``/etc/bagpipe-bgp/bgp.conf``):

    * ``ovs`` for the openvswitch agent:

    .. code-block:: ini

       [DATAPLANE_DRIVER_EVPN]
       dataplane_driver = ovs

    * ``linux`` for the linuxbridge agent:

    .. code-block:: ini

       [DATAPLANE_DRIVER_EVPN]
       dataplane_driver = linux


BaGPipe for BGPVPN
------------------

Information on how to use ``bagpipe`` driver for networking-bgpvpn_ is provided
in `BGPVPN bagpipe driver documentation`_.


BaGPipe for networking-sfc
--------------------------

To enable the use of networking-bagpipe driver for networking-sfc, the
following needs to be done:

* enable ``bagpipe`` driver for the ``networking-sfc`` service plugin, in
  ``/etc/neutron/neutron.conf`` and configure its parameters
  (see :ref:`neutron-sfc-config`):

    .. code-block:: ini

       [sfc]
       drivers = bagpipe

       [sfc_bagpipe]
       # examples, of course!
       as_number = 64517
       rtnn = 10000,30000

* add the ``bagpipe_sfc`` agent extension to the Neutron linuxbridge agent
  config in``/etc/neutron/plugins/ml2.ini``:

    .. code-block:: ini

       [agent]
       extensions = bagpipe_sfc

* :ref:`bagpipe-bgp` lightweight BGP VPN implementation, configured to
  use ``ovs`` as dataplane driver for IPVPNs, and ``linux`` as dataplane
  driver for EVPN (``/etc/bagpipe-bgp/bgp.conf``):

    .. code-block:: ini

       [DATAPLANE_DRIVER_IPVPN]
       dataplane_driver = ovs

       [DATAPLANE_DRIVER_EVPN]
       dataplane_driver = linux

In a devstack
~~~~~~~~~~~~~

To experiment with sfc driver in a devstack, the following is can be added
in your `local.conf` (replace stable/X with stable/queens for e.g. Openstack
Queens release) :

    .. code-block:: ini

       enable_plugin networking-sfc https://git.openstack.org/openstack/networking-bagpipe.git
       # enable_plugin networking-sfc https://git.openstack.org/openstack/networking-bagpipe.git stable/X
       enable_plugin networking-bagpipe https://git.openstack.org/openstack/networking-bagpipe.git
       # enable_plugin networking-bagpipe https://git.openstack.org/openstack/networking-bagpipe.git stable/X

       BAGPIPE_DATAPLANE_DRIVER_EVPN=linux
       BAGPIPE_DATAPLANE_DRIVER_IPVPN=ovs

       [[post-config|$NEUTRON_CONF]]

       [sfc]
       drivers = bagpipe

       [sfc_bagpipe]
       as_number = 64517
       rtnn = 10000,30000


       [[post-config|/$NEUTRON_CORE_PLUGIN_CONF]]

       [agent]
       extensions = bagpipe_sfc


.. _networking-bgpvpn: http://git.openstack.org/cgit/openstack/networking-bgpvpn
.. _GoBGP: http://osrg.github.io/gobgp
.. _sample configuration: http://git.openstack.org/cgit/openstack/networking-bagpipe/tree/samples/gobgp.conf
.. _BGPVPN bagpipe driver documentation: https://docs.openstack.org/networking-bgpvpn/latest/user/drivers/bagpipe/index.html
