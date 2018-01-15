============
Installation
============

Networking-bagpipe installation
-------------------------------

The details related to how a package should be installed may depend on your
environment.

If possible, you should rely on packages provided by your Linux and/or
Openstack distribution.

If you use ``pip``, follow these steps to install networking-bagpipe:

* identify the version of the networking-bagpipe package that matches
  your Openstack version:

  * Liberty: most recent of 3.0.x
  * Mitaka: most recent of 4.0.x
  * Newton: most recent of 5.0.x
  * Ocata: most recent of 6.0.x
  * Pike: most recent of 7.0.x
  * (see https://releases.openstack.org/index.html)

* indicate pip to (a) install precisely this version and (b) take into
  account Openstack upper constraints on package versions for dependencies
  (example for ocata):

  .. code-block:: console

     $ pip install -c  https://git.openstack.org/cgit/openstack/requirements/plain/upper-constraints.txt?h=stable/ocata networking-bagpipe=6.0.0

BaGPipe for Neutron L2
----------------------

Installation in a devstack test/development environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* install devstack (whether stable/kilo or master)

* enable the devstack plugin by adding this to ``local.conf``:

  * to use branch ``stable/X`` (e.g. `stable/mitaka`):

    .. code-block:: none

       enable_plugin networking-bagpipe https://git.openstack.org/openstack/networking-bagpipe.git stable/X

  * to use the development branch:

    .. code-block:: none

       enable_plugin networking-bagpipe https://git.openstack.org/openstack/networking-bagpipe.git master

* enable bagpipe ML2 by adding this to ``local.conf``:

  .. code-block:: ini

    ENABLE_BAGPIPE_L2=True

* note that with devstack, :ref:`bagpipe-bgp` is installed automatically as a git
  submodule of networking-bagpipe

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
ML2/linuxbridge configuration* as a starting point:

* installing networking-bagpipe python package:

  .. code-block:: console

     pip install -c http://git.openstack.org/cgit/openstack/requirements/plain/upper-constraints.txt?h=stable/<release> networking-bagpipe

* in ML2 configuration (``/etc/neutron/plugins/ml2.ini``):

  * adding the ``bagpipe`` mechanism driver (additionally to the
    ``linuxbridge`` driver which will still handle ``flat`` and ``vlan``
    networks)

You need to deploy a BGP Route Reflector, that will distribute BGP VPN routes
among compute and network nodes. This route reflector will need to support
E-VPN and, optionally, RT Constraints. One option, among others is to use
GoBGP_ (`sample configuration`_).

On compute node and network nodes the following needs to be done, *based on an
ML2/linuxbridge configuration* as a starting point:

* installing networking-bagpipe python package

* configuring Neutron linuxbridge agent for bagpipe
  ``/etc/neutron/plugins/ml2.ini``:

  * enabling ``bagpipe`` agent extension

  * disabling VXLAN

  * configuring the AS number and range to use to allocate BGP Route Targets
    for tenant networks

  * result:

    .. code-block:: ini

       [agent]
       extensions = bagpipe

       [vxlan]
       enable_vxlan = False

       [ml2_bagpipe_extension]
       as_number = 64512

* configuring :ref:`bagpipe-bgp`:

  * setting ``local_address`` to the compute node address (or the name of one
    of its interfaces e.g. 'eth0')

  * adding the Route Reflector IP to ``peers``

  * selecting ``linux`` dataplane driver for EVPN

BaGPipe for BGPVPN
------------------

Information on how to use ``bagpipe`` driver for networking-bgpvpn_ is provided
in `BGPVPN bagpipe driver documentation`_.


.. _networking-bgpvpn: http://git.openstack.org/cgit/openstack/networking-bgpvpn
.. _GoBGP: http://osrg.github.io/gobgp
.. _sample configuration: http://git.openstack.org/cgit/openstack/networking-bagpipe/tree/samples/gobgp.conf
.. _BGPVPN bagpipe driver documentation: https://docs.openstack.org/networking-bgpvpn/latest/user/drivers/bagpipe/index.html
