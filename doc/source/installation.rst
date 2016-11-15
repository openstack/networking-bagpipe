============
Installation
============

BaGPipe for Neutron L2
----------------------

Installation in a devstack test/development environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* install devstack (whether stable/kilo or master)

* enable the devstack plugin by adding this to ``local.conf``:

    * to use branch ``stable/X`` (e.g. `stable/mitaka`)::

        enable_plugin networking-bagpipe https://git.openstack.org/openstack/networking-bagpipe.git stable/X

    * to use the development branch::

        enable_plugin networking-bagpipe https://git.openstack.org/openstack/networking-bagpipe.git master

* enable bagpipe ML2 by adding this to ``local.conf``::

    ENABLE_BAGPIPE_L2=True

* note that with devstack, bagpipe-bgp_ is installed automatically as a git
  submodule of networking-bagpipe

* for multinode setups, configure bagpipe-bgp_ on each compute node, i.e.
  you need each bagpipe-bgp_ to peer with a BGP Route Reflector:

     * in `local.conf`::

        # IP of your route reflector or BGP router, or fakeRR:
        BAGPIPE_BGP_PEERS=1.2.3.4

     * for two compute nodes, you can use the FakeRR provided in bagpipe-bgp_

     * for more than two compute nodes, you can use GoBGP_
       (`sample configuration`_) or a commercial E-VPN implementation (e.g.
       vendors participating in `EANTC interop testing on E-VPN <http://www.eantc.de/fileadmin/eantc/downloads/events/2011-2015/MPLSSDN2015/EANTC-MPLSSDN2015-WhitePaper_online.pdf>`_)

Deployment
~~~~~~~~~~

On Neutron servers, the following needs to be done, *based on an
ML2/linuxbridge configuration* as a starting point:

* installing networking-bagpipe package

* in ML2 configuration (``/etc/neutron/plugins/ml2.ini``):

    * enabling the ``route_target`` type driver (typically keeping ``flat`` and
      ``vlan`` type drivers)

    * adding the ``bagpipe`` mechanism driver (additionally to the
      ``linuxbridge`` driver which will still handle ``flat`` and ``vlan``
      networks)

    * configuring the use of the ``route_target`` type for tenant networks

    * configuring the AS number and range to use to allocate BGP Route Targets
      for tenant networks

    * example result::

          [ml2]
          tenant_network_types = route_target
          type_drivers = flat,vlan,route_target
          mechanism_drivers = bagpipe,linuxbridge

          [ml2_type_route_target]
          rt_nn_ranges = 100:319,500:5190

          [ml2_bagpipe]
          as_number = 64512

You need to deploy a BGP Route Reflector, that will distribute BGP VPN routes
among compute and network nodes. This route reflector will need to support
E-VPN and, optionally, RT Constraints. One option, among others is to use
GoBGP_ (`sample configuration`_).

On compute node and network nodes the following needs to be done, *based on an
ML2/linuxbridge configuration* as a starting point:

* installing networking-bagpipe and bagpipe-bgp_ python packages

* configuring Neutron linuxbridge agent for bagpipe
  ``/etc/neutron/plugins/ml2.ini``:

    * enabling ``bagpipe`` agent extension

    * disabling VXLAN

    * result::

       [agent]
       extensions = bagpipe

       [vxlan]
       enable_vxlan = False

* configuring bagpipe-bgp_

    * setting ``local_address`` to the compute node address

    * adding the Route Reflector IP to ``peers``

    * enabling ``linux_vxlan.LinuxVXLANDataplaneDriver`` for EVPN



BaGPipe for BGPVPN
------------------

Information on how to use ``bagpipe`` driver for networking-bgpvpn_ is provided
in `BGPVPN bagpipe driver documentation`_.

.. _bagpipe-bgp: https://github.com/Orange-OpenSource/bagpipe-bgp
.. _networking-bgpvpn: https://github.com/openstack/networking-bgpvpn
.. _GoBGP: http://osrg.github.io/gobgp
.. _sample configuration: https://github.com/Orange-OpenSource/bagpipe-bgp/blob/master/samples/gobgp.conf
.. _BGPVPN bagpipe driver documentation: http://docs.openstack.org/developer/networking-bgpvpn/bagpipe
