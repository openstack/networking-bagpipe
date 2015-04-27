=====================
networking-bagpipe-l2
=====================

Mechanism driver for Neutron ML2 plugin using BGP E-VPNs/IP VPNs as a backend

* Free software: Apache license
* Source: http://git.openstack.org/cgit/stackforge/networking-bagpipe-l2
* Bugs: http://bugs.launchpad.net/bagpipe-l2

Overview
--------

This package includes:

* a Neutron ML2 mechanism driver ('bagpipe')
* a compute node agent

The mechanism driver allocates a BGP VPN identifier (called "route target") for each
new Neutron network. When a Neutron port goes up, the driver indicates to the agent
runnning on the corresponding compute node, which VPN identifier to use for the network
to which the port is attached. The agent then interacts with bagpipe-bgp on the same
compute node to trigger the creation of an E-VPN instance.

The compute node agent can also be used to establish interconnections between Neutron
networks and BGP/MPLS IP VPNs, using the BGPVPN service plugin (bgpvpn_ project) with
its bagpipe driver.


How to use ?
------------

* install a recent devstack (Kilo beta3 for all components except RC1 for Neutron)

* enable the devstack plugin by adding this to `local.conf`: ::

	enable_plugin networking-bagpipe-l2 git@github.com:stackforge/networking-bagpipe-l2.git

* `git clone git@github.com:stackforge/networking-bagpipe-l2.git` in /opt/stack (needed until https://review.openstack.org/#/c/168796/ is merged)

* run devstack (and let it fetch latest openstack code) with the following options: ::

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

* install and configure bagpipe-bgp_ on each compute node, with a peering to at least one common BGP Route Reflector: 

  * for two compute nodes, you can use the FakeRR provided in bagpipe-bgp_
  * for more than two compute nodes, you can use a commercial E-VPN implementation (e.g. vendors participating in `EANTC interop testing on E-VPN <http://www.eantc.de/fileadmin/eantc/downloads/events/2011-2015/MPLSSDN2015/EANTC-MPLSSDN2015-WhitePaper_online.pdf>`_)
  * (work is in progress to allow `OpenContrail BGP stack <https://github.com/Juniper/contrail-controller/tree/master/src/bgp>`_ to be used for BGP Route Reflection)

.. _bagpipe-bgp: https://github.com/Orange-OpenSource/bagpipe-bgp
.. _bgpvpn: https://github.com/stackforge/networking-bgpvpn

