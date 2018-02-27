Design overview
===============

The common design choices underlying bagpipe architecture are:

a. on Neutron server, allocate and associate BGP VPN constructs necessary to
   realize Neutron API abstractions: network, router, service chain,
   BGP VPN interconnection, etc.

b. pass the information about these BGP VPN constructs to the compute node agent
   via Openstack Neutron message bus (typically, but not necessarily RabbitMQ)

c. on compute node, a bagpipe extension of the Neutron agent (OVS or
   linuxbridge) passes the information to the local implementation of BGP VPN
   extensions (:ref:`bagpipe-bgp`) that will advertise and receive
   BGP VPN routes and populate the dataplane accordingly

d. depending on the use cases, BGP VPN routes are exchanged between compute
   nodes, between compute nodes and DC gateway IP/MPLS routers, or both ; the
   strategy to scale this control plane will depend on the deployment context
   but will typically involve BGP Route Reflectors and the use of the RT
   Constraints pub/sub mechanism (RFC4684_)

e. traffic is exchanged using an overlay encapsulation, with VXLAN as the
   typical choice for vswitch-to-vswitch, and MPLS-over-GRE or MPLS-over-UDP
   (future) as the target for vswitch-to-DC-gateway traffic

.. blockdiag:: overview.blockdiag

.. _RFC4684: http://tools.ietf.org/html/rfc4684
