========
Overview
========

BGP-based VPNs rely on extensions to the BGP routing protocol and dataplane
isolation (e.g. MPLS-over-x, VXLAN) to create multi-site isolated virtual
networks over a shared infrastructure, such as BGP/MPLS IPVPNs (RFC4364_) and
E-VPN (RFC7432_). They have been heavily used in IP/MPLS WAN backbones
since the early 2000's.

These BGP VPNs are relevant in the context of Neutron, for two distinct
use cases:

1. creating reachability between Neutron ports (typically VMs) and BGP VPNs
   outside the cloud datacenter (this use case can be relevantindependently
   of the backend chosen for Neutron)

2. leveraging these BGP VPNs in Neutron's backend, to benefit from the
   flexibility, robustness and scalability of the underlying technology
   (as do other existing backends such as OpenContrail, Nuage Networks,
   or Calico -- although the latter relies on plain, non-VPN, BGP)

BaGPipe proposal is to address these two use cases by implementing this
protocol stack -- both the BGP routing protocol VPN extensions and the
dataplane encapsulation -- in compute nodes or possibly ToR switches, and
articulating it with Neutron thanks to drivers and plugins.

The networking-bagpipe package includes:

* for use case 1: backend code for Neutron's BGPVPN Interconnection
  service plugin (networking-bgpvpn_) ; only compute node code (agent
  and BGP) is in networking-bagpipe, the Neutron server-side part,
  being currently in networking-bgpvpn_ package)

* for use case 2: a Neutron ML2 mechanism driver (base Neutron networks),
  a networking-sfc driver (service chaining)

* compute code common to both: agent extensions for Neutron agent
  (linuxbridge or openvswitch) to consolidate and pass information via
  its REST API to BaGPipe-BGP (a lightweight BGP VPN implementation)

.. _networking-bgpvpn: https://github.com/openstack/networking-bgpvpn
.. _RFC4364: http://tools.ietf.org/html/rfc4364
.. _RFC7432: http://tools.ietf.org/html/rfc7432
