# Copyright (c) 2017 Orange.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import netaddr
import sqlalchemy as sa
from sqlalchemy.orm import exc

from sqlalchemy import false
from sqlalchemy import true

from oslo_versionedobjects import fields as obj_fields

from neutron.api.rpc.callbacks import resources
from neutron.db import _model_query as model_query
from neutron.db import models_v2
from neutron.objects import base
from neutron.objects import common_types
from neutron.objects.ports import Port

from networking_bagpipe.db import sfc_db as bagpipe_db
from networking_bagpipe.driver import constants

from networking_sfc.db import sfc_db


@base.NeutronObjectRegistry.register
class BaGPipeChainHop(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = bagpipe_db.BaGPipeChainHop

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(),
        'rts': obj_fields.ListOfStringsField(),
        'ingress_gw': obj_fields.IPAddressField(),
        'egress_gw': obj_fields.IPAddressField(),
        'ingress_ppg': common_types.UUIDField(nullable=True,
                                              default=None),
        'egress_ppg': common_types.UUIDField(nullable=True,
                                             default=None),
        'ingress_network': common_types.UUIDField(nullable=True,
                                                  default=None),
        'egress_network': common_types.UUIDField(nullable=True,
                                                 default=None),
        'ingress_ports': obj_fields.ListOfStringsField(nullable=True),
        'egress_ports': obj_fields.ListOfStringsField(nullable=True),
        'readv_from_rts': obj_fields.ListOfStringsField(nullable=True,
                                                        default=None),
        'readv_to_rt': obj_fields.StringField(nullable=True,
                                              default=None),
        'attract_to_rt': obj_fields.StringField(nullable=True,
                                                default=None),
        'redirect_rts': obj_fields.ListOfStringsField(nullable=True,
                                                      default=None),
        'classifiers': obj_fields.StringField(nullable=True,
                                              default=None),
        'reverse_hop': obj_fields.BooleanField(default=False),

        'portchain_id': common_types.UUIDField(),
    }

    fields_no_update = ['id', 'project_id']

    primary_keys = ['portchain_id']

    foreign_keys = {
        'Network': {'ingress_network': 'id', 'egress_network': 'id'}
    }

    synthetic_fields = ['ingress_ports',
                        'egress_ports']

    rt_fields = {'rts', 'readv_from_rts', 'redirect_rts'}

    def from_db_object(self, db_obj):
        super(BaGPipeChainHop, self).from_db_object(db_obj)

        self._load_ingress_ports(db_obj)
        self._load_egress_ports(db_obj)

    def _load_ports_by_side(self, side):
        ports = []
        if getattr(self, side + '_ppg'):
            # pylint: disable=no-member
            reverse_side = (side if self.reverse_hop
                            else constants.REVERSE_PORT_SIDE[side])

            ports = (
                [getattr(pp, reverse_side)
                 for pp in model_query.get_collection_query(
                    self.obj_context,
                    sfc_db.PortPair,
                    filters={'portpairgroup_id': [getattr(self,
                                                          side + '_ppg')]})
                 ]
            )
        elif getattr(self, side + '_network'):
            port_objs = (
                Port.get_objects(self.obj_context,
                                 network_id=getattr(self, side + '_network'))
            )
            ports = [port_obj.id for port_obj in port_objs]

        setattr(self, side + '_ports', ports)
        self.obj_reset_changes([side + '_ports'])

    def _load_ingress_ports(self, db_obj=None):
        self._load_ports_by_side(constants.INGRESS)

    def _load_egress_ports(self, db_obj=None):
        self._load_ports_by_side(constants.EGRESS)

    @staticmethod
    def _is_port_in_pp(context, port_id):
        try:
            query = context.session.query(sfc_db.PortPair)
            query = query.filter(
                sa.or_(sfc_db.PortPair.ingress == port_id,
                       sfc_db.PortPair.egress == port_id))
            query.one()
            return True
        except exc.NoResultFound:
            return False

    @staticmethod
    def _get_chain_hops_for_port_by_ppg_side(context, port_id, side):
        reverse_side = constants.REVERSE_PORT_SIDE[side]

        query = context.session.query(bagpipe_db.BaGPipeChainHop)
        query = query.join(
            sfc_db.PortPairGroup,
            sfc_db.PortPairGroup.id ==
            getattr(bagpipe_db.BaGPipeChainHop, side + '_ppg'))
        query = query.join(
            sfc_db.PortPair,
            sfc_db.PortPair.portpairgroup_id == sfc_db.PortPairGroup.id)
        query = query.filter(
            sa.or_(
                sa.and_(getattr(sfc_db.PortPair, reverse_side) == port_id,
                        bagpipe_db.BaGPipeChainHop.reverse_hop == false()),
                sa.and_(getattr(sfc_db.PortPair, side) == port_id,
                        bagpipe_db.BaGPipeChainHop.reverse_hop == true())))

        return query.all()

    @staticmethod
    def _get_chain_hops_for_port_by_network_side(context, port_id, side):
        reverse_side = constants.REVERSE_PORT_SIDE[side]

        query = context.session.query(bagpipe_db.BaGPipeChainHop)
        query = query.join(
            models_v2.Network,
            sa.or_(
                sa.and_(
                    models_v2.Network.id ==
                    getattr(bagpipe_db.BaGPipeChainHop,
                            side + '_network'),
                    bagpipe_db.BaGPipeChainHop.reverse_hop == false()),
                sa.and_(
                    models_v2.Network.id ==
                    getattr(bagpipe_db.BaGPipeChainHop,
                            reverse_side + '_network'),
                    bagpipe_db.BaGPipeChainHop.reverse_hop == true()))
            )
        query = query.join(
            models_v2.Port,
            models_v2.Port.network_id == models_v2.Network.id)
        query = query.filter(models_v2.Port.id == port_id)

        return query.all()

    @classmethod
    def get_chain_hops_for_port_by_side(cls, context, port_id, side):
        db_objs = []
        if cls._is_port_in_pp(context, port_id):
            db_objs += (
                cls._get_chain_hops_for_port_by_ppg_side(context,
                                                         port_id,
                                                         side)
            )
        else:
            db_objs += (
                cls._get_chain_hops_for_port_by_network_side(context,
                                                             port_id,
                                                             side)
            )

        return [cls._load_object(context, db_obj) for db_obj in db_objs]

    @classmethod
    def get_objects(cls, context, _pager=None, validate_filters=True,
                    **kwargs):
        if 'port_id' in kwargs:
            port_id = kwargs.pop('port_id')
            chain_hops = []

            for side in [constants.INGRESS, constants.EGRESS]:
                chain_hops += cls.get_chain_hops_for_port_by_side(context,
                                                                  port_id,
                                                                  side)

            return chain_hops

        return super(BaGPipeChainHop, cls).get_objects(
            context, _pager=_pager, validate_filters=validate_filters,
            **kwargs)

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(BaGPipeChainHop, cls).modify_fields_from_db(db_obj)

        for field in cls.rt_fields:
            fields[field] = (fields[field].split(',')
                             if fields.get(field) else [])

        for gw_ip in ['ingress_gw', 'egress_gw']:
            if fields.get(gw_ip) is not None:
                fields[gw_ip] = netaddr.IPAddress(fields[gw_ip])

        return fields

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(BaGPipeChainHop, cls).modify_fields_to_db(fields)

        for field in cls.rt_fields:
            if result.get(field):
                result[field] = ','.join(result[field])

        for gw_ip in ['ingress_gw', 'egress_gw']:
            if result.get(gw_ip) is not None:
                result[gw_ip] = cls.filter_to_str(result[gw_ip])

        return result


@base.NeutronObjectRegistry.register
class BaGPipePortHops(base.NeutronObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    fields = {
        'port_id': common_types.UUIDField(),
        'ingress_hops': obj_fields.ListOfObjectsField(
            'BaGPipeChainHop',
            nullable=True),
        'egress_hops': obj_fields.ListOfObjectsField(
            'BaGPipeChainHop',
            nullable=True),
        'service_function_parameters': obj_fields.DictOfStringsField(
            nullable=True)
    }

    synthetic_fields = {'ingress_hops',
                        'egress_hops'}

    @classmethod
    def get_object(cls, context, **kwargs):
        port_id = kwargs['port_id']
        ingress_hops = (
            BaGPipeChainHop.get_chain_hops_for_port_by_side(context,
                                                            port_id,
                                                            constants.INGRESS)
        )
        egress_hops = (
            BaGPipeChainHop.get_chain_hops_for_port_by_side(context,
                                                            port_id,
                                                            constants.EGRESS)
        )
        return cls(port_id=port_id,
                   ingress_hops=ingress_hops,
                   egress_hops=egress_hops)

    @classmethod
    def get_objects(cls, context, **kwargs):
        raise NotImplementedError()


resources.register_resource_class(BaGPipeChainHop)
resources.register_resource_class(BaGPipePortHops)
