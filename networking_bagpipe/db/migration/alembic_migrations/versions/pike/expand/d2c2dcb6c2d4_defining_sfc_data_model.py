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
#

"""Defining SFC data-model

Revision ID: d2c2dcb6c2d4
Revises: 6185f1633a3d
Create Date: 2017-03-02 15:59:58.430218

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd2c2dcb6c2d4'
down_revision = 'd4d4d7f03b21'


def upgrade():
    op.create_table(
        'sfc_bagpipe_ppg_rtnn_associations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('ppg_id', sa.String(length=36),  nullable=False),
        sa.Column('rtnn', sa.Integer(), nullable=False),
        sa.Column('is_redirect', sa.Boolean(), nullable=False),
        sa.Column('reverse', sa.Boolean(), nullable=False),

        sa.PrimaryKeyConstraint('id', 'ppg_id'),
        sa.UniqueConstraint('rtnn')
    )

    op.create_table(
        'sfc_bagpipe_chain_hops',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=255), nullable=True),
        sa.Column('portchain_id', sa.String(length=36), nullable=False),
        sa.Column('rts', sa.String(length=255), nullable=True),
        sa.Column('ingress_gw', sa.String(length=64), nullable=False),
        sa.Column('egress_gw', sa.String(length=64), nullable=False),
        sa.Column('ingress_ppg', sa.String(length=36), nullable=True),
        sa.Column('egress_ppg', sa.String(length=36), nullable=True),
        sa.Column('ingress_network', sa.String(length=36), nullable=True),
        sa.Column('egress_network', sa.String(length=36), nullable=True),
        sa.Column('readv_from_rts', sa.String(length=255), nullable=True),
        sa.Column('readv_to_rt', sa.String(length=255), nullable=True),
        sa.Column('attract_to_rt', sa.String(length=255), nullable=True),
        sa.Column('redirect_rts', sa.String(length=255), nullable=True),
        sa.Column('classifiers', sa.String(length=255), nullable=True),
        sa.Column('reverse_hop', sa.Boolean(), nullable=False),

        sa.ForeignKeyConstraint(['ingress_network'],
                                ['networks.id']),
        sa.ForeignKeyConstraint(['egress_network'],
                                ['networks.id']),
        sa.PrimaryKeyConstraint('id', 'portchain_id')
    )
