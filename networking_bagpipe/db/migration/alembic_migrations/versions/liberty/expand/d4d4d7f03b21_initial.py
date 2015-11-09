# Copyright (c) 2015 Orange.
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

"""contract initial
Revision ID: d4d4d7f03b21
Revises: start_networking_bagpipe
Create Date: 2015-10-28 17:35:11.000000
"""

from alembic import op
import sqlalchemy as sa

from neutron.db.migration import cli

# revision identifiers, used by Alembic.
revision = 'd4d4d7f03b21'
down_revision = 'start_networking_bagpipe'
branch_labels = (cli.EXPAND_BRANCH,)


def upgrade():
    op.create_table(
        'ml2_route_target_allocations',
        sa.Column('rt_nn', sa.Integer, nullable=False,
                  autoincrement=False),
        sa.Column('allocated', sa.Boolean, nullable=False),
        sa.PrimaryKeyConstraint('rt_nn'))


def downgrade():
    op.drop_table('ml2_route_target_allocations')
