# Copyright 2025 NTT DATA Group
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

"""Remove linux bridge

Revision ID: 796580a58032
Revises: 0a2ee5cbb1a5
Create Date: 2025-03-02 13:56:36.549392

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '796580a58032'
down_revision = '0a2ee5cbb1a5'
depends_on = ('d2c2dcb6c2d4',)


def upgrade():
    table_names = [
        'sfc_bagpipe_ppg_rtnn_associations',
        'sfc_bagpipe_chain_hops'
    ]
    for table_name in table_names:
        op.drop_table(table_name)
