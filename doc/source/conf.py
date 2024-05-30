# -*- coding: utf-8 -*-
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys

sys.path.insert(0, os.path.abspath('../..'))
# -- General configuration ----------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinxcontrib.blockdiag',
    'sphinxcontrib.seqdiag',
    #'sphinx.ext.intersphinx',
    'openstackdocstheme',
    'oslo_config.sphinxext',
    'oslo_config.sphinxconfiggen',
]

# openstackdocstheme options
openstackdocs_repo_name = 'openstack/networking-bagpipe'
openstackdocs_pdf_link = True
openstackdocs_auto_name = False
openstackdocs_bug_project = 'networking-bagpipe'
openstackdocs_bug_tag = ''

# autodoc generation is a bit aggressive and a nuisance when doing heavy
# text edit cycles.
# execute "export SPHINX_DEBUG=1" in your terminal to disable

# The suffix of source filenames.
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# General information about the project.
project = 'networking-bagpipe'
copyright = '2013, OpenStack Foundation'

# If true, '()' will be appended to :func: etc. cross-reference text.
add_function_parentheses = True

# If true, the current module name will be prepended to all description
# unit titles (such as .. function::).
add_module_names = True

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'native'

# Example configuration for intersphinx: refer to the Python standard library.
#intersphinx_mapping = {'http://docs.python.org/': None}

# -- Options for HTML output --------------------------------------------------

# The theme to use for HTML and HTML Help pages.  Major themes that come with
# Sphinx are currently 'default' and 'sphinxdoc'.
# html_theme_path = ["."]
# html_theme = '_theme'
html_static_path = ['_static']
html_theme = 'openstackdocs'


# Output file base name for HTML help builder.
htmlhelp_basename = '%sdoc' % project

# -- Options for LaTeX output -------------------------------------------------

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title, author, documentclass
# [howto/manual]).
latex_documents = [
    ('index',
     'doc-%s.tex' % project,
     '%s Documentation' % project,
     'OpenStack Foundation', 'manual'),
]

# -- Options for oslo_config.sphinxconfiggen ---------------------------------

_config_generator_config_files = [
    'neutron-agent.conf',
    'bagpipe-bgp.conf',
    'dataplane-evpn-linux-vxlan.conf',
    'dataplane-ipvpn-mpls-linux.conf',
    'dataplane-ipvpn-mpls-ovs.conf',
]

def _get_config_generator_config_definition(conf):
    config_file_path = '../../etc/oslo-config-generator/%s' % conf
    # oslo_config.sphinxconfiggen appends '.conf.sample' to the filename,
    # strip file extentension (.conf or .ini).
    output_file_path = '_static/config_samples/%s' % conf.rsplit('.', 1)[0]
    return (config_file_path, output_file_path)


config_generator_config_file = [
    _get_config_generator_config_definition(conf)
    for conf in _config_generator_config_files
]
