#!/bin/bash

# Save trace setting
_XTRACE_NETWORKING_BAGPIPE=$(set +o | grep xtrace)
set -o xtrace

if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
    # no-op
    :
elif [[ "$1" == "stack" && "$2" == "install" ]]; then
    setup_develop $NETWORKING_BAGPIPE_DIR
elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    if is_service_enabled neutron-agent || is_service_enabled q-agt ; then
        if is_neutron_legacy_enabled; then
            iniset /$Q_PLUGIN_CONF_FILE bagpipe bagpipe_bgp_port $BAGPIPE_SERVICE_PORT
        else
            iniset $NEUTRON_CORE_PLUGIN_CONF bagpipe_bgp_port $BAGPIPE_SERVICE_PORT
        fi
    fi
    if [[ "$ENABLE_BAGPIPE_L2" == "True" ]]; then
        if is_service_enabled neutron-agent || is_service_enabled q-agt ; then
            echo_summary "Configuring linuxbridge agent for bagpipe"
            if is_neutron_legacy_enabled; then
                iniset /$Q_PLUGIN_CONF_FILE ml2_bagpipe_extension as_number ${BAGPIPE_RT_ASN:-64512}
                iniset /$Q_PLUGIN_CONF_FILE vxlan arp_responder True
            else
                iniset $NEUTRON_CORE_PLUGIN_CONF ml2_bagpipe_extension as_number ${BAGPIPE_RT_ASN:-64512}
                iniset $NEUTRON_CORE_PLUGIN_CONF vxlan arp_responder True
            fi
            source $NEUTRON_DIR/devstack/lib/l2_agent
            plugin_agent_add_l2_agent_extension bagpipe
            configure_l2_agent
        fi
    fi
fi
if [[ "$1" == "unstack" ]]; then
    rm -f $TOP_DIR/lib/neutron_plugins/${BAGPIPE_L2_AGENT}_agent
fi
if [[ "$1" == "clean" ]]; then
    #no-op
    :
fi

echo "Running bagpipe-bgp devstack plugin..."
source $NETWORKING_BAGPIPE_DIR/devstack/plugin.sh.bagpipe_bgp $1 $2 || die $LINEO "error in bagpipe-bgp plugin.sh ($1 $2)"

# Restore trace setting
${_XTRACE_NETWORKING_BAGPIPE}
