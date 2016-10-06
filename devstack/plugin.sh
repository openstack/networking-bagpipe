#!/bin/bash

# Save trace setting
_XTRACE_NETWORKING_BAGPIPE=$(set +o | grep xtrace)
set -o xtrace

if [[ "$1" == "source" ]]; then
    # no-op
    :
elif [[ "$1" == "stack" && "$2" == "install" ]]; then
    setup_develop $NETWORKING_BAGPIPE_DIR
elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    if is_service_enabled q-agt && [[ "$Q_AGENT" == "bagpipe-linuxbridge" ]]; then
        echo_summary "Configuring linuxbridge agent for bagpipe"
        source $NEUTRON_DIR/devstack/lib/l2_agent
        plugin_agent_add_l2_agent_extension bagpipe
        iniset /$Q_PLUGIN_CONF_FILE vxlan enable_vxlan False
        configure_l2_agent
    fi
fi
if [[ "$1" == "unstack" ]]; then
    rm -f $TOP_DIR/lib/neutron_plugins/${BAGPIPE_L2_AGENT}_agent
fi
if [[ "$1" == "clean" ]]; then
    #no-op
    :
fi

if [[ -d "$BAGPIPE_DIR" ]]; then
    echo "Running bagpipe-bgp devstack plugin..."
    source $BAGPIPE_DIR/devstack/plugin.sh $1 $2
    echo "$BAGPIPE_DIR/devstack/plugin.sh $1 $2: $?"
fi


# Restore trace setting
${_XTRACE_NETWORKING_BAGPIPE}
