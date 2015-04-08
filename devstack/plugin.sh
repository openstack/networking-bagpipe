#!/bin/bash

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set +o xtrace

if [[ "$1" == "source" ]]; then
	# no-op
	:
elif [[ "$1" == "stack" && "$2" == "install" ]]; then
	setup_develop $NETWORKING_BAGPIPE_L2_DIR
elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
	bagpipe-l2-db-manage --config-file $NEUTRON_CONF --config-file /$Q_PLUGIN_CONF_FILE upgrade head
fi
if [[ "$1" == "unstack" ]]; then
	rm -f $TOP_DIR/lib/neutron_plugins/${BAGPIPE_L2_AGENT}_agent
fi
if [[ "$1" == "clean" ]]; then
	#no-op
	:
fi

set +x
$xtrace

