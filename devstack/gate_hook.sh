#!/bin/sh

GATE_DEST=$BASE/new

VENV=${1:-"tempest"}

DEVSTACK_PATH=$GATE_DEST/devstack
NEUTRON_PATH=$GATE_DEST/neutron
BAGPIPE_PATH=$GATE_DEST/networking-bagpipe
GATE_HOOKS=$NEUTRON_PATH/neutron/tests/contrib/hooks
BAGPIPE_GATE_HOOKS=$BAGPIPE_PATH/devstack/gate-hooks
LOCAL_CONF=$DEVSTACK_PATH/late-local.conf
DSCONF=/tmp/devstack-tools/bin/dsconf

# Install devstack-tools used to produce local.conf; we can't rely on
# test-requirements.txt because the gate hook is triggered before neutron is
# installed
sudo -H pip install virtualenv
virtualenv /tmp/devstack-tools
/tmp/devstack-tools/bin/pip install -U devstack-tools==0.4.0

# Inject config from bagipe hook into localrc
function load_bagpipe_rc_hook {
    local hook="$1"
    local tmpfile
    local config
    tmpfile=$(tempfile)
    config=$(cat $BAGPIPE_GATE_HOOKS/$hook)
    echo "[[local|localrc]]" > $tmpfile
    $DSCONF setlc_raw $tmpfile "$config"
    $DSCONF merge_lc $LOCAL_CONF $tmpfile
    rm -f $tmpfile
}


case $VENV in
"functional"|"fullstack")
    VENV=dsvm-$VENV

    # The following need to be set before sourcing
    # configure_for_func_testing.
    GATE_STACK_USER=stack
    PROJECT_NAME=networking-bagpipe
    IS_GATE=True
    LOCAL_CONF=$DEVSTACK_PATH/local.conf

    source $DEVSTACK_PATH/functions
    source $NEUTRON_PATH/devstack/lib/ovs

    source $NEUTRON_PATH/tools/configure_for_func_testing.sh

    configure_host_for_func_testing

    # to be replaced by project config bindep trigger
    sudo PATH=/usr/sbin:/sbin:$PATH DEBIAN_FRONTEND=noninteractive \
            apt-get -q --option "Dpkg::Options::=--force-confold" \
            --assume-yes install fping

    # prepare base environment for ./stack.sh
    load_bagpipe_rc_hook stack_base

    # enable monitoring
    load_bagpipe_rc_hook dstat

    # have devstack know about our devstack plugin
    load_bagpipe_rc_hook bagpipe

    # setup go environement variables in devstack
    load_bagpipe_rc_hook go-env
    # create same go environement
    source $BAGPIPE_GATE_HOOKS/go-env
    sudo mkdir -p $GOPATH
    sudo chown -R $STACK_USER:$STACK_USER $GOPATH

    # install gobgp via our devstack plugin
    load_bagpipe_rc_hook gobgp

    # Make the workspace owned by the stack user
    sudo chown -R $STACK_USER:$STACK_USER $BASE

    # temporary fix for bug 1693689
    export IPV4_ADDRS_SAFE_TO_USE=${DEVSTACK_GATE_IPV4_ADDRS_SAFE_TO_USE:-${DEVSTACK_GATE_FIXED_RANGE:-10.1.0.0/20}}

    # deploy devstack as per local.conf
    cd $DEVSTACK_PATH && sudo -E -H -u $GATE_STACK_USER ./stack.sh
    ;;

"tempest")
    $GATE_DEST/devstack-gate/devstack-vm-gate.sh
    ;;

*)
    echo "Unrecognized environment $VENV".
    exit 1
esac

