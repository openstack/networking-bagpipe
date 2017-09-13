#!/usr/bin/env bash

set -xe

GATE_DEST=$BASE/new
PROJECT_DIR="$BASE/new/networking-bagpipe"
SCRIPTS_DIR="/usr/os-testr-env/bin/"

venv=${1:-"functional"}

function generate_testr_results {
    # Give job user rights to access tox logs
    sudo -H -u $owner chmod o+rw .
    sudo -H -u $owner chmod o+rw -R .stestr
    if [ -f ".stestr/0" ] ; then
        .tox/$venv/bin/subunit-1to2 < .stestr/0 > ./stestr.subunit
        $SCRIPTS_DIR/subunit2html ./stestr.subunit testr_results.html
        gzip -9 ./stestr.subunit
        gzip -9 ./testr_results.html
        sudo mv ./*.gz /opt/stack/logs/
    fi
}

function generate_log_index {
    local xtrace
    xtrace=$(set +o | grep xtrace)
    set +o xtrace

    virtualenv /tmp/os-log-merger
    /tmp/os-log-merger/bin/pip install -U os-log-merger==1.1.0
    files=$(find /opt/stack/logs/$venv-logs -name '*.txt' -o -name '*.log')
    # -a3 to truncate common path prefix
    # || true to avoid the whole run failure because of os-log-merger crashes and such
    # TODO(ihrachys) remove || true when we have more trust in os-log-merger
    contents=$(/tmp/os-log-merger/bin/os-log-merger -a3 $files || true)
    # don't store DEBUG level messages because they are not very useful,
    # and are not indexed by logstash anyway
    echo "$contents" | grep -v DEBUG | sudo tee /opt/stack/logs/$venv-index.txt > /dev/null

    $xtrace
}

if [[ "$venv" == *functional* ]] || [[ "$venv" == *fullstack* ]]; then
    venv=dsvm-$venv
    owner=stack

    # source go environment to obtain the same one as the one of the devstack plugin
    source $PROJECT_DIR/devstack/gate-hooks/go-env
    # and prepare for sudo using a PATH derived from that
    sudo_env="PATH=$PATH"

    # Set owner permissions according to job's requirements.
    cd $PROJECT_DIR
    sudo chown -R $owner:stack $PROJECT_DIR

    # fix iptables so that BGP traffic from simulated computes to the gobgp instance
    # in th default netns, isn't dropped
    sudo iptables -I openstack-INPUT -i cnt-+ -j ACCEPT
    # ditto for traffic on br- interfaces
    sudo iptables -I openstack-INPUT -i br-+ -j ACCEPT

    # Run tests
    echo "Running neutron $venv test suite"
    set +e
    sudo -E -H -u $owner $sudo_env tox -ve $venv
    testr_exit_code=$?
    set -e

    # move and zip tox logs into log directory
    sudo mv $PROJECT_DIR/.tox/$venv/log /opt/stack/logs/tox
    sudo -H -u $owner chmod o+rw -R /opt/stack/logs/tox/
    gzip -9 /opt/stack/logs/tox/*.log

    # Collect and parse results
    generate_testr_results
    generate_log_index
    exit $testr_exit_code
fi
