#!/bin/sh

export HYPERTABLE_HOME=$BENCH_ROOT/bin/hypertable
export CONFIG=$HYPERTABLE_HOME/conf/hypertable.cfg

# For debugging; remove when using collect-data.py
#export RECORD_BASEDIR=/tmp/dcr-galtekar
# IMPORTANT: environemnt should not be inherited, since hypertable uses
# the shell "_" environment variable to determine location of exe. But
# since _ is set to dcr's binary, hypertable will be confused.
#export RECORD_CMD="bdr-record --modules=Record --opts=Sys.Env.Inherit=0;Sys.Debug.Level=5;Record.MaxRate=max;Sys.Classifier.UseAnnotations=0"
export RECORD_CMD="bdr-record"
#export RECORD_CMD="pin-profile"


RUN_ONCE="true"

while [ "$1" != "${1##[-+]}" ]; do
    case $1 in
        --repeat)
            RUN_ONCE="false"
            shift
            ;;
        *)
            echo $"$0: Invalid option - $1"
            exit 1;;
    esac
done


# Start a fresh instance of the servers
$HYPERTABLE_HOME/bin/kill-servers.sh
sleep 3
#$HYPERTABLE_HOME/bin/start-all-servers.sh --valgrind-meta --valgrind-master --valgrind-range-server local
#$HYPERTABLE_HOME/bin/start-all-servers.sh --valgrind-range local
#$HYPERTABLE_HOME/bin/start-all-servers.sh local
#--valgrind-master --valgrind-range local
$HYPERTABLE_HOME/bin/start-all-servers.sh --valgrind-meta --valgrind-master --valgrind-range local
#$RECORD_CMD $HYPERTABLE_HOME/bin/start-all-servers.sh local

sleep 3
# XXX: client needs to be invoked with environment inherited, since
# client_work.sh uses HYPERTABLE_HOME var.

./client.sh --record
#./client.sh
#$RECORD_CMD ./client.sh

./kill.sh
