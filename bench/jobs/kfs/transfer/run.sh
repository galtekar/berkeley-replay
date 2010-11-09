#!/bin/sh

BUILD_ROOT="$BENCH_ROOT/build/kfs"
SCRIPT_ROOT="$BENCH_ROOT/src/kfs/scripts"
MACHINES_FILE="$SCRIPT_ROOT/machines2.cfg"
DATA_DIR=$BENCH_ROOT/jobs/data_files
RECORD_CMD="bdr-record"
#RECORD_CMD="pin-profile"

# Setup the workload machines
# -s is for "serial" as in one at a time; needed to avoid a race in the
# script when using just one node
$SCRIPT_ROOT/kfssetup.py -f $MACHINES_FILE -s -b $BUILD_ROOT

# Launch everything
$SCRIPT_ROOT/kfslaunch.py -f $MACHINES_FILE --start &

# Give the range servers a chance to report to the master
sleep 20

# XXX: files over 500K may result in out-of-memory error during taint
# flow -- due to the fact that kfs reads in the data file 64MB at a
# time, hence requiring 64mb of taint state
#$RECORD_CMD -- cptokfs -s localhost -p 20000 -d $DATA_DIR/2.dat -k /
$RECORD_CMD cptokfs -s localhost -p 20000 -d /home/galtekar/src/tst_zero -k /

$SCRIPT_ROOT/kfslaunch.py -f $MACHINES_FILE --stop
