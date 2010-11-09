#!/bin/sh

BIN_ROOT=$BENCH_ROOT/bin/openssh-5.1p1/
DATA_DIR=$BENCH_ROOT/jobs/data_files
PORT=40050

RECORD_CMD=bdr-record

# Create the file to be transferred
# XXX: was originaly count=100000, but taint flow produces OOM error
SIZE_2MB=4000
SIZE_50MB=100000
dd if=/dev/zero of=$DATA_DIR/tmp.dat count=$SIZE_2MB

# Start the server
$RECORD_CMD $BIN_ROOT/sbin/sshd -f $BIN_ROOT/etc/sshd_config -D -p $PORT -d -e &

# Give the server a chance to start up
sleep 5

# Begin the transfer; that's a capital P for port
$RECORD_CMD $BIN_ROOT/bin/scp -P $PORT $DATA_DIR/tmp.dat localhost:/tmp/
