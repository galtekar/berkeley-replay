#!/bin/bash
#
# Copyright 2008 Doug Judd (Zvents, Inc.)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at 
#
# http://www.apache.org/licenses/LICENSE-2.0 
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


this="$0"
while [ -h "$this" ]; do
  ls=`ls -ld "$this"`
  link=`expr "$ls" : '.*-> \(.*\)$'`
  if expr "$link" : '.*/.*' > /dev/null; then
    this="$link"
  else
    this=`dirname "$this"`/"$link"
  fi
done

# convert relative path to absolute path

bin=`dirname "$this"`
script=`basename "$this"`
bin=`cd "$bin"; pwd`
this="$bin/$script"


#
# The installation directory
#
pushd . >& /dev/null
HYPERTABLE_HOME=`dirname "$this"`/..
cd $HYPERTABLE_HOME
export HYPERTABLE_HOME=`pwd`
popd >& /dev/null


#
# Make sure log and run directories exist
#
if [ ! -d $HYPERTABLE_HOME/run ] ; then
    mkdir $HYPERTABLE_HOME/run
fi
if [ ! -d $HYPERTABLE_HOME/log ] ; then
    mkdir $HYPERTABLE_HOME/log
fi

VALGRIND_METASERVER=
VALGRIND_RANGESERVER=
VALGRIND_MASTER=
SLEEP_TIME=10
CONFIG_FILE=$HYPERTABLE_HOME/conf/hypertable.cfg

START_RANGESERVER="true"
START_MASTER="true"


while [ "$1" != "${1##[-+]}" ]; do
    case $1 in
	'')    
	    echo $"$0: Usage: start-test-servers.sh [local|hadoop|kosmos]"
	    exit 1;;   
   --valgrind-meta)
	    VALGRIND_METASERVER="$RECORD_CMD"
	    shift
       ;;
	--valgrind-range)
	    VALGRIND_RANGESERVER="$RECORD_CMD"
	    shift
	    ;;
	--valgrind-master)
	    VALGRIND_MASTER="$RECORD_CMD"
	    shift
	    ;;
	--no-range-server)
	    START_RANGESERVER="false"
	    shift
	    ;;
	--no-master)
	    START_MASTER="false"
	    shift
	    ;;
	*)     
	    echo $"$0: Usage: start-test-servers.sh [local|hadoop|kosmos]"
	    exit 1;;
    esac
done

if [ "$#" -eq 0 ]; then
    echo $"$0: Usage: start-test-servers.sh [local|hadoop|kosmos]"
    exit 1
fi

START_COMMITLOG_BROKER=no
RANGESERVER_OPTS=

#
# Start DfsBroker
#
PIDFILE=$HYPERTABLE_HOME/run/DfsBroker.$1.pid

# galtekar: we don't redirect to a log file (observe that the
# redirection is commented out below). This is to accomodate a vkernel
# bug that currently requires we stdout be a tty.
LOGFILE=$HYPERTABLE_HOME/log/DfsBroker.$1.log

$HYPERTABLE_HOME/bin/serverup dfsbroker
if [ $? != 0 ] ; then

  if [ "$1" == "hadoop" ] ; then
      nohup $HYPERTABLE_HOME/bin/jrun --pidfile $PIDFILE org.hypertable.DfsBroker.hadoop.main --verbose 1>& $LOGFILE &
#      START_COMMITLOG_BROKER=yes
  elif [ "$1" == "kosmos" ] ; then
      $HYPERTABLE_HOME/bin/kosmosBroker --pidfile=$PIDFILE --verbose 1>& $LOGFILE &   
  elif [ "$1" == "local" ] ; then
      $HYPERTABLE_HOME/bin/localBroker --pidfile=$PIDFILE --verbose 1>& $LOGFILE &    
  else
      echo $"$0: Usage: start-test-servers.sh [local|hadoop|kosmos]"      
      exit 1
  fi

  sleep 1
  $HYPERTABLE_HOME/bin/serverup dfsbroker
  if [ $? != 0 ] ; then
      echo -n "DfsBroker ($1) hasn't come up yet, trying again in $SLEEP_TIME seconds ..."
      sleep $SLEEP_TIME
      echo ""
      $HYPERTABLE_HOME/bin/serverup dfsbroker
      if [ $? != 0 ] ; then
	  tail -100 $LOGFILE
	  echo "Problem starting DfsBroker ($1)";
	  exit 1
      fi
  fi
  echo "Successfully started DFSBroker ($1)"
fi


#
# Commit Log broker
#
$HYPERTABLE_HOME/bin/serverup --host=localhost --port=38031 dfsbroker
if [ "$START_COMMITLOG_BROKER" == "yes" ] ; then
      $HYPERTABLE_HOME/bin/localBroker --listen-port=38031 --pidfile=$HYPERTABLE_HOME/run/CommitLog.DfsBroker.$1.pid --verbose 1>& $HYPERTABLE_HOME/log/CommitLog.DfsBroker.$1.log &
      RANGESERVER_OPTS=--log-broker=localhost:38031

  sleep 1
  $HYPERTABLE_HOME/bin/serverup --host=localhost --port=38031 dfsbroker
  if [ $? != 0 ] ; then
      echo -n "DfsBroker (local) hasn't come up yet, trying again in $SLEEP_TIME seconds ..."
      sleep $SLEEP_TIME
      echo ""
      $HYPERTABLE_HOME/bin/serverup --host=localhost --port=38031 dfsbroker
      if [ $? != 0 ] ; then
	  tail -100 $LOGFILE
	  echo "Problem starting Commit Log DfsBroker (local)";
	  exit 1
      fi
  fi
  echo "Successfully started Commit Log DFSBroker (local)"
fi


#
# Reset state
#
rm -rf $HYPERTABLE_HOME/log/hypertable/*
$HYPERTABLE_HOME/bin/dfsclient --eval "rmdir /hypertable"
rm -rf $HYPERTABLE_HOME/hyperspace/*


#
# Start Hyperspace
#
PIDFILE=$HYPERTABLE_HOME/run/Hyperspace.pid
LOGFILE=$HYPERTABLE_HOME/log/Hyperspace.log

if [ ! -d $HYPERTABLE_HOME/hyperspace ] ; then
    mkdir $HYPERTABLE_HOME/hyperspace
fi

$HYPERTABLE_HOME/bin/serverup hyperspace
if [ $? != 0 ] ; then
    $VALGRIND_METASERVER $HYPERTABLE_HOME/bin/Hyperspace.Master --pidfile=$PIDFILE --verbose 1>& $LOGFILE &
    sleep 1
    $HYPERTABLE_HOME/bin/serverup hyperspace
    if [ $? != 0 ] ; then
	echo -n "Hyperspace hasn't come up yet, trying again in $SLEEP_TIME seconds ..."
	sleep $SLEEP_TIME
	echo ""
	$HYPERTABLE_HOME/bin/serverup hyperspace
	if [ $? != 0 ] ; then
	    tail -100 $LOGFILE
	    echo "Problem starting Hyperspace";
	    exit 1
	fi
    fi
fi
echo "Successfully started Hyperspace"

#
# Start Hypertable.Master
#
if [ "$START_MASTER" == "true" ] ; then

    PIDFILE=$HYPERTABLE_HOME/run/Hypertable.Master.pid
    LOGFILE=$HYPERTABLE_HOME/log/Hypertable.Master.log

    $HYPERTABLE_HOME/bin/serverup master
    if [ $? != 0 ] ; then
	$VALGRIND_MASTER $HYPERTABLE_HOME/bin/Hypertable.Master --pidfile=$PIDFILE --verbose 1>& $LOGFILE &
	sleep 1
	$HYPERTABLE_HOME/bin/serverup master
	if [ $? != 0 ] ; then
	    echo -n "Hypertable.Master hasn't come up yet, trying again in $SLEEP_TIME seconds ..."
	    sleep $SLEEP_TIME
	    echo ""
	    $HYPERTABLE_HOME/bin/serverup master
	    if [ $? != 0 ] ; then
		tail -100 $LOGFILE
		echo "Problem statring Hypertable.Master";
		exit 1
	    fi
	fi
    fi
    echo "Successfully started Hypertable.Master"
else
    exit 0
fi

#
# Start Hypertable.RangeServer
#
if [ "$START_RANGESERVER" == "true" ] ; then

    PIDFILE=$HYPERTABLE_HOME/run/Hypertable.RangeServer.pid
    LOGFILE=$HYPERTABLE_HOME/log/Hypertable.RangeServer.log

    $HYPERTABLE_HOME/bin/serverup rangeserver
    if [ $? != 0 ] ; then
	$VALGRIND_RANGESERVER  $HYPERTABLE_HOME/bin/Hypertable.RangeServer $RANGESERVER_OPTS --pidfile=$PIDFILE --verbose 1>& $LOGFILE &
	sleep 1
	$HYPERTABLE_HOME/bin/serverup rangeserver
	if [ $? != 0 ] ; then
	    echo -n "Hypertable.RangeServer hasn't come up yet, trying again in $SLEEP_TIME seconds ..."
	    sleep $SLEEP_TIME
	    echo ""
	    $HYPERTABLE_HOME/bin/serverup rangeserver
	    if [ $? != 0 ] ; then
		tail -100 $LOGFILE
		echo "Problem starting Hypertable.RangeServer";
		exit 1
	    fi
	fi
    fi
    echo "Successfully started Hypertable.RangeServer"
else
    exit 0
fi
