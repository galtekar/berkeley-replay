#!/bin/sh

RUN_ONCE="true"
WANTS_RECORD="false"
RECORD_CMD="bdr-record"
#RECORD_CMD="pin-profile"

while [ "$1" != "${1##[-+]}" ]; do
    case $1 in
        --repeat)
            RUN_ONCE="false"
            shift
            ;;
        --record)
        WANTS_RECORD="true"
        shift
        ;;
        *)
            echo $"$0: Invalid option - $1"
            exit 1;;
    esac
done

DFS="hadoop"
if [ "$#" -ne 0 ]; then
  DFS=$1
  shift
fi

while true; do
  rm count.output
  rm dbdump

  #cap -S config=$CONFIG -S dfs=$DFS dist
  #cap -S config=$CONFIG -S dfs=$DFS stop
  #cap -S config=$CONFIG -S dfs=$DFS cleandb
  #cap -S config=$CONFIG -S dfs=$DFS start

  #sleep 5

  $HYPERTABLE_HOME/bin/hypertable --no-prompt --config=$CONFIG \
      < query-log-create.hql
  if [ $? != 0 ] ; then
     echo "Unable to create table 'query-log', exiting ..."
     exit 1
  fi


  # issue #63 can be reproduced with 4 workers (1MB splits)
  for ((c=1; c<=1; c++))
  do
     RECORD_CLIENT=
     if [ $WANTS_RECORD == "true" ] ; then
        RECORD_CLIENT="$RECORD_CMD"
     fi
     ($RECORD_CLIENT ./client_work.sh
     if [ $? != 0 ] ; then
        echo "Problem loading table 'query-log', exiting ..."
        exit 1
     fi
     ) &
  done

  wait

  exit 0

  $HYPERTABLE_HOME/bin/hypertable --batch --config=$CONFIG < dump-query-log.hql > dbdump
  wc -l dbdump > count.output
  diff count.output count.golden
  if [ $? != 0 ] ; then
     echo "Got count:"
     cat count.output
     echo "Test failed, exiting ..."
     exit 1
  fi


  #cap -S config=$CONFIG -S dfs=$DFS stop
  #cap -S config=$CONFIG -S dfs=$DFS start

  sleep 5

  time $HYPERTABLE_HOME/bin/hypertable --batch --config=$CONFIG \
      < dump-query-log.hql > dbdump

  wc -l dbdump > count.output
  diff count.output count.golden
  if [ $? != 0 ] ; then
      echo "Test failed (recovery), exiting ..."
      exit 1
  fi

  echo "Test passed."
  if [ $RUN_ONCE == "true" ] ; then
      exit 0
  fi
done
