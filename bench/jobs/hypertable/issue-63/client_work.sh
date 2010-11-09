#!/bin/sh

# We need this sub-script as a result of a bug in DCR : it won't let us 
# pipe from the starting shell as required here.
$HYPERTABLE_HOME/bin/hypertable --no-prompt --batch --config=$CONFIG < load.hql

exit 0
