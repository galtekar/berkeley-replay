#!/bin/sh
LOGGING_LIBS="liblog/.libs/liblog.so.0 libckpt/.libs/libckpt.so.0"
LOGGING_CMD="plab/liblog"
LOGGING_CFG="plab/liblog.cfg"
LOGGER_EXE="logger/loggerbin logger/logger.py logger/log2xmlbin"
REPLAY_LIBS="libreplay/.libs/libreplay.so libckpt/.libs/librestart.so"
REPLAY_EXE="console/trace_logs.py console/friday.py libckpt/ckpt_restart gdb/gdb logger/log2xmlbin"
REPLAY_CONSOLE="console/replay_console.py"
REPLAY_CFG="console/replay.cfg"
SRC_DIRS="libckpt libcommon liblog libreplay"

PACKAGE_DIRS="remote_package local_package"

PACKAGE_SUBDIRS="remote_package/libs remote_package/logger remote_package/logs remote_package/run local_package/exe local_package/libs local_package/log_cache local_package/src"


make -s || exit

set -x
for dir in $PACKAGE_DIRS
do rm -rf $dir
mkdir $dir
done

for dir in $PACKAGE_SUBDIRS
do mkdir $dir
done

cp $LOGGING_LIBS remote_package/libs/
cp $LOGGING_CMD remote_package/
cp $LOGGING_CFG remote_package/run/
cp $LOGGER_EXE remote_package/logger/
cp $LOGGING_LIBS $REPLAY_LIBS local_package/libs/
cp $REPLAY_EXE local_package/exe/
cp $REPLAY_CONSOLE local_package/replay
chmod +x local_package/replay
cp $REPLAY_CFG local_package/

for srcdir in $SRC_DIRS
do cp $srcdir/*.h $srcdir/*.c local_package/src
done
