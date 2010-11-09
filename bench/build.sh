#!/bin/sh
# Script to build and install all applications in suite.
# When script is done, the build output for each app should be in 
# $BENCH_ROOT/build, while the runnable installation should be in
# $BENCH_ROOT/bin.

BUILD_ROOT=$BENCH_ROOT/build
BIN_ROOT=$BENCH_ROOT/bin
SRC_ROOT=$BENCH_ROOT/src

# Hypertable
function build_hypertable() {
   mkdir -p $BUILD_ROOT/hypertable
   mkdir -p $BIN_ROOT/hypertable
   cd $BUILD_ROOT/hypertable
   cmake -DCMAKE_INSTALL_PREFIX= -DCMAKE_BUILD_TYPE="Debug" $SRC_ROOT/hypertable
   make install DESTDIR=$BIN_ROOT/hypertable
}

function build_openssh() {
   cd $SRC_ROOT/openssh-5.1p1/
   ./configure --prefix=$BIN_ROOT/openssh-5.1p1
   make
   make install
   ln -s $SRC_ROOT/openssh-5.1p1 $BUILD_ROOT/openssh-5.1p1
}

function build_memcached() {
   cd $SRC_ROOT/memcached-1.4.5/
   sudo apt-get install libevent-dev
   ./configure --prefix=$BIN_ROOT/memcached-1.4.5
   make install
   ln -s $SRC_ROOT/memcached-1.4.5 $BUILD_ROOT/memcached-1.4.5
}

function build_kfs() {
   ln -s $SRC_ROOT/kfs/build $BUILD_ROOT/kfs
   cd $BUILD_ROOT/kfs
   cmake $SRC_ROOT/kfs
   make
   make install
}

function build_all() {
   build_hypertable
   build_kfs
   build_openssh
   build_memcached
}

while [ "$1" != "${1##[-+]}" ]; do
   case $1 in 
      --hypertable)
      build_hypertable
      shift
      ;;
      --openssh)
      build_openssh
      shift
      ;;
      --kfs)
      build_kfs
      shift
      ;;
      --memcached)
      build_memcached
      shift
      ;;
      --all)
      build_all
      shift
      ;;
      *)
      printf "Usage: ./build [--kfs,--openssh,...,--all]"
   esac
done

