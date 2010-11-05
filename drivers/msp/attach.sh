#!/bin/sh

gdb -ex "file vmlinux" -ex "target remote host:8832" -x debug.cmd
