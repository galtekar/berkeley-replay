#!/usr/bin/env python2.6
#
# author: Gautam Altekar
# $Id: stack-trace.py,v 2010/9/2 galtekar Exp $
#
# vim:ts=4:sw=4:expandtab

"""Script for printing stack traces of running tasks.
   Depends on GDB."""

import sys, commands, subprocess, os, getopt


def get_stack_trace(tid):
    print "-"*70
    f = open("/proc/%d/cmdline"%(tid))
    cmdline = f.read()
    f.close()
    print tid, cmdline
    print "-"*70
    cmd = "gdb -ex \"attach %d\" -ex \"bt\" --batch --quiet"%(tid)
    return commands.getoutput(cmd)

def trace_by_process_name(name):
    output = commands.getoutput("ps aux|grep " + name)
    lines = output.split('\n')
    for line in lines:
        proginfo = line.split()
        print get_stack_trace(int(proginfo[1]))


##### Main work.
if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["tid=", "name="])
    except getopt.GetoptError, ge:
        print( "Caught:" + str(ge) )
        sys.exit(-1)

    for opt, arg in opts:
        #print opt, arg
        if opt in ("--tid"):
            for tid in arg.split(','):
                print get_stack_trace(int(tid))
        elif opt in ("--name"):
            for name in arg.split(','):
                print trace_by_process_name(name)
        else:
            usage()
            sys.exit(-1)
