#!/usr/bin/env python

# Copyright (C) 2010 The Regents of the University of California. 
# 
# All rights reserved.
#
# Author: Gautam Altekar

######################################################################
#
# A simple plugin that replays a previously recorded execution.
# No analysis is performed. This is useful for testing and demo
# purposes.
#

import sys, getopt, os
sys.path.append("../engine")
import controller

opt_quiet = False

class TtyOutput:
    def __init__(self, group):
        probe_list = [\
            ("io:device:write:return", self._on_post_tty_write),
        ]
        for (spec, cb) in probe_list:
            group.add_probe(spec, cb)

    def _on_post_tty_write(self, task, ev):
        print ev.msg.get_data()
        

def usage():
    my_name = os.path.basename(sys.argv[0])
    print "Usage: %s [options] <recording> ..."%(my_name)
    

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "q", ["quiet"])
    except getopt.GetoptError, ge:
        misc.die( "Caught:" + str(ge) )

    for opt, arg in opts:
        if opt in ("-q", "--quiet"):
            opt_quiet = True

    if len(args) == 0:
        usage()
        sys.exit(-1)

    group = controller.Controller()
    group.add_members(args[0:])
    tty = TtyOutput(group)
    group.go()

# vim:ts=4:sw=4:expandtab
