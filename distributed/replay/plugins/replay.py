#!/usr/bin/env python
# Copyright (C) 2010 The Regents of the University of California. 
# 
# All rights reserved.
#
# Author: Gautam Altekar
#
# vim:ts=4:sw=4:expandtab

######################################################################
#
# A simple plugin that replays a previously recorded execution.
# No analysis is performed. This is useful for testing and demo
# purposes.

import sys, getopt, os, time
sys.path.append(os.path.dirname(sys.argv[0])+"/../engine")
sys.path.append(os.path.dirname(sys.argv[0])+"/../common")
import controller, misc
from progressbar import *

class TtyOutput:
    def __init__(self, group):
        probe_list = [\
            ("io:device:write:return", self._on_post_tty_write),
        ]
        for (spec, cb) in probe_list:
            group.add_probe(spec, cb)

    def _on_post_tty_write(self, task, ev):
        #print ev.msg
        return
        

def usage():
    my_name = os.path.basename(sys.argv[0])
    print "usage: %s [options] <recording> ..."%(my_name)
    

misc.QUIET = False
if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "q", ["quiet"])
    except getopt.GetoptError, ge:
        misc.die( "Caught:" + str(ge) )

    for opt, arg in opts:
        if opt in ("-q", "--quiet"):
            misc.QUIET = True

    if len(args) == 0:
        usage()
        sys.exit(-1)

    group = controller.Controller()
    group.add_members(args[0:])
    tty = TtyOutput(group)

    misc.DEBUG = False
    start_time = time.time()
    (virt_start_time, virt_end_time) = group.get_time()
    total_length = virt_end_time - virt_start_time
    #print virt_start_time, virt_end_time, total_length
    widgets = ['Replay:', Percentage(), ' ', Bar(marker=RotatingMarker()), ' ']
    pbar = ProgressBar(widgets=widgets, maxval=total_length).start()
    while True:
        new_vclock = group.advance("+1")
        if not new_vclock:
            break
        #print "Progress: ", new_vclock - virt_start_time
        pbar.update(new_vclock - virt_start_time)
    pbar.finish()
    finish_time = time.time()

    misc.log("Replayed %f virtual second(s) in %f second(s)."%(total_length / 1000000.0, finish_time - start_time))
