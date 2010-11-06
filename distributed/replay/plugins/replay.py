#!/usr/bin/env python
#
# Copyright (C) 2010 The Regents of the University of California. 
# 
# All rights reserved.
#
# Author: Gautam Altekar
#
# vim:ts=4:sw=4:expandtab
######################################################################

######################################################################
#
# Summary:
#
#   A simple program that replays a previously recorded execution. It
#   uses plugin architecture to echo tty output to the currrent tty
#   or user-specified file(s).
#
######################################################################

import sys, getopt, os, time
sys.path.append(os.path.dirname(sys.argv[0])+"/../engine")
sys.path.append(os.path.dirname(sys.argv[0])+"/../common")
import controller, misc
from progressbar import *

class Plugin:
    def __init__(self, name, probe_spec_list):
        self.name = name
        self.probe_spec_list = probe_spec_list

class TtyOutput(Plugin):
    def __init__(self, output_by_str, output_file):
        self.output_by_str = output_by_str
        self.output_file = output_file
        self.file_by_id = {}
        Plugin.__init__(self, "tty-output", [\
            ("io:device:write:return", self._on_tty_write),
            ("sys:task:start:return", self._on_task_start) ])

    def _get_task_id(self, task):
        if self.output_by_str == "group":
            return 1
        elif self.output_by_str == "node":
            return task.ctrl.node_index
        elif self.output_by_str == "task":
            return task.index

    def _on_task_start(self, task, ev):
        #print "Started task:", task.index
        id = self._get_task_id(task)
        if id not in self.file_by_id:
            self.file_by_id[id] = open(self.output_file + "." + str(id), "w+")

    def _do_output(self, task, s):
        f = self.file_by_id[self._get_task_id(task)]
        f.write(s)

    def _on_tty_write(self, task, ev):
        for s in task.get_iov_bytes(ev.msg.iov_list):
            self._do_output(task, s)

        
def usage():
    my_name = os.path.basename(sys.argv[0])
    print "usage: %s [options] <recording> ..."%(my_name)
   

misc.QUIET = False
misc.DEBUG = False
opt_tty_output_by = "group"
opt_tty_output_file = None

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "qho:",\
                ["quiet", "help", "tty-output-file=", "tty-output-by="])
    except getopt.GetoptError, ge:
        misc.die( str(ge) )

    for opt, arg in opts:
        if opt in ("-q", "--quiet"):
            misc.QUIET = True
        elif opt in ("-o", "--tty-output-file"):
            opt_tty_output_file = arg
        elif opt in ("--tty-output-by"):
            modes = ("group", "node", "task")
            if arg not in modes:
                misc.die("supported grouping modes are:", modes)
            opt_tty_output_by = arg
        elif opt in ("-h", "--help"):
            usage()
            sys.exit(-1)

    if len(args) == 0:
        usage()
        sys.exit(-1)

    plugins = []
    if opt_tty_output_file:
        plugins.append(TtyOutput(opt_tty_output_by, opt_tty_output_file))
    group = controller.Controller(plugins=plugins)
    group.load(args)

    misc.log("All systems go: %d node(s), %d task(s), %d probe(s)."%(len(group.nodes_by_uuid), len(group.task_by_tid), len(group.probe_list)))

    start_time = time.time()
    (virt_start_time, virt_end_time) = group.get_time()
    total_length = virt_end_time - virt_start_time
    #print virt_start_time, virt_end_time, total_length
    if misc.QUIET == False:
        widgets = ['Replay:', Percentage(), ' ', Bar(marker=RotatingMarker()), ' ']
        pbar = ProgressBar(widgets=widgets, maxval=total_length).start()
    while True:
        new_vclock = group.advance("+1")
        if not new_vclock:
            break
        if misc.QUIET == False:
            pbar.update(new_vclock - virt_start_time)
    if misc.QUIET == False:
        pbar.finish()
    finish_time = time.time()

    misc.log("Replayed %f virtual second(s) in %f second(s)."%(total_length / 1000000.0, finish_time - start_time))
