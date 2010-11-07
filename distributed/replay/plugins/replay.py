#!/usr/bin/env python
#
# Copyright (C) 2010 The Regents of the University of California. 
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
#   Simply replays a recording, using the plugin architecture to echo 
#   tty output to the currrent tty or user-specified file(s). Useful
#   for testing and demos.
#
######################################################################

import sys, getopt, os, time
sys.path.append(os.path.dirname(sys.argv[0])+"/../engine")
sys.path.append(os.path.dirname(sys.argv[0])+"/../common")
import controller, misc
from progressbar import *
from options import *

############################
## Options
misc.QUIET = False
misc.DEBUG = False
opt_tty_output_by = "group"
opt_tty_output_file = None

my_name = os.path.basename(sys.argv[0])

class TtyOutput(controller.Plugin):
    def __init__(self, output_by_str, output_file):
        self.output_by_str = output_by_str
        self.output_file = output_file
        self.file_by_id = {}
        controller.Plugin.__init__(self, "tty-output", [\
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

class MyOptions(Options):
    def __init__(self):
        Options.__init__(self, {
            "quiet" : (None, "suppress all status messages", self.__quiet),
            "tty-file" : ( "FILE", "send tty output to FILE",
                self.__tty_file),
            "tty-group" : ( "GROUP", "group tty output by GROUP=[group|node|task]", self.__tty_group),
        })
        return

    def __quiet(self):
        misc.QUIET = True

    def __tty_file(self, arg):
        global opt_tty_output_file
        opt_tty_output_file = arg

    def __tty_group(self, arg):
        global opt_tty_output_by
        modes = ("group", "node", "task")
        if arg not in modes:
            misc.die("supported grouping modes are:", modes)
        opt_tty_output_by = arg

    def usage(self):
        print "Usage: %s [options] <URI> ..."%(my_name)
        print "Summary: Replays recording(s) identified by URI arg(s)."

        print "\nSupported URIs:"
        print "   file     e.g., file:/tmp/bdr-user/recordings/*"
        print "   hdfs     e.g., hdfs:/hadoop/cluster5/hdfs-run"
        print "   Wildcards are permitted."
        Options.usage(self)
        return

def do_replay():
    plugins = []
    if opt_tty_output_file:
        plugins.append(TtyOutput(opt_tty_output_by, opt_tty_output_file))
    group = controller.Controller(plugins=plugins)
    group.load(args)

    misc.log("All systems go: %d node(s), %d task(s), %d probe(s)."%(len(group.nodes_by_uuid), len(group.task_by_tid), len(group.probe_list)))

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
    return total_length

if __name__ == "__main__":
    opt_parser = MyOptions()
    args = opt_parser.parse()

    if len(args) == 0:
        print "%s: missing recording URI"%(my_name)
        print "Try `%s --help' for more information."%(my_name)
        sys.exit(-1)

    start_time = time.time()
    total_length = do_replay()
    finish_time = time.time()

    misc.log("Replayed %f virtual second(s) in %f second(s)."%(total_length / 1000000.0, finish_time - start_time))
