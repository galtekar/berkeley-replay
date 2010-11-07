#!/usr/bin/env python

######################################################################
# 
# Copyright (C) 2010 The Regents of the University of California. 
# All rights reserved.
#
# Author: Gautam Altekar
#
# vim:ts=4:sw=4:expandtab
#
# Summary:
#
#   Replays a recording. Optionally, enables distributed analyses to be
#   performed on the replaying execution.
#
######################################################################

import sys, getopt, os, time
sys.path.append(os.path.dirname(sys.argv[0])+"/../engine")
sys.path.append(os.path.dirname(sys.argv[0])+"/../common")
import controller, misc
from progressbar import *
from options import *
import tty, classify

############################
## Options
misc.QUIET = False
misc.DEBUG = False
opt_tty_output_by = "group"
opt_tty_output_file = None
opt_classify_plane = False

my_name = os.path.basename(sys.argv[0])

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
        print "Summary: Replays recording(s) identified by URI(s)."

        print "\nSupported URIs:"
        print "   file     e.g., file:/tmp/bdr-user/recordings/*"
        print "   hdfs     e.g., hdfs:/hadoop/cluster5/hdfs-run"
        print "   Wildcards are permitted."
        Options.usage(self)
        return

def do_replay():
    plugins = []
    if opt_tty_output_file:
        plugins.append(tty.TtyOutput(opt_tty_output_by, opt_tty_output_file))

    if opt_classify_plane:
        file_gid = classify.FileGID()
        origin_files = []

        # XXX: must come after members are added for syscall handlers to 
        # be called -- this is an annoying requirement
        gold_standard = classify.TaintClassifier(origin_files, file_gid)
        detectors = [classify.DataRateClassifier(file_gid), classify.TokenBucketClassifier(file_gid)]
        detectors.append(gold_standard)
        plugins.extend(detectors)
        plugins.append(file_gid)

    group = controller.Controller(plugins=plugins)

    # XXX: this is a hack; ideally, dcgen should be enabled by dtaint
    if opt_classify_plane:
        group.dcgen_enabled = True
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
        print "%s: missing recording's URI"%(my_name)
        print "Try `%s --help' for more information."%(my_name)
        sys.exit(-1)

    start_time = time.time()
    total_length = do_replay()
    finish_time = time.time()

    misc.log("Replayed %f virtual second(s) in %f second(s)."%(total_length / 1000000.0, finish_time - start_time))
