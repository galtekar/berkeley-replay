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
sys.path.append(os.path.dirname(sys.argv[0])+"/../replay/engine")
sys.path.append(os.path.dirname(sys.argv[0])+"/../common")
import controller, misc
from progressbar import *
from options import *
from tool import *
import tty
import classify

############################
## Options
misc.QUIET = False
misc.DEBUG = False
opt_tty_output_by = "group"
tty_file = None
tool_file = None
chosen_tool = None

my_name = os.path.basename(sys.argv[0])

class MyOptions(HelpOptions):
    def __init__(self, tools):
        opts = {
            "tool" : ListOption("NAME", tools.keys(), "null", "use tool named NAME", 
                self.__set_tool),
            "quiet" : ArglessOption("suppress all status messages", 
                self.__quiet),
            "tty-file" : ArgOption("FILE", "send tty output to FILE", 
                self.__tty_file),
            "tty-fd" : ArgOption("FD", "send tty output to file descriptor FD",
                self.__tty_fd),
            "tool-file" : ArgOption("FILE", "send tool output to FILE", 
                self.__tool_file),
            "tool-fd" : ArgOption("FD", "send tool output to file descriptor FD", 
                self.__tool_fd),
            #"tty-group" : ListOption("GROUP", ["group", "node", "task"], "group", "group tty output by GROUP", self.__tty_group)
        }
        basesec = OptionSection("base", "Options available to all tools", opts)
        optsecs = {}
        for tool in tools.values():
            if tool.optsec:
                optsecs[tool.name] = tool.optsec

        HelpOptions.__init__(self, basesec, optsecs)
        return

    def __quiet(self):
        misc.QUIET = True

    def __tty_file(self, arg):
        global tty_file
        tty_file = open(arg, "w+")

    def __tty_fd(self, arg):
        global tty_file
        if arg == "1":
            tty_file = sys.stdout
        elif arg == "2":
            tty_file = sys.stderr

    def __tool_file(self, arg):
        global tool_file
        tool_file = open(arg, "w+")

    def __tool_fd(self, arg):
        global tool_file
        if arg == "1":
            tool_file = sys.stdout
        elif arg == "2":
            tool_file = sys.stderr

    def __tty_group(self, arg):
        global opt_tty_output_by
        modes = ("group", "node", "task")
        if arg not in modes:
            misc.die("supported grouping modes are:", modes)
        opt_tty_output_by = arg

    def __set_tool(self, arg):
        if arg in tools:
            global chosen_tool
            chosen_tool = tools[arg]
        else:
            misc.die("supported tools are:", tools.keys())


    def usage(self):
        print "Usage: %s [options] <URI> ..."%(my_name)
        print "Summary: Replays recording(s) identified by URI(s)."

        print "\nSupported URIs:"
        print "   file     e.g., file:/tmp/bdr-user/recordings/*"
        #print "   hdfs     e.g., hdfs:/hadoop/cluster5/hdfs-run"
        print "   Wildcards are permitted."

        print "\nSupported tools:"
        for (k, v) in sorted(tools.items()):
            print "   %-30s %s"%(k, v.desc)
        Options.usage(self)
        return

class NullTool(Tool):
    def __init__(self):
        Tool.__init__(self, "null", None, "does no analysis")

    def setup(self):
        return []

    def finish(self):
        return

def do_replay_work(group):
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

def do_replay():
    plugins = []
    if tty_file:
        plugins.append(tty.TtyFileOutput(tty_file))

    tool_plugins = chosen_tool.setup(tool_file)
    group = controller.Controller(plugins=plugins+tool_plugins)
    group.load(args)
    total_length = do_replay_work(group)
    chosen_tool.finish()
    return total_length


register(NullTool())

if __name__ == "__main__":
    opt_parser = MyOptions(tools)
    args = opt_parser.parse()

    if len(args) == 0:
        print "%s: missing recording's URI"%(my_name)
        print "Try `%s --help' for more information."%(my_name)
        sys.exit(-1)

    start_time = time.time()
    total_length = do_replay()
    finish_time = time.time()

    misc.log("Replayed %f virtual second(s) in %f second(s)."%(total_length / 1000000.0, finish_time - start_time))

