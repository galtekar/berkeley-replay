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
#   A plugin for dumping tasks' tty output to files per a grouping of
#   the user's choice.
#
######################################################################

import controller

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

class TtyFileOutput(controller.Plugin):
    def __init__(self, file):
        self.ofile = file
        controller.Plugin.__init__(self, "tty-file-output",\
                [("io:device:write:return", self._on_tty_write)])
        return

    def _on_tty_write(self, task, ev):
        for s in task.get_iov_bytes(ev.msg.iov_list):
            self.ofile.write(s)
