#!/usr/bin/env python2.6

######################################################################
# 
# Copyright (C) 2010 The Regents of the University of California. 
# All rights reserved.
#
# Author: Gautam Altekar
#
# vim:ts=4:sw=4:expandtab
#
######################################################################

"""
This plugin obtains info about the control and data planes of a 
program execution using BDR.
"""

import sys, os
import controller, dtaint, itertools, misc
from options import *
from tool import *

class TokenBucket:
    def __init__(self, rate, size, curr_ts):
        self.rate = rate
        self.size = size
        self.bucket = rate
        assert(self.bucket <= self.size)
        self.update_ts = curr_ts

    def fill(self, curr_ts):
        """Fill the token bucket, assuming that the current timestamp 
        @curr_ts is in microseconds."""
        elapsed_time = curr_ts - self.update_ts
        nr_tokens_to_add = min(self.size - self.bucket,\
                (self.rate * elapsed_time) / 1000000)
        self.bucket += nr_tokens_to_add
        #print "Elapsed:", elapsed_time, "Added:", nr_tokens_to_add, "Bucket:", self.bucket
        assert(self.bucket <= self.size)
        self.update_ts = curr_ts

    def consume(self, nr_tokens):
        """Returns number of tokens consumed."""
        nr_tokens_to_rm = min(self.bucket, nr_tokens)
        self.bucket -= nr_tokens_to_rm
        assert(self.bucket >= 0)
        return nr_tokens_to_rm

    def is_consumable(self, nr_tokens):
        """Can we consume any more tokens? i.e., Have we reached
        the data-rate limit?"""
        return self.bucket >= nr_tokens

class Range:
    def __init__(self, start, len):
        self.start = start
        self.len = len
        self.end = start+len

    def subsumes(self, range):
        return self.start <= range.start and range.end <= self.end

    def overlaps(self, range):
        return not (self.end <= range.start or range.end <= range.start)

    def intersection(self, range_b):
        if self.overlaps(range_b):
            if self.subsumes(range_b):
                return Range(range_b.start, range_b.len)
            elif range_b.subsumes(self):
                return Range(self.start, self.len)
            elif self.start < range_b.start:
                return Range(range_b.start, self.end - range_b.start)
            elif range_b.start < self.start:
                return Range(self.start, range_b.end - self.start)
        else:
            return None
    
    def __repr__(self):
        return "(%d, %d)"%(self.start, self.len)


class ChannelProfile:
    def __init__(self):
        self.range_list = []

    def add(self, range):
        """Add a range to the profile. Coalesce contiguous
        ranges in order to reduce memory requirements."""
        range_to_add = range
        if len(self.range_list):
            last = self.range_list[-1]
            # Try to coalesce the ranges
            if last.end == range.start:
                range_to_add = Range(last.start, last.len +
                        range.len)
                self.range_list.pop()
        self.range_list.append(range_to_add)
        return

    def intersects(self, range_b):
        nr_intersect_bytes = 0
        for range in self.range_list:
            if range.start >= range_b.end:
                break
            irange = range.intersection(range_b)
            if irange:
                nr_intersect_bytes += irange.len
        return nr_intersect_bytes

# Assigns a globally unique id to every open file in the distributed
# execution.
class FileGID(controller.Plugin):
    def __init__(self):
        self.gid_map = {}
        self.global_fd_count = 0
        probe_list = [\
            ("io:file,ipc:open:return", self.on_file_open),
            ("io:file,ipc:put:return", self.on_file_put) ]
        controller.Plugin.__init__(self, "file-gid", probe_list)

    def _make_key(self, task, ev):
        # filename needn't be part of the key for it to be globally
        # unique, but it's still useful for debugging
        return (task.ctrl.node_index, ev.file.object_id, ev.file.name)

    def on_file_open(self, task, ev):
        # Note that pid rather than node_index won't work, since it 
        # need not be unique across sessions.
        key = self._make_key(task, ev)
        if key not in self.gid_map:
            self.gid_map[key] = self.global_fd_count
            self.global_fd_count += 1
        log("Open:", ev.file.name, "Key:", key, "Gid:", self.gid_map[key])
        return

    def on_file_put(self, task, ev):
        key = self._make_key(task, ev)
        log("Close:", key)
        if key in self.gid_map:
            del self.gid_map[key]
        else:
            log("WARNING: %s was never in gid_map!\n", key)
        return

    def lookup(self, task, ev):
        key = self._make_key(task, ev)
        log("Lookup:", ev.file.name)
        return (self.gid_map[key], ev.file.name)


class Classifier(controller.Plugin):
    def __init__(self, file_gid):
        self.profile_by_id = {}
        self.length_by_id = {}
        self.file_gid = file_gid
        controller.Plugin.__init__(self, "classifier", [\
           ("io:file,ipc:peek,dequeue:return", 
                   self.on_post_ipc_read),
           ("io:file,ipc:write:return", self.on_post_ipc_write)])
        
    def _update_profile(self, id, range):
        """Update the plane profile, were a profile is a list of
        ranges. Each range indicates the starting position and
        length in the data stream at which control plane data was
        detected."""
        profile = self.profile_by_id[id]
        #print "Profile:", profile
        profile.add(range)
        #print "New profile:", profile
        #print "Stored profile:", self.profile_by_id[id]
        return

    def _on_post_ipc(self, task, ev):
        file_id = self.file_gid.lookup(task, ev)
        if file_id not in self.length_by_id:
            self.length_by_id[file_id] = 0
        log(self, ": considering", file_id)
        if file_id not in self.profile_by_id:
            log(self, ": inserting", file_id)
            self.profile_by_id[file_id] = ChannelProfile()
        for range in self._virtual_detect_control_bytes(task, ev):
            self._update_profile(file_id, range)
        self.length_by_id[file_id] += ev.msg.len
        return

    def on_post_ipc_read(self, task, ev):
        misc.debug("Classifier:", task.index, "recv:", \
                (ev.msg.id, ev.msg.len))
        self._on_post_ipc(task, ev)
        return

    def on_post_ipc_write(self, task, ev):
        misc.debug("Classifier:", task.index, "sent:", \
                (ev.msg.id, ev.msg.len))
        self._on_post_ipc(task, ev)
        return


class DataRateClassifier(Classifier):
    def __init__(self, file_gid):
        Classifier.__init__(self, file_gid)

        self.last_time = 0
        self.nr_bytes_in_window = 0
        self.THRESHOLD_BYTES_PER_SEC = 100000
        self.WINDOW_SIZE_SEC = 1

    def _virtual_detect_control_bytes(self, task, ev):
        id = self.file_gid.lookup(task, ev)
        len = ev.msg.len
        curr_time = task.clock

        if self.last_time == 0:
            self.last_time = curr_time
        # Calculate only for the specified window
        US_PER_SEC = 1000000
        elapsed_time_us = curr_time - self.last_time
        if elapsed_time_us/US_PER_SEC > self.WINDOW_SIZE_SEC:
            self.nr_bytes_in_window = 0
            self.last_time = curr_time
        else:
            self.nr_bytes_in_window += ev.msg.len

        # XXX: what happens if elapsed time is 0?
        bytes_per_sec = self.nr_bytes_in_window / self.WINDOW_SIZE_SEC
        if bytes_per_sec < self.THRESHOLD_BYTES_PER_SEC:
            return [ Range(self.length_by_id[id], ev.msg.len) ]
        else:
            return []


class TokenBucketClassifier(Classifier):
    def __init__(self, file_gid):
        Classifier.__init__(self, file_gid)
        self.bucket_by_id = {}

    def _update_bucket(self, tb, len, curr_time):
        tb.fill(curr_time)
        return tb.consume(len)

    def _virtual_detect_control_bytes(self, task, ev):
        id = self.file_gid.lookup(task, ev)
        len = ev.msg.len
        curr_time = task.clock

        RATE = 100000
        MAX_BUCKET_SIZE = 1000000
        #print "Id:", id
        if id not in self.bucket_by_id:
            self.bucket_by_id[id] = TokenBucket(RATE,\
                MAX_BUCKET_SIZE, curr_time)
        tb = self.bucket_by_id[id]
        nr_bytes_consumed = self._update_bucket(tb, len, curr_time)
        self.bucket_by_id[id] = tb
        assert(nr_bytes_consumed <= len)
        #print (nr_bytes_total, len, nr_bytes_consumed)
        return [ Range(self.length_by_id[id], nr_bytes_consumed) ]

#    def on_syscall(self, task, ev):
#        print "Task", task.index, "made syscall:", ev.sysno
#        print "Clock:", task.clock
#
#    def on_post_device_write(self, task, ev):
#        print "Device write:" #, ev.msg.get_bytes()


class TaintClassifier(Classifier, dtaint.DTaint):
    def __init__(self, origin_files, file_gid):
        # Ordering of base constructor calls is important: we want
        # the classifer callbacks to be made after the taint module
        # has run so that the classifier callbacks have access to
        # updated taint state.
        dtaint.DTaint.__init__(self, origin_files)
        Classifier.__init__(self, file_gid)

    def _virtual_detect_control_bytes(self, task, ev):
        id = self.file_gid.lookup(task, ev)
        nr_bytes_total = self.length_by_id[id]

        # Careful: taint bit need not be consecutive in the taint
        # string
        range_list = []
        for (key, group) in itertools.groupby(ev.msg.get_taint()):
            group_len = sum(1 for _ in group)
            if key == '\0':
                range_list.append(Range(nr_bytes_total, group_len))
            nr_bytes_total += group_len
        return range_list


######################################################################
# Main Script
#
#origin_files = set(["/home/galtekar/tst", "/scratch/galtekar/src/logreplay/bench/jobs/data_files/*", "/home/galtekar/src/logreplay/bench/jobs/data_files/*","/scratch/galtekar/src/logreplay/bench/jobs/hypertable/issue-63/*.tsv"])
origin_files = set()

def compute_stats(base, target):
    log("*"*70)
    log(target)
    log("*"*70)

    stat_map = {}
    for (id, base_profile) in base.profile_by_id.items():
        found_control_bytes = 0
        total_control_bytes = 0
        for range in base_profile.range_list:
            target_profile = target.profile_by_id[id]
            found_control_bytes += target_profile.intersects(range)
            total_control_bytes += range.len
        if total_control_bytes:
            false_negatives = 100 - (float(found_control_bytes) /\
                float(total_control_bytes) * 100.0)
        else:
            false_negatives = 0.0
        log("Id:", id, "False negatives (%):", false_negatives)
        #stat_map[id].false_negatives = false_negatives

    for (id, target_profile) in target.profile_by_id.items():
        false_control_bytes = 0
        total_control_bytes = 0
        for range in target_profile.range_list:
            base_profile = base.profile_by_id[id]
            false_control_bytes += range.len - base_profile.intersects(range)
            total_control_bytes += range.len
        if total_control_bytes:
            false_positives = float(false_control_bytes) /\
                float(total_control_bytes) * 100.0
        else:
            false_positives = 0.0
        log("Id:", id, "False positives (%):", false_positives)

class ClassifyTool(Tool):
    def __init__(self):
        opts = {
            "data-files" : ArgOption("LIST", "track data from files in LIST", self.__set_origin_files)
        }
        optsec = OptionSection("pc", "Plane classifier options", opts)
        Tool.__init__(self, "pc", optsec, "classifies code as 'control' or 'data'")

    def __set_origin_files(self, arg):
        origin_files.add(arg)
        return

    def setup(self, log_file):
        self.log_file = log_file
        plugins = []

        file_gid = FileGID()
        self.gold_standard = TaintClassifier(origin_files, file_gid)
        self.detectors = [DataRateClassifier(file_gid), TokenBucketClassifier(file_gid)]


        # XXX: this is a hack; eventually, we won't need to enable 
        # explicitly since dcgen will be on all the time (if there is no 
        # taint, then there will be no need for instrumentation)
        #group.dcgen_enabled = True
        return self.detectors + [file_gid, self.gold_standard]

    def log(self, *args, **kwargs):
        if self.log_file:
            string = "[%s]: "%(self.name) + ' '.join( map( str, args ))
            self.log_file.write(string + "\n")

    def finish(self):
        for detector in self.detectors:
            compute_stats(self.gold_standard, detector)
            #print detector, ":", detector.profile_by_id
            #print detector, ":", detector.file_gid.gid_map

my_tool = ClassifyTool()
register(my_tool)
log = my_tool.log

#if __name__ == "__main__":
#    group = controller.Controller()
#    #group.dbg_level = 0
#
#    # XXX: needs to be enabled before adding members; should work
#    # before or after
#    group.dcgen_enabled = True
#    group.load(["file:/tmp/bdr-galtekar/recordings/*"])
#
#    # XXX: must come after members are added for syscall handlers to 
#    # be called -- this is an annoying requirement
#    gold_standard = TaintClassifier(group, origin_files)
#
#    #DataRateClassifier(group)
#    detectors = [DataRateClassifier(group), TokenBucketClassifier(group)]
#
#    group.advance("forever")
#
#    #print "Gold standard:", gold_standard.profile_by_id
#    #print "Gold standard:", gold_standard.file_gid.gid_map
#
#    for detector in detectors:
#        compute_stats(gold_standard, detector)
#        #print detector, ":", detector.profile_by_id
#        #print detector, ":", detector.file_gid.gid_map
