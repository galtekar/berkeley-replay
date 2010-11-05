# vim:ts=4:sw=4:expandtab

######################################################################
# DTaint : A BDR plugin for tracking taint through a distributed
# system.
#
# Copyright (C) 2010 University of California. All rights reserved.
#
# Author: Gautam Altekar
#
# How it works:
#      The main challenge is in propagating taint across nodes;
#      lower layers take care of the intra-node propagation for us.
#      We leverage the unique global ids assigned to each message.
#      Namely, we map from that global id to a taint metadata 
#      associated with that message.
#
# Limitations:
#      o We are conservative in how we treat tainted files : the
#      entire file is assumed to be tainted if a tainted byte is 
#      written to it. This may lead to overtainting, though we haven't 
#      seen in our limited use of this (e.g., to classify control and
#      data plane code).

import fnmatch, syscall, binascii, common

common.DEBUG = False

class DTaint:
    def __init__(self, group, origin_files):
        self.msg_map = {}
        self.origin_files = origin_files
        self.tainted_files = set()
        self.TEST_UNTAINTED_CASE = False

        # XXX: eventually, we won't need to set a flag, since dcgen will 
        # be on all the time
        probe_list = [\
            ("io:ipc:write:return", self._dtaint_on_post_non_file_ipc_send),
            ("io:ipc:peek,dequeue:return", self._dtaint_on_post_non_file_ipc_recv),
            ("io:file:write:return", self._dtaint_on_post_file_ipc_write),
            ("io:file:peek,dequeue:return", self._dtaint_on_post_file_ipc_read),
            ("syscall::open*:return", self._dtaint_on_post_file_open),
        ]
        for (spec, cb) in probe_list:
            group.add_probe(spec, cb)

    def _dtaint_on_post_file_open(self, task, ev):
        """Determine if the file being opened is a user-data file or
        not, per the list of user-data files specified at the command
        line."""
        fd = ev.sysres
        if fd >= 0:
            filename = task.get_filename_by_fd(fd)
            is_data_file = False
            global_filename = "%d:%s"%(task.ctrl.node_index, filename)
            if global_filename not in self.tainted_files:
                for name in self.origin_files:
                    if fnmatch.fnmatch(filename, name):
                        is_data_file = True
                        break
            else:
                is_data_file = True
            #print "is_data_file:", is_data_file
            if is_data_file and self.TEST_UNTAINTED_CASE == False:
                task.set_plane_by_fd(fd)
            if is_data_file:
                print(\
                    "Opened user-data file: name=%s is_data_file=%d"%(\
                    filename, is_data_file))
        return

    def _dtaint_on_post_file_ipc_write(self, task, ev):
        """Propagate taint into files. We conservatively mark the whole 
        file as tainted."""
        ev.taint_bytes = ev.msg.get_taint()
        common.debug("Writing to file:", ev.file.name,\
                binascii.hexlify(ev.taint_bytes[0:16]), "...")
        assert(len(ev.taint_bytes) == ev.msg.len)
        if ev.taint_bytes.count('\0') != len(ev.taint_bytes):
            global_filename = "%d:%s"%(task.ctrl.node_index, ev.file.name)
            common.debug("Tainting file:", global_filename)
            self.tainted_files.add(global_filename)
            ev.file.set_data_plane()
            if self.TEST_UNTAINTED_CASE:
                assert(0)
        return

    def _dtaint_on_post_file_ipc_read(self, task, ev):
        common.debug("Reading from file:", ev.file.name)
        ev.taint_bytes = ev.msg.get_taint()
        return

    def _dtaint_on_post_non_file_ipc_send(self, task, ev):
        """Tag outgoing message with taint meta-data."""
        common.debug("Task", task.index, "sent:", (ev.msg.id, ev.msg.len))
        if ev.msg.id:
            ev.taint_bytes = ev.msg.get_taint()
            #taint_bytes = ''.join([ str(0) ] * __MSG__.len)
            assert( len(ev.taint_bytes) == ev.msg.len )
            common.debug(\
                    "%d bytes tainted: "%(ev.taint_bytes.count('\1')),\
                    binascii.hexlify(ev.taint_bytes[0:16]), "...")
            self.msg_map[ev.msg.id] = ev.taint_bytes
            if self.TEST_UNTAINTED_CASE:
                assert( ev.taint_bytes.count('\0') == len(ev.taint_bytes) )
        else:
            # Untagged message; assume it's untainted
            ev.taint_bytes = '\0'*ev.msg.len
        return

    def _dtaint_on_post_non_file_ipc_recv(self, task, ev):
        """Extract taint meta-data from incoming message."""
        common.debug("Task", task.index, "received:", (ev.msg.id, ev.msg.len))
        if ev.msg.id:
            # Messsage should've been sent already; bug otherwise
            assert(ev.msg.id in self.msg_map)

            ev.taint_bytes = self.msg_map[ev.msg.id][0:ev.msg.len]
            if self.TEST_UNTAINTED_CASE:
                assert( ev.taint_bytes.count('\0') == len(ev.taint_bytes) )
            ev.msg.set_taint(ev.taint_bytes)
            if ev.spec.function != "peek":
                # Message is being dequeued, so dequeue
                # corresponding taint
                self.msg_map[ev.msg.id] = \
                        self.msg_map[ev.msg.id][ev.msg.len:]
                if len(self.msg_map[ev.msg.id]) == 0:
                    del self.msg_map[ev.msg.id]
        else:
            # Untagged message; assume it's untainted
            ev.taint_bytes = '\0'*ev.msg.len
        return

#class FileOriginDTaint(DTaint):
#    def __init__(self, group, origin_files):
#        DTaint.__init__(self, group)
#        group.add_probe("syscall::open*:return", self.FO_on_post_file_open)
