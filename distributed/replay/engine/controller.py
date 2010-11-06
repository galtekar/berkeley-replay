# Copyright (C) 2010 Regents of the University of California
# All rights reserved.
#
# Author: Gautam Altekar
import sys, os, heapq, socket, random, select, dbm, atexit, xmlrpclib
import controllee, misc, msg_stub, probe, events, struct
import urlparse_custom, urlparse, dfs, fnmatch, recording
from misc import *
import solver

env = os.environ

my_dir=os.path.dirname(sys.argv[0])
REPLAY_DONE_BIN=my_dir+"/worker.py"

class Task:
    def __init__( self, index, ctrl, pid, tid ):
        self.index = index
        self.ctrl = ctrl
        self.pid = pid
        self.tid = tid
        self.var_cache = {}

        self.STATE_REG = 0
        self.STATE_MEM = 1

    # XXX: These should be cached.
    @property
    def vclock(self):
        return self.ctrl.get_status()[0]

    @property
    def clock(self):
        return self.ctrl.get_status()[2]

    def _get_sub_formula( self, ctrl, byte_name_list, radius ):
        # XXX: join sub-formulas connected across nodes
    #try:
        form_str_list = ctrl.node.lookup_var( str(ctrl.rec), byte_name_list )

    #except xmlrpclib.Fault, err:
        #if err.faultString.

        return form_str_list
        #return "%s : BITVECTOR(1); ASSERT( %s = 0bin1);"%(str(byte),\
        #        str(byte))

    def _update_cache( self, ctrl, byte_list ):
        byte_name_list = [ str(byte) for byte in byte_list ]
        form_str_list = self._get_sub_formula(ctrl, byte_name_list, 0)
        for form_str in form_str_list:
            #misc.debug("formula:", form_str)
            start_time = time.time() 
            sol = solver.solve_formula(form_str)
            end_time = time.time()
            #misc.debug( sol )
            misc.log( "Solving formula: ")
            misc.out( form_str[0:128], "..." )
            misc.log( "Solved in ", end_time - start_time, "seconds.")
            self.var_cache.update(sol)

    def _read_state( self, kind, start_offset, len_bytes ):
        symbyte_list = []
        if kind == self.STATE_REG:
            func = self.ctrl.read_reg
        elif kind == self.STATE_MEM:
            func = self.ctrl.read_mem
        else:
            assert( 0 )

        symbyte_list = func(self.tid, start_offset, len_bytes)
        #misc.debug( "symbyte_list:", symbyte_list )

        # Lookup in the cache first
        unresolved_bytes = []
        for byte in symbyte_list:
            var_name = str(byte)
            if byte.is_symbolic and False: # XXX: disabled for hotdep paper
                if var_name not in self.var_cache:
                    unresolved_bytes.append(byte)

        # Resolve the cache misses, update the cache
        misc.debug(len(unresolved_bytes), "bytes unresolved")
        if len(unresolved_bytes):
            self._update_cache(self.ctrl, unresolved_bytes)
      
        # Okay, everything should be resolved and in the cache now.
        val_list = []
        for byte in symbyte_list:
            if byte.is_symbolic and False: # XXX: disabled for hotdep paper
                var_name = str(byte)
                try:
                    var_val = self.var_cache[var_name]
                except KeyError:
                    # If a symbolic input isn't used by the program,
                    # then it won't be in the formula (due to lazy
                    # declaration). In that case, it's safe to return an
                    # arbitrary value. We pick 0.
                    var_val = self.var_cache[var_name] = 0

                byte_val = (var_val >> (byte.idx*8)) & 0xFF
                val_list.append(byte_val)
            else:
                val_list.append(byte.val)
        return ''.join([ struct.pack('B', val) for val in val_list ])

    def get_reg_bytes( self, start_offset, len_bytes ):
        return self._read_state( self.STATE_REG, start_offset, len_bytes )

    def get_mem_bytes( self, start_offset, len_bytes ):
        return self._read_state( self.STATE_MEM, start_offset, len_bytes )

    def set_brkpt( self, brkpt_kind, loc ):
        self.ctrl.set_brkpt( self.tid, brkpt_kind, loc )
        return

    def del_brkpt( self, brkpt_kind, loc ):
        self.ctrl.del_brkpt( self.tid, brkpt_kind, loc )
        return

    def get_filename_by_fd( self, fd ):
        return self.ctrl.get_filename_by_fd( self.tid, fd )

    def set_plane_by_fd( self, fd ):
        self.ctrl.set_plane_by_fd( self.tid, fd )
        return

    def __repr__( self ):
        return "index=%d tid=%d ctrl=%s"%(self.index, self.tid,\
                self.ctrl)


group_set = set()

class Node(xmlrpclib.ServerProxy):
    def __init__( self, url_str ):
        xmlrpclib.ServerProxy.__init__(self, url_str)
        self.url = urlparse.urlparse(url_str)
        return

class ControllerException(Exception):
    pass

class Controller:
    """The heart of the distributed replay engine. It manages all of
    the controllees (i.e., sessions) while they replay. Extension
    modules query the controller for distributed (i.e., controllee) 
    state."""

    def __init__( self, dbg_level=0, start_vclock=0,
            jit_enabled=True, verify_enabled=False ):
        self.replay_controllees_by_index = {}  
        self.nr_controllees_created = 0
        self.tasks_by_index = {}     
        self.nr_tasks_created = 0
        self.nr_nodes_created = 0
        self.nodes_by_uuid = {}
        self.current_tasks_by_index = set()
        self.task_by_tid = {}

        self._read_config()

        self.dbg_level = dbg_level
        self.start_vclock = start_vclock
        self.jit_enabled = jit_enabled
        self.verify_enabled = verify_enabled
        self.dcgen_enabled = False

        self.node_list = []
        self._start_workers(self.node_list)

        group_set.add(self)

    def _read_config(self):
        SECTION_NAME = "replay"
        DEFAULT_PREFS = { 
                "cache_base_dir" : "/tmp/bdr-"+env["USER"]+"/replay-cache/",
                "vkernel_bin" : "/usr/bin/bdr-kernel",
                "hadoop_bin" : "/usr/bin/hadoop",
        }
        pref = misc.load_preferences(SECTION_NAME, DEFAULT_PREFS)
        if not pref:
            die("ERROR: Problem with configuration files\n")

    def _start_workers(self, node_list):
        misc.out( 'Bringing up the cluster...' )
        node_names = set([ "localhost" ])

        ssh_bin = misc.get_conf("ssh_bin")

        #widgets = ['Nodes:', Percentage(), ' ', Bar(marker=RotatingMarker()), ' ']
        #pbar = ProgressBar(widgets=widgets, maxval=len(node_names)).start()
        count = 0
        for hostname in node_names:
            node = None
            for i in xrange(2):
                try:
                    node = Node("http://%s:8000/"%(hostname))
                    node.ping()
                except:
                    #print "Starting " + REPLAY_DONE_BIN
                    if i == 0:
                        child = misc.start_child( [ssh_bin, hostname, REPLAY_DRONE_BIN ], out_file=file('worker.out', 'a') )
                        time.sleep(1)
                else:
                    break

            if node.ping():
                node_list.append(node)
            else:
                misc.error( 'Problem initializing replay node', hostname )
            count += 1
            #pbar.update(count)
        #pbar.finish()
        misc.out( 'All %d node(s) initialized.'%(len(node_names)) )

    def _add_task( self, ctrl, pid, tid ):
        index = self.nr_tasks_created

        task = Task( index, ctrl, pid, tid )
        self.task_by_tid[tid] = task

        self.nr_tasks_created += 1
        self.tasks_by_index[index] = task
        self.current_tasks_by_index.add(index)

    def _remove_task( self, tid ):
        index = self.task_by_tid[tid].index

        # Update local
        del self.task_by_tid[tid]

        # Update parent
        del self.tasks_by_index[index]
        if index in self.current_tasks_by_index:
            self.current_tasks_by_index.remove(index)
        misc.debug( "after remove:", self.tasks_by_index )


    def kill_ctrl( self, ctrl ):
        debug( "Removing ctrl index:", ctrl.index )
        del self.replay_controllees_by_index[ctrl.index]
        ctrl.kill( "shutdown" )

    def kill_all_ctrls( self ):
        for ctrl in self.replay_controllees_by_index.values():
            self.kill_ctrl( ctrl )
        
    def _join_id_list( self, id_list ):
        """Returns intersection of id_list and list of current replay
        indices."""
        max_i = self.nr_tasks_created
        #if id_list == "all":
        #    indices = range(max_i)
        #else:
        assert isinstance( id_list, list )

        # Now match against valid replay indices
        indices = [i for i in id_list if (i < max_i)]
        debug( id_list, " -> ", indices )
        return indices

    def get_active_tasks( self ):
        debug( "active tasks:", self.tasks_by_index )
        if not self.current_tasks_by_index:
            return []
        return [self.tasks_by_index[idx] for idx in self._join_id_list( list(self.current_tasks_by_index) )]

    def set_active_tasks( self, ids ):
        self.current_tasks_by_index = set(ids)
        return

    def get_all_tasks( self ):
        return self.tasks_by_index.values()

    def _start_one_replay( self, rec, node ):
        """Helper for start_replay."""
        at_vclock_str = ""
        if self.start_vclock:
            at_vclock_str = "to %d"%self.start_vclock
        # Accept connections from controllees
        misc.out( "Loading", rec.url.geturl(), at_vclock_str )

        try:
            #if misc.is_known_control(rec.url.geturl()):
            #    mode_str = "Replay,DCGen"
            #else:
            if self.dcgen_enabled == True:
                mode_str = "Replay,DCGen"
            else:
                mode_str = "Replay"

            opt_list = ["DCGen.OutputFormula=false","DCGen.AssumeUnknown=%s"%(misc.unknowns),"Base.Debug.PauseOnAbort=true"]

            # Assign node indices: per thread, per node, etc.
            if rec.node_uuid in self.nodes_by_uuid:
                node_index = self.nodes_by_uuid[rec.node_uuid]
            else:
                node_index = self.nr_nodes_created
                self.nodes_by_uuid[rec.node_uuid] = node_index
                self.nr_nodes_created += 1
            ctrl_index = self.nr_controllees_created
            self.nr_controllees_created += 1

            ctrl = controllee.start( rec, mode_str, ctrl_index,\
                    node_index, opt_list, dbg_level=self.dbg_level)
            event = ctrl.wait()
            self._handle_event(event)
            ctrl.node = node

            # Officially register the controllee
            self.replay_controllees_by_index[ctrl.index] = ctrl

            #misc.out( "Replay controllee #%d ready."%ctrl.index )
            if self.start_vclock:
                # Roll up to requested time.
                self.advance_controllers( self.start_vclock )

                if (ctrl.get_status()[0] < self.start_vclock):
                    error( "ERROR: could not advance", addr, at_vclock_str )
        except socket.timeout:
            error( "Session startup timed-out." )
        return


    def _expand_url_list(self, words):
        url_list = []
        for word in words:
            url = urlparse.urlparse( word )
            if not url.scheme:
                error( "Invalid url:", word )
                continue
            try:
                fs = dfs.urlopen( url )
            except dfs.FsException as e:
                error( "Can't open URL:", str(e) )
                continue
            else:
                assert( fs )
                dir_url = urlparse.urljoin( url.path, './' )
                for name in fs.listdirs( dir_url ):
                    if fnmatch.fnmatch( name, os.path.basename( url.path ) ):
                        sub_url = urlparse.urljoin( url.geturl(), name )
                        debug( "sub_url:", sub_url )
                        url_list.append( urlparse.urlparse( sub_url ) )
        return url_list

    def _get_rec_list(self, url_list):
        rec_list = []
        for url in url_list:
            try:
                rec = recording.Recording( url )
            except Exception as e:
                if str(e) == "Recording not found":
                    misc.out( "Recording ", url.geturl(), "is invalid." )
                elif str(e) == "Invalid URL":
                    misc.out( "Invalid URL" )
                else:
                    raise
                continue
            else:
                rec_list.append( rec )
        return rec_list

    def add_members( self, url_list ):
        """Opens a replay process for a specified address and time.
        If start_vclock is None, start replay from beginning of available
        logs. Otherwise, find a log that starts at (or crosses, if
        exact==False) start_vclock."""

        # Parse the recording urls
        rec_list = self._get_rec_list(self._expand_url_list(url_list))
        if len(rec_list) == 0:
            raise ControllerException("No recordings found")

        # Start the vkernel on worker nodes.
        # Simple round-robin assignment of recordings to nodes
        i = 0
        for rec in rec_list:
            # Workers need to know 
            if rec.url.scheme == 'file':
                rec.url = urlparse.urlparse(\
                        "ssh://%s/%s"%(socket.gethostname(), rec.url.path))
            node = self.node_list[ i % len(self.node_list) ]
            cached_path = node.cache_recording(str(rec), rec.url.geturl())
            rec.cache_url = urlparse.urlparse(\
                    "ssh://%s/%s"%(node.url.hostname, cached_path))
            self._start_one_replay( rec, node )
            i = i + 1
        return

    def _handle_event(self, event):
        is_ctrl_dead = False

        if isinstance( event, events.StartEvent ):
            event.task = self._add_task( event.ctrl, event.pid, event.tid )
        else:
            if isinstance( event, events.ShutdownEvent ):
                is_ctrl_dead = True
                self.kill_ctrl(event.ctrl)
            else:
                event.task = self.task_by_tid[event.tid]
                if isinstance( event, events.ExitEvent ):
                    self._remove_task( event.tid )

        (got_hit, should_continue) = probe.check_for_hits( event )
        return (is_ctrl_dead, should_continue)


    def _advance_controllees( self, target_vclock ):
        """Continues replay up to first log entry at or after target 
        vclock. Calling with "+<usecs>" advances that far.
        (If replaying multiple programs, each will advance that far
        from the earliest current time).
        """
        # First put the proper set of controllers into a heap.
        scheduler_heap = [(ctrl.get_status()[0],ctrl) for ctrl in
                self.replay_controllees_by_index.values()]
        heapq.heapify( scheduler_heap )

        # Which controllers are still working:
        ctrl_str_list = [str(ctrl) for ignore,ctrl in scheduler_heap]
        if not ctrl_str_list:
            error( "No recordings to replay." )
            return
#        elif len(ctrl_str_list) == 1:
#            note( "Advancing recordings:", ctrl_str_list[0] )
#        else:
#            ctrl_str_list.sort()
#            note( "Advancing %d recordings:\n"%len(ctrl_str_list),
#                 "\n".join(ctrl_str_list) )

        # Convert relative time if necessary
        lowest_vclock,ctrl = scheduler_heap[0]
        assert( lowest_vclock )
        if target_vclock and str(target_vclock).startswith("+"):
            if str(target_vclock)=="++":   # Handy shortcut
                target_vclock = "forever"
            else:
                target_vclock = safe_long(target_vclock[1:]) + lowest_vclock


        if target_vclock:
            if target_vclock == "forever":
                # A string is greater than any long, so this time will
                #  never be reached.
                pass        # No qualifier on "advancing..." above.
            else:
                target_vclock = safe_long(target_vclock)    # Make sure to convert from string
                misc.out( "\tto time %d (%s)"%(target_vclock,
                        time.ctime(target_vclock/1000000)) )
        else:
            misc.out( "\tone step" )
        orig_vclock = None        # For timing statistics

        # Now repeatedly advance the first node in the heap.
        while( True ):
            if not scheduler_heap:
                break
            lowest_vclock, ctrl = heapq.heappop( scheduler_heap )
            if not orig_vclock:
                orig_vclock = lowest_vclock
            #if random.random() < 0.001:    # Status message
            #    misc.out( lowest_vclock )
            if target_vclock and (lowest_vclock >= target_vclock):
                break       # Advanced far enough
            # Now run the controller for a bit.
            # Ignore main hook (dummy_trap) for a few iterations?
            next_clock = target_vclock     # None < long < "forever"
            if scheduler_heap:
                next_clock = min(scheduler_heap[0][0],next_clock)
            misc.debug( "Advancing to:", next_clock )
            ctrl.advance( next_clock )

            # Wait for controller event or error
            tid = None
            while( True ):
                try:
                    sock_list = [ ctrl.sock, ctrl.child.stdout ]
                    debug( "sock_list:", sock_list )
                    ready_socks = select.select( sock_list, [], sock_list )
                    debug( "ready_socks:", ready_socks )
                    ## XXX: output should be done via a probe, get rid of
                    # this code
                    # galtekar: May be useful for debugging
                    if ctrl.child.stdout in ready_socks[0]:
                        out_str = ctrl.child.stdout.read( )
                        if out_str:
                            # Like print, but without the spaces
                            # and newlines
                            if True:
                                if len(self.replay_controllees_by_index) > 1:
                                    prefix = "#%3d:"%(ctrl.index)
                                    print prefix, out_str
                                else:
                                    sys.stdout.write(out_str)
                            else:
                                sys.stdout.write( out_str )
                    elif ctrl.child.stdout in ready_socks[2]:
                        misc.error( "Controller pipe broken" )
                        return

                    if ctrl.sock in ready_socks[0]:
                        event = ctrl.wait()
                        break
                    elif ctrl.sock in ready_socks[2]:
                        misc.error( "Controller pipe broken" )
                        return
                except KeyboardInterrupt:
                    ctrl.pause()

            # Controller should now be stopped and awaiting commands
            debug( "event?:", event )

            (is_ctrl_dead, should_continue) = self._handle_event(event)

            # Reschedule the controllee
            if is_ctrl_dead == False:
                new_vclock = ctrl.get_status()[0]
                #print( "New time:", new_vclock )
                misc.debug( "New time:", new_vclock )
                heapq.heappush( scheduler_heap, (new_vclock,ctrl) )

            if should_continue == False or not target_vclock: # Only want to step once
                break
        # FIXME: print out new status, if more than one in original ctrl_list?
        return

    def advance(self, target_vclock=None):
        self._advance_controllees(target_vclock)
        return

    def go(self):
        self.advance("forever")
        return

    def add_probe(self, spec, func=None):
        pr = probe.create(spec, self, func)
        misc.out( "Global probe %d: %s"%(pr.index, pr) )
        return


@atexit.register
def cleanup():
    for group in group_set:
        group.kill_all_ctrls()
    return

# vim:ts=4:sw=4:expandtab

