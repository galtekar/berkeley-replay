# vim:ts=4:sw=4:expandtab
#
import sys, os, struct, socket
import misc, msg_stub, events

class ControlleeException(Exception):
    pass

class SymByte:
    def __init__( self, tuple ):
        #sb_p->is_symbolic, sb_p->un.val, sb_p->un.var.byte, 
        #sb_p->un.var.is_origin, 
        #sb_p->un.var.name, sb_p->un.var.bb_exec_count
        #misc.debug( "tuple:", tuple )
        assert(len(tuple) == 6)
        assert(tuple[0] == 0 or tuple[0] == 1)

        self.is_symbolic = True if tuple[0] == 1 else False
        self.val = tuple[1]
        self.idx = tuple[2]
        self.is_origin = tuple[3]
        self.name = tuple[4]
        self.bb_exec_count = tuple[5]

    def __repr__( self ):
        if self.is_symbolic == True:
            type_str = "OV" if self.is_origin else "TV"
            return "%sv0e%dn%d"%(type_str, self.bb_exec_count, self.name)
        else:
            return str(self.val)

    
class Controllee:
    """All info for a VCPU being replayed."""

    def __init__( self, idx, node_idx, rec, child, sock ):
        # subprocess.Popen objects for GDBs, indexed by app pid
        self.index = idx
        self.node_index = node_idx
        self.rec = rec
        self.state = "running"
        self.sock = sock
        self.child = child
        self.last_stop_code = None
        self.last_stop_tid = None

    def kill( self, reason ):
        self.state = reason
        self.sock.close()
        self.child.kill()
        self.child.wait()

    def get_status( self ):
        req_msg = struct.pack( '!L', msg_stub.MSG_REQ_STATUS )
        self.sock.sendall( req_msg )

        fmt = '!QQQB'
        reply_msg = misc.recvall( self.sock, struct.calcsize( fmt ) )
        (curr_vclock, end_vclock, clock, is_value_det) = struct.unpack( fmt, reply_msg )

        return (curr_vclock, end_vclock, clock, is_value_det)

    def advance( self, next_clock ):
        """Helper function for advance_controllers."""
        misc.debug( "Advancing", self )
        self.last_stop_code = None
        self.last_stop_tid = None

        self.state = "running"

        if next_clock:
            if next_clock == "forever":
                next_clock = 0
        else:
            next_clock = 1 # Step

        req_msg = struct.pack( '!LQ', msg_stub.MSG_REQ_CONT, next_clock )
        self.sock.sendall( req_msg )

#        fmt = '!L'
#        reply_msg = misc.recvall( self.sock, struct.calcsize( fmt ) )
#        (res,) = struct.unpack( fmt, reply_msg )
#        assert( res == 0 )

    def _read_state( self, msg_tag, task_id, start, data_len ):
        if task_id < 0 or data_len <= 0:
            raise Exception, "Invalid argument"

        req_msg = struct.pack( '!LLLL', msg_tag, task_id, start, data_len )
        self.sock.sendall( req_msg )
       
        fmt = '!L'
        reply_msg = misc.recvall( self.sock, struct.calcsize(fmt) )
        (res_len, ) = struct.unpack( fmt, reply_msg )
        assert( res_len >= 0 )

        #misc.debug( "res_len, data_len:", res_len, data_len )
        if res_len != data_len:
            raise Exception, "Invalid argument"

        byte_list = []
        fmt = '!BBBBQQ'
        chunk_size = struct.calcsize( fmt )
        msg_size = res_len * chunk_size
        data_msg = misc.recvall( self.sock, msg_size )

        #misc.debug( "state received:", len(data_msg), msg_size )
        assert( data_msg )
        assert( len(data_msg) == msg_size )

        i = 0
        while i < len(data_msg):
            #misc.debug( "data:", i )
            tuple = struct.unpack( fmt, data_msg[i:i+chunk_size] )
            byte_list.append(SymByte(tuple))
            i = i + chunk_size

        return byte_list

    def read_mem( self, task_id, start, data_len ):
        return self._read_state( msg_stub.MSG_REQ_READMEM, task_id, start, data_len )

    def read_reg( self, task_id, start, data_len ):
        return self._read_state( msg_stub.MSG_REQ_READREG, task_id, start, data_len )

    def get_filename_by_fd( self, task_id, fd ):
        req_msg = struct.pack( '!LLL', msg_stub.MSG_REQ_GET_FILENAME_BY_FD,\
                task_id, fd )
        self.sock.sendall( req_msg )
        fmt = 'L'
        reply_msg = misc.recvall( self.sock, struct.calcsize(fmt) )
        ( filename_len, ) = struct.unpack( '!L', reply_msg )
        reply_msg = misc.recvall( self.sock, filename_len )
        ( filename, ) = struct.unpack( "%ds"%(filename_len), reply_msg )
        return filename.strip()

    def set_plane_by_fd( self, task_id, fd ):
        req_msg = struct.pack( '!LLL', msg_stub.MSG_REQ_SET_PLANE_BY_FD,\
                task_id, fd )
        self.sock.sendall( req_msg )
        return

    def get_tid_list( self ):
        req_msg = struct.pack( '!L', msg_stub.MSG_REQ_TASKLIST )
        self.sock.sendall( req_msg )

        fmt = '!L'
        chunk_size = struct.calcsize(fmt)
        reply_msg = misc.recvall( self.sock, chunk_size )
        (list_len, )= struct.unpack( fmt, reply_msg )

        data_msg = misc.recvall( self.sock, list_len * chunk_size )
        tid_list = []
        i = 0
        while i < len(data_msg):
            (task_tid,) = struct.unpack( fmt, data_msg[i:i+chunk_size] )
            tid_list.append( task_tid )
            i = i + chunk_size
        misc.debug( "tid_list:", tid_list )
        return tid_list

    def get_task_info( self, task_tid ):
        assert( 0 )
        req_msg = struct.pack( '!L', msg_stub.MSG_REQ_TASKINFO )
        self.sock.sendall( req_msg )

        fmt = '!L'
        chunk_size = struct.calcsize(fmt)
        reply_msg = misc.recvall( self.sock, chunk_size )
        (list_len, ) = struct.unpack( fmt, reply_msg )
        return

    def _do_brkpt_work( self, msg_type, tid, brkpt_kind, sysno_list ):
        # XXX: currently we stop on every syscall; add selective
        # sysno stopping later
        req_msg = struct.pack( '!LLLL', msg_type, tid, brkpt_kind, 4 )
        self.sock.sendall( req_msg )

        fmt = '!L'
        chunk_size = struct.calcsize(fmt)
        reply_msg = misc.recvall( self.sock, chunk_size )
        (err_code, ) = struct.unpack( fmt, reply_msg )
        assert( err_code == 0 )

    def set_brkpt( self, tid, brkpt_kind, sysno_list ):
        self._do_brkpt_work( msg_stub.MSG_REQ_SET_BRKPT, tid,
                brkpt_kind, sysno_list )

    def del_brkpt( self, tid, brkpt_kind, loc ):
        self._do_brkpt_work( msg_stub.MSG_REQ_DEL_BRKPT, tid,
                brkpt_kind, sysno_list )
    
    def wait( self ):
        while self.state == "running":
            fmt = '!LL'
            msg = misc.recvall( self.sock, struct.calcsize( fmt ) )
            if msg:
                (self.last_stop_code, self.last_stop_tid) = struct.unpack( fmt, msg )
                self.state = "stopped"
            else:
                raise ControlleeException("Connection broken")

        assert( self.last_stop_tid > 0 )
        ev = events.create( self, self.last_stop_tid, self.last_stop_code )
        return ev

    def __hash__( self ):
        return self.index

    def __cmp__( self, other ):
        return cmp(self.index, other.index)

    def __repr__( self ):
        return ("<Recording #%d: %s>"%(self.index, self.rec.url.geturl()))

# Creates a server sock. Optimizes for performance depending on
# whether target is 
def _make_server_socket(rec):
    if rec.cache_url.hostname == "localhost":
        serv_sock = socket.socket( socket.AF_UNIX, socket.SOCK_STREAM )
        sockpath = rec.cache_url.path + "/sock"
        try:
            os.remove(sockpath)
        except:
            pass
        serv_sock.bind( sockpath )
        serv_port = serv_sock.getsockname()
    else:
        ANY_INTERFACE = '' # as opposed to socket.gethostname()
        serv_sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        serv_sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
        serv_sock.setsockopt( socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 )
        serv_sock.bind( (ANY_INTERFACE, 0 ) )
        serv_port = str(serv_sock.getsockname()[1])
    serv_sock.listen( 10 ) # We really only need 0 backlog, right?
    serv_sock.settimeout(3)

    return (serv_sock, serv_port)

def _shutdown_server_socket(serv_sock):
    if serv_sock.family == socket.AF_UNIX:
        sockpath = serv_sock.getsockname()
        os.remove(sockpath)
    serv_sock.shutdown( socket.SHUT_RDWR )

def start( rec, mode_str, id, node_id, opt_list=[], dbg_level=0, quiet=True ):
    """Start a controllee."""
    ssh_bin = misc.get_conf("ssh_bin")
    replay_bin = rec.vkernel_bin
    assert(len(replay_bin) > 0)


    if rec.cache_url.hostname:
        hostname = rec.cache_url.hostname
    else:
        hostname = "localhost"

    misc.debug( "hostname:", hostname )

    (serv_sock, server_port) = _make_server_socket(rec)
    misc.debug( "server_port:", server_port )

    opt_list = [ 
                "Base.DirectExecutionEnabled=%d"%(int(misc.get_conf("de_enabled"))),
                "Base.Debug.Level=%d"%(dbg_level),
                "Base.TtyReplayEnabled=1",
                "Base.CtrlHost=%s"%(socket.gethostname()),
                "Base.CtrlPort=%s"%(server_port) ] + opt_list

    cmd_str = "%s -m %s -o '%s' %s"%(replay_bin, mode_str, \
                ';'.join( opt_list ), rec.cache_url.path)

    # Multiple -t options forces pseudo-tty allocation, which is needed
    # since the vkernel assumes that /dev/tty is available and open.
    child = misc.start_child([ssh_bin, "-t", "-t", hostname, cmd_str],
                should_block=False)

    client_sock, client_addr = serv_sock.accept()
    misc.debug("Got connect from", client_sock, client_addr)
    ctrl = Controllee( id, node_id, rec, child, client_sock )
    ctrl.wait()

    _shutdown_server_socket(serv_sock)
    return ctrl
