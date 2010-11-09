# vim:ts=4:sw=4:expandtab

import struct
import misc, msg_stub, syscall

###### Classes
class EventSpec:
    pass

class Event:
    def __init__(self, ctrl, tid):
        self.ctrl = ctrl
        self.tid = tid
        self.spec = EventSpec()

class SessionEvent(Event):
    def __init__(self, ctrl, tid):
        Event.__init__(self, ctrl, tid)
        self.spec.provider = "session"

class ShutdownEvent(SessionEvent):
    def __init__(self, ctrl, tid):
        SessionEvent.__init__(self, ctrl, tid)
        self.spec.function = "shutdown"

class TaskEvent(Event):
    def __init__( self, ctrl, tid ):
        Event.__init__( self, ctrl, tid )
        self.task = None
        self.spec.provider = "task"

class StartEvent(TaskEvent):
    def __init__( self, ctrl, tid ):
        TaskEvent.__init__( self, ctrl, tid )
        # XXX: implement MSG_GET_TASK_INFO in the vkernel
#        req_msg = struct.pack( '!L', msg_stub.MSG_GET_TASK_INFO )
#        self.ctrl.sock.sendall( req_msg )
#        fmt = '!L'
#        reply_msg = misc.recvall( self.ctrl.sock, struct.calcsize(fmt) )
#        (self.pid, ) = struct.unpack(fmt, reply_msg)
        self.pid = 5000
        self.spec.function = "start"

class ExitEvent(TaskEvent):
    def __init__(self, ctrl, tid):
        TaskEvent.__init__(self, ctrl, tid)
        self.spec.function = "exit"

### XXX: unify vclock hit/brkpt/sys_entry events? */
class StopEvent(TaskEvent):
    def __init__(self, ctrl, tid):
        TaskEvent.__init__(self, ctrl, tid )
        self.spec.function = "stop"

class BrkptEvent(TaskEvent):
    def __init__(self, ctrl, tid):
        TaskEvent.__init__(self, ctrl, tid)

class SyscallEvent(Event):
    def __init__(self, ctrl, tid):
        Event.__init__(self, ctrl, tid)
        self._get_syscall_info()
        self.spec.provider = "syscall"
        self.spec.function = syscall.get_name(self.sysno)

    def _get_syscall_info(self):
        fmt = '!L'
        msg = misc.recvall( self.ctrl.sock, struct.calcsize( fmt ) )
        (self.sysno, ) = struct.unpack( fmt, msg )


    @property
    def sysres(self):
        WORD_SIZE = 4
        # offsets into user_regs_struct
        # XXX: compute these automatically from wihtin a c module
        offmap = { "bx" : 0, "cx" : 4, "dx" : 8, "si" : 12,\
                   "di" : 16, "bp" : 20, "ax" : 24, "ds" : 28,\
                   "es" : 32, "fs" : 36, "gs" : 40, "ip" : 48,\
                   "cs" : 52, "flags" : 56, "sp" : 60, "ss" : 64 }

        def get_reg_bytes_as_int( task, regname ):
            data_str = task.get_reg_bytes( offmap[regname], WORD_SIZE )
            assert( len(data_str) == WORD_SIZE )
            ( val, ) = struct.unpack( 'l', data_str )
            return val

        return get_reg_bytes_as_int(self.task, "ax")


class Message():
    def __init__( self, ctrl, id, len):
        self.ctrl = ctrl
        self.id = id
        self.len = len

    def get_taint( self ):
        req_msg = struct.pack( '!L', msg_stub.MSG_REQ_GET_MSG_TAINT )
        self.ctrl.sock.sendall( req_msg )

        taint_bytes = misc.recvall( self.ctrl.sock, self.len )
        assert( len(taint_bytes) == self.len )
        return taint_bytes

    def set_taint( self, taint_bytes ):
        req_msg = struct.pack( '!L', msg_stub.MSG_REQ_SET_MSG_TAINT )
        self.ctrl.sock.sendall( req_msg)
        self.ctrl.sock.sendall( taint_bytes )

class File():
    def __init__(self, ctrl, ino_major, sock_family, sock_type, sock_proto, object_id):
        self.ctrl = ctrl
        self.ino_major = ino_major
        self.sock_family = sock_family
        self.sock_type = sock_type
        self.sock_proto = sock_proto
        self.object_id = object_id
       
    @property
    def name( self ):
        req_msg = struct.pack( '!L', msg_stub.MSG_REQ_GET_FILE_NAME )
        self.ctrl.sock.sendall( req_msg )

        fmt = '!L'
        reply_msg = misc.recvall( self.ctrl.sock, struct.calcsize(fmt) )
        (name_len, ) = struct.unpack(fmt, reply_msg)
        file_name = misc.recvall( self.ctrl.sock, name_len )
        return file_name.strip()

    def set_data_plane( self ):
        req_msg = struct.pack( '!LL', msg_stub.MSG_REQ_SET_FILE_PLANE, 1 )
        self.ctrl.sock.sendall( req_msg )
        return


class IoEvent(Event):
    def __init__(self, ctrl, tid):
        Event.__init__(self, ctrl, tid)
        self.spec.provider = "io"

    @property
    def file(self):
        req_msg = struct.pack( '!L', msg_stub.MSG_REQ_GET_FILE_INFO )
        self.ctrl.sock.sendall( req_msg )
        fmt = '!LLLLL'
        msg = misc.recvall(self.ctrl.sock, struct.calcsize(fmt))
        (ino_major,sock_family,sock_type,sock_proto,object_id) =\
                struct.unpack(fmt, msg)
        return File(self.ctrl, ino_major, sock_family, sock_type, sock_proto, object_id)

class IoOpenEvent(IoEvent):
    def __init__(self, ctrl, tid):
        IoEvent.__init__(self, ctrl, tid)
        self.spec.function = "open"

class IoCloseEvent(IoEvent):
    def __init__(self, ctrl, tid):
        IoEvent.__init__(self, ctrl, tid)
        self.spec.function = "close"

class IoPutEvent(IoEvent):
    def __init__(self, ctrl, tid):
        IoEvent.__init__(self, ctrl, tid)
        self.spec.function = "put"

class IoMsgEvent(IoEvent):
    def __init__(self, ctrl, tid):
        IoEvent.__init__(self, ctrl, tid)

    @property
    def msg(self):
        req_msg = struct.pack( '!L', msg_stub.MSG_REQ_GET_MSG_INFO )
        self.ctrl.sock.sendall( req_msg )
        fmt = '!LLLLQL'
        data = misc.recvall(self.ctrl.sock, struct.calcsize(fmt))
        (id1,id2,id3,id4,msg_idx,buf_len) = struct.unpack(fmt, data)
        id_str = "%d-%d-%d-%d-%d"%(id1,id2,id3,id4,msg_idx)
        if id_str == "0-0-0-0-0":
            id_str = None
        return Message(self.ctrl, id_str, buf_len)

class IoPeekEvent(IoMsgEvent):
    def __init__(self, ctrl, tid):
        IoMsgEvent.__init__(self, ctrl, tid)
        self.spec.function = "peek"

class IoDequeueEvent(IoMsgEvent):
    def __init__(self, ctrl, tid):
        IoMsgEvent.__init__(self, ctrl, tid)
        self.spec.function = "dequeue"

class IoWriteEvent(IoMsgEvent):
    def __init__(self, ctrl, tid):
        IoMsgEvent.__init__(self, ctrl, tid)
        self.spec.function = "write"



_event_map = { 
    msg_stub.EVENT_TASK_START : (lambda c,t: StartEvent(c,t)),
    msg_stub.EVENT_TASK_EXIT : (lambda c,t: ExitEvent(c,t)),
    msg_stub.EVENT_STOP : (lambda c,t: StopEvent(c,t)),
    msg_stub.EVENT_SHUTDOWN : (lambda c,t: ShutdownEvent(c,t)),
    msg_stub.EVENT_BRKPT_HIT : (lambda c,t: BrkptEvent(c,t)),
    msg_stub.EVENT_SYSCALL : (lambda c,t: SyscallEvent(c,t)),
    msg_stub.EVENT_FILE_PEEK : (lambda c,t: IoPeekEvent(c,t)),
    msg_stub.EVENT_FILE_DEQUEUE : (lambda c,t: IoDequeueEvent(c,t)),
    msg_stub.EVENT_FILE_OPEN : (lambda c,t: IoOpenEvent(c,t)),
    msg_stub.EVENT_FILE_WRITE : (lambda c,t: IoWriteEvent(c,t)),
    msg_stub.EVENT_FILE_CLOSE : (lambda c,t: IoCloseEvent(c,t)),
    msg_stub.EVENT_FILE_PUT : (lambda c,t: IoPutEvent(c,t))
}

###### Functions
def create(ctrl, tid, event_code):
    create_event_func = _event_map[event_code]
    ev = create_event_func(ctrl, tid)
    return ev
