# author: Gautam Altekar
# $Id: probe.py,v 1.18 2010/07/09 11:48:16 galtekar Exp $
#
# vim:ts=4:sw=4:expandtab

import struct, sys
import misc, action, controller, syscall, msg_stub, events, fnmatch

_probe_map = {}
_nr_probes_created = 0

class ProbeException(Exception):
    pass

class ProbeSpec:
    def __init__( self, spec, valid_specs ):
        spec_list = spec.strip().split(':')
        if len(spec_list) == 4:
            self.provider = spec_list[0]
            self.modules = \
                self._find_spec_matches("module", spec_list[1], valid_specs[0])
            self.functions = \
                self._find_spec_matches("function", spec_list[2], valid_specs[1])
            self.names = \
                self._find_spec_matches("name", spec_list[3], valid_specs[2])
        else:
            raise ProbeException("Invalid probe spec; needs 4 components")

    def _find_spec_matches( self, comp_name, comp_str, possible_matches ):
        result = set()
        if comp_str in [ '', '*' ]:
            result = possible_matches
        else:
            for comp in comp_str.split(','):
                matches = fnmatch.filter(possible_matches, comp)
                if len(matches) == 0:
                    raise ProbeException("Invalid %s specifier: %s"%(comp_name, comp))
                result = result.union(matches)
        return result


#####
# Abstract base class for all probes.
class Probe:
    def __init__( self, ctrl_group, spec, valid_specs ):
        global _nr_probes_created

        self.spec = ProbeSpec(spec, valid_specs)
        self.is_enabled = False
        self.action = None # Do nothing, will stop replay
        self.nr_hits = 0
        self.index = _nr_probes_created
        _nr_probes_created += 1
        _probe_map[self.index] = self
        self.ctrl_group = ctrl_group
        self.task_list = None
        self.output_file = sys.stdout

        self.action_locals = {}

    def enable( self ):
        self.is_enabled = True
        self.task_list = self.ctrl_group.get_active_tasks()

        for task in self.task_list:
            self.enable_on_task(task)

    def disable( self ):
        self.is_enabled = False

        for task in self.task_list:
            self.disable_on_task(task)
        self.task_list = None

    def on_event( self ):
        # Needs to be overridden by a derived class
        assert( 0 )

    def refresh( self ):
        self.disable()
        self.enable()

#class SourceProbe(Probe):
#    def __init__( self, ctrl_group, spec ):
#        Probe.__init__( self, ctrl_group, spec, [ "entry", "return" ] )
#
#    def on_event( self, event ):
#        if isinstance( event, events.TaskEvent ):
#            task = event.task
#            if isinstance( event, BrkptEvent ):
#                if self.loc_spec == "entry":
#                    if event.addr in self.entry_addr_by_task[task.index]:
#                        return True
#                elif self.loc_spec == "return":
#                    if event.addr in self.return_addr_by_task[task.index]:
#                        self.return_addr_by_task[task.index].remove(event.addr)
#                        return True
#                    elif event.addr in self.entry_addr_by_task[task.index]:
#                        ret_addr = task.get_frame().ret_addr
#                        task.set_brkpt( ret_addr )
#                        self.return_addr_by_task[task.index].add( ret_addr )
#            elif isinstance( event, ObjectLoadEvent ):
#                self.refresh()
#        return False
#
#    def enable( self ):
#        Probe.enable( self )
#
#        self.entry_addr_by_task = {}
#        self.return_addr_by_task = {}
#
#    def enable_on_task( self, task ):
#        if self.function == None:
#            func_list = task.symbols.get_all_functions(self.module)
#        else:
#            func_list = [ self.function ]
#
#        for func in func_list:
#            addr = task.symbols.resolve_function( func )
#            task.set_brkpt( addr )
#            if task.index in self.entry_addr_by_task:
#                self.entry_addr_by_task[task.index].add(addr)
#            else:
#                self.entry_addr_by_task[task.index] = set([addr])
#
#    def disable( self ):
#        Probe.disable( self )
#
#    def disable_on_task( self, task ):
#
#        for addr in self.entry_addr_by_task[task.index]:
#            task.del_brkpt( addr )
#
#        if self.loc_spec == "return":
#            if task.index in self.return_addr_by_task:
#                for addr in self.return_addr_by_task[task.index]:
#                    task.del_brkpt( addr )
#        else:
#            assert( len(self.return_addr_by_task) == 0 )
#
class SyscallProbe(Probe):
    def __init__( self, ctrl_group, spec ):
        valid_specs = (["main", "libs"], syscall.index_by_name.keys(),\
                ["entry", "return"])
        Probe.__init__(self, ctrl_group, spec, valid_specs)

        self.sysno_list = []
        #print "function list:", self.spec.functions
        for name in self.spec.functions:
            sysno = syscall.index_by_name[name]
            self.sysno_list.append(sysno)
        assert(len(self.sysno_list) > 0)
        assert(len(self.sysno_list) == len(set(self.sysno_list)))

        self.brkpt_list = []
        self.brkpt_list.append(msg_stub.BRKPT_SYSCALL)
        assert(len(self.brkpt_list))

    def on_event(self, event):

        if event.sysno in self.sysno_list:# and event.spec.name in self.spec.names:
#            for arg_index, reg in [ (0, "bx") , (1, "cx"), (2, "dx"), (3, "si"), (4, "di"), (5, "bp") ]:
#                self.arg_list[arg_index] = get_reg_bytes_as_int(event.task, reg)
            return True
        return False

    def enable_on_task( self, task ):
        assert(len(self.brkpt_list))
        assert(len(self.sysno_list))
        #print self.brkpt_list
        #print self.sysno_list
        for brkpt_kind in self.brkpt_list:
            task.set_brkpt( brkpt_kind, self.sysno_list )

    def disable_on_task( self, task ):
        assert(len(self.brkpt_list))
        assert(len(self.sysno_list))
        for brkpt_kind in self.brkpt_list:
            task.del_brkpt( brkpt_kind, self.sysno_list )


class IoProbe(Probe):
    def __init__(self, ctrl_group, spec):
        self._io_module_map = {
            "ipc" : ([msg_stub.INODE_PIPE, msg_stub.INODE_SOCKET], None, None),
            "pipe" : ([msg_stub.INODE_PIPE], None, None),
            "socket" : ([msg_stub.INODE_SOCKET], None, None),
            "unix" : ([msg_stub.INODE_SOCKET], [ msg_stub.SOCK_FAMILY_UNIX ], None),
            "inet" : ([msg_stub.INODE_SOCKET], [ msg_stub.SOCK_FAMILY_INET ], None),
            "tcp" : ([msg_stub.INODE_SOCKET], None, [ msg_stub.SOCK_PROTO_TCP ]),
            "udp" : ([msg_stub.INODE_SOCKET], None, [ msg_stub.SOCK_PROTO_UDP ]),
            "file" : ([msg_stub.INODE_FILE], None, None ),
            "device" : ([msg_stub.INODE_DEVICE], None, None )
        }
        func_map = { 
                "write" : msg_stub.BRKPT_FILE_WRITE,
                "peek" : msg_stub.BRKPT_FILE_PEEK,
                "dequeue" : msg_stub.BRKPT_FILE_DEQUEUE,
                "open" : msg_stub.BRKPT_FILE_OPEN,
                "close" : msg_stub.BRKPT_FILE_CLOSE,
                "put" : msg_stub.BRKPT_FILE_PUT
                }
        valid_specs = (self._io_module_map.keys(), func_map.keys(),\
                ["entry", "return"])
        Probe.__init__(self, ctrl_group, spec, valid_specs)

        self.brkpt_list = []
        for (key, value) in func_map.items():
            if key in self.spec.functions:
                self.brkpt_list.append(value)

    def on_event(self, event):
        for module in self.spec.modules:
            (major_tup, family_tup, proto_tup) = self._io_module_map[module]
            file = event.file
            if file.ino_major in major_tup and\
               (family_tup == None or file.sock_family in family_tup) and\
               (proto_tup == None or file.sock_proto in proto_tup):
                return True
        return False

    def enable_on_task(self, task):
        for brkpt_kind in self.brkpt_list:
            task.set_brkpt(brkpt_kind, 0)

    def disable_on_task(self, task):
        for brkpt_kind in self.brkpt_list:
            task.del_brkpt(brkpt_kind, 0)


############################
# Internal methods

def _set_probe_action( pr, action_func ):
    """Attaches an action script to be executed when a probe is
    triggered."""

    if action_func:
        pr.action_func = action_func
    else:
        try:
            pr.action = action.read_and_compile()
        except ProbeException, pe:
            error( "Caught exception:", pe )
    return True

############################
# External methods

def check_for_hits( event ):
    # If there are no hits, we keep going by default
    got_hit = False
    should_continue = True 
    misc.debug("Event provider:", event.spec.provider, "function:",
            event.spec.function)
    for pr in _probe_map.values():
        misc.debug("Probe:", pr, "provider:",
                pr.spec.provider, "functions:", pr.spec.functions)
        if pr.is_enabled == True and \
           event.spec.provider == pr.spec.provider and \
           event.spec.function in pr.spec.functions and \
           pr.on_event( event ) == True:
            got_hit = True
            pr.nr_hits += 1
            should_continue &= action.run( pr, event )
    return ( got_hit, should_continue )


############################
# Console-accessible methods

_probe_providers = {
        #"source"  : lambda g,w: SourceProbe(g,w),
        "syscall" : lambda g,w: SyscallProbe(g,w),
        "io"      : lambda g,w: IoProbe(g,w),
        }

#def add(spec, func=None):
#    ctrl_group = controller._master
#    spec_list = spec.split(':')
#    provider_spec = spec_list[0]
#    try:
#        try:
#            pr = _probe_providers[provider_spec](ctrl_group, spec)
#        except KeyError:
#            misc.error("Unrecognized probe provider:", provider_spec)
#            return True
#	    pr.enable()
#    except ProbeException, pe:
#	    misc.error( "Caught exception:", pe )
#    else:
#	    misc.out( "Global probe %d: %s"%(pr.index, pr) )
#
#    return _set_probe_action( pr, func )'

def create(spec, group, func):
    provider_spec = spec.split(':')[0]
    try:
        pr = _probe_providers[provider_spec](group, spec)
    except KeyError:
        raise ProbeException("Unrecognized probe provider:",
            provider_spec)

	pr.enable()
    _set_probe_action( pr, func )
    return pr


def add_wrapper( words ):
    if len(words) < 1:
        misc.error( "Requires at least one argument" )
        return True
    return add(words[0], None)

def list_wrapper( words ):
    nr_enabled = 0
    for index, pr in sorted(_probe_map.items()):
        print pr.index, pr.spec.provider, pr.spec.modules, \
                pr.spec.functions, pr.spec.names, pr.is_enabled
        if pr.is_enabled:
            nr_enabled += 1
    print "%d/%d probes enabled"%(nr_enabled, len(_probe_map))
    return True

def enable_wrapper( words ):
    if len(words) < 1:
        misc.error( "Requires at least one probe id argument" )
        return True

    for word in words:
        index = int(word)
        pr = _probe_map[index]
        if pr.is_enabled == False:
            pr.enable()
    return True

def disable_wrapper( words ):
    if len(words) < 1:
        misc.error( "Requires at least one probe id argument" )
        return True

    for word in words:
        index = int(word)
        pr = _probe_map[index]
        if pr.is_enabled == True:
            pr.disable()
    return True
