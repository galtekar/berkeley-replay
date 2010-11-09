#!/usr/bin/env python
#
# Copyright (c) 2005-2006 Regents of the University of California.
# All rights reserved.

# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following
#    disclaimer in the documentation and/or other materials
#    provided with the distribution.
# 3. Neither the name of the University nor the names of its
#    contributors may be used to endorse or promote products
#    derived from this software without specific prior written
#    permission.

# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS
# IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
# REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# author: Dennis Geels
# $Id: replay_console.py,v 1.54 2006/10/04 04:10:31 galtekar Exp $

"""Library for controlling replay."""

import os, sys, fcntl, select, readline, re, ConfigParser, random, socket
import heapq, code, traceback, subprocess, pprint, pdb, time, signal, getopt
sys.path.append("exe/")
import trace_logs, friday

# Globals:
DEBUG = False
ECHO_DEBUG = False
LOG_OUTPUT = True
OMIT_EMPTY_LINES = True
_log_filename="%s.log"%sys.argv[0]
_output_log = None
def set_fg( ansi_fg ):
    return os.popen("tput setaf %d"%ansi_fg).read()
def set_fgbg( ansi_fg, ansi_bg ):
    return (os.popen("tput setaf %d"%ansi_fg).read()+
            os.popen("tput setab %d"%ansi_bg).read())
(_BLACK, _RED, _GREEN, _YELLOW, _BLUE, _MAGENTA, _CYAN, _WHITE) = range(8)
# colors we know look alright:
#fg\ bg:   B/W  _BLACK, _RED, _GREEN, _YELLOW, _BLUE, _MAGENTA, _CYAN, _WHITE
# _BLACK:	          *       *       *                *      *      *
# _RED:	    *      *              /       *       *               /      *
# _GREEN:   /      *      /                       *        /             /
# _YELLOW:         *      *       /               *        *      
# _BLUE:                  *       *       *                *      *      *
# _MAGENTA: *      *              /       /       *               /      *
# _CYAN:    /      *      /                       *        /             /
# _WHITE:          *      *       *               *        *      /
_output_orig = os.popen("tput op").read()
_output_normal = set_fgbg( _WHITE, _BLACK )
_output_debug = set_fgbg( _MAGENTA, _BLACK )
_output_app = set_fgbg( _GREEN, _BLACK )
_output_user = set_fgbg( _CYAN, _BLACK )
_output_echo_debug = set_fgbg( _RED, _BLACK )
_output_meta = set_fgbg( _BLACK, _MAGENTA )
_output_error = set_fgbg( _BLACK, _RED )
_output_from_gdb = set_fgbg( _YELLOW, _BLACK )
_output_to_gdb = set_fgbg( _BLUE, _YELLOW )
_output_friday = set_fgbg( _WHITE, _BLUE )
_output_trace_logs = set_fgbg( _BLUE, _GREEN )
_preferences = None	# A ConfigParser object
_replay_controllers = []	# A list of Replay_Controller objects.
_stopped_indices = {}	# Indices of dead in _replay_controllers.
_dead_controllers = []	# Replay_Controllers that have finished.
_current_replay_ids = None	# Once set, should be "all" or list
_last_gdb_cmd_words = None	# Text typed into console, split on whitespace
_last_advance_words = None	# Text typed into console, split on whitespace
_normal_prompt = "\nrdb: "
_gdb_prompt = "(gdb) "	# Used by gdb mode and to parse gdb output
_cl_binaries = []	# Executable files listed on command line.
_cl_script = []		# input lines to process before prompting user.
    
def abspath( p ):
    "Returns an absolute version of path p."
    return os.path.abspath(os.path.expanduser(p))

_gdb_bin = abspath("exe/gdb")
    
# Constants:
default_prefs = { "local_cache" : "./log_cache/",
                  "history_file" : "./.replay_history",
                  "remote_dir" : "logreplay/logs/",	# location of remote logs
                  "app_path": ".:~/:/usr/local/bin:/usr/bin",
                  "app_src_path" : "app_src/",
                  "log_prefix" : "*",
                  "restart_bin" : "exe/ckpt_restart",
                  "log2xml_bin" : "exe/log2xmlbin",
                  "logreplay_src_dir": "src",
                  "ssh_params" : " -C -o BatchMode=yes -o StrictHostKeyChecking=no",
                  "lib_dir" : abspath("libs"),	# Need abspath so
                                        # restart_bin can start elsewhere.
                  }

gdb_info_proc_re = re.compile( r'process (?P<pid>\d+)', re.DOTALL )
gdb_print_re = re.compile( r'\$\d+ = (?P<var>.*)', re.DOTALL )
#gdb_print_string_re = re.compile( r'\$\d+ =( 0x[0-9a-f]+)? "(?P<var>.*)"', re.DOTALL )
gdb_print_string_re = re.compile( r'"(?P<var>.*)"', re.DOTALL )
gdb_type_re = re.compile( r'type = (?P<type>.*)' )
gdb_bytes_re = re.compile( r'.*:(?P<bytes>.*)' )
gdb_print_bytes_re = re.compile( r'\$\d+ = {(?P<bytes>.*)}', re.DOTALL )
gdb_info_break_re = re.compile(r'(?P<num>\d+)\s+(?P<type>break|(hw )?watch)point'
                               r'\s+(?P<disp>keep|del|dis)\s+(?P<enabled>y|n)'
                               r'\s+(?P<addr>0x[0-9a-f]+)?\s+in (?P<where>.*)')
gdb_set_break_re = re.compile(r'Breakpoint (?P<num>\d+) at (?P<addr>0x[0-9a-f]+)')

app_exit_re = re.compile(r'Program (exited (with code (?P<code>\d+)|normally))|(.* Aborted.)')
ckpt_name_re = re.compile(r'(?P<appname>\w+)\.(?P<addr>(\d+\.){3}\d+)' )
replay_addr_re = re.compile( r'(^|@)(?P<addr>[-\w\.]+)($|:)' )
language_warning_re = re.compile( r'Current language:\s+auto; currently \w+')

gdb_hook_break_name = "hook_for_gdb"
gdb_hook_break_number = 1

gdb_hook_names = [
    "LL_HOOK_WRAPPER_TRAP",	# end of each replay wrapper
    "LL_HOOK_NEXT_LOG",		# about to rotate logs
    "LL_HOOK_FORK",		# forking child proc
    "LL_HOOK_SIGNAL",		# scheduling next proc
    "LL_HOOK_WAIT",		# thread is waiting
    "LL_HOOK_THREAD_EXIT",	# thread died
    "LL_HOOK_STOP_REPLAY",	# internal consistency check
    "LL_HOOK_SEGV",    		# seg fault--presumably artificial
    ]
gdb_hook_codes = dict( [(v,i) for i,v in enumerate( gdb_hook_names )] )

gdb_vclock_name = "_shared_info->vclock"
gdb_proc_list_name = "_shared_info->head"
gdb_replay_pid_field = "replay_mode_id.pid"

_gdb_failstop_all_flag = "stop_if_inconsistent"
_gdb_failstop_here_flag = "(*(int*)datum)"
_history_count_default = 40

class Replay_Controller:
    """All info for a process family being replayed in gdb.

    All threads and child processes from a single parent process share
    a log and must be replayed together.  Each process has its own gdb
    controlling it, but they share a single output tty.
    """
    def __init__(self, addr, start_vclock, child_proc,
                 app_pid, app_output, app_executable):
        self.addr = addr
        self.start = safe_long(start_vclock)
        # subprocess.Popen objects for GDBs, indexed by app pid
        self.children = {app_pid:child_proc}	
        self.current_child = app_pid	# Which child to run?
        self.next_child = None	# Valid only during handoff.
        self.app_out = app_output
        self.index = len(_replay_controllers)
        self.state = "running"
	self.alive = True
        self.app_executable = app_executable
        self.gdb_hook_break_addr = None	# set later
        # Update globals:
        _replay_controllers.append( self )
        global _current_replay_ids    
        _current_replay_ids = [self.index]	
    def set_next_pid(self, next_pid):
        """Mark a PID for imminent hand off."""
        self.next_child = next_pid
    def switch_children(self):
        """Hand off active status to the next child."""
        assert( self.next_child )
        debug( "Switching from PID", self.current_child, "to",
               self.next_child, color=_output_meta )
        self.current_child = self.next_child
        self.next_child = None
    def kill_current_child(self):
        """Remove a process from children.  Must switch then!"""
        del self.children[self.current_child]
    def add(self, child_proc, child_pid):
        "Adds a child process (via a controlling gdb)."
        self.children[child_pid] = child_proc
    def vclock(self):
        return get_long(self, gdb_vclock_name)
    def gdb(self, child_pid=None):
        """Returns the Popen object for the process.

        If child_pid is None, this method returns the
        one which is currently active."""
        return self.children[(child_pid or self.current_child)]
    def __hash__(self):
	return self.index
    def __cmp__(self, other):
	return cmp(self.index, other.index)
    def __repr__(self):
        return ("<Replay #%d: %s@%s %s>"%(self.index, self.addr,
                                          str(self.vclock()), self.state))

class Timer:
    def __init__(self, name):
        self.name = name
        self.times = []
        self.last_index = -1	# index of last end() == len(times)-1
    def start(self):
        self.start_time=time.time()
    def end(self):
        end = time.time()
        self.last_index += 1
        self.times.append( (self.start_time,end,end-self.start_time))

def log_in_color( string, color ):
    "Prints string to the log, in color."""
    if not LOG_OUTPUT: return
    global _output_log
    if not _output_log:
        _output_log = file( _log_filename, "a" )
    # first emit color escape codes
    string = string.replace( "\n", "%s\n%s"%(_output_normal,color))    
    _output_log.write( "%s%s"%(color,string) )
    _output_log.flush()

def print_in_color( string, color=None ):
    """Prints a string to the console, in color."""
    if not color:
        raise Exception( "No color specified for '%s'\n"%string )
    log_in_color( string, color )
    string = string.replace( "\n", "%s\n%s"%(_output_normal,color))
    sys.stdout.write("%s%s"%(color,string))

def out( string ):
    """Prints some normal feedback.

    Calls through to main colorized output functions."""
    print_in_color( string+"\n", _output_normal )

def note( *args, **kwargs ):
    """Prints and logs notable output.
    
    Calls through to main colorized output functions."""
    string = " ".join( map( str, args ) )
    color = _output_meta
    if "color" in kwargs:
        color = kwargs["color"]
    print_in_color( string+"\n", color )

    
def debug( *args, **kwargs ):
    """Prints and logs debug output.
    
    Calls through to main colorized output functions."""
    if DEBUG:
        string = " ".join( map( str, args ) )
        color = _output_debug
        if "color" in kwargs:
            color = kwargs["color"]
        print_in_color( string+"\n", color )

def debugf( *args, **kwargs ):
    """Prints and logs debug output (format string version).    
    
    Calls through to main colorized output functions."""
    if DEBUG:
        string = args[0]%args[1:]
        color = _output_debug
        if "color" in kwargs:
            color = kwargs["color"]
        print_in_color( string+"\n", color )

def error( *args ):
    """Prints an error message.

    Calls through to main colorized output functions."""
    string = " ".join( map( str, args ) )    
    print_in_color( string+"\n", _output_error )

def prompt( prompt_str ):
    print_in_color( "", _output_normal )
    if _cl_script:
        input = _cl_script.pop(0)
        print_in_color( "script: '%s'\n"%input, color=_output_user )
        readline.add_history( input )
    else:
        try:
            input = raw_input( prompt_str )
            debugf( "user: '%s'", input, color=_output_user )
        except EOFError:
            stop_all_controllers()
    return input

def reset_colors():
    sys.stdout.write( "%s\n"%_output_orig)

def color_check():
    if False:
        for af in range(8):
            sys.stdout.write( "%s %d \t"%(set_fg(af), af ))
            for ab in range(8):
                sys.stdout.write( "%s %d/%d \t"%(set_fgbg(af,ab), af, ab ))
        reset_colors()
    
def toggle_debug( ignore=None):
    """Change DEBUG, ECHO_DEBUG flags.

    More of a cycle than a toggle:
    (0,0) -> (1,0) -> (1,1) -> (0,0)
    """
    global DEBUG, ECHO_DEBUG
    if DEBUG and ECHO_DEBUG:
        debug( "Disabling DEBUG output" )
        DEBUG = False
        ECHO_DEBUG = False
    else:
        if DEBUG:
            debug( "Enabling ECHO_DEBUG output" )
            ECHO_DEBUG = True
        else:
            DEBUG = True
            debug( "Enabling DEBUG output" )
    return True

def safe_long( string ):
    """Cast a string to a long, returning None on error."""
    try:
        l = long(string)
        return l
    except (ValueError, TypeError):
        error( "Invalid number:'%s'"%string )
        return None

def load_preferences():
    """Reads in the configuration files.

    Reads 'replay.cfg', '.replay.cfg', and '~/.replay.cfg',
    with the the first occurrence of duplicate keys overriding any
    later ones.  It then reads the protocol-specific configuration
    file, determined by the 'protocol' variable.

    Returns True iff no problems occur.
    """
    global _preferences
    _preferences = ConfigParser.SafeConfigParser()
    # Put defaults into "main", rather than as ConfigParser defaults,
    # because we want to be able to detect when an option is overridden: 
    _preferences.add_section("replay")
    for opt,val in default_prefs.items():
        _preferences.set("replay",opt,val)
    for cfg in [abspath("~/.replay.cfg"),".replay.cfg","replay.cfg" ]:
        _preferences.read( cfg )
    if ((not _preferences.has_option("replay", "remote_user")) and
        ("USER" in os.environ)):
        _preferences.set("replay","remote_user",os.environ["USER"])
    debug( "Preferences:", _preferences.items("replay"))
    # Overwrite some globals from trace_logs.
    trace_logs.load_preferences( _preferences )
    trace_logs.load_cache()
    return True

# get_conf: machine-specific preferences
get_conf = trace_logs.get_conf

def start_child( command ):
    "Runs the command in a subprocess."
    debugf( "Adding %s to env", get_conf("lib_dir"))
    local_lib_env = {"LD_LIBRARY_PATH":get_conf("lib_dir")}
    debug( "Starting", command )
    child = subprocess.Popen( command, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,
                              env=local_lib_env )
    debug( "subprocess", child, child.pid )
    #    make_async( child.stdin )
    make_async( child.stdout )
    #if child.childerr: make_async( child.childerr )
    return child

def make_async( fd ):
    "fcntl wrapper"
    flags = fcntl.fcntl( fd, fcntl.F_GETFL )
    fcntl.fcntl( fd, fcntl.F_SETFL, (flags|os.O_NDELAY) )

def write_command( ctrl, s, child_pid=None ):
    """Feeds a string to gdb's stdin.

    If child_pid is None, the currently active child is called.
    Overriding this default is risky, because inactive children may be
      blocked in the application, limiting their actions."""
    debug( "to gdb(", child_pid, "):", s, color=_output_to_gdb )
    ctrl.gdb(child_pid).stdin.write(s)
    if s[-1:] != "\n":
        ctrl.gdb(child_pid).stdin.write("\n")
    ctrl.gdb(child_pid).stdin.flush()

def apply_regexes( text, regexes ):
    """Splices out matches from a text string.

    regexes is a list of regular expressions.  They are applied in
    order, removing anything matching each in turn."""
    for rexp in regexes:
        if ECHO_DEBUG:
            match = rexp.search( text )
            if match:
                debugf("removing: '%s'", match.group(), color=_output_echo_debug )
        text = rexp.sub( "", text )
    return text

def drain_app( pipe ):
    """Read everything from an application pipe."""
    while select.select( [pipe],[],[],0 )[0]:
        text = pipe.read()
        if not text:
            debug( " EOF! " * 8 )
            break
        for line in text.splitlines(True):
            print_in_color( line, _output_app )

def wait_for_app( app_popen ):
    """Wait for expected string on application stdout.

    Saves PID from application output string to app_popen.real_pid.
    """
    expected_re = re.compile( r'<(?P<pid>\d+)>: Waiting for gdb' )
    full_text = ""
    debugf( "Waiting for '%s' on proc %d", expected_re.pattern,app_popen.pid)
    while select.select( [app_popen.stdout],[],[] )[0]:
        debug( "...")
        text = app_popen.stdout.read()
        for line in text.splitlines(True):
            print_in_color( line, _output_app )
        full_text += text
        match = expected_re.search( full_text )
        if match:
            app_popen.real_pid = long(match.group("pid"))
            debug( "Found pid", app_popen.real_pid )
            return

def handle_segfault( ctrl ):
    """Continues replay after SIGSEGV in application.

    Presumably the segfault was caused by our implementation of
    watchpoints in Friday, which removes write permissions on the
    pages that contain watched variables.  If this is not the case,
    kill the process.
    	If we did hit a watched page, temporarily restore permissions
    and step over the instruction.
    	Next run any hooks installed on the watchpoint by the user.
        Finally, restore watchpoints.
    Returns True if replay should ignore segfault and continue.
    """
    if COLLECT_TIMERS: _timers["handle_segfault"].start()
    fault_addr = get_long( ctrl, "((ucontext_t*)datum)->uc_mcontext.cr2")
    start_addr = friday.Page.baseaddr(fault_addr)
    if not friday.is_watched_page( ctrl, start_addr ):
#        FIXME: more info.
	 #    Allow the user to inspect the app upon genuine segfault.
    #    stop_controller( ctrl, "segfault" )
        return False
    debugf( "SEGV at 0x%x/0x%x", fault_addr, start_addr )
    REG_EIP = 14	# PC register number for x86.
    fault_pc = get_long( ctrl,
                         "(unsigned long)((ucontext_t*)datum)->uc_mcontext.gregs[14]")
    debugf( "PC: 0x%x", fault_pc )
    if COLLECT_TIMERS: _timers["unprotect"].start()    
    friday.make_writable( ctrl, start_addr )
    if COLLECT_TIMERS: _timers["unprotect"].end()        
    # Set a temporary breakpoint at the faulting instruction,
    #  then continue.  We should exit signal handler and
    #  resume execution

    if COLLECT_TIMERS: _timers["continue"].start()
#    call_gdb_quiet( ctrl, "call dump_mem( mprotect_remove, 20 )" )    
    call_gdb_quiet( ctrl, "disable %d"%gdb_hook_break_number )
    call_gdb_quiet( ctrl, "tbreak *0x%x"%fault_pc )
#    call_gdb_quiet( ctrl, "call dump_mem( mprotect_remove, 20 )" )        
    call_gdb_quiet( ctrl, "continue" )
    call_gdb_quiet( ctrl, "enable %d"%gdb_hook_break_number )

    if COLLECT_TIMERS: _timers["continue"].end()            
    # Now step over faulting instruction
    debugf( "PC: 0x%x", get_pc(ctrl) )
    call_gdb_quiet( ctrl, "stepi" )
    debugf( "After step PC: 0x%x", get_pc(ctrl) )
    if COLLECT_TIMERS: _timers["reprotect"].start()
    friday.make_readonly( ctrl, start_addr )	# back to orignal state
    if COLLECT_TIMERS: _timers["reprotect"].end()        
    # Run hooks
    if COLLECT_TIMERS: _timers["run_hooks"].start()
    (should_continue,false_positive,modified) = friday.run_hooks( ctrl, fault_addr )
    if COLLECT_TIMERS: _timers["run_hooks"].end()
    if not COLLECT_TIMERS:
        pass
    elif false_positive:
        _class_timings["fp"].add(_timers["run_hooks"].last_index)
    elif modified:
        _class_timings["mod"].add(_timers["run_hooks"].last_index)
    else:
        _class_timings["unchanged"].add(_timers["run_hooks"].last_index)
    if COLLECT_TIMERS: _timers["handle_segfault"].end()
#    call_gdb_quiet( ctrl, "enable 2" )

    return should_continue
    
def is_at_hook( ctrl, pc ):
    """If we've hit an internal breakpoint, return the name."""
    debugf( "Checking for hook: %s vs. %s", pc, ctrl.gdb_hook_break_addr )
    if pc and (pc == ctrl.gdb_hook_break_addr):    
        hook_code = get_long( ctrl, "(long)code" )
        debug( "hook code:", hook_code, color=_output_meta )
        assert( 0 <= hook_code < len(gdb_hook_names) )
        return gdb_hook_names[hook_code]
    return None
        
def check_for_breakpoints( ctrl ):
    """If we have hit a breakpoint, handle it.

    First, check for internal breakpoints.
     Look at current PC, check against gdb_hook_break_addr, and
     handle whatever bookkeeping is necessary.
    Second, call friday.check_user_breaks()
    """
    pc = get_pc( ctrl )
    hook_name = is_at_hook( ctrl, pc )
    if hook_name:
        if hook_name == "LL_HOOK_WRAPPER_TRAP":
            # Bottom of each libreplay handler
            pass
        elif hook_name == "LL_HOOK_NEXT_LOG":
            # About to rotate logs
            new_log = get_string( ctrl, "(char*)datum" )
            debug( "Should rotate in log", new_log, color=_output_meta )
            try:
                trace_logs.ensure_in_cache( new_log )
            except trace_logs.TraceException, te:
                error( "Caught exception:", te )
                # Could not open next log.  Terminate replay.
                hook_name = "LL_HOOK_LOG_FAILURE"
            
        elif hook_name == "LL_HOOK_FORK":
            # Forked off a child
            child_pid = get_long( ctrl, "*(pid_t*)datum" )
            if child_pid in ctrl.children:
                # Be sure to only attach once
                pass
            else:
                debug( "Parent forked child #", child_pid, color=_output_meta )
                
                attach_to_child( ctrl, child_pid )
                # A fork also precedes a wait/handoff:
                ctrl.next_child = child_pid

        elif hook_name == "LL_HOOK_SIGNAL":
            # Tells us what process will run next
            ctrl.next_child = get_long( ctrl, "*(pid_t*)datum")
            assert( ctrl.next_child and
                    (ctrl.next_child != ctrl.current_child) )
            debug( "Next PID:", ctrl.next_child, color=_output_meta)

        elif ((hook_name == "LL_HOOK_WAIT")
              or (hook_name == "LL_HOOK_THREAD_EXIT")):
            # Switch to the next thread.
            if ctrl.next_child:
                ctrl.switch_children()
            else:
                # Switching threads, or something else we can ignore
                debug( "Just waiting", color=_output_meta)
        elif hook_name == "LL_HOOK_STOP_REPLAY":
            # Hit an internal consistency check
            if get_long( ctrl, _gdb_failstop_here_flag ):
                error( "Failed consistency check. ",
                       "Use 'override' command to continue." )
        elif hook_name == "LL_HOOK_SEGV":
            # Seg fault in application.  Probably hit a watchpoint.
            should_continue = handle_segfault( ctrl )
            if not should_continue:	# Make sure we stop here.
                hook_name = "LL_HOOK_SEGV_STOP"
        else:
            raise Exception, ("Unexpected hook:"+hook_name)
        return hook_name	# Hit hook breakpoint
    else:
        (found_break,should_continue) = friday.check_user_breaks( ctrl, pc )
        if found_break:
            if should_continue:
                hook_name = "LL_USER_BREAK"
            else:
                hook_name = "LL_USER_BREAK_STOP"
        # else: leave hook_name == None
        return hook_name

def remove_extra_warnings( output ):
    """Prune out some asynchronous messages from GDB output."""
    output = output.replace( "Loaded symbols for ../libs/libreplay.so\n", "" )
    if -1 < output.find( "Current language" ):
        if ECHO_DEBUG:
            debugf("removing language warning: '%s'", output,
                   color=_output_echo_debug)
        output = language_warning_re.sub( "", output )
    return output
        
def read_output( ctrl, action="print", wait_for_prompt=True, child_pid=None,
                 may_hit_breakpoint=True ):
    """Reads output from a subprocess until '(gdb)' is found.

    Set action to "return", "discard", or "print" (default).
    Normally blocks until gdb prompt is read, so controller can keep
      synchronized with gdb.
    Returns (str,str) tuple, including output (if action==return) and
      a the name of an internal hook iff the process was stopped on our
      internal breakpoint.
    """
    debugf( "Reading output[%s]...", child_pid )
    final_output = []
    empty_iters = 0
    max_empty_iters = 5
    gdb_out = ctrl.gdb(child_pid).stdout
    read_fd_set = [ctrl.app_out,gdb_out]
    while True:
        if empty_iters > max_empty_iters:
            raise Exception, "read_output breaking out of infinite loop" 
        if wait_for_prompt:	# block
            ready = select.select(read_fd_set,[],[] )[0]
        else:	# It is possible that neither output is ready
            ready = select.select(read_fd_set,[],[],0 )[0]
        if ECHO_DEBUG:
            ready_names = [name for fd, name in \
                           zip(read_fd_set, ["app","gdb"]) if fd in ready]
            debug( "ready: ", ready_names, color=_output_echo_debug )
        if ctrl.app_out in ready:
            drain_app( ctrl.app_out )
            #continue
        if gdb_out not in ready:
            if wait_for_prompt:
                continue	# prompt will appear eventually.
            else:
                break	# immediately; rest of loop expects output
        output = gdb_out.read()
        if not output:
            empty_iters += 1
            if ECHO_DEBUG: debug("*", color=_output_echo_debug )
            continue
        output = remove_extra_warnings( output )
        # Check for end of output
        should_break = False
        if output.endswith( _gdb_prompt ):
            if action != "discard":
                if ECHO_DEBUG:
                    debugf("removing: '%s'", _gdb_prompt,
                           color=_output_echo_debug)
                output = output[:0-len(_gdb_prompt)]
            should_break = True	# break out of select loop
        # Now deal with output text:
        if action == "print":
            print_in_color( output, _output_from_gdb )
        elif ECHO_DEBUG:
            debug( output, color=_output_echo_debug )
        final_output.append( output )
        if should_break:
            break
    # Output finished.  Now we can check the process' status.
    hook = None
    output_str = None
    if may_hit_breakpoint:
        hook = check_for_breakpoints( ctrl )
    if action == "return":
        output_str = "".join(final_output)
    return( output_str, hook )

def drain_all_output():
    "Calls read_output() for each controller."
    for ctrl in all_controllers():
        for pid in ctrl.children:
            debugf( "draining #%d:%d", ctrl.index, pid )
            read_output( ctrl, wait_for_prompt=False, child_pid=pid,
                         may_hit_breakpoint=False )
    debug( "drain_all_output finished" )

def discard_output( ctrl, child_pid=None ):
    "Like read_output, but silent"
    read_output( ctrl, action="discard", child_pid=child_pid )


def get_inferior_pid( ctrl ):
    """Returns the PID of the replay app.

    Calls "info proc" in gdb and parses the inferior's info."""
    debug( "Reading info proc" )
    output = call_gdb( ctrl, "info proc\n", action="return",
                       may_hit_breakpoint=False )
    debug( "get_inferior_pid:", output )
    match = gdb_info_proc_re.search( output )
    if match:
        return long( match.group('pid') )
    else:
        return None

def get_pc( ctrl, child_pid=None ):
    "Returns current Program Counter."
    return get_long( ctrl, "(unsigned long)$eip", child_pid )

def get_type( ctrl, name, child_pid=None ):
    """Returns the type (as string) of a variable."""
    debug( "Reading type of", name )
    output = call_gdb( ctrl, "whatis %s\n"%name, action="return",
                       child=child_pid, may_hit_breakpoint=False )
    debug( "get_type:", output )
    match = gdb_type_re.search( output )
    if match:
        return match.group('type').strip()
    else:
        return None

def get_long( ctrl, name, child_pid=None ):
    """Returns a value (as long) from gdb."""
    debug( "Reading variable", name )
    output = call_gdb( ctrl, "print %s\n"%name, action="return",
                       child=child_pid, may_hit_breakpoint=False )
    debug( "get_long:", output )
    match = gdb_print_re.search( output )
    if match:
        return safe_long( match.group('var').split()[0] )
    else:
        return None

def get_string( ctrl, name ):
    """Returns a value (as string) from gdb."""
    debug( "Reading variable", name )
    output = call_gdb( ctrl, "print %s\n"%name, action="return",
                       may_hit_breakpoint=False )
    debug( "get_string:", output )
    match = gdb_print_string_re.search( output )
    if match:
        return match.group('var')
    else:
        return None

def get_bytes( ctrl, addr, len ):
    """Returns len consecutive 8-bit values from addr, as ints."""
    if not isinstance( addr, str ):  # long/integer type.
	addr = "0x%x"%addr
    debugf( "Reading 0x%x bytes at %s", len, addr )
    output = call_gdb( ctrl, "x /%dbx %s\n"%(len,addr), action="return",
                       may_hit_breakpoint=False )
    debug( "get_bytes:", output )
    byte_list = []
    for line in output.splitlines():
        match = gdb_bytes_re.search( line )
        if not match: break
        debug( "match:", match.groups())
        byte_list.extend( [int(s,16) for s in match.group('bytes').split()])
    return byte_list

def get_as_bytes( ctrl, name ):
    """Returns a value (as byte array) from gdb.

    Unlike get_bytes, this method prints a value directly instead of
    using the address and length."""
    debugf( "Reading '%s' as bytes", name )
    output = call_gdb( ctrl, "print /x (char[])%s\n"%name, action="return",
                       may_hit_breakpoint=False )
    debug( "get_as_bytes:", output )
    match = gdb_print_bytes_re.search( output )
    debug( "match:", match.groups())
    def hex_drop_comma( text ):
	if text.endswith( ',' ):
	    return int(text[:-1],16)
	return int(text,16)
    byte_list = [hex_drop_comma(s) for s in match.group('bytes').split()] 
    return byte_list

def load_source_files( ctrl, child_pid=None ):
    """Updates the source code search path for gdb."""
    main_src_dir = get_conf("logreplay_src_dir",ctrl.addr)
    app_src_path = get_conf("app_src_path",ctrl.addr)
    if app_src_path:
        app_src_dirs = app_src_path.split(':')
    else:
        app_src_dirs = []
    app_bin_dir = os.path.dirname(ctrl.app_executable)
    for subdir in [main_src_dir] + app_src_dirs + [app_bin_dir]:
        subdir = abspath(subdir)
	debug( "adding source directory", subdir )
	call_gdb_quiet( ctrl, "directory %s"%subdir, child_pid )
    return

def read_args():
    """Parses and handles command-line arguments.

    Currently you can pass in a list of filenames for executables that
    you might debug, so we don't have to prompt you later.

    Also added ability to specify scripts to run.
    """
    global _cl_binaries, _cl_script
    script_file = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "",
                                   ["binary=", "rc=", "script="])
    except getopt.GetoptError, ge:
        die( "Caught:" + str(ge) )

    for opt, arg in opts:
        debug( opt, "=", arg )
        if opt in ("--binary"):
            _cl_binaries.append( arg )
        elif opt in ("--rc", "--script"):
            script_file = arg
    _cl_binaries.extend( args )
    debug( "_cl_binaries:", _cl_binaries )
    debug( "script:", script_file)
    rc_lines = []
    if script_file:
        try:
            script = file(script_file).read()
            _cl_script = script.splitlines()
        except IOError:
            error( "Could not read script file '%s'"%script_file )
    debug( "_cl_script:", _cl_script )
    return

def get_application_file( ckpt_filename ):
    match = ckpt_name_re.match( os.path.basename(ckpt_filename) )
    if not match:
        return None
    app_name = match.group("appname")
    addr = match.group("addr")
    debugf( "Looking for %s (%s)", app_name, addr, color=_output_meta )
    # First check files named on command line.
    for filename in _cl_binaries:
        if filename.endswith(app_name):
            filename = abspath(filename)
            return filename
    all_path = "%s:%s"%(get_conf("app_path",addr),
                        os.environ.get("PATH",""))
    abs_path_list = [abspath(p) for p in all_path.split(':')]
    for dir in abs_path_list:
        filename = "%s/%s"%(dir,app_name)
        debug( "Trying", filename, color=_output_meta )
        if os.path.exists( filename ):
            debug("Found matching executable:", filename, color=_output_meta)
            return filename
    else:
        out( "Where is local executable for '%s'?"%app_name )
        # Search history file for suggestions
        cached_name = None
        for idx in range(readline.get_current_history_length()-1,0,-1):
            history_item = readline.get_history_item( idx )
            if history_item.endswith( app_name ):
                cached_name = history_item
                break
        filename = None
        while not filename:
            filename = prompt( "enter file path " +
                    (": ","(%s): "%cached_name)[bool(cached_name)] )
            if cached_name and not filename:	# Use cache suggestion
                # Refetch from dict; cached_name added format sugar.
                filename = cached_name
        filename = abspath(filename)
        if ((not filename.endswith(app_name))
            and os.path.exists( filename + "/" + app_name )):
            filename = filename + "/" + app_name	# Maybe they only provided the directory?            
            # Remember for next time:
            debugf( "Saving %s to history", filename, color=_output_meta )
            readline.replace_history_item(readline.get_current_history_length()-1, filename)
            return filename
        elif os.path.exists( filename ):	# Just a renamed executable?
            return filename
        else:
            return None

def call_break_in_gdb( ctrl, spec, child=None ):
    """Sets a breakpoint in one process. Returns (index, address)."""
    cmd = "break " + spec
    debugf( "setting '%s'", cmd )
    output = call_gdb( ctrl, cmd, action="return",
                       child=child, may_hit_breakpoint=False )
    debugf( "break command returned '%s'", output )
    match = gdb_set_break_re.search( output )
    if not match:
        error( "ERROR: gdb returned '%s'"%output )
        return (None,None)
    index = int(match.group('num'))
    addr = long(match.group('addr'),16)
    debug( "set breakpoint", (index,addr))
    return (index, addr)

def set_hooks( ctrl ):
    """Sets internal "hook" breakpoint. Saves address.

    Returns True iff breakpoint was set and output parsed successfully."""
    index,addr = call_break_in_gdb( ctrl, gdb_hook_break_name )
    if not index:
        error( "ERROR: could not set internal breakpoint")
        return False
    assert index == gdb_hook_break_number
    ctrl.gdb_hook_break_addr = addr
    debug( "hook addr:", ctrl.gdb_hook_break_addr )
    return True

def resolve_dns( name ):
    "Replaces any embedded DNS name with IP equivalent."
    match = replay_addr_re.search( name )
    try:
        if match:
            debugf( "Looking up '%s'", match.group('addr') )
            ip = socket.gethostbyname(match.group('addr'))
            new_name = name.replace( match.group('addr'), ip )
            debug( "resolved:", new_name )
            return new_name
    except socket.timeout:
        error( "DNS lookup timed out" )
    except socket.error,e:
        debug( "DNS lookup failed:", e )
    return None

def parse_time( word ):
    """Returns a vclock, in microseconds.

    Input format is [-]<count>[{h,m,s}]."""
    multiplier = 1
    if word[-1] == "s":
        multiplier = 1000000
        word = word[:-1]
    elif word[-1] == "m":
        multiplier = 60000000
        word = word[:-1]
    elif word.endswith("h"):
        multiplier = 3600000000
        word = word[:-1]
    if word == "now":
        count = long(time.time()*1000000)
    else:
        count = safe_long(word)
    debug( "parse_time:", count, multiplier )
    if count:
        count *= multiplier
        if count < 0:
            count += long(time.time()*1000000)
        elif multiplier > 1:
            error( "Questionable vclock '%d'"%count )
    return count

def parse_replay_time( words ):
    "Returns the starting vclock, and optionally end vclock."
    start_vclock = parse_time(words[0])
    range_end = None
    if not start_vclock:
        error( "Invalid start time '%s'"%words[0] )
    elif len(words) > 1:
        if (len(words) == 3) and (words[1] in ("to","-")):
            del words[1]
        if len(words) != 2:
            error( "Invalid range '%s'"%(" ".join(words)))
        else:
            range_end = parse_time(words[1])
            if not range_end:
                error( "Invalid range end '%s'"%words[0] )
            if start_vclock > range_end:
                error( "Inverted range: %d > %d"%(start_vclock, range_end))
    debug( "parse_replay_time:", start_vclock, range_end )
    return start_vclock, range_end

def replay_wrapper( words ):
    "Calls start_replay."
    if not (1 <= len(words) <= 4):
        error( "Invalid usage" )
        print_help()
        return True
    note( "Replaying", words )
    addrs = []
    addr = resolve_dns( words[0] )
    if addr:
        addrs.append( addr )
    else:
        addr_filename = abspath(words[0])
        debugf( "Trying file '%s'", addr_filename )
        if os.path.exists( addr_filename ):
            addr_file = file(addr_filename)
            addrs = addr_file.read().splitlines()
            debug( "addrs:", addrs )
            addrs = map( resolve_dns, addrs )
            debug( "addrs:", addrs )
    if not addrs:
        error( "Invalid address '%s'"%words[0] )
        return True
    if len( words ) > 1:
        vclock, range_end = parse_replay_time( words[1:] )
    else:
        vclock = range_end = None
    for addr in addrs:
        start_replay( addr, vclock, range_end=range_end )
    return True
    
def start_replay( addr, start_vclock, exact=False, range_end=None ):
    """Opens a replay process for a specified address and time.

    If start_vclock is None, start replay from beginning of available logs.
    Otherwise, find a log that starts at (or crosses, if exact==False)
    start_vclock.
    """
    debugf( "Starting replay for %s@%s",
            addr, (str(start_vclock),"ANY")[not start_vclock])
    try:
        log_list = trace_logs.fetch_log( addr, start_vclock,
                                         exact=exact, range_end=range_end, with_ckpt=True )
        debug( "fetch_log returned:", log_list )
    except trace_logs.TraceException, te:
        error( "Caught exception:", te )
        log_list = []
    if not log_list:
        error( "No matching logs for %s@%s"%\
               (addr, (str(start_vclock),"ANY")[not start_vclock]) )
    else:
        for log_info in log_list:
            start_one_replay( log_info, addr, start_vclock )
    return

    
def start_one_replay( log_info, addr, start_vclock ):
    """Helper for start_replay."""
    
    if ((log_info.ckpt is None) or (not log_info.ckpt.is_local)):
        error( "Could not find ckpt for %s@%s"%\
               (addr, (str(start_vclock),"ANY")[not start_vclock]) )
        return
    at_vclock_str = ""
    if start_vclock:
        at_vclock_str = "to %d"%start_vclock
    app_file = get_application_file( log_info.ckpt.filename )
    if not app_file:
        error( "ERROR: No symbol file; cannot replay", addr )
        return

    # First get paths to restart binary and checkpoint.
    orig_wd = os.getcwd()
    ckpt_filename = abspath(log_info.ckpt.filename)
    restart_bin = abspath(get_conf("restart_bin",addr))
    # Move into cache directory so checkpoint can find libs, logs.
    cache_dir = get_conf("local_cache",addr)
    os.chdir( cache_dir )
    # Run restart binary, which restores original application, which 
    #  loads libreplay, which spins until GDB attaches.
    debug( "restart_bin: ", restart_bin )
        
    app_proc = start_child([restart_bin,ckpt_filename] )
    # Let libreplay initialization complete.
    wait_for_app( app_proc )	# Sets app_proc.real_pid
    
    # Next start gdb.
    child = start_child( [_gdb_bin, app_file] )

    # Move back to original working directory before we forget.
    os.chdir( orig_wd )
    
    # Initialize the Controller data structure.
    # We do this ASAP, so we can use ctrl for the rest of initialization.
    ctrl = Replay_Controller( addr, log_info.start, child,
                              app_proc.real_pid, app_proc.stdout, app_file )
    note( "Starting replay for", addr, at_vclock_str )
    # Now we can interact with gdb
    discard_output( ctrl )	# Finally discard initial output
    load_source_files( ctrl )	# Find local source files.

    # Attach to child.
    call_gdb( ctrl, "attach %d"%(app_proc.real_pid), action="discard" )

    # Did restore work?  Try to read the application PID
    inf_pid = get_inferior_pid(ctrl)
    if not inf_pid:
        error( "ERROR: could not replay", addr )
        return
    #assert inf_pid == ctrl.current_child
    # Discourage background threads from running
    call_gdb_quiet( ctrl, "set scheduler-locking step" )
    # Let liblog signal handler see segfaults, for mprotect wizardry.
    call_gdb_quiet( ctrl, "handle SIGSEGV nostop noprint" )
    # Now set our own breakpoints:
    if not set_hooks( ctrl ):
        error( "ERROR: could not replay", addr )
        return
    # If multiple processes were restored, must attach to others.
    attach_to_children( ctrl )
    
    note( "Replay process #%d ready."%ctrl.current_child )
    # Now, should call "up" or something to get back to application?
    if start_vclock:
        advance_controllers( start_vclock )	# Roll up to requested time.
    if (ctrl.index in _stopped_indices) or (not ctrl.vclock()):
        error( "ERROR: could not advance", addr, at_vclock_str )
    return

def attach_to_children( ctrl ):
    """Finds and attaches to secondary application processes.

    Searches the process' _shared_info structure for PIDs for
      secondary processes, then calls attach_to_child()."""
    def read_replay_pid():
        return get_long( ctrl, "%s->%s"%(proc_info_name,gdb_replay_pid_field))
    proc_info_name = gdb_proc_list_name
    replay_pid = read_replay_pid()
    assert( replay_pid )	# Always at least one element in list.
    while( replay_pid ):
        debug( "Scanning pids:", replay_pid )
        if replay_pid != ctrl.current_child:
            attach_to_child( ctrl, replay_pid )
            # The child should be somewhere in my_cond_wait; make sure
            #  that it's in wait_trap:
            if get_long( ctrl, "holding_locks", replay_pid ):
                call_gdb( ctrl, "continue", replay_pid, action="discard" )
            else:
                debug( "Not holding locks" )
        else:
            debugf( "Our pid: %d; skipping.", replay_pid, color=_output_meta)
        # Advance to next proc_info_t struct in list.
        # get_long() will return None once we reach NULL.
        proc_info_name += "->next"
        replay_pid = read_replay_pid()

    
def attach_to_child( ctrl, child_pid ):
    """Starts a gdb process that attaches to newly forked app child.

    When this function is called, the parent application process is
      still considered the active one, so we must explicitly provide
      the child pid to call_gdb(), discard_output(), etc.
    """
    child = start_child( [_gdb_bin, ctrl.app_executable] )
    ctrl.add( child, child_pid )
    discard_output( ctrl, child_pid )	# Discard initial output
    note( "Added child #%d to %s"%(child_pid,ctrl) )
    # Move into cache directory so checkpoint can find libs, logs.
    cache_dir = get_conf("local_cache",ctrl.addr)
    call_gdb_quiet( ctrl, "cd %s"%cache_dir, child_pid )
    load_source_files( ctrl, child_pid )	# Find local source files.
    # Now attach to child.
    call_gdb( ctrl, "attach %d"%child_pid, child_pid, action="discard" )
    # Now set our own breakpoints:
    copy_parent_breakpoints( ctrl, child_pid )
    # Distributed Watchpoints should "just work".
    call_gdb_quiet( ctrl, "handle SIGSEGV nostop noprint", child_pid )
    # Discourage background threads from running
    call_gdb_quiet( ctrl, "set scheduler-locking step", child_pid )
    debug( "gdb replay fully initialized." )        
    return

def copy_parent_breakpoints( ctrl, child_pid ):
    """Set breakpoints from parent in child.

    Reads breakpoint info from current process in controller, then
    sets each breakpoint in child with same enable/disable status.
    """
    break_info_cmd = "info breakpoints"
    text = call_gdb( ctrl, break_info_cmd, action="return",
                     may_hit_breakpoint=False )
    debug( "parent breakpoints:", text )
    break_num = 1
    for line in text.splitlines()[1:]:
        # FIXME -- handle "hw watchpoint", too!
        match = gdb_info_break_re.match( line )
        if not match:
            debug( "Ignoring breakpoint info:", line )
        else:
            # Set breakpoint at same address. Do not attempt to parse
            #  match.group("where")
            assert break_num == int(match.group("num"))
            break_cmd = "%s *%s"%(match.group("type"),match.group("addr"))
            call_gdb_quiet( ctrl, break_cmd, child_pid )
            if match.group("enabled") == "n":
                disable_cmd = "disable %d"%break_num
                call_gdb_quiet( ctrl, disable_cmd, child_pid )
            break_num += 1
    # Finally, copy any Friday state.
    for point in friday._points:
	if (isinstance( point, friday.BreakPoint ) and
	    (ctrl.index in point.by_child) and
	    (ctrl.current_child in point.by_child[ctrl.index])):
	    point.by_child[ctrl.index][child_pid] = point.by_child[ctrl.index][ctrl.current_child]
    return

def list_all( ignore=None ):
    "Prints out each live replay_controller."
    current = []
    if _current_replay_ids: current = current_controllers()
    if not all_controllers():
        out( " No active processes." )
        return True
    all = all_controllers()
    active = 0
    for ctrl in all:
        prefix = " "
        if ctrl in current:
            prefix = "*"
            active += 1
        out( " %s %s"%(prefix,str(ctrl)) )
    out( "%d/%d currently active"%(active,len(all)))
    return True

def advance_wrapper( spec ):
    "Parses vclock, calls advance_controllers."
    if len(spec) > 1:
        error( "Too many arguments" )
        print_help()
        return True
    if not spec:
        vclock = None
    else:
        vclock = spec[0]
    global _last_advance_words
    _last_advance_words = spec
    advance_controllers( vclock )
    return True

def continue_wrapper( spec ):
    "Overrides gdb continue.  Equivalent to 'advance forever'."
    if spec:
        error( "Too many arguments--perhaps you want gdb continue?" )
        print_help()
        return True
    return advance_wrapper( ["forever"] )

def advance_one( ctrl, next_clock ):
    """Helper function for advance_controllers.

    Calls 'continue' in one gdb.  Depending on next_vclock, will
    make hook breakpoint conditional, for efficiency."""
    debug( "Advancing", ctrl, color=_output_meta )
    continue_condition = None
    if (next_clock == "forever"):
        # No reason to stop in each wrapper. 
        continue_condition = ("(code != %d)"%\
                              (gdb_hook_codes["LL_HOOK_WRAPPER_TRAP"]))
    elif next_clock:
        # Skip wrapper trap until requested time
        continue_condition = ("(code != %d) || (%s >= %d)"%\
                              (gdb_hook_codes["LL_HOOK_WRAPPER_TRAP"],
                               gdb_vclock_name,next_clock))
    if continue_condition:
        call_gdb_quiet( ctrl, "condition %d %s"%(gdb_hook_break_number,
                                                 continue_condition) )
    write_command( ctrl, "continue" )
    if COLLECT_TIMERS: _timers["advance_one"].start()
    text, hook = read_output( ctrl, "return" )
    if COLLECT_TIMERS and hook and hook.startswith("LL_HOOK_SEGV"):
        _timers["advance_one"].end()        
    if continue_condition:	# Clear condition.
        call_gdb_quiet( ctrl, "condition %d"%(gdb_hook_break_number,) )
    return (text, hook)
    
def advance_controllers( target_vclock ):
    """Continues replay up to first log entry at or after target vclock.
    
    Calling with "+<usecs>" advances that far.
      (If replaying multiple programs, each will advance that far
      from the earliest current time).
    """
    if COLLECT_TIMERS: _timers["advance"].start()    
    # First put the proper set of controllers into a heap.
    scheduler_heap = [(ctrl.vclock(),ctrl) for ctrl in current_controllers()]
    heapq.heapify( scheduler_heap )
    # Check that gdb can read vclock properly
    while( scheduler_heap ):
        lowest_vclock,ctrl = scheduler_heap[0]
        if not lowest_vclock:
            error( "Could not read vclock." )
            kill_controller( ctrl )
            heapq.heappop( scheduler_heap )
        else:
            # Convert relative time if necessary
            if target_vclock and str(target_vclock).startswith("+"):
                if str(target_vclock)=="++":	# Handy shortcut
                    target_vclock = "forever"
                else:
                    target_vclock = safe_long(target_vclock[1:]) + lowest_vclock
            break	# Rest of heap must have nonzero times
    # Which controllers are still working:
    ctrl_str_list = [str(ctrl) for ignore,ctrl in scheduler_heap]
    if not ctrl_str_list:
        error( "No programs to replay." )
        return
    elif len(ctrl_str_list) == 1:
        note( "Advancing program:", ctrl_str_list[0] )
    else:
        ctrl_str_list.sort()
        note( "Advancing %d programs:\n"%len(ctrl_str_list),
              "\n".join(ctrl_str_list) )
    if target_vclock:
        if target_vclock == "forever":
            # A string is greater than any long, so this time will
            #  never be reached.
            pass	# No qualifier on "advancing..." above.
        else:
            target_vclock = safe_long(target_vclock)	# Make sure to convert from string
            note( "\tto time", target_vclock )
    else:
        note( "\tone step" )
    orig_vclock = None	# For timing statistics
    # Now repeatedly advance the first node in the heap.
    while( True ):
        if not scheduler_heap:
            break
        lowest_vclock, ctrl = heapq.heappop( scheduler_heap )
        if not orig_vclock:
            orig_vclock = lowest_vclock
        if random.random() < 0.001:	# Status message
            note( lowest_vclock )
        if target_vclock and (lowest_vclock >= target_vclock):
            break	# Avanced far enough
        # Now run the controller for a bit.
        # Ignore main hook (dummy_trap) for a few iterations?
        next_clock = target_vclock	# None < long < "forever"
        if scheduler_heap:
            next_clock = min(scheduler_heap[0][0],next_clock)
        orig_child = ctrl.current_child	# In case we switch
        text, current_hook_name = advance_one( ctrl, next_clock )

        debug( "hook?:", current_hook_name )
        # Some internal breakpoints should not be ignored:        
        hit_internal_breakpoint = force_stop = log_failed = False
        if current_hook_name:
            hit_internal_breakpoint = True
            if ((current_hook_name == "LL_HOOK_STOP_REPLAY")
                and (0 != get_long( ctrl, _gdb_failstop_here_flag ))):
                # Give user a chance to disable/ignore sanity checks
                force_stop = True
            elif current_hook_name == "LL_HOOK_SEGV_STOP":
                # WatchPoint says to stop.
                force_stop = True
            elif current_hook_name == "LL_HOOK_LOG_FAILURE":
                log_failed = True
            elif current_hook_name == "LL_USER_BREAK_STOP":
                # User breakpoint which did not have "continue" command.
                force_stop = True
            debug( "force_stop:", force_stop )
        # Remove useless output caused by hook commands
        text = apply_regexes( text, [re.compile(r'Continuing.\n')] )
        if hit_internal_breakpoint:
            # FIXME: Is breakpoint always last output?  Would it
            #  suffice to delete one following line
            text = apply_regexes( text, [re.compile(r'Breakpoint \d+, ' +
#                                                    gdb_hook_break_name +
                                                    r'.*', re.S)] )
        for line in text.splitlines(True):	# keep newlines
            if( (not OMIT_EMPTY_LINES) or line.strip() ):
                print_in_color( line, _output_from_gdb )
            else:
                if ECHO_DEBUG: debugf( "omitting: '%s'", line,
                                       color=_output_echo_debug )
        if log_failed or app_exit_re.search(text):	# Application died.
            debugf( "Process #%d died", ctrl.current_child,
                    color=_output_meta )
            ctrl.kill_current_child()
            if (not log_failed) and ctrl.next_child:	# Found handoff to next process.
                ctrl.switch_children()
                # Continue with next child?
                #hit_internal_breakpoint = True
            else:	# Should be last/only process.
                if (not log_failed) and (not ctrl.children):
                    note( "Replay ended" )
                else:
                    error( "Replay ended abruptly." )
                stop_controller( ctrl, "ended" )
                continue
        new_vclock = ctrl.vclock()
        if not new_vclock:
            error( "Could not read vclock." )
            kill_controller( ctrl )
        else:	# Reschedule
            debug( "New time:", new_vclock, color=_output_meta )
            heapq.heappush( scheduler_heap, (new_vclock,ctrl) )
        if( force_stop
            or (not hit_internal_breakpoint)	# user breakpoint
            or (not target_vclock) ):	# Only want to step once
            break
    # FIXME: print out new status, if more than one in original ctrl_list?
    # Print out line we stopped at, like GDB?
    if COLLECT_TIMERS:
        _timers["advance"].end()
        _class_timings["advance"].add(_timers["advance"].last_index)
        note( "Replayed %f virtual seconds (%d to %d)\n"%\
              ((lowest_vclock-orig_vclock)*.000001,orig_vclock,lowest_vclock))
    return

def stop_controller( ctrl, reason="stopped" ):
    """Deletes and clean up this controller(s).

    Free references to the controller, but do not slice up
    _replay_controllers, because we don't want to change the other indices.
    """
    note( "stopping program #%d (%s)"%(ctrl.index,reason) )
    ctrl.state = reason
    ctrl.alive = False
    if reason == "died":	# Save for post mortem
        _dead_controllers.append( ctrl )
    else:
        for app_pid, gdb_proc in ctrl.children.items():
            debug( "app:", app_pid )
            os.kill( app_pid, signal.SIGTERM )            
            debug( "Killing", gdb_proc.pid, gdb_proc )
            os.kill( gdb_proc.pid, signal.SIGTERM )
            debug( "waiting")
            ret = gdb_proc.wait()
            debug( "done:", ret)            
        ctrl.children.clear()
    _replay_controllers[ctrl.index] = None
    _stopped_indices[ctrl.index] = reason


def die( msg=None ):
    if msg:
        error( msg )
    reset_colors()	# reset colors, ensure newline.
    sys.exit(3)
    
def stop_all_controllers():
    """Shutdown all subprocesses."""
    for ctrl in all_controllers():    
        stop_controller( ctrl, "shutdown" )
    die()
    
def stop_wrapper( should_be_none=None ):
    """Called by console for input "end"."""
    if should_be_none:
        error( "Too many arguments" )
        print_help()
    else:
        for ctrl in current_controllers():
            stop_controller( ctrl )
    return True

def kill_controller( ctrl ):
    """Like stop_controller, but adds controller to the dead list."""
    stop_controller( ctrl, "died" )

def override_failstops( spec ):
    "Set libreplay flags to ignore consistency check failures."
    var = None
    if len(spec) > 1:
        error( "Too many arguments." )
        print_help()
    if (not spec) or (spec[0] == "one"):
        var = _gdb_failstop_here_flag
    elif spec[0] == "all":
        var = _gdb_failstop_all_flag
    else:
        error( "Invalid argument: '%s'"%spec[0] )
        print_help()
    if var:
        for ctrl in current_controllers():
            call_gdb_quiet( ctrl, "set %s=0\n"%var )
    return True
    

def call_gdb( ctrl, cmd, child=None, action="print",
              may_hit_breakpoint=True ):
    "Passes a command to gdb."
    write_command( ctrl, cmd, child )
    text, ignore = read_output( ctrl, action=action, child_pid=child,
                                may_hit_breakpoint=may_hit_breakpoint )
    return text

def call_gdb_quiet( ctrl, cmd, child=None ):
    "Calls call_gdb() for internal use."
    return call_gdb( ctrl, cmd, child,
                     action="discard", may_hit_breakpoint=False )

def call_gdb_wrapper( words ):
    "Thin wrapper for call_gdb."
    global _last_gdb_cmd_words
    _last_gdb_cmd_words = words
    current = current_controllers()
    for ctrl in current:
        if len(current) > 1:
            note( ctrl )
        call_gdb( ctrl, " ".join(words) )
    return True

def print_gdb( words ):
    "Thin wrapper for call_gdb_wrapper."
    words.insert( 0, "print" )
    return call_gdb_wrapper( words );

def info_gdb( words ):
    """Prints info on our data structures, or calls through to gdb.

    If the topic name looks like "watchpoints", print out information
    on all the current WatchPoints in the Friday library.
    Otherwise, call through to GDB.
    """
    if words and (("watchpoints".startswith(words[0]))
                  or ("breakpoints".startswith(words[0]))):
        return friday.print_info()
    else:
        words.insert( 0, "info" )
        return call_gdb_wrapper( words );

def forall_pids( words ):
    """Sends cmd to all processes in program(s).

    Normally commands are sent to the current process in the
    controller(s).  If multiple processes are running (e.g due to
    fork()) this function broadcasts the command to all of them.
    """
    for ctrl in current_controllers():
        for child in ctrl.children:
            note("PID %d in %s:"%(child,str(ctrl)) )
            call_gdb( ctrl, " ".join(words), child )
    return True

def print_history( spec ):
    "Prints recent console input history."
    if len(spec) > 1:
        error( "Too many arguments" )
        print_help()
    else:
        if spec:
            count = safe_long(spec[0])
            if (not count) or (count <= 0):
                error( "Invalid count" )
                print_help()
                return True
        else:
            count = _history_count_default
        current_idx = readline.get_current_history_length()
        first_idx = max(0,current_idx-count)
        for idx in range(first_idx,current_idx):
            out( " %d  %s"%(idx, readline.get_history_item(idx)) )
    return True

def redo_history( spec ):
    "Re-executes command from readline history."
    if len(spec) != 1:
        error( "Invalid history index" )
        print_help()
        return True
    else:
        if spec[0] == "!":
            idx = readline.get_current_history_length()-1
        else:
            idx = safe_long( spec[0] )
    if (not idx) or (idx < 0):
        error( "Invalid history index" )
        print_help()
        return True
    old_cmd = readline.get_history_item(idx)
    print_in_color( "  %s\n"%old_cmd, _output_user )    
    current_idx = readline.get_current_history_length()
    # replace_() seems to be off-by-one relative to history
    readline.replace_history_item( current_idx-1, old_cmd )
    return process_input( old_cmd )

def print_in_python( words ):
    """Pretty-prints the current value of named variables.

    Like call_in_python below, use Friday's namespace.
    """
    for word in words:
        out( "\t%s:\t%s"%(word,pprint.pformat( eval(word,vars(friday)) )) )
    return True

def call_in_python( words ):
    """Executes a statement directly in python.

    We use the Friday module's namespace, to make it easier to set up
    state that is accessed by WatchPoint commands.  To access state in
    the main module, use "main.<var>".
    """
    stmt = " ".join(words)
    try:
        exec stmt in vars(friday)
    except Exception, e:
        error( "Caught exception:", e )
    return True

########################################
# Console Interface

def print_help( ignore=None ):
    "Displays accepted user input."
    out( """Input format: <replay_id> <command> [<args>]

    replay_id:	When multiple programs are being replayed, you may
    		apply a command to a single program by specifying its
    		index here.  Indices start at 0, and are shown by the
    		"ids" command.  Comma-separated lists of indices are
    		allowed. The string "all" is also acceptible, and is
    		the default.
                Once specified, the replay_id is used for all
    		successive commands until overridden.
                Console commands (see below) ignore replay_id.

    command:	What you want the console to do.  Most commands are
    		passed directly to gdb for the current or named
    		replay program.  In addition, some commands are
    		provided by the console itself, and some are more
    		advanced versions of normal gdb commands that
    		coordinate and operate on multiple replay programs.

                As in gdb, prefixes are acceptible in lieu of the full
                command name.  Currently prefixes for our console
                override equivalents from gdb.
                Exceptions: 'p' => gdb 'print', 'i' => gdb 'info'
    
    console commands:
    	help		: prints this message
        quit		: exits replay console
        replay [<user>@]<node>[:<path>] [<vclock>]	: starts replaying a process,
        		also sets replay_id for following commands.
                        <node> may be IPv4 address or DNS name.
        replay file [<vclock>]	: replays all nodes listed in file.
        ids		: shows programs being replayed
        python <stmt>	: executes a python statement directly
        pp <exp>...	: prints python variables
        history	<count>	: prints recent console input history
        !! | ! <num>	: re-executes command from history
	debug		: toggles internal console debugging output                    

    advanced/wrapped gdb commands:
        end		: stops replaying the process
        gdb <cmd>	: passes cmd directly to gdb.  Normally "gdb"
        		  can be omitted.  Use this for conflicting
                          commands, like "help" and "watch".
        advance [<vclock>|+<microseconds>|++]	: advances program(s)
        		  to specified time, by specified number of
                          (virtual) microseconds, or until breakpoint.
	continue	: equivalent to "advance ++".                        
        forall <cmd>	: sends cmd to all processes in program(s).
        		  Useful for operating on parent/child
                          processes simultaneously.
	override one|all	: ignores/disables internal consistency checks
        watch <exp>...	: sets a distributed watchpoint
        enable <num>	: (re-)enables a distributed break/watchpoint.
        disable <num>	: disables a distributed break/watchpoint
        commands [num]	: attaches a python hook to a distributed
        		  watchpoint or breakpoint.  If number is
                          ambiguous, prefix with "b" or "w" (default).
                          Ex.: commands b3
        
    """ )
    return True

# A list of accepted commands, in (<name>,<func>) tuples.
# The function should return True if execution should continue, else False.
_console_commands = [
    ("help", print_help),
    ("?", print_help),
    ("quit", lambda x: False),	# Return False to exit main loop
    ("exit", lambda x: False),	
    ("info", info_gdb),
    ("ids", list_all),
    ("print", print_gdb),
    ("pp", print_in_python),
    ("python", call_in_python),
    ("history", print_history),
    ("!", redo_history),
    ("replay", replay_wrapper),
    ("debug", toggle_debug),
    ("watch", friday.watch),
    ("advance", advance_wrapper),
    ("continue", continue_wrapper),
    ("commands", friday.add_hook),
    ("enable", friday.enable),
    ("disable", friday.disable),
    ("break", friday.add_breakpoint),
    ("end", stop_wrapper),
    ("gdb", call_gdb_wrapper),
    ("forall", forall_pids),
    ("override", override_failstops),
    ]

#FIXME: Add hook to trace_msg.  Use current log entry to find previous
# recv to start search?

def process_input( line ):
    """Processes a single line of user input.

    See print_help() for acceptible input format."""
    line = line.strip()
    if line.startswith('#'):
        return True
    if line.startswith('!'):
        words = ['!'] + line[1:].split()
    else:
        words = line.split()
    global _last_gdb_cmd_words, _last_advance_words
    if not words:	# Empty line.  Repeat input like gdb.
        # Cannot just pass newline, because gdb cannot differentiate
        #  between user commands and ours.  Ours should not repeat.
        if _last_gdb_cmd_words is not None:
            call_gdb_wrapper( _last_gdb_cmd_words )
        elif _last_advance_words is not None:
            advance_wrapper( _last_advance_words )
        return True
    else:
        # New command; forget last one.
        _last_gdb_cmd_words = None
        _last_advance_words = None

    # First check whether line includes specific replay id.
    ids = parse_replay_id( words[0] )
    if ids:	# Change global
        global _current_replay_ids
        _current_replay_ids = ids
        words.pop(0)
    # Now check whether command is one that we handle ourselves
    if not words:	# Only replay_id: no command here.
        return True
    cmd = words[0]
    for name,func in _console_commands:
        if name.startswith( cmd ):
            return func( words[1:] )
    else:
        debugf( "Assuming '%s' is gdb command", cmd, color=_output_meta )
        return call_gdb_wrapper( words )
    
def parse_replay_id( id ):
    """Tries to parse an replay id.

    Acceptible input is the string "all", an id number (small
    integer), or a comma-separated list of id numbers.
    If the input could not be parsed, this method returns None.
    Otherwise it returns a list of integers, or "all".
    """
    if id == "all":
        return id
    try:
        # Evaluate into a list, in empty environment
        parsed = eval( "[%s]"%id, { "__builtins__":{}}, {} )
    except NameError, ne:        # Probably a command.
        return None
    except SyntaxError, se:
        return None	# Probably shared keyword, like 'print'
    if (isinstance( parsed, list ) and
        not [x for x in parsed if not isinstance( x, int )]):
        # a list of ints
        return parsed
    else:
        error( "Not an id: '%s'"%id )
        return None

def join_id_list( id_list ):
    """Returns intersection of id_list and list of current replay indices."""
    max_i = len(_replay_controllers)
    if id_list == "all":
        indices = range(max_i)
    else:
        assert isinstance( id_list, list )
        indices = id_list
    # Now match against valid replay indices
    indices = [i for i in indices if ((i < max_i) and
                                      not i in _stopped_indices)]
    debug( id_list, " -> ", indices )
    return indices

def all_controllers():
    return [_replay_controllers[idx] for idx in join_id_list( "all" )]

def current_controllers():
    if not _current_replay_ids:
        error("That command is invalid without replay id" )
        return []
    return [_replay_controllers[idx] for idx in join_id_list( _current_replay_ids )]


# Timing statistics:
COLLECT_TIMERS = True
_timers = {}
_timer_names = ["advance","advance_one","handle_segfault","unprotect","continue",
                "run_hooks","reprotect"]
_class_names = ["fp","unchanged","mod","advance"]
_class_timings = {}

def init_timers():
    for name in _timer_names:
        _timers[name] = Timer(name)
    for name in _class_names:
        _class_timings[name] = set()

def dump_timers( out_file=sys.stdout ):
    import math
    def s( sample ):
        "sample standard deviation"
        n = float(len(sample))
        avg_sq = (sum(sample)/n)**2
        sum_sq = sum([x*x for x in sample])
        return math.sqrt( (sum_sq/n) - avg_sq )
    for class_name in _class_names:
        print >>out_file, "*"*20, class_name, "*"*20
        for name in _timer_names:
            times = [c for i,(a,b,c) in enumerate(_timers[name].times) \
                     if i in _class_timings[class_name]]
            if not times:
                print >>out_file, "%s[0]"%name
                continue
            avg = sum(times)/len(times)
            stddev = s(times)
            print >>out_file, "%s[%d]: \t%f\t%f\t%f\t(%f)"%(name,len(times),min(times),
                             avg,max(times),stddev)
            
            buckets = [0,]*251
            for t in times:
                bkt = min(250,int(t*500))
                buckets[bkt]+=1
            for bkt in range(251):
                if buckets[bkt]:
                    print >>out_file, "%d:\t%d"%(2*bkt,buckets[bkt])


########################################
# Main loop

def main_loop():
    """Read, parse, and process a line of input from the user.

    Each line is saved to the local history_file."""
    if COLLECT_TIMERS: init_timers()
    if not load_preferences():
        die("ERROR: Problem with configuration files\n")
    history_filename = abspath(get_conf("history_file"))
    try:
        readline.read_history_file(history_filename)
    except IOError: pass
    # start with script commands, if provided:
    while True:
        line = prompt( _normal_prompt )
        try:
            readline.write_history_file(history_filename)
        except IOError: pass
        try:
            do_continue = process_input( line )
        except Exception, e:
            error( "Caught exception:", e )
            traceback.print_exc()
            while True:
                answer = prompt( "\nContinue? (yes/no): " )
                if not answer:
                    continue
                if "yes".startswith( answer ):
                    do_continue = True
                    drain_all_output()
                    break
                elif "no".startswith( answer ):
                    do_continue = False
                    break
        if not do_continue:
            stop_all_controllers()
            break

if __name__ == "__main__":
    try:
        # Skip a line and start background colors.
        import curses
        curses.setupterm()
        out( " "*curses.tigetnum('cols') )
    except Exception:
        pass
    out( "Berkeley Replay Debugger (rdb), Copyright 2005-2006" )
    read_args()
    main_loop()
