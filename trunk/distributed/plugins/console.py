#!/usr/bin/env python2.6
#
# Copyright (C) 2010 University of California. All rights reserved.
#
# Author: Gautam Altekar
#
# $Id: replay_console.py,v 1.54 2006/10/04 04:10:31 galtekar Exp $
#
# vim:ts=4:sw=4:expandtab

"""Library for controlling replay."""

import os, sys, fcntl, select, readline, re, ConfigParser, random, socket
import code, traceback, subprocess, pprint, pdb, time, signal, getopt
import collections, fnmatch
import controllee, msg_stub, misc, controller, dfs, probe, action
import urlparse_custom, urlparse
import time, atexit

from progressbar import *
from misc import *

# Globals:
OMIT_EMPTY_LINES = True
_last_advance_words = None	# Text typed into console, split on whitespace
_normal_prompt = "\nconsole: "

# Constants:

_history_count_default = 40
_replay_and_exit = None # indicates non-interactive mode replay
_cl_script = []		# input lines to process before prompting user.

group = None

SECTION_NAME = "console"
DEFAULT_PREFS = { 
        "history_file" : "./.replay_history",
}


def prompt( prompt_str ):
    if _cl_script:
        input = _cl_script.pop(0)
        readline.add_history(input)
    else:
        try:
            input = raw_input( prompt_str )
            debugf( "user: '%s'", input )
        except EOFError:
            for _group in controller.group_list:
                _group.kill_all_ctrls()
            die()
    return input

def read_args():
    """Parses and handles command-line arguments.  Currently you can
    pass in a list of filenames for executables that you might debug,
    so we don't have to prompt you later.  Also added ability to specify
    scripts to run.
    """
    global _cl_script
    script_file = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "",\
                ["replay=", "rc=", "script=", "debug"])
    except getopt.GetoptError, ge:
        die( "Option error: " + str(ge) )

    for opt, arg in opts:
        if opt in ("--debug"):
            misc.DEBUG = True
        elif opt in ("--replay"):
            global _replay_and_exit
            _replay_and_exit = arg
        elif opt in ("--rc", "--script"):
            script_file = arg

    if script_file:
        try:
            script = file(script_file).read()
            _cl_script = script.splitlines()
        except IOError:
            misc.error( "could not read script file '%s'"%script_file )
    return

def parse_time( word ):
    """Returns a vclock, in microseconds.  Input format is
    [-]<count>[{h,m,s}]."""
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


_url_schemes = {
        "hdfs" : [],
        "file" : []
}
def replay_completer( words, partial_word ):
    if len(words) == 1:
        return None

    url = urlparse.urlparse( words[1] )
    #print partial_word, url.geturl()
    if len(url.scheme) == 0:
        return [ w for w in sorted( _url_schemes.keys() ) if w.startswith(\
            partial_word ) ]

    #print "scheme:", url.scheme
    fs = None
    if url.scheme == 'hdfs':
        if len(url.hostname) and len(url.path):
            #print "Contacting hdfs:", url.hostname, url.port
            fs = dfs.Hdfs( url.hostname, url.port )


    if fs:
        dir_list = fs.listdirs( os.path.dirname( url.path ) )
        #print "\n", url.path, entry_list, entry_name_list, partial_word, len(partial_word)
        if len( partial_word ) == 0:
            return dir_list
        else:
            basename_so_far = os.path.basename( url.path )
            #print "basename:", basename_so_far
            #print "match:", fnmatch.filter( dir_list,\
            #        basename_so_far )
            return [ w for w in dir_list \
                    if w.startswith( basename_so_far ) ] +\
                    fnmatch.filter( dir_list, basename_so_far )
    return None


def replay_and_exit_wrapper( spec ):
    replay_wrapper( spec )
    continue_wrapper( None )
    return False


def replay_wrapper( words ):
    "Calls start_replay."

    ###
    # Process the options
    try:
       opts, args = getopt.getopt( words, 'd:nv', [ 'debug-level=', 'no-jit',
            'verify' ] )
    except getopt.GetoptError as ge:
        error( "Option error:", str(ge) )
        print_help()
        return True
    do_jit = True
    do_verify = False
    dbg_level = 0
    for opt, arg in opts:
        if opt in ("-n", "--no-jit"):
            do_jit = False
        elif opt in ("-v", "--verify"):
            do_verify = True
        elif opt in ("-d", "--debug-level"):
            try:
               dbg_level = int(arg)
            except ValueError:
               misc.error( "debug level must be an integer" )
               return True
        else:
            misc.error( "invalid options" )
            return True
    debug(args)
    if len(args) < 1:
        misc.error( "Must give at least on recording" )
        return True

    global group
    group = controller.Controller(dbg_level=dbg_level,
            jit_enabled=do_jit, verify_enabled=do_verify)
    group.add_members(args)
    return True

def dump_state_wrapper( func, words ):
    "Examines controlles' state."
    if len(words) < 1:
        error( "Too few arguments" )
        print_help()
        return True

    for task in group.get_active_tasks():
        for word in words:
            l = word.split(',')
            if len(l) == 2:
                try:
                    expr = l[0]
                    len = int(l[1], 0)
                    byte_list = func( expr, len )
                    if byte_list:
                        print byte_list
                except Exception as e:
                    if str(e) == "Invalid argument":
                        error ("dump failed:", str(e) )
                    else:
                        raise
            else:
                error( "Invalid state specifier:", word )
    return True

def dump_mem_wrapper( words ):
    "Examines controllees' memory."
    return dump_state_wrapper( Task.read_mem, words )

def dump_reg_wrapper( words ):
    "Examines controlles' registers."
    return dump_state_wrapper( Task.read_reg, words )

def advance_wrapper( spec=None ):
    "Parses vclock, calls advance_controllers."
    if spec and len(spec) > 1:
        error( "Too many arguments" )
        print_help()
        return True
    if not spec:
        vclock = None
    else:
        vclock = spec[0]
    global _last_advance_words
    _last_advance_words = spec
    group.advance_controllers( vclock )
    return True

def continue_wrapper( spec ):
    "Equivalent to 'advance forever'."
    if spec:
        error( "Too many arguments." )
        print_help()
        return True
    return advance_wrapper( ["forever"] )

def list_all_wrapper( ignore=None ):
    "Prints out each live replay_controller."
    task_map = group.tasks_by_index
    active_task_list = group.get_active_tasks()

    if len(task_map) == 0:
        misc.out( " No tasks." )
        return True

    debug( task_map.values() )

    print "GlobalTID".rjust(9), "SessionID".rjust(9), "Length(s)".rjust(9), "Quality".rjust(7), "Recording"
    for index, task in sorted(task_map.items()):
        debug( "task:", task )
        prefix = " "
        if task in active_task_list:
            prefix = "*"
        (start_vclock, end_vclock, is_value_det) = task.ctrl.get_status()

        #print 'value_det:', is_value_det
        length_secs = (end_vclock - start_vclock) / 1000000
        quality_str = "Value" if is_value_det else "Control"

        #out( " %s %s %s"%(prefix,str(ctrl), time.ctime( vclock /
        #    1000000 )) )
        #misc.out( "%s %3d: %s %d %d %s"%\
        #        (prefix, index, str(task.tid), task.ctrl.index, length_secs, quality_str) )
        print str(index).rjust(9), str(task.ctrl.index).rjust(9), str(length_secs).rjust(9), quality_str.rjust(7), task.ctrl.rec.url.geturl()
    misc.out( "%d/%d tasks currently active."%(len(active_task_list),len(task_map)))
    return True
    
def die( msg=None ):
    if msg:
        error( msg )
    sys.exit(3)

def kill_wrapper( should_be_none=None ):
    """Called by console for input "end"."""
    if should_be_none:
        error( "Too many arguments" )
        print_help()
    else:
        for task in group.get_active_tasks():
            group.remove_task( task )
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
            misc.out( " %d  %s"%(idx, readline.get_history_item(idx)) )
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
    print( "  %s\n"%old_cmd )    
    current_idx = readline.get_current_history_length()
    # replace_() seems to be off-by-one relative to history
    readline.replace_history_item( current_idx-1, old_cmd )
    return process_input( old_cmd )

def print_in_python( words ):
    """Pretty-prints the current value of named variables.
    Like call_in_python below, use Friday's namespace.
    """
    try:
        for word in words:
            misc.out( "\t%s:\t%s"%(word,pprint.pformat( eval(word,vars(action)) )) )
    except Exception, e:
        misc.error( "Caught exception:", e )
    return True

def call_in_python( words ):
    """Executes a statement directly in python.
    We use the Friday module's namespace, to make it easier to set up
    state that is accessed by WatchPoint commands.  To access state in
    the main module, use "main.<var>".
    """
    stmt = " ".join(words)
    try:
        exec stmt in vars(action)
    except Exception, e:
        misc.error( "Caught exception:", e )
    return True

########################################
# Console Interface

def print_help( ignore=None ):
    "Displays accepted user input."
    misc.out( """Command format: [replay_id] <command> [<args>]

    replay_id:  When multiple programs are being replayed, you may
            apply a command to a single program by specifying its
            index here.  Indices start at 0, and are shown by the
            "ids" command.  Comma-separated lists of indices are
            allowed. The string "all" is also acceptible, and is
            the default. Once specified, the replay_id is used for all
            successive commands until overridden. Console commands
            (see below) ignore replay_id.

    command:   What you want the console to do.
    
    	help        : prints this message
        quit        : exits replay console
        add         : add recordings to the current replay set
        remove      : remove recordings from the current replay set
        ids         : shows programs being replayed
        python      : executes a python statement directly
        pp          : prints python variables
        history     : prints recent console input history
        !! | !      : re-executes command from history
        debug       : toggles internal console debugging output 
        advance     : advances replay execution
        continue    : advances replay execution till end
    """ )
    return True

# A list of accepted commands, in (<name>,<func>) tuples.
# The function should return True if execution should continue, else False.
_console_commands = {
    "help" : ( print_help, None ),
    "?" : ( print_help, None ),
    "quit" : ( lambda x: False, None ),	# Return False to exit main loop
    "exit" : ( lambda x: False, None ),	
    "history" : ( print_history, None ),
    "!" : ( redo_history, None ),
    "debug" : ( toggle_debug, None ),
    "load" : ( replay_wrapper, replay_completer ),
    "replay" : ( replay_and_exit_wrapper, None ),
    "kill" : ( kill_wrapper, None ),
    "list" : ( list_all_wrapper, None ),
    "advance" : ( advance_wrapper, None ),
    "continue" : ( continue_wrapper, None ),
    "dump-mem" : ( dump_mem_wrapper, None ),
    "dump-reg" : ( dump_reg_wrapper, None ),
    "probe-add" : ( probe.add_wrapper, None ),
    "probe-enable" : ( probe.enable_wrapper, None ),
    "probe-disable" : ( probe.disable_wrapper, None ),
    "probe-list" : ( probe.list_wrapper, None ),
    "python" : ( call_in_python, None ),
    "pp" : ( print_in_python, None ),
    }

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
    global _last_advance_words
    if not words:	# Empty line.  Repeat input like gdb.
        # Cannot just pass newline, because gdb cannot differentiate
        #  between user commands and ours.  Ours should not repeat.
        if _last_advance_words is not None:
            advance_wrapper( _last_advance_words )
        return True
    else:
        # New command; forget last one.
        _last_advance_words = None

    # First check whether line includes specific replay id.
    ids = parse_replay_id( words[0] )
    if ids:	# Change global
        group.set_active_tasks( ids )
        words.pop(0)
    # Now check whether command is one that we handle ourselves
    if not words:	# Only replay_id: no command here.
        return True
    cmd = words[0]
    for name in _console_commands.keys():
        if name.startswith( cmd ):
            command_handler = _console_commands[name][0]
            return command_handler( words[1:] )
    else:
        error( "Invalid command." )
        return True
    
def parse_replay_id( id ):
    """Tries to parse an replay id.

    Acceptible input is the string "all", an id number (small
    integer), or a comma-separated list of id numbers.
    If the input could not be parsed, this method returns None.
    Otherwise it returns a list of integers, or "all".
    """
    if id == "all":
        return group.get_all_tasks()
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

class Completor:
    def __init__( self, options):
        self.options = options
        self.current_candidates = []
        return

    def build_candidates( self ):
        origline = readline.get_line_buffer()
        words = origline.split()
        begin = readline.get_begidx()
        end = readline.get_endidx()
        being_completed = origline[begin:end]

        #print "current(%d,%d):"%(begin,end), being_completed
        #print "words:", words
        if not words:
            self.current_candidates = sorted( self.options.keys() )
        else:
            if begin == 0:
                # The first word is being completed
                self.current_candidates = [ w for w in \
                        self.options.keys() if \
                        w.startswith(being_completed) ]
            else:
                #print "h1"
                first_word = words[0]
                if first_word in _console_commands:
                    completer = _console_commands[first_word][1]
                    if completer:
                        #print "h2"
                        self.current_candidates = completer(words, being_completed)

        return

    def complete( self, text, state ):
        if state == 0:
            self.build_candidates()

        #print "current_candidates(%d):"%(state), self.current_candidates
        if state < len(self.current_candidates): 
            return self.current_candidates[state]
        else:
            return None


########################################
# Main loop


@atexit.register
def kill_controllers():
    group.kill_all_ctrls()

def main_loop():
    """Read, parse, and process a line of input from the user.

    Each line is saved to the local history_file."""
    history_filename = misc.abspath(misc.get_conf("history_file"))
    try:
        readline.read_history_file(history_filename)
    except IOError: pass

    readline.set_completer( Completor( _console_commands ).complete )
    readline.set_completer_delims( ' /' )
    readline.parse_and_bind( 'tab: complete' )


    while True:
        if not _replay_and_exit:
            line = prompt( _normal_prompt )
        try:
            readline.write_history_file(history_filename)
        except IOError: pass
        try:
            if _replay_and_exit:
                do_continue = process_input( "replay " + _replay_and_exit )
            else:
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
                    break
                elif "no".startswith( answer ):
                    do_continue = False
                    break
        if not do_continue:
            kill_controllers()
            die()
            break


if __name__ == "__main__":
    try:
        # Skip a line and start background colors.
        import curses
        curses.setupterm()
        misc.out( " "*curses.tigetnum('cols') )
    except Exception:
        pass
    misc.log( "Berkeley Replay Console (console)" )
    misc.log( "Copyright 2005-2010 University of California. All rights reserved." )
    read_args()
    main_loop()

###############################
## External API
#def load_sessions(url_list):
#    read_config()
#    replay_wrapper(url_list)
#
#def replay():
#    continue_wrapper(None)
#
#def add_probe(spec_str, action_func):
#    probe.add(spec_str, action_func)
