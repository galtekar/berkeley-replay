#!/usr/bin/env python
# Copyright (C) 2010 Regents of the University of California
# All rights reserved.
#
# Author: Gautam Altekar

# Design choices:
#
# o We chose to exec the vkerne rather than fork-and-exec. Invoking
# scripts assume pid of app is same as os.getpid().

import sys, os, ConfigParser, time, signal, socket, re
import getopt, struct, uuid, tempfile, errno
sys.path.append(os.path.dirname(sys.argv[0])+"/../common")
import misc, dfs

# Configuration info
_section_name = "record"
_default_prefs = { "reg_port" : "5892", "rpc_port" : "5891" }
_save_dir = None
_save_dir_prefix = None
_vkernel_opts = {}

DEFAULT_DEBUG_LEVEL = 5
_debug_level = None # None indicates release mode (no debugging)

my_name = "bdr-record"
my_dir = os.path.dirname(sys.argv[0])
server_bin = my_dir + "/bdr-portserv"	
server_out = my_dir + "/server.out"
env = os.environ


def call_as_daemon( cmd_list, output_filename ):
    """Forks off a daemon that exec's a command.
    Uses standard double-fork method."""
    misc.log("%s: starting '%s'"%(my_name," ".join(cmd_list)))
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid > 0:
        os.waitpid( pid, 0 )
        return	# Parent returns to rest of script.
    else:	# Child thread.
        sys.stdin.close()
        os.setsid()
        signal.signal(signal.SIGHUP,signal.SIG_IGN)
        pid = os.fork()
        if pid > 0: os._exit(0)	# Discard first child
        else:	# Second child is now a daemon.
            try:		# Redirect all output to log.
                output_file = file( output_filename, "a" )
                os.dup2( output_file.fileno(), sys.stdout.fileno() )
                os.dup2( output_file.fileno(), sys.stderr.fileno() )
            except IOError, e:
                print >>sys.__stderr__, e
                sys.exit( "Could not open log file\n" )
            # Finall, exec command.
            os.execvp( cmd_list[0], cmd_list )
    raise Exception, "Should never reach this line"

def query_port_server( query_port ):
    "Sends an uptime query to the local logger."
    sock = socket.socket()
    sock.settimeout( 5 )
    sock.connect( ("localhost",query_port) )
    msg = struct.pack( '!c', 'U' )
    sock.sendall( msg )
    uptime_str = sock.recv( 512 )
    sock.close()
    match = re.match( "Portserv uptime resp: (\d+) (.+)", uptime_str )
    if match:
        return (int(match.group(1)), match.group(2))
    else:
        return None

def start_port_server():
    # Check that port server is up; if not, start it.
    portserv_rpc_port = int(misc.get_conf("rpc_port"))	# For now
    num_tries = 64
    for try_i in range( num_tries ):	# Give it a few tries.
        try:
            response = query_port_server( portserv_rpc_port )
            if not response:
                misc.die( "Port server provided invalid response.\n" )
            else:
                (uptime, pserv_uuid) = response
            # else:
            misc.log( "Port server running (up %ds, uuid %s)"%(uptime,
                pserv_uuid) )
            break	# Everything is ready.
        except socket.error, e:
            if isinstance( e.args, tuple ):
                e_errno, e_str = e.args
                if errno.ECONNREFUSED == e_errno:
                    # This error is expected if portserv is not running yet.
                    if try_i+1 < num_tries:	# Try again.
                        call_as_daemon( [server_bin,misc.get_conf("reg_port"),misc.get_conf("rpc_port")], server_out )
                        time.sleep(1+try_i)	# Give the logger a second, then try again.
                else: raise e	# Not ECONNREFUSED
            else: raise e	# Only a string socket.error
    return pserv_uuid

def sigchld_handler( signum, frame ):
    #os.wait()
    raise Exception, "SIGCHLD"
    return

#class EventHandler( pyinotify.ProcessEvent ):
#    def process_IN_CLOSE_WRITE( self, event ):
#       print "Closed write:", event.pathname
def write_rec_config(rec_dir, session_id, node_id, vkernel_bin):
    import ConfigParser

    config = ConfigParser.SafeConfigParser()
    config.add_section('main')
    config.set('main', 'session_id', session_id)
    config.set('main', 'node_id', node_id)
    config.set('main', 'vkernel_bin', vkernel_bin)

    with open(rec_dir + '/rec.bdx', 'wb') as configfile:
        config.write(configfile)

def start_record( args ):
    global _save_dir, _vkernel_opts, _save_dir_prefix

#    if "Base.Debug.Level" in _vkernel_opts:
#        vkernel_bin = misc.get_conf("debug_bin")
#    else:
#        vkernel_bin = misc.get_conf("release_bin")
    vkernel_bin = my_dir + "/bdr-kernel"

    vkernel_bin = os.path.abspath(os.path.expanduser(vkernel_bin))
    if not os.path.exists(vkernel_bin):
        misc.die( "error: cannot find vkernel executable '%s'"%(vkernel_bin) )

    pserv_uuid = start_port_server()
    # Make local session directory
    session_base_dir = "/tmp/bdr-" + env["USER"] + "/recordings"
    try:
        os.makedirs( session_base_dir )
    except os.error, e:
        pass

    if _save_dir:
        try:
            os.makedirs( _save_dir )
        except os.error, e:
            misc.error( "Specified session directory already exists." )
            sys.exit(-1)
    else:
        # If no prefix is given, use the executable's name -- makes it
        # easy for us to map recordings to programs with an 'ls'.
        if not _save_dir_prefix:
            _save_dir_prefix = os.path.basename(args[0]) + "-"
        _save_dir = tempfile.mkdtemp(dir=session_base_dir, prefix=_save_dir_prefix)

    write_rec_config(_save_dir, str(uuid.uuid4()), str(pserv_uuid), vkernel_bin)

    # Start the replay core
    misc.log( "Saving to %s."%(_save_dir) )
    _vkernel_opts["Record.Dir"] = _save_dir

    vk_opt_str = ";".join(["%s=%s"%(key, str(value)) for (key,\
        value) in _vkernel_opts.items()])

    rec_opts = [ "-m", "Record", "-o", vk_opt_str ]

    #signal.signal( signal.SIGCHLD, sigchld_handler )

    #print "child:", os.getpid(), os.getpgid(0)
    # Give child control of the tty, if there is a tty; there
    # may not be if we're being run over ssh <-- fds 0,1,2 are
    # most likely pipes
    try:
        tty_file = open("/dev/tty")
    except:
        # XXX: jobs run over ssh don't have a controlling tty by
        # default, but the vkernel requires a controlling tty at
        # the moment. Use two -t options with ssh to force
        # pseudo-tty allocation, and to hence work around this
        # problem.
        misc.die( "KNOWN BUG: must have a controlling tty (ssh workaround: use -t option)." )
    else:
        tty_file.close()

#    #print os.tcgetpgrp(tty_fd)
#    if os.isatty(tty_fd):
#        # Take control of the controlling terminal
#        #if os.tcgetpgrp(tty_fd) == os.getpgid(0):
#        #    os.tcsetpgrp(tty_fd, os.getpid())
#        pass
#    else:
#    # Child must be the leader of the group; otherwise
#    # its output will not be permitted on the tty.
#    #os.setpgrp()
    
    args[0] = os.path.abspath(os.path.expanduser(args[0]))
    try:
        mode_str = misc.get_conf("mode")
    except ConfigParser.NoOptionError:
        mode_str = "default"

    if mode_str != "native":
        exec_args = [vkernel_bin] + rec_opts + args
        exec_bin = vkernel_bin
    else:
        exec_args = args
        exec_bin = args[0]
    misc.log( "Executing", args, "in %s mode."%(mode_str) )
    #print exec_bin, exec_args

    try:
        # Some programs (e.g., Hypertable) look at the "_" environ
        # variable to locate the binary's path and associated files.
        # Bash, by default, fill this with this script's location. If
        # we pass that in to vkernel, it will use it (unless environment
        # inheritance is off), and then the app will be confused.
        # Hence we replace with the path of the binary.
        exec_env = os.environ.copy()
        exec_env["_"] = args[0]
        os.execve( exec_bin, exec_args, exec_env )
        assert(0) # Should've detected potential problems earlier
    except os.error, e:
        e_errno, e_str = e
        misc.log( "error:", e_str )
        sys.exit( e_errno )
    return


def show_banner():
    try:
        dbg_lvl = _vkernel_opts["Base.Debug.Level"]
    except:
        dbg_lvl = 0
        
    dbg_str = "debug-level=%d"%(dbg_lvl)
        
    misc.log( "Berkeley Deterministic Replay (%s)"%(dbg_str) )
    misc.log( "Copyright 2004-2010 University of California. All rights reserved." )

def usage():
    print "usage: %s [options] <prog-and-args>"%(my_name)


def read_args():
    global _save_dir, _save_dir_prefix, _vkernel_opts
    try:
        opts, args = getopt.getopt(sys.argv[1:], "s:d:p:rahv", \
                ["save-dir=", "debug=", "release", "session-dir-prefix=", \
                    "verbose", "pause", "disable-de", \
                    "disable-tags","help"])
    except getopt.GetoptError, ge:
        misc.log( str(ge) )
        misc.die( "Use --help for more information." )

    for opt, arg in opts:
        #print opt, arg
        if opt in ("-s", "--save-dir"):
            save_dir = arg
        elif opt in ("-d", "--debug"):
            _vkernel_opts["Base.Debug.Level"] = int(arg)
        elif opt in ("-r", "--release"):
            if str("Base.Debug.Level") in _vkernel_opts:
                del _vkernel_opts["Base.Debug.Level"]
        elif opt in ("-v", "--verbose"):
            misc.QUIET = False
            #_vkernel_opts["Base.TtyReplayEnabled"] = 1
        elif opt in ("-p", "--session-dir-prefix"):
            save_dir_prefix = arg
        elif opt in ("-a", "--pause"):
            _vkernel_opts["Base.Debug.PauseOnAbort"] = 1
        elif opt in ("--disable-de"):
            _vkernel_opts["Base.DirectExecutionEnabled"] = 0
        elif opt in ("--disable-tags"):
            _vkernel_opts["Base.IpcTagsEnabled"] = 0
        else:
            usage()
            sys.exit(-1)
    return args

def read_config():
    global _vkernel_opts
    config_parser = misc.load_preferences(_section_name, _default_prefs)

    try:
        _vkernel_opts["Base.Debug.Level"] = int(misc.get_conf("debug"))
    except ConfigParser.NoOptionError:
        pass
    
    try:
        _vkernel_opts["Base.Debug.PauseOnAbort"] = int(misc.get_conf("pause_on_abort"))
    except:
        pass

    try:
        _vkernel_opts["Base.DirectExecutionEnabled"] = int(misc.get_conf("de_enabled"))
    except:
        pass

    try:
        _vkernel_opts["Base.IpcTagsEnabled"] = int(misc.get_conf("ipc_tags_enabled"))
    except ConfigParser.NoOptionError:
        pass


def version_check():
    v = sys.version_info
    if v[0] == 2 and v[1] >= 6:
        return True
    return False

##### Main work.
if __name__ == "__main__":

    # Configuration options take precendence
    read_config()
    args = read_args()

    if not version_check():
        misc.die( "Python 2.6 or greater required.\n" )

    if len(args) == 0:
        usage()
        sys.exit(-1)
    if not os.path.exists(args[0]):
        try:
            full_path = misc.find_file(args[0], env["PATH"])
        except KeyError:
            # PATH env var not set
            pass
        if full_path == None:
            misc.die( "error: cannot find executable", args[0] )
        else:
            args[0] = full_path
    ## Check that it's executable
    if not os.path.isfile(args[0]) or not os.access(args[0], os.X_OK):
        misc.die( "error:", args[0], "cannot be executed" )

    start_record( args )


# vim:ts=4:sw=4:expandtab

