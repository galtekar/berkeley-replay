#!/usr/bin/python

# Copyright (c) 2005 Regents of the University of California.
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
# $Id: i3d.py,v 1.7 2005/09/27 21:01:23 geels Exp $
#
# Control/monitor script for i3_server

import os, sys, ConfigParser, signal, commands, glob, time, re

##########
# Globals
DEBUG = True

# Configuration file info
conf_file = "i3d.conf"
default_conf = { "pgid_file" : "/var/run/i3d.pgid",
                 "log" : "i3d.log",
                 "chord_conf" : "chord.conf",
                 "port" : "5486",
                 "diff_bin": "/usr/bin/xdelta",
                 "md5_bin": "/usr/bin/md5sum",
                 "logger_bin": "/usr/local/bin/logger",
                 "logger_port": "5485",
                 "logger_dir" : ".",
                 "ckpt_period" : "600000000",	# 600 seconds
                 "logger_pgid_file": "/var/run/logger.pgid",
                 "liblog" : "/usr/local/lib/liblog.so",
                 "logger_out": "logger.out",
                 "max_log_space_mb": "10",
                 }
required_keys = ("executable", "diff_base", "max_log_space_mb", "tag")
# Need to convert relative pathnames:
path_keys = ("pgid_file", "log", "chord_conf", "diff_bin",
             "logger_bin", "logger_dir", "liblog",
             "logger_pgid_file", "logger_out",
             "executable", "diff_base", )


####################
# Helper Functions
def call_as_daemon( cmd_string, output_filename, pgid_filename,
                    environment ):
    """Forks off a daemon that exec's a command.

    Uses standard double-fork method."""
    if DEBUG: print "Calling '%s' as daemon\n"%cmd_string
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid > 0: return	# Parent returns to rest of script.
    else:	# Child thread.
        os.setsid()
        signal.signal(signal.SIGHUP,signal.SIG_IGN)
        
        pid = os.fork()
        if pid > 0: os._exit(0)	# Discard first child
        else:	# Second child is now a daemon.
            try:		# Redirect all output to log.
                output_file = file( output_filename, "a", 0 )
                os.dup2( output_file.fileno(), sys.stdout.fileno() )
                os.dup2( output_file.fileno(), sys.stderr.fileno() )
            except IOError, e:
                print >>sys.__stderr__, e
                sys.exit( "Could not open log file\n" )
            # Now write out process group id.
            pgidfile = file( pgid_filename, "w" )
            print >>pgidfile, os.getpgrp()
            pgidfile.close()
            # Finall, exec command.
            arg_list = cmd_string.split()
            os.execve( arg_list[0], arg_list, environment )
    raise Exception, "Should never reach this line"

def stop_daemon( pgid_file ):
    """Kills the progress group named in pgid_file."""
    if not os.path.exists( pgid_file ):
        return
    try:
        pf = open( pgid_file )
        lines = pf.readlines()
        pgid = long(lines[0])
    except IOError, e:
        print >>sys.stderr, e
        sys.exit("Could not read PGID\n")
    print "Killing process group %d"%pgid
    try:
        os.killpg( pgid, signal.SIGTERM )
    except OSError, e:
        print >>sys.stderr, e
        sys.exit("Could not kill %d\n"%pgid)
    os.remove( pgid_file )

def clean_logs():
    "Periodic cleanup function"
    print "Called at %s"%(time.ctime(),)
    print  "Compressing logs..."
    clear_space()

def compress_ckpts():
    "Replaces checkpoints with a delta."
    base_hash = verify_base_hash( conf["diff_base"] )
    if not base_hash:
        print( "Invalid diff base: %s\n"%conf["diff_base"] )
        return
    for ckpt in glob.glob( conf["logger_dir"] + "/*ckpt" ):
        new_delta = ckpt+".diff."+base_hash
        cmd = "%s delta %s %s %s"%(conf["diff_bin"], conf["diff_base"],
                                   ckpt, new_delta )
        print cmd
        status, output = commands.getstatusoutput( cmd )
        #if status == 0 and os.path.exists( new_delta ):
        if os.path.exists( new_delta ):
            if status != 0:	# xdelta never returns 0?
                print "%s returned %d\n"%(conf["diff_bin"],status)
            os.remove( ckpt )
        else:
            sys.exit( "%s returned %d\n"%(conf["diff_bin"],status))

def verify_base_hash( filename ):
    """Verifies the hash/checksum of a file.

    The filename contains the hash in hex, using the format of
    diff_base_name_re.  If the hash matches, it is returned."""
    output = commands.getoutput( "%s %s"%(conf["md5_bin"], filename) )
    hash_hex = output.split()[0]
    if filename.endswith( "base."+hash_hex ):
        return hash_hex
    else:
        return None
    
        

def clear_space():
    "Removes logs until logger_dir consumes less than max_log_space_mb."
    logs = glob.glob( conf["logger_dir"] + "/liblog*log" )
    logname_re = re.compile( r'liblog\.(?P<tag>[\.\w]*)\.(?P<time>\d+)\.log' )
    tags = {}
    for log in logs:
        match = logname_re.search(log)
        assert match
        #print log, match.groupdict()
        tag = match.group("tag")
        if tag not in tags:
            tags[tag] = []
        tags[tag].append( log )
    compressed = []
    #print tags
    for tag,logs in tags.items():	# clear for each tag separately
        logs.sort()
        for log in logs[:-1]:
            print "Compressing", log
            os.system( "gzip %s"%log )
            compressed.append( log+".gz" )
        print "Ignoring", logs[-1]
    while( du( conf["logger_dir"] ) >= long(conf["max_log_space_mb"]) ):
        oldest_log = compressed.pop( 0 )
        if DEBUG: print "Removing %s"%oldest_log
        os.remove( oldest_log )

def du( dir ):
    "Returns the size of dir, in MB."
    output = commands.getoutput( "du -sm %s"%dir )
    size_mb = long(output.split()[0])
    return size_mb


##########################################
# Main command processing

# Read i3d.conf from same directory as i3d.py.
base_dir = os.path.dirname( sys.argv[0] )
conf_file = os.path.join( base_dir, conf_file )
conf_parser = ConfigParser.SafeConfigParser( default_conf )
conf_parser.read( conf_file )
# Convert to hashtable:
conf = dict(conf_parser.items("main"))

for key in required_keys:
    if key not in conf:
        sys.exit("%s missing required key %s\n"%(conf_file,key))
    if key in path_keys:	# Does the right thing.
        conf[key] = os.path.join( base_dir, conf[key] )

if len(sys.argv) < 2:
    sys.exit("Usage: %s [start|stop|start-logger|stop-logger|clean]"%sys.argv[0])
command = sys.argv[1]

if command in ("start","restart","start-nolog"):
    stop_daemon( conf["pgid_file"] )
    cmd = "%(executable)s %(chord_conf)s %(port)s"%conf
    if command == "start-nolog":
        env = {}
    else:
        env = { "LOGGER_DIR": conf["logger_dir"],
                "LOGGER_PORT": conf["logger_port"],
                "LOGGER_ROTATE_PERIOD_US": conf["ckpt_period"],
                "LOGGER_TAG": conf["tag"],
                "LD_LIBRARY_PATH": os.path.dirname(conf["liblog"]),
                "LD_PRELOAD": os.path.basename(conf["liblog"]) }
    call_as_daemon( cmd, conf["log"], conf["pgid_file"], env )

elif command == "stop":
    stop_daemon( conf["pgid_file"] )

elif command == "clean":
    clean_logs()

elif command == "start-logger":
    stop_daemon( conf["logger_pgid_file"] )
    cmd = "%(logger_bin)s %(logger_port)s"%conf
    env = {}
    call_as_daemon( cmd, conf["logger_out"],
                    conf["logger_pgid_file"], env ) 
    
elif command == "stop-logger":
    stop_daemon( conf["logger_pgid_file"] )
    
else:
    sys.exit("Invalid command '%s'\n"%command )


