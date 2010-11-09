#!/usr/bin/env python
#
# Copyright (c) 2006 Regents of the University of California.
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
# $Id: logger.py,v 1.3 2006/07/03 20:25:36 geels Exp $

# This is a wrapper script for ``loggerbin''. It's safer to invoke
# than the binary because this script performs cleanup operations.

# Start the logger.

"""logger.py: watchdog script for loggerbin

This script:
	1) Starts up ./loggerbin
	2) Periodically rotates logs
	3) Cleans up shared memory segments on shutdown.


Log Rotation:
  Sorts the liblog files in a specified directory, then repeatedly
removes the oldest (ckpt,log) set until the directory fits within the
specified space.
  If log rotation falls more than two periods behind, we assume that
we are unable to control disk usage properly, and abort.


"""

import sys, os, ConfigParser, time, re, glob, bisect, commands, pprint, signal

me = os.path.basename(sys.argv[0])

def out( *args ):
    print "(%s):\t"%me, " ".join(map( str, args ))

def usage():
    print( "USAGE: %s <port> <# shm segments to preallocate>"%sys.argv[0] )

########################################
config_filename = "../run/liblog.cfg"
config_section = "liblog"
limit_option_name = "log_space_limit"
dir_option_name = "log_dir"
utilization_goal = 0.8	# Do not really use all of available space
rotate_period_s = 30
max_skipped_periods = 8
max_failed_uptime_s = 60

# Should be same as trace_logs.logname_re:
logname_re = re.compile( r'^(.*/)?(?P<appname>[^/]+?)\.'
                         r'(?P<addr>(\d+\.){3}\d+)'
                         r'(\.(?P<pid>\d+))?\.(?P<pgid>\d+)'
                         r'\.(?P<epoch>\d+)'
                         r'\.((?P<time>\d+)|(?P<libname>\S+))'
                         r'\.(?P<suffix>(lib|log(\.xml)?|ckpt(\.master)?)(\.gz)?)$' )

limit_re = re.compile( r'(?P<num>\d+)\s*(?P<suffix>[GMKk]?B?)' )


def parse_limit( limit_str ):
    """Returns the number of bytes represented by a string.

    String is a number, optionally ending in MB,kB,K, etc."""
    match = limit_re.match( limit_str )
    if not match:
        clean_and_die( "Invalid %s: %s\n"%(limit_option_name,limit_str) )
    num = long(match.group("num"))
    suffix = match.group("suffix")
    if suffix in ("K","KB","k","kB"):
        num *= 1024
    elif suffix in ("M","MB"):
        num *= 1048576
    elif suffix in ("G","GB"):
        num *= 1073741824
    return num

def try_gzip( filename ):
    """Runs gzip on file.

    Returns old filename on error, new filename if successul.
    """
    if filename.endswith("gz"):
        return filename
    compressed_name = filename + ".gz"
    out( "Compressing %s"%filename )
    cmd = "gzip %s"%filename
    status, output = commands.getstatusoutput( cmd )
    if status != 0:	# Just ignore.
        out( "'%s' returned %d"%(cmd,status) )
        try: os.remove( compressed_name )
        except: pass
        return filename
    else:
        return compressed_name

def clear_logs( compress_tails=False ):
    """Limits space consumed by the log directory.

    Reads configuration variables from liblog's config file.
    Groups files by checkpoint period.
    Checkpoints more than one minute old are compressed.
    Files from oldest checkpoint periods are deleted until the total
      directory fits within allocated space.
    Age is determined by mtime of checkpoint, not virtual clock in
      filename. 
    """
    # First read config file
    config_parser = ConfigParser.SafeConfigParser()
    config_parser.read(config_filename)
    for option in dir_option_name, limit_option_name:
        if not config_parser.has_option( config_section, option ):
            clean_and_die( "Missing configuration variable: %s\n"%option )
    log_dir = config_parser.get(config_section,dir_option_name)
    space_limit = parse_limit( config_parser.get(config_section,
                                                 limit_option_name ))
    float_mb = 1048576.0
    out( "Rotating logs at", time.ctime() )
    out( "Limiting '%s' to %.1f MB"%(log_dir, (space_limit/float_mb)) )
    du_out = commands.getoutput( "du -sb %s"%log_dir )
    # Assume command succeeds.
    total_bytes = float(du_out.split()[0])
    out( "Starting size is %.1f MB"%(total_bytes/float_mb) )

    # Now find and group all the files.
    files = glob.glob( log_dir + "/*" )
    ckpt_groups = {}	# Maps checkpoint vclock to file list
    epoch_tails = {}	# Maps epoch to its most recent period
    for f in files:
        match = logname_re.match( f )
        if not match:
            out( "Unexpected filename: %s"%f )
        else:
            if not match.group("time"):
                assert match.group("libname")
                # libraries; don't group with other files.
                try_gzip( f )	# Do compress, though.
            else:
                vclock = long(match.group("time"))
                if vclock not in ckpt_groups:
                    ckpt_groups[vclock] = []
                ckpt_groups[vclock].append( f )
                # Remember tail of each epoch 
                epoch = long(match.group("epoch"))
                if ((epoch not in epoch_tails) or
                    (vclock > epoch_tails[epoch])):
                    epoch_tails[epoch] = vclock
                    
    # Now sort the files by checkpoint mtime
    sorted_groups = []
    for vclock, file_list in ckpt_groups.items():
        for f in file_list:
            match = logname_re.match( f )
            if match.group("suffix").startswith("ckpt"):
                epoch = long(match.group("epoch"))
                bisect.insort( sorted_groups,
                               (os.stat(f).st_mtime,epoch,vclock,file_list) )
                break

    #out( "all groups:", pprint.pformat( sorted_groups ))
    # Now compress checkpoints and keep track of total usage.
    time_now = time.time()
    size_so_far = 0
    # Iterate across checkpoint groups, newest to oldest.
    # Compress what we can, delete what we must.
    for mtime, epoch, vclock, file_list in sorted_groups[-1::-1]:
        if size_so_far < space_limit*utilization_goal:
            # Still have room in the directory.  Keep this checkpoint
            # group, but compress what you can.
            for f in file_list:
                if (compress_tails or
                    vclock != epoch_tails[epoch]):
                    f = try_gzip( f )
                else:
                    out( "Not compressing:", f )
                    # don't compress most recent checkpoints and
                    #  logs, because they may still be open.
                f_size = long(os.stat(f).st_size)
                size_so_far += f_size
        else:
            # Delete everything else.
            for f in file_list:
                out( "Deleting %s"%f )
                os.remove( f )

    # Done.
    du_out = commands.getoutput( "du -sb %s"%log_dir )
    # Assume command succeeds.
    total_bytes = float(du_out.split()[0])
    out( "Total size of '%s' is now %.1f MB (%.1f)"%\
          (log_dir, (total_bytes/float_mb), (size_so_far/float_mb)))


def start_logger( logger_args ):
    """Fork off loggerbin process.

    Returns loggerbin PID"""
    cmd_list = ["./loggerbin"] + logger_args
    out( "Starting:", cmd_list )
    pid = os.fork()
    if pid > 0:		# parent
        return pid
    else:		# child
        os.execv( cmd_list[0], cmd_list )
    raise Exception, "Should never reach this line"        

def remove_shm_segments():
    "Calls through to shell ipcs, ipcrm"
    username = os.environ["USER"]
    out( "Removing shm segments for", username )
    ipcs_out = commands.getoutput( "ipcs -m" )
    #out( "ipcs -m returned:", ipcs_out)
    for line in ipcs_out.splitlines():
        if 0 <= line.find( username ):
            shmid = line.split()[1]
            cmd = "ipcrm -m %s"%shmid
            status, ipcrm_out = commands.getstatusoutput( cmd )
            #out( "%s => '%s', %d"%(cmd, ipcrm_out, status) )

def clean_and_die( ret=0, all_logs=False ):
    "Clean shutdown routine"
    out( "Cleaning up %s..."%("","all logs ")[bool(all_logs)])
    clear_logs( all_logs )    # Compress _all_ logs
    remove_shm_segments()
    out( "Done.")
    out( "*"*60 )    
    sys.exit(ret)

######################################################################
# Main Script

if __name__ == "__main__":
    out( "*"*60 )
    out( "Running at", time.ctime())
    #out( "Command line:", sys.argv )
    if len(sys.argv) > 3:
        usage()
        clean_and_die(-2)
    # Move into logger/
    run_dir = os.path.dirname(sys.argv[0])
    os.chdir(run_dir)

    # Start up loggerbin
    logger_pid = start_logger( sys.argv[1:] )
    start_time = time.time()
    last_rotate_time = start_time
    while True:
        # Check whether loggerbin still running:
        pid, status = os.waitpid( logger_pid, os.WNOHANG )
        if pid:
            out( "waitpid returned:", (pid,status) )
            compress_all_logs = False
            if (time.time() - start_time) > max_failed_uptime_s:
                compress_all_logs = True
            clean_and_die( status, all_logs=compress_all_logs )
        #else:
            #out( "Logger still running" )
        sys.stdout.flush()

        # else: logger still running.  rotate logs?
        now = time.time()
        time_since = now - last_rotate_time
        #out( time_since, "seconds since last rotation" )
        if time_since > max_skipped_periods * rotate_period_s:
            # FIXME -- check current size before dying?
            out( "Falling too far behind.  Dying." )
            os.kill( logger_pid, signal.SIGINT )
            time.sleep(30)
            os.kill( logger_pid, signal.SIGKILL )
            clean_and_die(3)
        elif time_since > rotate_period_s:
            # Rotate every N seconds, not N seconds from now, because
            #  we don't want to ignore rotation latency.
            last_rotate_time += rotate_period_s
            clear_logs()
        # rest for a while:
        time.sleep( rotate_period_s/4 )
    
raise Exception, "Should never reach this line"        







