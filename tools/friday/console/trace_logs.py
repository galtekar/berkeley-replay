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
# $Id: trace_logs.py,v 1.30 2006/07/10 20:45:20 geels Exp $

"""Utility functions for tracing causes and actions across a network.
"""

import os, sys, re, commands, bisect, glob, pickle, pprint
import copy, stat, ConfigParser

if __name__ == "__main__":
    sys.exit( "\nThis library has no stand-alone functionality\n" )

import __main__	# for handle to console functions

##### Constants
DEBUG = False
VERBOSE_DEBUG = False
MAX_TRACE_LOOPS = 4	# How many logs to scan before giving up
IGNORE_REMOTE_REPO = False

##### Configuration/Preferences
# See load_preferences(), get_conf()
_preferences = None

##### Log Cache
# Maps ip address to Epoch_Map objects (which are keyed by epoch).
_local_cache = {}

##### Regular Expressions
send_re = re.compile( r'<sendto r=.* t="(?P<dst>[^:]+).*' +
                      r'bytes="(?P<bytes>[0-9a-f]+)" '+
                      r'tag="(?P<tag>[^"]+)" vc="(?P<time>\d+)"')
recv_re = re.compile( r'<recvfrom r=.*' + 
                      r'bytes="(?P<bytes>[0-9a-f]+)" ' +
                      r'tag="(?P<tag>[^"]+)"' )
logname_re = re.compile( r'^(.*/)?(?P<appname>[^/]+?)\.'
                         r'(?P<addr>(\d+\.){3}\d+)'
                         r'(\.(?P<pid>\d+))?\.(?P<pgid>\d+)'
                         r'\.(?P<epoch>\d+)'
                         r'\.((?P<time>\d+)|(?P<libname>\S+))'
                         r'\.(?P<suffix>(lib|log(\.xml)?|ckpt(\.master)?)(\.gz)?)$' )
tag_re = re.compile( r'tag="(?P<tag>[^"]+)"' )
vc_re = re.compile( r'vc="(?P<time>\d+)"' )
zipped_re = re.compile( r'\.gz$')
binary_log_re = re.compile( r'\.log$')
connect_failed_re = re.compile( r'Operation timed out' )
permission_denied_re = re.compile( r'Permission denied' )
remote_addr_re = re.compile( r'((?P<user>\w+)@)?(?P<ip>[\d\.]+)'
                             r'(:(?P<dir>[\S]*))?' )

##### Return codes for check_status()
MAYBE_DEAD, PROBABLY_DEAD, PROBABLY_ALIVE = "dead?", "Dead.", "Alive."

##### Return codes for routed_correctly()
ROUTE_CORRECT, ROUTE_FAILED, ROUTE_INCORRECT, ROUTE_LOOPED, ROUTE_UNDEFINED \
               = "correct", "failed", "incorrect", "looped", "undefined"

##### Return codes for diagnose_*()
JOIN_INCONSISTENCY, LEAVE_INCONSISTENCY, FP_INCONSISTENCY = \
                    "join", "leave", "false positive"

##### Flags for trace_*()
LOOP_FLAG = 'loop'

class TraceException(Exception):
    pass

class ConnectException(TraceException):
    pass

class PermissionException(TraceException):
    pass

class MissingLogException(TraceException):
    pass

class File_Location:
    """Filename and local status"""
    def __init__(self, filename, is_local):
        self.filename = filename
        self.is_local = is_local
    def __repr__(self):
        return "<%s:%s>"%(self.filename,
                          ("remote","local")[self.is_local])
    def __eq__(self, other):
        return (isinstance(other,File_Location) and
                (self.filename==other.filename) and
                (self.is_local==other.is_local))
    def update(self, cached):
        """Replaces any internal state with cached state that overrides it."""
        if not cached:
            return
        if self.is_local:
            assert( self == cached )
        else:
            assert( cached.is_local )
            self.filename = cached.filename
            self.is_local = True
        return

class Log_Info:
    """Metadata for single log and checkpoint pair

    Includes location of files, start vclock, and end vclock.
    Latter may be None if unknown (requires scanning log).
    """
    def __init__(self, log_loc, ckpt_loc, other_ckpts, epoch, start, end=None):
        self.log=log_loc
        self.ckpt=ckpt_loc
        self.other_ckpts=other_ckpts
        self.libs={}	# Will be replaced in Epoch_Info.add_lib
        self.epoch=epoch
        self.start=start
        self.end=end
    def __cmp__(self, other):
        # FIXME: is this sufficient?  Do we ever use __cmp__ for more
        #  than sorting by time?
        if isinstance( other, Log_Info ):	# sort on start
            return cmp( self.start, other.start )
        else:	# Allow direct comparison to vclocks, for searching
            return cmp( self.start, other )
    def __repr__(self):
        return ("(Log_Info epoch=%d start=%d end=%s log=%s ckpt=%s others=%s libs=%s)"%
                (self.epoch,self.start,repr(self.end),repr(self.log),repr(self.ckpt),
                 repr(self.other_ckpts),repr(self.libs)))
    def update(self, cached):
        """Replaces any internal state with cached state that overrides it."""
        if not cached:
            return
        assert self.start == cached.start
        assert self.epoch == cached.epoch
        self.log.update( cached.log )
        self.ckpt.update( cached.ckpt )
        for pid, cached_loc in cached.other_ckpts.items():
            if pid in self.other_ckpts:
                self.other_ckpts[pid].update( cached_loc )
            else:
                self.other_ckpts[pid] = copy.deepcopy( cached_loc )
        for lib_name, cached_loc in cached.libs.items():
            if lib_name in self.libs:
                self.libs[lib_name].update( cached_loc )
            else:
                self.libs[lib_name] = copy.deepcopy( cached_loc )
        if self.end:
            assert self.end == cached.end
        else:
            self.end = cached.end
        return

class Epoch_Info:
    """Metadata for a single run of logs"""
    def __init__(self, node, epoch):
        self.node = node
        self.epoch = epoch
        self.logs = []	# List of Log_Info objects
        self.libs = {}	# Shared libs: <libname>->File_Location
    def get_log( self, start_vclock ):
        """Return the Log_Info that starts exactly at a vclock, or None"""
        if not self.logs:
            return None
        idx = bisect.bisect( self.logs, start_vclock )
        if idx == 0:	# Earlier than all logs
            return None
        else:		# Look at last log started before vclock.
            idx -= 1
        if self.logs[idx] == start_vclock:
            return self.logs[idx]
        else:
            return None
    def add_log( self, log_info ):
        assert self.get_log( log_info.start ) is None
        bisect.insort( self.logs, log_info )
        assert not log_info.libs	# Should be brand new (empty)
        log_info.libs = self.libs	# Each log needs to see libs.
    def add_lib( self, lib_name, lib_loc ):
        assert lib_name not in self.libs
        self.libs[lib_name] = lib_loc
    def __repr__(self):
        return ("(Epoch_Info node=%s epoch=%d logs=%s libs=%s)"%
                (repr(self.node), self.epoch, repr(self.logs),
                 repr(self.libs)))
    def update(self, cached):
        """Replaces any internal state with cached state that overrides it."""
        if not cached:
            return
        assert decode_addr(self.node) == decode_addr(cached.node)
        assert self.epoch == cached.epoch
        for cached_log in cached.logs:
            log = self.get_log( cached_log.start )
            if log:
                log.update( cached_log )
            else:
                self.add_log( copy.deepcopy( cached_log ) )
        for lib_name, cached_loc in cached.libs.items():
            if lib_name in self.libs:
                self.libs[lib_name].update( cached_loc )
            else:
                self.libs[lib_name] = copy.deepcopy( cached_loc )

class Epoch_Map(dict):
    """A map of Epoch_Info objects.

    We override update(), so that matching epochs are themselves
    updated, rather than replaced.
    """
    def update( self, cached_map ):
        """Replaces any internal state with cached state that overrides it."""        
        if VERBOSE_DEBUG:
            debug(  "Epoch_Map.update():" )
            debug_pprint(self, cached_map)
        if not cached_map:
            return
        for epoch, cached_info in cached_map.items():
            if epoch in self:
                self[epoch].update( cached_info )
            else:
                self[epoch] = copy.deepcopy( cached_info )
        if VERBOSE_DEBUG: debug_pprint( self )

    def search( self, vclock, want_all=True, accept_late=False ):
        """Finds the Log_Info(s) that includes a log for a specified vclock.

        Searches Epoch_Map for any Log_Info objects that cover vclock.
        Usually the result will be a matching Log_Info or None; If
        multiple logs may exist for a given vclock, the user is asked
        to select one of the candidate logs, unless want_all==True.
        
        If vclock is None, just take the earliest log from each epoch.
    """
        if VERBOSE_DEBUG:
            debugf( "epoch search: %s want: %s",
                    (str(vclock),"ANY")[not vclock], ("ONE","ALL")[want_all])
            debug_pprint( self.values() )
            
        # FIXME -- check some invariants on start, end times.
        candidates = []
        looks_like_hole = []
        if vclock is None:
            debug( "returning first log for each epoch" )
            candidates = [epoch_info.logs[0] for epoch_info in self.values()]
        else:
            for epoch_info in self.values():
                idx = bisect.bisect( epoch_info.logs, vclock )
                if VERBOSE_DEBUG: debug(  "Searching", epoch_info, idx )
                best_log = None
                if idx == 0:	# No log started before vclock
                    if accept_late:	# Take the first one anyway.
                        best_log = epoch_info.logs[idx]
                else:
                    # Look at last log started before vclock.
                    best_log = epoch_info.logs[idx-1]
                if best_log:
                    if VERBOSE_DEBUG: debug(  "Best log:", best_log )
                    if best_log.end is None:
                        assert best_log.log.is_local is False
                        debug( "Looking for end vclock for ", best_log.log )
                        try:
                            cached_info = download_to_cache( epoch_info.node,
                                                           best_log.log )
                            best_log.update( cached_info )
                        except TraceException, te:
                            debug( te )
                            pass	# Oh, well.  We tried.
                    if (best_log.end is None) or (vclock <= best_log.end):
                        candidates.append( best_log )
                    elif idx < len(epoch_info.logs):	# Not last log
                        debugf( "Epoch at %d has hole at %d",
                                epoch_info.epoch, vclock )
                        looks_like_hole.append( epoch_info )
        if len(candidates) == 0:
            debug( "Found no matching logs." )
            #FIXME -- do something about  looks_like_hole.
            return candidates
        elif len(candidates) == 1:
            return candidates
        else:
            if want_all:	# More than one match; just return them all.
                return candidates
            else: # Punt to user.
                out( "Found multiple epochs%s"% \
                      (" with logs for "+str(vclock),"")[not vclock] )
                def extract_keys(c):
                    match = logname_re.search(c.log.filename)
                    assert match
                    return (match.group("appname"),c.epoch,
                            long(match.group("pgid")),c)
                with_keys = [extract_keys(c) for c in candidates]
                with_keys.sort()
                for i, (appname,epoch,pgid,c) in enumerate( with_keys ):
                    if c.end:
                        end_str = "%d"%c.end
                    else:
                        end_str = "unknown"
                    out( "(%d) %s[#%d@%d], from %d to %s"%\
                          (i,appname,pgid,epoch,c.start,end_str))
                idx = None
                while idx is None:
                    idx_str = __main__.prompt( "Please choose a log: " )
                    idx = __main__.safe_long( idx_str )
                return [with_keys[idx][3]]

##### Utility Functions
def out( string ):
    """Prints some normal feedback.

    Calls through to main colorized output functions."""
    # Support operation in non-console __main__:
    if not hasattr(__main__, "print_in_color"):
        print string  
    else:
        __main__.print_in_color( string+"\n", __main__._output_normal)


def debug( *args ):
    """Prints and logs debug output.
    
    Calls through to main colorized output functions."""
    # Support operation in non-console __main__:
    if DEBUG:
        string = " ".join( map( str, args ) )
        if not hasattr(__main__, "print_in_color"):
            print string  
        else:
            __main__.print_in_color( string+"\n", __main__._output_trace_logs )
def debug_pprint( *args ):
    """Pretty-prints objects to debug output."""
    if DEBUG: debug( " ".join( map( pprint.pformat, args ) ) )

def debugf( *args ):
    """Prints and logs debug output (format string version).
    
    Calls through to main colorized output functions."""
    if DEBUG: debug( args[0]%args[1:] )

            
#####
# Added config file support:
def load_preferences( config_parser ):
    global _preferences
    _preferences = config_parser
    
def get_conf( name, host=None ):
    """Reads a config file variable.

    If "host" is set, this method earches for a matching section name
    before falling back to default value."""
    matching_sections = set()
    if host:
        for section in _preferences.sections():
            # TODO: quote "."?
            if re.match( section, host ):
                matching_sections.add( section )
    # Check all matching sections, starting with longest name.
    #   This will approximate a "most specific" regex order.
    #   Could also try ignoring regex syntactic variables, or parsging
    #    out section name clues (like hostname dots).
    for section in sorted( matching_sections,
                          key=lambda n: -1*len(n) ):
        if VERBOSE_DEBUG: debugf( "looking for %s in %s", name, section )
        if _preferences.has_option( section, name ):
            return _preferences.get( section, name )
    else:
        # Fall back on "default" section
        if VERBOSE_DEBUG: debug( "looking for default", name )
        return _preferences.get( "replay", name )
    

def decode_addr( node_addr ):
    """Parses a remote location spec.

    Input is format [user@]<ip_address>[:directory].
    If the user or directory elements are missing, they are filled in
    from the preferences object.
    """
    match = remote_addr_re.match(node_addr)
    assert match
    md = match.groupdict()
    if VERBOSE_DEBUG: debug_pprint( md )
    if "ip" not in md:
        raise Exception, "No IP address found in '%s'"%node_addr
    elements = (md["user"] or get_conf("remote_user",md["ip"]),
                md["ip"],
                md["dir"] or get_conf("remote_dir",md["ip"]))
    if VERBOSE_DEBUG: debug_pprint( elements )
    return elements

def add_defaults( node_addr ):
    """Parses remote location spec, fills in defaults.

    Uses decode_addr to parse address, then replaces missing elements
    with their defaults.
    """
    return "%s@%s:%s"%decode_addr( node_addr )
    

##### Some callbacks that protocol-specific libraries must define
# Breaks the message header down into human-readable fields.
def parse_msg( msg_hex ):
    raise TraceException, "Must define protocol-specific parse_msg()"

# Returns True iff the message is a data plane packet.
def data_plane( msg_hex ):
    raise TraceException, "Must define protocol-specific data_plane()"

# Should return a protocol-specific target address, or None if the
#  message is control plane traffic.
def get_destination( msg_hex ):
    raise TraceException, "Must define protocol-specific get_destination()"

# FIXME: Several of these callbacks must be replaced or retooled now
#   that we use gdb to read symbols, instead of human-readable checkpoints.

# Should return a list of protocol-specific domains for which the node
# was responsible at a given time.  If ckpt_name is provided, use that
# file instead of creating a new checkpoint; ignore other arguments.
def get_addr_list( node_addr, vclock, ckpt_name=None ):
    raise TraceException, "Must define protocol-specific get_addr_list()"

# Return a sorted (sub-)list of nodes that may be the final
# destination for a message, ordered by priority.
def get_owners( msg_hex, node_list ):
    raise TraceException, "Must define protocol-specific get_owners()"    

# Parse a checkpoint and return the protocol-specific node name or ID.
def find_name( ckpt_filename ):
    raise TraceException, "Must define protocol-specific find_name()"    
    
# Should create a new checkpoint.  Returns the local filename.
def create_checkpoint( node_addr, vclock ):
    raise TraceException, "Must define protocol-specific create_checkpoint()"

# Returns True iff forwarding from a to b gets closer to x.
def forward_progress( x, a, b ):
    raise TraceException, "Must define protocol-specific forward_progress()"

# Returns True iff named log proves that the logged node contained a
# route to the neighbour within the specified time period.  This
# proof may come from explicit logged messages, parsing control
# traffic, etc.
def log_contained_route( log_filename, neighbour, range=None ):
    raise TraceException, "Must define protocol-specific log_contained_route()"
    
##### Node List
# This variable must be set somehow to enable the tracing tools to
# detect incorrect routing.
node_map = None

class Node:
    """A node's address and protocl-specific name"""
    def __init__(self, addr, name):
        self.addr=addr
        self.name=name
    def __repr__(self):
        return ("(Node %s@%s)"%(self.name,self.addr))

# There could be many ways to gather the full list of nodes in a
# network.  Ideally we would control the configuration files, and have
# this list ready externally.  The following method is provided as a
# convenient alternative.
# Assumes node names never change.
def read_nodes_in_cache():
    """Returns a list of Node objects for those listed in the cache."""
    node_map = {}
    for addr in _local_cache:
        found = False
        for epoch_info in _local_cache[addr].values():
            for log_info in epoch_info.logs:
                if log_info.ckpt and log_info.ckpt.is_local:
                    name = find_name( log_info.ckpt.filename )
                    if name:
                        node_map[addr] = Node(addr,name)
                        found = True
                        break
            if found: break
        else:
            debug( "No name found for ", addr )
    return node_map

##### A few useful hex-parsing methods:
def parse_byte( hex_list ):
    """Pops and parses the next two characters into an unsigned int."""
    return int( hex_list.pop(0)+hex_list.pop(0), 16 )

def parse_unsigned( hex_list, num_bytes ):
    """Pops and parses the next few characters into an unsigned int."""
    ret = 0
    for i in range(num_bytes):
        ret = ret*256 + parse_byte( hex_list )
    return ret

def parse_short( hex_list ):
    return parse_unsigned( hex_list, 2 )

def parse_int( hex_list ):
    return parse_unsigned( hex_list, 4 )

def parse_addr( hex_list ):
    """Pops and parses the next 6 bytes into an address:port string."""
    return( "%d.%d.%d.%d:%d"%
            (parse_byte( hex_list ),parse_byte( hex_list ),
             parse_byte( hex_list ),parse_byte( hex_list ),
             parse_short( hex_list )) )

def print_msg( msg_hex ):
    """Just calls parse_msg() for now."""
    debug( parse_msg( msg_hex ) )

def list_sends( filename ):
    """Greps out all 'send' events from a log

    Returns a list of (tag,dst,time,bytes) tuples."""
    log = open( filename, "r" )
    send_list = []
    for line in log:
        if line.startswith("<send"):
            match = send_re.match( line )
            assert match
            send_list.append( (match.group('dst'),
                               long(match.group('time')),
                               match.group('tag'),
                               match.group('bytes')) )
    log.close()
    return send_list

def split_tag( tag ):
    """Parses the tag and returns (ip,pgid,vclock)."""
    ip,vclock = tag.split('@',1)
    return (ip,vclock)

def find_tag( tag, filename, list_len = 1, recv_only = False,
              send_only = False, list_before = False ):
    """Finds a specified tag in a log

    Returns a list of (line_no, line) tuples starting at the line
    with the tag.
    """
    log = open( filename, "r" )
    line_no = 0
    stop_line = -1
    ret_list = []
    matched = False
    for line in log:
        #debug( line )
        line_no += 1
        if matched:	# collect next list_len lines
            if line_no >= stop_line:
                break
            elif list_before:	# return previous list_len lines
                break
        else:
            match = tag_re.search( line )
            if match and match.group('tag') == tag and \
               ((not recv_only) or line.startswith("<recv")) and \
               ((not send_only) or line.startswith("<send")):
                matched = line_no
                stop_line = line_no+list_len
                #debugf( "Found %s at %d, stop before %d",
                #	 tag, line_no, stop_line )
        ret_list.append( (line_no, line) )
        del ret_list[:-list_len]	# sliding window
    else:	# Did not finish with ret_list
        if not matched:
            ret_list = []
        elif line_no < stop_line:	# matched, then hit EOF
            keep_lines = line_no-matched+1
            del ret_list[:-keep_lines]
    return ret_list

def best_destination( msg_hex, vclock ):
    """Returns the "owner" of a destination.

    The final destination of a message may change over time, as the
    network changes.  This method uses a protocol-specific
    get_owners() method to determine the set of possible destinations
    for a message, then returns the first one that was online at the
    specified time."""
    if not node_map:
        # TODO: if node names can change, must reload node list
        # according to vclock, using get_addr_list?
        debug( "Please define node_map variable." )
        raise TraceException, "No node list defined"
    if data_plane( msg_hex ):
        id = get_destination( msg_hex )
        assert id
    else:
        raise TraceException, "Not a data-layer message: "+msg_hex
    ordered_dests = get_owners( id, node_map.values() )
    # Find first node that is probably alive.
    for dest in ordered_dests:
        debug( "Checking", dest )
        if check_status( dest.addr, vclock ) is PROBABLY_ALIVE:
            return dest
    else:
        raise TraceException, "No destinations found for "+msg_hex
    

def check_for_loop( dst_addr, path, flags ):
    """Returns True iff an address is already listed in a path.

    Also sets LOOP_FLAG in flags to the indices of the first dup."""
    for i, (src, tag, parsed_msg) in enumerate(path[1:]):
        idx = i+1        # Start at index 1 - Do not include source
        if dst_addr == src:
            debug( "\tLOOPING!" )
            if LOOP_FLAG not in flags:
                # Remember the indices of the duplicate addresses.
                flags[LOOP_FLAG] = (idx, len(path))
                return True
    else:
        return False
    

def trace_next_hop( tag, dst_addr, path, flags ):
    """A helper for trace_msg.

    Finds a matching recvfrom() entry in the destination log, scans
    for subsequent sendto() entries, and iterates.
    Returns a list of all paths traced.
    """
    #debug( tag, dst_addr )
    src_addr, timestamp = split_tag(tag)
    # We can't tell exactly what the receiving timestamp will be, or
    # therefore in which log the receive will be found, but we know it
    # will be at least greater than the sending timestamp.    
    dst_timestamp = long(timestamp)+1
    exact_clock = False
    loop_count = 0
    while True:	# Search all later logs
        # Warning -- if the message was never received, this search
        # will not stop until it runs out of remote logs.
        debugf( "Looking for %d on %s", dst_timestamp,dst_addr )
        try:
            log_info = fetch_log( dst_addr, dst_timestamp, exact=exact_clock )
        except ConnectException, ce:
            # Node is offline now; assume it was dead at
            # dst_timestamp, too, unless contrary evidence found.
            debug("Unreachable:", dst_addr )
            if check_status( dst_addr, dst_timestamp ) is PROBABLY_ALIVE:
                debug("Lost message trail")
                return path + [(dst_addr,"trace broken")]
            else:	# Assume node was DEAD
                debug("Message probably dropped here.")
                return path + [(dst_addr,"dropped")]
        except PermissionException, pe:
            # Node is online, but we can't scan the logs.  Assume that
            # the node did not fail.
            debugf("Cannot read %s; Lost message trail", dst_addr)
            return path + [(dst_addr,"trace broken")]
        except MissingLogException, mle:
            # Node is online, but there is no log at dst_timestamp.
            # Assume the node failed temporarily.
            debug("No log available for that period. ",
                  "Message probably dropped here.")
            return path + [(dst_addr,"dropped")]
        max_event_handler_len = 100
        debug( "Found ", log_info.log.filename )
        lines = find_tag( tag, log_info.log.filename,
                          list_len=max_event_handler_len,
                          recv_only=True )
        #debug_pprint( "Lines: ", lines )
        outgoing_tags = []
        if lines:
            assert lines[0][1].startswith( "<recv" )
            for line_no, line in lines[1:]:
                #debug( line )
                if line.startswith( "<send" ):
                    match = send_re.match( line )
                    outgoing_tags.append( (match.group('tag'),
                                           match.group('dst'),
                                           match.group('bytes')) )
                elif line.startswith( "<sel" ):
                    break
            else:	# Still haven't reached end of event handler.
                raise TraceException, "Unexpectedly long event handler"
            break	# Done with this hop.
        else:	# Must have later receive timestamp. Try next log.
            loop_count += 1
            if loop_count >= MAX_TRACE_LOOPS:
                debugf( "Cannot find tag %s after %d loops.", tag,loop_count)
                while True:
                    ri = raw_input( "\nContinue? (yes/no): " )
                    if "yes".startswith(ri):
                        loop_count = 0
                        break
                    elif "no".startswith(ri):
                        debug("Cannot find tag on receiver. ",
                              "Message probably dropped here.")
                        return path + [(dst_addr,"dropped by network")]
            debug("Not in this log; checking next one...")
            dst_timestamp = log_info.end
            exact_clock = True
    
    #debug("Found outgoing messages: ", outgoing_tags)
    if not outgoing_tags:
        debug( "No outgoing messages")
        return path + [(dst_addr,"end")]
    paths = []
    for next_tag, next_addr, msg_bytes in outgoing_tags:    # DFS
        debug( next_tag, " -> ", next_addr )
        debug( parse_msg( msg_bytes ) )
        check_for_loop( next_addr, path, flags )
        paths.extend( trace_next_hop( next_tag, next_addr,
                                      path + [(dst_addr,next_tag,msg_bytes)],
                                      flags ))
    return paths

def trace_prev_hop( tag, path, flags ):
    """A helper for trace_msg_reverse.

    Finds a matching sendto() entry in the destination log, scans
    for the previous recvfrom() entry, and iterates.
    Returns the path.
    """
    debugf( "trace_prev_hop(%s)\n", tag)
    src_addr, timestamp = split_tag(tag)
    debugf( "Looking for %s on %s", timestamp,src_addr)
    try:
        log_info = fetch_log( src_addr, long(timestamp) )
    except ConnectException, ce:
        debug("Unreachable:", src_addr)
        return ["unreachable"] + path
    except (PermissionException, MissingLogException), mle:
        debug("No log available for that period.")
        return ["missing log"] + path
    max_event_handler_len = 1000
    #debug( "Found " + log_info )
    lines = find_tag( tag, log_info.log.filename,
                      list_len=max_event_handler_len,
                      send_only=True, list_before=True )
    lines.reverse()
    #debug_pprint( lines[:12] )
    if lines:
        assert lines[0][1].startswith( "<send" )
        for line_no, line in lines[1:]:
            #debug( line )
            if line.startswith( "<recv" ):
                match = recv_re.match( line )
                prev_tag = match.group('tag')
                debug( prev_tag, " -> ", src_addr )
                debug( parse_msg( match.group('bytes') ))
                src, timestamp = split_tag(prev_tag)
                # check_for_loop ignores first entry:
                path.insert( 0, (src,prev_tag,match.group('bytes')))
                check_for_loop( src, path, flags )
                return trace_prev_hop( prev_tag, path, flags )
                    
            elif (line.startswith( "<sel" ) or
                  line.startswith( "<start" )):
                debug( "No incoming message" )
                return ["start"] + path
        else:	# Still haven't reached start of event handler.
            raise TraceException, "Unexpectedly long event handler"
    else: # Did not find tag.
        raise TraceExeption, ("Event %s not found in %s"%
                              (tag,log_info.log.filename))
                              

def trace_msg_reverse( tag, flags=None ):
    """Follow a message trail back to its source.

    The message with specified tag is found on its source node.
    Any message received in the same event handler is iteratively
    traced back to its source node.
    Returns the path, in forward order, up to but not including the
    message with the specified tag.
    """
    if flags is None:	# Caller doesn't care about flags.
        flags={}
    return trace_prev_hop( tag, [], flags )
    

def trace_msg( tag, flags=None ):
    """Follow a message trail.

    The message with specified tag is followed from its source node to
    its destination.  Then any message sent immediately by the
    destination is followed similarly.  If multiple messages are sent
    at a single node, all paths are followed, depth-first."""
    node_addr, timestamp = split_tag(tag)
    if flags is None:	# Caller doesn't care about flags.
        flags={}
    try:
        log_info = fetch_log( node_addr, long(timestamp) )
    except (ConnectException,PermissionException), ce:
        debug("Unreachable:", dst_addr, " Cannot trace message." )
        return [node_addr, "unreachable"]
    except MissingLogException, mle:
        debug("No log available for that period. Cannot trace message.")
        return [node_addr, "missing log"]
    lines = find_tag( tag, log_info.log.filename, send_only=True )
    if not lines:
        raise TraceException, "Could not find tag " + tag
    line_no, text = lines[0]
    match = send_re.match( text )
    if not match:
        raise TraceException, "Expected send: " + text
    dst_addr = match.group( 'dst' )
    debug( tag, " -> ", dst_addr )
    debug( parse_msg( match.group('bytes') ))
    return trace_next_hop( tag, dst_addr,
                           [(node_addr,tag,match.group('bytes'))],
                           flags )

def trace_full_path( tag ):
    debug( "Reverse trace: " )
    first_part = trace_msg_reverse( tag )
    debug( "Forward trace: " )
    second_part = trace_msg( tag )
    return first_part + second_part

def trace_many( send_list, slice = None ):
    """Calls trace_msg() on a list of tags.

    Usage: trace_many( send_list, slice = None )"""
    
    if slice:
        iter = send_list[slice].__iter__()
    else:
        iter = send_list.__iter__()
    for dst_addr, time, tag, bytes in iter:
        debug( "\nTracing", tag)
        try:
            #trace_msg( tag )
            #debug( "-"*30)
            #trace_msg_reverse(tag)
            #debug( "-"*30)
            debug_pprint( trace_full_path( tag ))
        except TraceException, te:
            debug( "Caught: ", te)


def routed_correctly( tag ):
    """Compares a message trace to the expected destination.

    Calls trace_msg() and best_destination(), checks whether
    the message trail ended safely at the best destination.
    Also looks for loops.
    """
    debug( "Tracing msg:", tag)
    flags = {}
    path = trace_msg( tag, flags )
    node_addr, tag_a, msg_hex = path[0]
    if not data_plane( msg_hex ):
        debug("Not data plane" )
        return ROUTE_UNDEFINED
    if LOOP_FLAG in flags:
        # Trumps other failures -- probably caused them.
        debug( "Message looped")
        return ROUTE_LOOPED
    end_addr, cause = path[-1]
    if cause != "end":	# Not a graceful end to trace
        return ROUTE_FAILED
    assert tag == tag_a
    node_addr, vclock = split_tag(tag)
    debug( "Looking for owner of:", tag  )
    best_node = best_destination( msg_hex, long(vclock) )
    if end_addr == best_node.addr:
        return ROUTE_CORRECT
    else:
        debugf("Went to %s instead of %s", end_addr, best_node.addr)
        return ROUTE_INCORRECT

def dropped_route( src_addr, dst_addr, vclock ):
    """Determines whether route was dropped recently.
    
    Returns True if src lacks a route to dst at time vclock because
    it recently dropped it, False if because dst has just joined the
    network, and src has not yet learned of it."""
    # First find out when dst joined network.
    # That question is hard to answer.  Epoch time should lower bound
    # vclock on src, but no gaurantees.
    # FIXME -- add causal search back from dst's first messages
    # received to src's vclock.
    debug("Checking for dropped route at", vclock)
    log_info = fetch_log( dst_addr, vclock )	# Should not fail now
    src_vclock_lower_bound = log_info.epoch	# FIXME - see note above.
    debug( "Destination started at", src_vclock_lower_bound)
    while( src_vclock_bound >= vclock ):
        # Scan all of src_addr's logs, looking for routes to dst_addr.
        try:
            log_info = fetch_log( dst_addr, vclock )
        except TraceException, te:
            # Cannot tell for sure, but no proof of false positive
            debug("Cannot check source logs")
            return False
        if log_info and log_info.log and log_info.log.is_local:
            if log_contained_route( log_info.log.filename, dst_addr,
                                    range=(src_vclock_bound,vclock) ):
                return True	# Had route, then dropped.
            elif log_info.start == log_info.epoch:
                return False	# Source started here; never had route.
            else:
                vclock = log_info.start-1	# Try previous log
        else:
            debug("Cannot check source logs")
            return False

            
def diagnose_loop( tag ):
    """Determines what caused a forwarding loop.

    Returns a (where,why) tuple.
    There are two cases (IIRC) in which routing table inconsistency
    can cause a loop (the 'why' above):
    A) LEAVE_INCONSISTENCY: backup destination doesn't realize that
       the primary has died, so tries to bounce message
    B) JOIN_ or FP_INCONSISTENCY: penultimate node avoids primary
       destination because it has not heard of it yet (or has
       incorrectly dropped route, resp.).  Backup tries to correct.
    """
    debug("Tracing msg:", tag)
    flags = {}
    path = trace_msg( tag, flags )
    if LOOP_FLAG not in flags:
        # Trumps other failures -- probably caused them.
        raise TraceException, "Message did not loop"
    first,dup = flags[LOOP_FLAG]
    if DEBUG:
        debug("Loop segment:")
        for i in range(first,dup+1): debug(  path[i])
    node_addr, tag_a, msg_hex = path[0]
    assert tag == tag_a
    node_addr, vclock = split_tag(tag)
    # TODO -- consider failures that occur while message is in flight.
    best_node = best_destination( msg_hex, long(vclock) )
    debug("Destination: ", best_node)
    id = get_destination( msg_hex )
    for i in range(first,dup+1):
        hop_src, hop_dst = path[i][0], path[i+1][0]
        if hop_dst == best_node.addr:	# correct node.
            # Case (A) above.
            new_ckpt = create_checkpoint( best_node.addr, vclock )
            debug(  "Destination did not hold msg;  ", \
                    "it only accepts addresses: " )
            debug_pprint(get_addr_list( best_node.addr, vclock, new_ckpt ))
            debug(  "Presumably previous owner just died.")
            debugf(  "See %s for full checkpoint", new_ckpt)
            # FIXME -- add method that checks for nearby joins/leaves.
            # next, print out 
            return( best_node, LEAVE_INCONSISTENCY )

        elif not forward_progress( id, hop_src, hop_dst ):
            # Case (B) above.  Check for backward progress.
            debugf("Forwarding wrong direction: %s -> %s ",
                  node_map[hop_src],node_map[hop_dst])
            # Now, why did hop_src mess up?
            # FIXME -- Fine for chord, but for other protocols there
            # might be a third node to which hop_src should have
            # forwarded msg, instead of best_node.  Check all?
            if dropped_route( hop_src, best_node.addr, vclock ):
                return( node_map[hop_src], FP_INCONSISTENCY )
            else:
                return( node_map[hop_src], JOIN_INCONSISTENCY )
            

def diagnose_incorrect_route( tag ):
    #FIXME -- Problem is easily located at both of last two nodes in
    #path. Must now explain routing table inconsistency.
    pass
    
    
def fetch_log_list( node_addr ):
    """Downloads the list of <log,ckpt> pairs from a remote machine.
    
    Returns a map of Epoch_Info objects representing the remote logs,
    keyed by their epoch times.
    """
    if VERBOSE_DEBUG:
        debug("fetch_log_list:", node_addr)
    if IGNORE_REMOTE_REPO:
	return Epoch_Map()
    user, ip, dir = decode_addr( node_addr )        
    debug("Fetching list from", node_addr)
    fetch_list_cmd = ("ssh %s %s@%s ls %s/*" % 
                      (get_conf("ssh_params",ip),
                       user, ip, dir ))
    if VERBOSE_DEBUG: debug("Calling", fetch_list_cmd)
    status, output = commands.getstatusoutput( fetch_list_cmd )
    if VERBOSE_DEBUG:
        debugf( "Returned status: %d, output:%s\n", status, output )
    if( status != 0 ):
        for line in output.split('\n'):
            if connect_failed_re.search( line ):
                raise ConnectException, line
            elif permission_denied_re.search( line ):
                raise PermissionException, line
    
    # Split output into lines, ignore error output
    epochs = Epoch_Map()	# Keyed by epoch time
    for line in output.split('\n'):
        match = logname_re.search( line )
        if not match:
            debug( "Ignoring text:", line)
            continue
        else:
            epoch = long(match.group('epoch'))
            if epoch not in epochs:
                epochs[epoch] = Epoch_Info( node_addr, epoch )
            # libraries are bound to epoch:
            if match.group('suffix').startswith("lib"):
                epochs[epoch].add_lib( match.group('libname'),
                                       File_Location( line, False ))
                continue
            # other files are bound to a ckpt vclock
            start_vclock = long(match.group('time'))
            log_info = epochs[epoch].get_log( start_vclock )
            if not log_info:
                log_info = Log_Info( None, None, {}, epoch, start_vclock )
                epochs[epoch].add_log( log_info )
            if match.group('suffix').startswith("ckpt.master"):
                # Not true during cleanup: original and diff present
                assert log_info.ckpt is None
                log_info.ckpt = File_Location( line, False )
            elif match.group('suffix').startswith("ckpt"):
                pid = match.group('pid')
                assert pid not in log_info.other_ckpts
                log_info.other_ckpts[pid] = File_Location( line, False )
            elif match.group('suffix').startswith("log"):
                if not log_info.log:
                    log_info.log = File_Location( line, False )             
                else:	# We've already got one.
                    # Must be one binary, one expanded.  Choose binary (smaller)
                    if binary_log_re.search( line ):
                        assert not binary_log_re.search( log_info.log.filename )
                        log_info.log = File_Location( line, False )
                    else:
                        assert binary_log_re.search( log_info.log.filename )
                        # leave log_info.log as is.
            else:
                raise Exception, "Unexpected suffix: %s"%match.group('suffix')
    if not epochs:
        raise MissingLogException, "No logs found on %s"%node_addr
    return epochs

def find_log( node_addr, vclock, want_all=False, accept_late=False ):
    """Looks for a <log,ckpt> pair on node_addr covering a vclock.

    Returns the best match, or the entire list, if want_all==True.

    If vclock is none, return the earliest log for that node.
    """
    if VERBOSE_DEBUG:
        debug( "find_log:", node_addr, vclock, ("ONE","ALL")[want_all])
    cache_epochs = None
    user, ip, dir = decode_addr( node_addr )
    if ip in _local_cache:
        cache_epochs = _local_cache[ip]
        if VERBOSE_DEBUG: debug_pprint( "Cache had: ", cache_epochs)
    try:
        epochs = fetch_log_list( node_addr )
    except TraceException, te:
        if cache_epochs:	# Already have a partial answer
            epochs = Epoch_Map()
        else:
            raise te
    epochs.update( cache_epochs )	# Some are already downloaded
    matching_info_list = epochs.search( vclock, want_all, accept_late )
    if not matching_info_list:
        raise MissingLogException, "No match for %s@%s"%(node_addr,
                                                         (str(vclock),"ANY")[not vclock])
    if want_all:
        return matching_info_list
    else:
        assert len(matching_info_list) == 1
        return matching_info_list[0]	# singleton list

def check_status( node_addr, vclock ):
    """Tries to determine whether a node was alive at a given time.
    This question is hard, both because clocks are not synchronized
    and because information can be lost during a later failure.
    """
    try:
        log_info = fetch_log( node_addr, vclock )
    except (ConnectException,PermissionException), ce:
        # Cannot tell much for sure.
        debug( ce )
        return MAYBE_DEAD
    except MissingLogException, mle:
        # The log is not there now; probably never existed.
        debug( mle )
        return PROBABLY_DEAD
    else:
        # Found a log for that vclock.
        assert log_info
        return PROBABLY_ALIVE
    

def fetch_log( node_addr, vclock, exact=False, range_end=None, with_ckpt=False ):
    """Downloads log(s) from a remote machine

    This functionality could probably be well provided by running a
    lightweight https server on each remote box.  For now, we use ssh
    to read the remote log directory, then use scp to download the
    best log.
    if exact==True, vclock must match the log's start_vclock.
    if range_end is not None, fetch all logs that overlap range 
       [vclock, range_end).  Also, exact must be False.
    if with_ckpt==True, fetch the matching checkpoint(s).
    Returns a list of cached Log_Info objects.
    if vclock is None, find the first log for a node.  This option is
    	incompatible with exact=True.
    """
    if VERBOSE_DEBUG:
        debug( "fetch_log:", node_addr, vclock, ("","-"+str(range_end))[bool(range_end)],
               ("any","exact")[exact])
    # If we need an exact match, find all, then prune here.
    log_list = []
    if exact or range_end:
        assert not (exact and range_end)
        assert vclock
        candidates = find_log( node_addr, vclock, want_all=True,
                               accept_late=bool(range_end) )
        if VERBOSE_DEBUG:
            debug( "find_log returned:", candidates)
        for log in candidates:
            if exact and (log.start == vclock):
                log_list.append( log )
                break
            elif (log.start < range_end) and (log.end > vclock):
                log_list.append( log )
        if not log_list:
            raise MissingLogException, "No exact match for %s@%d"%(node_addr,vclock)
    else:
        log_list.append( find_log( node_addr, vclock, False ) )
        if VERBOSE_DEBUG:
            debug( "find_log returned:", log_list[0])
    assert log_list	# Otherwise, MissingLogException
    for log_info in log_list:	# download all files for all log_info objects.
        if not log_info.log:
            raise MissingLogException, "No log for %s@%d"%(node_addr,vclock)
        cached_info = None	# Keep track of latest version in cache
        if not log_info.log.is_local:
            cached_info = download_to_cache( node_addr, log_info.log )
        if with_ckpt:
            if not log_info.ckpt:
                raise MissingLogException, "No ckpt for %s@%d"%(node_addr,vclock)        
            if not log_info.ckpt.is_local:
                cached_info = download_to_cache( node_addr, log_info.ckpt )
            for pid, other in log_info.other_ckpts.items():
                if not other.is_local:
                    cached_info = download_to_cache( node_addr, other )
            for lib_name, lib_loc in log_info.libs.items():
                if not lib_loc.is_local:
                    # Does not return Log_Info for libs:
                    download_to_cache( node_addr, lib_loc )
                    # If only libs were downloaded, cached_info would not
                    #  be set, and update below would fail.
                    # For now, just disallow that case:
                    assert( cached_info )
        log_info.update( cached_info )
    return log_list

def fetch_latest_log( node_addr ):
    """Downloads the last log,ckpt pair on a remote machine.

    Selects the last log of the last epoch on remote machine."""
    debug("Fetching a log from", node_addr)
    epochs = fetch_log_list( node_addr )
    epoch_list = epochs.keys()
    epoch_list.sort()
    last_epoch = epochs[epoch_list[-1]]
    last_log = last_epoch.logs[-1]
    # Use fetch_log, which will use cache intelligently.
    return fetch_log( node_addr, last_log.start, exact=True )
    
def fetch_all_logs( node_addr ):
    """Downloads all log,ckpt pairs from a remote machine."""
    debug("Fetching all logs from", node_addr)
    epochs = fetch_log_list( node_addr )
    for epoch in epochs:
        for log in epochs[epoch].logs:
            fetch_log( node_addr, log.start, exact=True )

def download_file( node_addr, file_loc ):
    """Downloads a remote file.

    Uses scp."""
    assert not file_loc.is_local
    debug("downloading", file_loc.filename)
    user, ip, dir = decode_addr( node_addr )
    copy_cmd = ("scp %s %s@%s:%s %s/" %
                (get_conf("ssh_params",ip),
                 user, ip, file_loc.filename,
                 get_conf("local_cache")))
    if VERBOSE_DEBUG: debug( copy_cmd )
    status, output = commands.getstatusoutput( copy_cmd )
    #debug( "Status: ", status)
    if( status != 0 ):
        for line in output.split('\n'):
            if connect_failed_re.search( line ):
                raise ConnectException, line
            elif permission_denied_re.search( line ):
                raise PermissionException, line
        else:
            raise MissingLogException, file_loc.filename
    local_filename = "%s/%s"%(get_conf("local_cache"),
                              os.path.basename(file_loc.filename))
    match = zipped_re.search( local_filename )
    if match:	# For simplicity, unzip before caching
        local_filename = unzip_file( local_filename )
    match = binary_log_re.search( local_filename )
    if match:	# For simplicity, expand before caching
        local_filename = expand_log_xml( local_filename )
    return File_Location( local_filename, is_local=True )

def download_to_cache( node_addr, file_loc ):
    """Wrapper for download_file + cache_insert"""
    new_loc = download_file( node_addr, file_loc )
    return cache_insert( node_addr, new_loc.filename )

def unzip_file( filename ):
    """Unzips a downloaded file."""
    debug("unzipping", filename)
    match = zipped_re.search( filename )
    assert match
    new_filename = filename[:match.start()]	# remove .gz suffix
    cmd = "gunzip %s"%(filename,)
    if new_filename.endswith( "log" ):
        cmd = "gunzip -c %s > %s"%(filename,new_filename)
    if VERBOSE_DEBUG: debug( "Calling", cmd )
    status, output = commands.getstatusoutput( cmd )
    #if status == 0 and os.path.exists( new_filename ):
    if (os.path.exists( new_filename ) and
        (long(os.stat(new_filename).st_size) > 0)):
        os.chmod( new_filename, stat.S_IRWXU )
        if os.path.exists( filename ):
            os.remove( filename )
    else:
        raise TraceException( "gunzip returned %d\n"%status )
    return new_filename

def expand_log_xml( filename ):
    """Converts a binary log to readable (pseudo-)xml."""
    debug( "expanding ", filename)
    match = binary_log_re.search( filename )
    assert match
    new_filename = filename + ".xml"	# add suffix.
    cmd = "%s %s"%(get_conf("log2xml_bin"),filename)
    if VERBOSE_DEBUG: debug( "Calling", cmd )
    status, output = commands.getstatusoutput( cmd )
    if status == 0 and os.path.exists( new_filename ):
        os.remove( filename )
    else:
        raise TraceException( "'%s' returned %d\n"%(cmd,status) )
    return new_filename

def pickle_cache():
    cache_pickle_file = "%s/db.pkl"%get_conf("local_cache")    
    cache_file = file( cache_pickle_file, "wb" )
    pickle.dump( _local_cache, cache_file, pickle.HIGHEST_PROTOCOL )
    cache_file.close()

def unpickle_cache( cache_pickle_file ):
    cache_file = file( cache_pickle_file, "rb" )
    global _local_cache
    _local_cache = pickle.load( cache_file )
    cache_file.close()

def ensure_in_cache( log_filename ):
    if VERBOSE_DEBUG:
        debug( "ensure_in_cache:", log_filename)
    match = logname_re.search( log_filename )
    assert match
    node_ip, vclock, epoch = (match.group('addr'),
                                long(match.group('time')),
                                long(match.group('epoch')))
    base_filename = log_filename[:match.start('suffix')] + "log"
    base_filename = os.path.basename(base_filename)
    candidates = get_cache_info( node_ip, vclock )
    if VERBOSE_DEBUG: debug( "Cache had: ", candidates )
    for log_info in candidates:
        if ((log_info.epoch == epoch) and (log_info.start == vclock)):
            return	# Perfect match
    else:
        # Get remote info from Epoch_Info object.
        assert node_ip in _local_cache
        node_addr = _local_cache[node_ip][epoch].node
        user, ip, dir = decode_addr( node_addr )        
        remote_filename = "%s/%s"%(dir,base_filename)

        debug( "Need for cache:", remote_filename)
        for suffix in [".gz","",".xml.gz",".xml"]:
            full_remote_filename = remote_filename + suffix
            debug( "Trying to download:", full_remote_filename)
            try:
                location = download_file( node_addr,
                                          File_Location( full_remote_filename, is_local=False ) )
            except MissingLogException:	# Try compressed version.
                debug( "Download failed." )
            else:
                break
        else:
            raise MissingLogException, remote_filename
        cache_insert( node_addr, location.filename )

def get_cache_info( node_addr, vclock ):
    """Returns a list of matching Log_Info objects."""
    if VERBOSE_DEBUG:
        debug( "get_cache_info: ", node_addr, vclock )
    if node_addr in _local_cache:
        return _local_cache[node_addr].search( vclock )
    else:
        return []
    

def cache_insert( node_addr, local_filename ):
    """Remember a log or checkpoint that has been downloaded.

    Returns the cached Log_Info, or None if the file is a library.
    """
    if VERBOSE_DEBUG: debug( "cache_insert", node_addr, local_filename)
    match = logname_re.search( local_filename )
    if not match:
        raise TraceException, "Invalid filename: "+local_filename
    node_ip = match.group('addr')
    epoch = long(match.group('epoch'))
    suffix = match.group('suffix')
    # Open relevant Log_Info object from cache:
    if node_ip not in _local_cache:
        _local_cache[node_ip] = Epoch_Map()
    if epoch not in _local_cache[node_ip]:
        _local_cache[node_ip][epoch] = Epoch_Info( node_addr, epoch )
    if suffix.startswith("lib"):
        _local_cache[node_ip][epoch].add_lib( match.group('libname'),
                                              File_Location(local_filename, True))
        pickle_cache()	# make it durable
        return None	# No particular Log_Info to return.
    # else:
    start_vclock = long(match.group('time'))
    cache_info = _local_cache[node_ip][epoch].get_log(start_vclock )
    if not cache_info:
        cache_info = Log_Info( None, None, {}, epoch, start_vclock )
        _local_cache[node_ip][epoch].add_log( cache_info )
    if suffix.startswith("ckpt.master"):
        assert cache_info.ckpt is None
        cache_info.ckpt = File_Location( local_filename, True )
    elif suffix.startswith("ckpt"):
        pid = match.group('pid')
        assert pid not in cache_info.other_ckpts
        cache_info.other_ckpts[pid] = File_Location( local_filename, True )
    elif suffix.startswith("log"):
        if not cache_info.log:
            cache_info.log = File_Location( local_filename, True )            
        else:	# We've already got one.
            # Must be one binary, one expanded.  Choose expanded (cheaper)
            if binary_log_re.search( local_filename ):
                assert not binary_log_re.search( cache_info.log.filename )
                # leave cache_info.log as is.
            else:
                assert binary_log_re.search( cache_info.log.filename )
                cache_info.log = File_Location( local_filename, True ) 
        if cache_info.end is None:	# Search for end vclock
            # Start with a simple default, in case log is unreadable:            
            cache_info.end = cache_info.start	
            try:
                log = file( local_filename, "r" )
                for line in log:
                    match = vc_re.search( line )
                    if match:
                        vc = long(match.group( 'time' ))
                        if vc > 0:	# logger corrupts end sometimes.
                            cache_info.end = vc
                log.close()
            except IOError, e:
                debug( "Caught:", e)
                debugf( "Assuming log %s ends at %s",
                        local_filename,cache_info.end )
    else:
        raise Exception, "Unexpected suffix: %s"%match.group('suffix')
    pickle_cache()	# make it durable
    return cache_info

def reread_cache( dir ):
    """Adds each file in dir to cache.

    All metadata is extracted from filename.
    Specifically, non-default remote user and directory information
    are lost."""
    debug( "Loading log cache...")
    _local_cache.clear()
    files = glob.glob( dir + "/*log" )
    files += glob.glob( dir + "/*log.xml" )
    files += glob.glob( dir + "/*ckpt.master" )
    files += glob.glob( dir + "/*ckpt" )
    for filename in files:
        # Need the node addr.  Heuristic: use IP (ignore path component).
        match = logname_re.search( filename )
        node_ip = match.group('addr')
        full_addr = add_defaults( node_ip )
        debug( filename, node_ip, full_addr )
        cache_insert( full_addr, filename )

def load_cache():
    local_cache_dir = get_conf("local_cache")
    cache_pickle_file = "%s/db.pkl"%local_cache_dir
    if os.path.exists( cache_pickle_file ):
        unpickle_cache( cache_pickle_file )
    else:
        if not (os.path.exists( local_cache_dir ) and
                os.path.isdir( local_cache_dir )):
            os.mkdir( local_cache_dir )
        reread_cache( local_cache_dir )

