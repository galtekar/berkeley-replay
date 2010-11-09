"""Chord-specific callbacks for trace_logs.py"""

import trace_logs, os, sys, re, random

local_chord_dir = os.path.expanduser("~/i3/work/i3/chord/")
if( "CHORD_DIR" in os.environ ):
    local_chord_dir = os.environ["CHORD_DIR"]
CHORD_ROUTE, CHORD_FS = 0,1
ID_LEN_HEX = 40
id_re = re.compile( r'<id>"(?P<id>[0-9a-f]+)"</id>' )

def create_checkpoint( node_addr, vclock  ):
    """Drop a new checkpoint at a specified time.

    Use replay to advance a node to the right point,
    then write a new checkpoint."""
    replay_exe = "%s/chord_replay"%(local_chord_dir,)
    vclock = long(vclock)	# Allow string input
    cmd = ("%s/chord_replay --prefix %s/plab --node %s --time %d --drop %d" %
           (local_chord_dir,trace_logs.local_log_dir,
            node_addr,vclock,vclock))
    print >>sys.stderr, cmd
    os.system( cmd )
    new_ckpt_name = "%s/plab.chord.%s.%d.ckpt.rep" % \
                    (trace_logs.local_log_dir, node_addr, vclock)
    return new_ckpt_name


def get_addr_list( node_addr, vclock, ckpt_name=None ):
    if not ckpt_name:	# Need to make a new one
        ckpt_name = create_checkpoint( node_addr, vclock )
    ckpt = file( ckpt_name, "r" )
    self_id = None
    prev_id = None
    finger_end_re = re.compile( r'</Fingers>' )
    for line in ckpt:
        if finger_end_re.search( line ):
            break
        match = id_re.search( line )
        if match:
            if not self_id:
                self_id = match.group('id')
            else:
                # Keep overwriting prev_id; we want the last one.
                prev_id = match.group('id')
    ckpt.close()
    os.remove( ckpt_name )
    return [(prev_id,self_id)]


def is_between( x, a, b ):
    """is x in (a,b) on circle?

    Copied from chord/util.c.
    Usually must also check for equality on b."""
    if a == b :
        return (x != a)
    elif a < b:
        return a < x < b
    else:
        return a < x or x < b

def forward_progress( x, a, b ):
    """Returns True iff forwarding from a to b gets closer to x."""
    return is_between( b, a, x )

def random_id():
    hex_list = []
    hex_chars = "0123456789abcdef"
    for i in range(ID_LEN_HEX):
        hex_list.append( random.choice( hex_chars ) )
    return "".join(hex_list)

def check_for_overlap( addr_list_a, addr_list_b ):
    """Check if any (start,end] in list a overlaps with any in list b."""
    for start_a, end_a in addr_list_a:
        for start_b, end_b in addr_list_b:
            if ((end_a == end_b) or
                is_between( end_a, start_b, end_b ) or
                is_between( end_b, start_a, end_a )):
                return True
    return False

def parse_id( hex_list ):
    """Pops the next ID_LEN_HEX bytes."""
    id = "".join(hex_list[:ID_LEN_HEX])	# Straight hex
    del hex_list[:ID_LEN_HEX]
    return id
    
def parse_data( hex_list ):
    return ("ttl: %d key: %s len: %d data: %s"%
            (trace_logs.parse_byte( hex_list ),
             parse_id( hex_list ),
             trace_logs.parse_short( hex_list ),
             "".join(hex_list)) )

def parse_fs( hex_list ):
    return ("ttl: %d need: %s reply: %s"%
            (trace_logs.parse_byte( hex_list ),
             parse_id( hex_list ),
             trace_logs.parse_addr( hex_list )))

def parse_fs_repl( hex_list ):
    return ("best: %s addr: %s"%
            (parse_id( hex_list ),
             trace_logs.parse_addr( hex_list )))

def parse_stab( hex_list ):
    return ("me: %s reply: %s"%
            (parse_id( hex_list ),
             trace_logs.parse_addr( hex_list )))

def parse_stab_repl( hex_list ):
    return ("pred: %s addr: %s"%
            (parse_id( hex_list ),
             trace_logs.parse_addr( hex_list )))

def parse_notify( hex_list ):
    return ("me: %s addr: %s"%
            (parse_id( hex_list ),
             trace_logs.parse_addr( hex_list )))

def parse_ping( hex_list ):
    return ("from: %s repl: %s time: %d"%
            (parse_id( hex_list ),
             trace_logs.parse_addr( hex_list ),
             trace_logs.parse_int( hex_list )))

def parse_pong( hex_list ):
    return ("from: %s addr: %s time: %d"%
            (parse_id( hex_list ),
             trace_logs.parse_addr( hex_list ),
             trace_logs.parse_int( hex_list )))

def parse_unknown( hex_list ):
    return "unknown: %s"%("".join(hex_list))

unpack_tuples = [("DATA",parse_data),
                 ("DATA_LAST",parse_data),
                 ("FS",parse_fs),
                 ("FS_REPL",parse_fs_repl),
                 ("STAB",parse_stab),
                 ("STAB_REPL",parse_stab_repl),
                 ("NOTIFY",parse_notify),
                 ("PING",parse_ping),
                 ("PONG",parse_pong),
                 ("GET_FINGERS",parse_unknown),
                 ("REPL_FINGERS",parse_unknown),
                 ("TRACEROUTE",parse_unknown),
                 ("TRACEROUTE_LAST",parse_unknown),
                 ("TRACEROUTE_REPL",parse_unknown)]

def parse_msg( hex_string ):
    hex_list = list(hex_string)
    msg_type = trace_logs.parse_byte( hex_list )
    tup = unpack_tuples[msg_type]
    return (tup[0], tup[1](hex_list) )
    
def get_destination( hex_string ):
    """Returns the target ID.

    If the message should be forwarded to an ID (data packet, finger
    stabilization), return the ID.  Otherwise, return None."""
    hex_list = list(hex_string)
    msg_type = trace_logs.parse_byte( hex_list )
    # Only certain message types have a destination ID.
    # The rest are sent to a specific IP addr:port
    if( msg_type in (CHORD_ROUTE,CHORD_FS) ):
        return parse_id( hex_list )
    else:
        return None

def data_plane( hex_string ):
    """Checks whether this message is a DATA packet."""
    hex_list = list(hex_string)
    return trace_logs.parse_byte( hex_list ) == CHORD_ROUTE

def get_owners( id, node_list ):
    """Sorts the node_list by ownership of the ID.

    The first node in the returned list is the current successor,
    and the rest of the ring will be listed in order afterwards.
    Assumes the node_list is a list of IDs.
    """
    assert( isinstance(id,str) and len(id)==ID_LEN_HEX)
    ret_list = node_list
    ret_list.sort( lambda x,y: cmp(x.name,y.name) )
    l = len(ret_list)
    for i, node in enumerate(ret_list):
        prev = ret_list[(i-1)%l]
        #if DEBUG: print >>sys.stderr, ("Checking %s in (%s,%s]"%
        #                               (id, prev, node))
        if (id == node.name) or \
               is_between( id, prev.name, node.name ): # Found owner
            ret_list = ret_list[i:] + ret_list[:i]
            break
    return ret_list

def find_name( ckpt_filename ):
    """Scans a checkpoint for the first <id> tag."""
    ckpt = file( ckpt_filename, "r" )
    for line in ckpt:
        match = id_re.search( line )
        if match:
            return match.group('id')
    else:
        return None

def log_contained_route( log_filename, neighbour, range=None ):
    """Looks for any message sent to neighbour."""
    log = gzip.open( filename, "r" )
    for line in log:
        match = send_re.match(line)
        if match and match.group('dst') == neighbour:
            # Check range:
            vclock = long(match.group('time'))
            if not range or (range[0] <= vclock <= range[1]):
                return True
    else:
        return False
    
    
trace_logs.parse_msg = parse_msg
trace_logs.data_plane = data_plane
trace_logs.get_destination = get_destination
trace_logs.get_addr_list = get_addr_list
trace_logs.get_owners = get_owners
trace_logs.find_name = find_name
trace_logs.create_checkpoint = create_checkpoint
trace_logs.forward_progress = forward_progress
trace_logs.log_contained_route = log_contained_route
