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
# author: Dennis Geels
# $Id: friday.py,v 1.18 2006/09/24 05:56:26 galtekar Exp $

"""Query processing library for liblog.
"""

# TODO: Commands, state, watchpoints on state?
# Specify length of final field somehow?
# If new processes are added, add to watchpoint?  In start_replay().

import sys, re, resource, traceback

if __name__ == "__main__":
    sys.exit( "\nThis library has no stand-alone functionality\n" )

import __main__
main = __main__	# more easily-typed reference
trace_logs = main.trace_logs

##### Constants
DEBUG = False
CALL_MPROTECT_DIRECTLY = False

_continue_cmd_re = re.compile( r'c(o(nt?)?)?($|\s)' )

# Detects pointers and arrays in C expressions
_sub_exp_split_re = re.compile( r'->|\[' )

# Detects C literals (currently, only numbers)
_c_literal_re = re.compile( r'^(0x[0-9a-fA-F]+|[0-9]+(\.[0-9]+)?)$')
# Detects C function calls.  Looks for a word followed by open paren.
_c_call_re = re.compile( r'\w\s*\(')

# Detects string types.
#_string_type_re = re.compile( r'char\s*(\*|\[)' )
_string_type_re = re.compile( r'char\s*\*' )
# Detects some integer types.
_integer_type_re = re.compile( r'(u_?)?(int(8|16|32|64)?|long)(_?t)?' )
# Detects pointer types.
_pointer_type_re = re.compile( r'\*[\)\s]*$' )

_pagesize = resource.getpagesize()

##### Globals

_points = []		# array of BreakPoint and WatchPoint objects.
_pages_by_ctrl = {}		# maps controller index to Page map.
_command_locals = {}	# local namespace for WatchPoint commands

##### Classes

class FridayException(Exception):
    "Base class for exceptions raised in this module."
    pass

class ParseException(FridayException):
    "Raised if input is unparseable."
    pass

class InputException(FridayException):
    "Raised if user request is invalid."

class SymbolException(FridayException):
    "Raised if GDB does not recognize symbol named by user."
    pass
    
class ShouldContinueException(FridayException):
    "Raised by compiled WatchPoint commands if they want to continue execution."
    pass

class Command:
    """Simple (code,flags) struct."""
    def __init__(self,code,flags):
        self.code = code
        self.flags = flags

class BreakPoint:
    """Bookkeeping for distributed breakpoints.

    string:	address specified by user.
    index: 	index of self in _points (different from GDB breakpoint list)
    enabled:	False iff disabled by user
    hits: 	Number of times triggered by app
    by_child: 	for each controller, a map from child PID to (GDB index,addr)
    command:	Python function to execute when watchpoint changes.
    """
    type_name = "breakpoint"
    def __init__(self, string):
        self.string = string
        self.index = len(_points)
        _points.append( self )
        self.enabled = False
        self.hits = 0
        self.by_child = {}
        self.command = None	# Do nothing -- will stop replay
    def __repr__(self):
        return "BreakPoint #%d (%s) [%d]"%\
               (self.index,self.string,self.hits)
    def print_info(self):
        out( "%d\t%s\t%s\t%d\t%s\t%s\t%s"%
             (self.index, "breakpoint", ("n","y")[self.enabled],
              self.hits, "N/A", "N/A", self.string) )
    
class WatchPoint:
    """Bookkeeping for distributed watchpoints.

    exps:	list of original expressions
    string: 	self.exps, joined into string
    subexps:	set of sub-expressions to watch
    frame:	($fp,$pc) for stack frame of variables, or None
    		  if all are global.  Assumes all subexps from one frame.
    addrs: 	for each process, map from expression to its location,len
    enabled:	False iff disabled by user
    values:	Current value at each process, as array of bytes
    hits: 	Number of times triggered by app
    mods: 	Number of times value changed by app
    false: 	Number of times something else on page was hit
    command:	Python function to execute when watchpoint changes.
    index: 	index of self in _points
    """
    type_name = "watchpoint"
    def __init__(self, exps, subexps):
        self.exps = exps
        self.string = "'%s'"%"','".join(exps)
        self.subexps = subexps
        self.frame = None
        self.addrs = {}	# Leave blank until set_watchpoint.
        self.enabled = False
        self.values = {}
        self.hits = 0
        self.mods = 0
        self.false = 0
        self.index = len(_points)
        _points.append( self )
        self.command = None	# Do nothing -- will stop replay
    def __repr__(self):
        return "WatchPoint #%d (%s) [%d:%d:%d]"%\
               (self.index,self.string,self.hits,self.mods,self.false)
    def print_info(self):
        out( "%d\t%s\t%s\t%d\t%d\t%d\t%s"%
             (self.index, "watchpoint", ("n","y")[self.enabled],
              self.hits, self.mods, self.false, self.string) )

class Page:
    """Just tracks WatchPoints for each page.

    addr: address of start of page in memory
    watchpoints: set of indices for WatchPoints affecting this page
    """
    def __init__(self, start_addr):
        self.addr = start_addr
        self.watchpoints = set()
        self.protected = False
    @staticmethod
    def baseaddr(addr):
        return addr & ~(_pagesize-1)
    def __repr__(self):
        return "Page[0x%x] %s: (%s)"%(self.addr,("rw","r")[self.protected],
                                      ",".join(map(str,self.watchpoints)))

class page_map_t(dict):
    """Simple dict with integer keys.  Prints in hex."""
    def repr_item(self, key):
        return "0x%x: %s"%(key,repr(self[key]))
    def __repr__(self):
        return "{" + ", ".join( map( self.repr_item, self ) ) + "}"

class page_set_t(set):
    """Simple set of integers.  Prints in hex."""
    def __repr__(self):
        return "[" + ", ".join( map( hex, self ) ) + "]"

class addr_tuple_t(tuple):
    """Simple (addr,len) tuple.  Prints in hex."""
    def __repr__(self):
        return "(0x%x+0x%x)"%self

class byte_tuple_t(tuple):
    """Simple set of integers.  Prints as large hex."""
    def __repr__(self):
        return "(" + " ".join( ["%.2x"%n for n in self]) + ")"
    

##### Utility Functions
def out( string ):
    """Prints some normal feedback.

    Calls through to main colorized output functions."""
    # Support operation in non-console __main__:
    if not hasattr(__main__, "print_in_color"):
        print string  
    else:
        __main__.print_in_color( string+"\n", __main__._output_normal )
    
def debug( *args ):
    """Prints and logs debug output.
    
    Calls through to main colorized output functions."""
    # Support operation in non-console __main__:
    if DEBUG:
        string = " ".join( map( str, args ) )
        if not hasattr(main, "print_in_color"):
            print string  
        else:
            main.print_in_color( string+"\n", main._output_friday )

def debugf( *args ):
    """Prints and logs debug output (format string version).
    
    Calls through to main colorized output functions."""
    if DEBUG: debug( args[0]%args[1:] )

def error( *args ):
    """Prints an error message.

    Calls through to main colorized output functions."""
    string = " ".join( map( str, args ) )    
    # Support operation in non-console __main__:    
    if not hasattr(__main__, "print_in_color"):
        print string
    else:
        __main__.print_in_color( string+"\n", __main__._output_error )

def usage():
    """Prints an error and the main help page.

    Calls through to main colorized output functions."""
    error( "Invalid Usage" )
    # Support operation in non-console __main__:
    if hasattr(__main__, "print_help"):
        __main__.print_help()

##### Functions
def find_closing_char( string, open, close ):
    """Finds the ']/)' matching the '[/(' that starts string.

    See find_closing_bracket.
    """
    assert string.startswith(open)
    nested = 0
    for i,c in enumerate(string):
        if c == open:
            nested += 1
        elif c == close:
            nested -= 1
            if nested == 0:
                return i+1
    raise ParseException( "No matching '%s' in '%s'"%(close,string) )
        
def find_closing_bracket( string ):
    """Finds the ']' matching the '[' that starts string.

    Returns the length of the bracketed prefix, which is equal to the
    index of the charachter _after_ the matching bracket, or throws a
    ParseException if it cannnot be found.
    We dont' use a regular expression because matching brackets is not
     a regular language.
    """
    return find_closing_char( string, '[', ']' )

def is_literal( string ):
    """Detects C literals.
    """
    return bool(_c_literal_re.match(string))

def is_call( string ):
    """Detects C function calls.
    """
    return bool(_c_call_re.search(string))
        
def find_subexps( string ):
    """Parses one C expresion.

    Returns a set of the subexpressions that should be watched in GDB,
    because their value might change, affecting the original
    expression's value.  The full expression is always included,
    unless it is a literal.

    For example, a->b.c[d] will return:
    	["a", "a->b.c", "d", "a->b.c[d]"]
    Basically we find all pointers and array indices.

    Restrictions on expressions (for now, at least):
      No parenthesis.  ex: (a.b).c
      No pointer dereferencing.  ex: *a.b
    """
    # Only "->" and "[]" could denote the a sub-expression that can
    # change value independently.
    debugf( "parce_c_exp: '%s'", string )
    
    subexps = set()
    if not is_literal( string ):
        if string.startswith("*"):
            if not is_literal(string[1:]):
                raise InputException( "Cannot watch address of non-literal expression")
        subexps.add( string )	# Include full expression
        pos = 0	# current search start index
        while True:
            match = _sub_exp_split_re.search( string, pos )
            if not match:
                break
            if match.group() == "->":		# pointer
                subexps.add( string[0:match.start()] )
                pos = match.end()
            else:
                subexp_len = find_closing_bracket( string[match.start():])
                subexp_end = match.start() + subexp_len
                pos = subexp_end	# skip to end of array reference
                index_subexp = string[match.start()+1:subexp_end-1].strip()
                subexps |= find_subexps( index_subexp )
        debug( "find_subexps returning:", subexps )
    #else: literal integer--no need to watch.
    return subexps

def join_false_whitespace( words ):
    """Join subexpressions together.

    If an expression included whitespace originally (e.g. a[ 4 ]), the
    console would split it into multiple words.  We rejoin.
    Assumptions: whitespace is only allowed after '[' and before ']'.
    """
    pos = 0
    while pos < len(words):
        while (words[pos].endswith( '[' ) or
               (pos+1<len(words) and words[pos+1].startswith( ']' ))):
            words[pos:pos+2] = ["".join(words[pos:pos+2])]
        pos += 1
    return words

def search_frames_in_proc( ctrl, subexps ):
    """Finds the stack frame where a variable is declared.

    GDB will only find local variables when they are in the scope of
    the currently-selected stack frame.  This function searches the
    stack, starting at the current one, until GDB resolves the
    expression.  It then checks whether the variable is located in
    that frame.  If so, it returns that frame pointer ($fp).
    Otherwise, it assumes that the variable is global, and returns None.
    """
    # TODO: handle multiple processes correctly.  Requires tracking
    #       frame pointers independently?
    frame = None	# Are all subexpressions in global scope?
    frames_popped = 0
    last_fp = None
    for exp in subexps:
        if exp.startswith("*"):
            break	# Watching an address.  Global scope.
        while True:
            #__main__.call_gdb( ctrl, "frame" )
            fp = __main__.get_long( ctrl, "(unsigned long)$fp" )
            if fp == last_fp:
                # top frame
                raise SymbolException("Cannot find frame for: '%s'"%exp)
            addr_cmd = "(unsigned long)&(%s)"%exp
            addr = __main__.get_long( ctrl, addr_cmd )
            if not addr:
                last_fp = fp
                frames_popped += 1
                __main__.call_gdb_quiet( ctrl, "up-silently" )
            else:
                sp = __main__.get_long( ctrl, "(unsigned long)$sp" )
                if sp <= addr <= fp:
		    # Need saved PC from parent to identify frame:
		    frames_popped += 1
		    __main__.call_gdb_quiet( ctrl, "up-silently" )
                    pc = __main__.get_long( ctrl, "(unsigned long)$pc" )                    
                    assert frame in (None,(fp,pc))
                    frame = (fp,pc)
                else:
                    pass	# global
                if frames_popped:
                    debugf( "replacing %d frames", frames_popped )
                    __main__.call_gdb_quiet( ctrl, "down-silently %d"%(frames_popped) )
                break
    return frame

def resolve_addrs_in_proc( ctrl, subexps, frame ):
    """Finds the current address for each expression.

    Returns a map of expression to <addr,len> tuples."""
    addr_map = {}
    frames_popped = 0
    last_fp = 0
    if frame:
        # Find the matching stack frame.  Assume that it is in or
        #  above the current one.
        # __main__.call_gdb( ctrl, "frame" )
        debug( "Looking for frame (%x,%x)"%frame )
        while True:
            fp = __main__.get_long( ctrl, "(unsigned long)$fp" )
            if fp == last_fp:
                # top frame
                raise SymbolException("Cannot find frame (%x,%x)"%frame)
            elif frame[0] == fp:
		# Need saved PC from parent to identify frame:
		frames_popped += 1
		__main__.call_gdb_quiet( ctrl, "up-silently" )
                pc = __main__.get_long( ctrl, "(unsigned long)$pc" )
                if frame[1] == pc:
                    break
		else:
		    raise SymbolException("Cannot find frame (%x,%x)"%frame)
            last_fp = fp
            frames_popped += 1
            __main__.call_gdb_quiet( ctrl, "up-silently" )
            
        debugf( "popped %d frames", frames_popped )
    # Now resolve each subexpressions
    for subexp in subexps:
        if subexp.startswith("*"):
            addr = long( subexp[1:] )
            len = 4	# Hardwired!
        else:
            addr_cmd = "(unsigned long)&(%s)"%subexp
            addr = __main__.get_long( ctrl, addr_cmd )
            len = __main__.get_long( ctrl, "sizeof( %s )"%subexp )
            #type = __main__.get_type( ctrl, subexp )
        type = "unknown"
        if None in (addr, len, type):
            raise SymbolException("GDB does not recognize: '%s'"%subexp)
        debugf( "resolved '%s' as '%s': 0x%x+0x%x", subexp, type, addr, len )
        addr_map[subexp] = addr_tuple_t((addr,len))
    # re-select original stack frame
    if frames_popped:
        __main__.call_gdb_quiet( ctrl, "down-silently %d"%(frames_popped) )
    debugf( "resolve_addrs[%d]: %s", ctrl.index, addr_map )
    return addr_map

def get_page_set( addr_map ):
    """Converts a map of addresses to a set of pages.

    Returns a set containing the base address for each page."""
    page_set = page_set_t()
    debug( "get_page_set", addr_map )
    for exp,(addr,len) in addr_map.items():
        base = Page.baseaddr(addr)
        while( base < addr+len ):
            page_set.add( base )
            base += _pagesize
    debug( addr_map, "->", page_set )
    return page_set

def watch_page( ctrl, wp, base_addr ):
    """Add a WatchPoint to a single page."""
    debugf( "watch_page( %d, %d, 0x%x)", ctrl.index, wp.index, base_addr )
    page_map = _pages_by_ctrl[ctrl.index]
    if base_addr not in page_map:
        # First WatchPoint on this page.
        page_map[base_addr] = Page( base_addr )
        make_readonly( ctrl, base_addr )
    page_map[base_addr].watchpoints.add(wp.index)

def store_values_of_exp( ctrl, wp ):
    """Reads and saves the current value of each expression."""
    byte_values = []
    for exp in wp.exps:
        addr,len = wp.addrs[ctrl.index][exp]
        debugf( "reading %s from 0x%x+0x%x", exp, addr, len )
        bytes = __main__.get_bytes( ctrl, addr, len )
        #debug( "found:", byte_list_t(bytes) )
        byte_values.extend( bytes )
    wp.values[ctrl.index] = byte_tuple_t(byte_values)
    debug( "found:", wp.values[ctrl.index] )

def reset_watchpoint_on_proc( ctrl, wp ):
    """Recalculates and sets watchpoint locations for one process.

    This method should be called whenever an internal subexpression in
      the watchpoint has been modified, because the location of later
      subexpression variables may move.
    Returns True if watchpoint was reset successfully.
    """
    # FIXME -- What if watchpoint is set on multiple child procs?
    # First find current pages
    old_pages = get_page_set( wp.addrs[ctrl.index] )
    # Now update variable locations
    try:
        wp.addrs[ctrl.index] = resolve_addrs_in_proc( ctrl, wp.subexps, wp.frame )
    except SymbolException, se:
        debug( "Caught:", se )
        error( "Watchpoint %d no longer in scope for process %d"%(wp.index,ctrl.index) )
        remove_watchpoint_from_proc( ctrl, wp )        
        return False
    # And find new pages
    new_pages = get_page_set( wp.addrs[ctrl.index] )
    # remove watchpoint from defunct pages
    for base in (old_pages-new_pages):
        unwatch_page( ctrl, wp, base )
    # and add new ones
    for base in (new_pages-old_pages):
        watch_page( ctrl, wp, base )
    # In case expression moved, save new values.
    store_values_of_exp( ctrl, wp )
    return True

def set_watchpoint_in_proc( ctrl, wp ):
    """Helper for set_watchpoint().  Handles a single process."""
    if ctrl.index not in _pages_by_ctrl:
        _pages_by_ctrl[ctrl.index] = page_map_t()
    # Find the location of each subexpression:
    wp.frame = search_frames_in_proc( ctrl, wp.subexps )
    wp.addrs[ctrl.index] = resolve_addrs_in_proc( ctrl, wp.subexps, wp.frame )
    # Make sure each page is protected:
    for base in get_page_set( wp.addrs[ctrl.index] ):
        watch_page( ctrl, wp, base )	
    # Save current value of full expression.
    store_values_of_exp( ctrl, wp )
    debug( "current value:", wp.values[ctrl.index] )

def set_watchpoint( wp ):
    """Call through to GDB (or mprotect) to set watchpoint at symbol.
    """
    debug( "set_watchpoint:", wp )
    current = __main__.current_controllers()
    wp.addrs.clear()
    for ctrl in current:
        set_watchpoint_in_proc( ctrl, wp )
    wp.enabled = True

def set_breakpoint_in_proc( ctrl, bp ):
    """Helper for set_breakpoint."""
    bp.by_child[ctrl.index] = {}
    for child in ctrl.children:
        index,addr = main.call_break_in_gdb( ctrl, bp.string, child )
        if None in (index,addr):
            raise SymbolException("GDB does not recognize: '%s'"%bp.string)
        bp.by_child[ctrl.index][child] = (index,addr)
    debugf( "by_child[%d]: %s", ctrl.index, str(bp.by_child[ctrl.index]))
        
def set_breakpoint( bp ):
    """Call through to GDB to set breakpoint.
    """
    debug( "set_breakpoint:", bp )
    current = __main__.current_controllers()
    bp.by_child.clear()
    for ctrl in current:
        set_breakpoint_in_proc( ctrl, bp )
    bp.enabled = True

def enable_breakpoint( bp ):
    """Re-enables a distributed breakpoint.

    Sets breakpoint for new nodes as necessary."""    
    debug( "enable_breakpoint:", bp )
    ctrls = [(i,__main__._replay_controllers[i]) for i in bp.by_child]
    # first re-enable old ones
    for i, ctrl in ctrls:
        if not ctrl:
            debug( "Forgetting dead controller:", i )
            del bp.by_child[i]
        else:
            for child in ctrl.children:
                index,addr = bp.by_child[i][child]
                cmd = "enable %d"%index
                main.call_gdb_quiet( ctrl, cmd, child )
    # now check for new processes.
    current = __main__.current_controllers()
    for ctrl in current:
        if ctrl.index not in bp.by_child:
            debug( "Adding breakpoint for", ctrl )
            set_breakpoint_in_proc( ctrl, bp )
    bp.enabled = True
    

def unwatch_page( ctrl, wp, base_addr ):
    """Remove a WatchPoint to a single page."""
    debugf( "unwatch_page( %d, %d, 0x%x)", ctrl.index, wp.index, base_addr )
    page_map = _pages_by_ctrl[ctrl.index]	# assume ctrl in table
    if ((base_addr not in page_map) or
        (wp.index not in page_map[base_addr].watchpoints)):
        debugf( "skipping 0x%x: already cleared", base_addr )
    else:
        page_map[base_addr].watchpoints.remove(wp.index)
        if not page_map[base_addr].watchpoints:
            # last WatchPoint on this page.
            # TODO: it's possible page was originally readonly.
            make_writable( ctrl, page_map[base_addr].addr )
            del page_map[base_addr]

def remove_watchpoint_from_proc( ctrl, wp ):
    """Helper for remove_watchpoint().  Handles a single process."""
    for base in get_page_set( wp.addrs[ctrl.index] ):
        unwatch_page( ctrl, wp, base )
    debugf( "all pages[%d]: %s", ctrl.index, _pages_by_ctrl[ctrl.index] )
    

def remove_watchpoint( wp ):
    """Removes a WatchPoint previously set with set_watchpoint
    """
    debug( "remove_watchpoint:", wp )
    ctrls = [(i,__main__._replay_controllers[i]) for i in wp.addrs]
    for i, ctrl in ctrls:
        if not ctrl:
            debug( "Forgetting dead controller:", i )
            del wp.addrs[i]
        else:
            remove_watchpoint_from_proc( ctrl, wp )
    wp.enabled = False

def disable_breakpoint( bp ):
    """Removes a BreakPoint previously set with set_breakpoint
    """
    debug( "disable_breakpoint:", bp )
    ctrls = [(i,__main__._replay_controllers[i]) for i in bp.by_child]
    for i, ctrl in ctrls:
        if not ctrl:
            debug( "Forgetting dead controller:", i )
            del bp.by_child[i]
        else:
            for child in ctrl.children:
                index,addr = bp.by_child[i][child]
                cmd = "disable %d"%index
                main.call_gdb_quiet( ctrl, cmd, child )
    bp.enabled = False
    

def is_watched_page( ctrl, start_addr ):
    """Returns True iff address is start of Page with active WatchPoint."""
    return ((ctrl.index in _pages_by_ctrl) and
            (start_addr in _pages_by_ctrl[ctrl.index]))
                
def make_readonly( ctrl, start_addr ):
    """Uses call_mprotect() to remove write permissions to a page.
    """
    page = _pages_by_ctrl[ctrl.index][start_addr]
    debugf( "make_readonly: 0x%x", start_addr )    
    assert not page.protected
    call_mprotect( ctrl, start_addr, False )
    page.protected = True
#    __main__.call_gdb_quiet( ctrl, "call mprotect( 0x%x, 1, 1 )"%start_addr )

def make_all_readonly( ctrl ):
    page_map = _pages_by_ctrl[ctrl.index]
    for start_addr in page_map:
        make_readonly( ctrl, start_addr )

def make_writable( ctrl, start_addr ):
    """Uses call_mprotect() to return write permissions to a page.
    """
    page = _pages_by_ctrl[ctrl.index][start_addr]
    debugf( "make_writable: 0x%x", start_addr )
    assert page.protected
    call_mprotect( ctrl, start_addr, True )
    page.protected = False

def make_all_writable( ctrl ):
    page_map = _pages_by_ctrl[ctrl.index]
    for start_addr in page_map:
        make_writable( ctrl, start_addr )

def call_mprotect( ctrl, start_addr, writable ):
    """Call mprotect() to remove all access permissions to a page.
    Raises a FridayException if call fails.
    """
    cmds = ["set $old_eip = $eip",
            "set page_start_addr = 0x%x"%start_addr,
            "set $eip = mprotect_%s"%('remove','restore')[writable],
            "c",
            "set $eip = $old_eip"]
    if CALL_MPROTECT_DIRECTLY:
        cmds = ["call syscall(SYS_mprotect, 0x%x, %d, %d )"%(start_addr,1,(1,3)[writable])]
    for child in ctrl.children:
        for cmd in cmds:
            __main__.call_gdb_quiet( ctrl, cmd, child )
        
def check_user_breaks( ctrl, pc ):
    """Runs user-specified commands for breakpoints at pc."""
    debug( "check_user_breaks", ctrl, pc )
    child = ctrl.current_child
    # TODO: build index by addr for each child
    found_break = False
    should_continue = True
    if pc:
        for p in _points:
            if (p.enabled and
		isinstance( p, BreakPoint ) and
		(ctrl.index in p.by_child) and
		(child in p.by_child[ctrl.index])):
		# This breakpoint is enabled and set for this process.
                index, addr = p.by_child[ctrl.index][child]
                debugf( "break %d(%d) at %x vs. %x", p.index, index, addr, pc )
                if addr == pc:
                    if not p.command or "silent" not in p.command.flags:
                        out( "Process #%d hit breakpoint %d: %s"%(ctrl.index,p.index,p.string))
                    found_break = True
                    p.hits += 1
                    should_continue &= run_command( ctrl, p )
    debug( "returning:", (found_break,should_continue) )
    return (found_break,should_continue)


def run_command( ctrl, point ):
    """Run the commands attached to a break/watchpoint.

    Returns True if the code raised a ShouldContinueException.
    """

    # galtekar: Allows handler to get info about the watchpoint
    # it is stopped on. Useful for retrieving aux info associated
    # with the watchpoint index.
    command_globals = globals()
    command_globals["current_wp"] = point

    should_continue = False
    if (point.command and
	(isinstance( point, WatchPoint) or (ctrl.index in point.by_child))):
        _command_locals["__NODE__"] = ctrl
        _command_locals["__ALL__"] = __main__.current_controllers()
        # The next two variables support disabling watchpoints temporarily.
        _command_locals["__SAFE__"] = bool("safe" in point.command.flags)
        _command_locals["__WRITABLE_NODES__"] = set()
        try:
            exec point.command.code in command_globals, _command_locals
        except ShouldContinueException, sce:
            debug( "caught continue exception" )
            should_continue = True
        except Exception, e:
            error( "Caught exception in user-provided commands:", e )
            error( traceback.format_exc() )
        # If any nodes were unprotected, restore their watchpoints:
        # TODO: if there are multiple watchpoints triggered, wait until end.
        if _command_locals["__WRITABLE_NODES__"]:
            nodes = [main._replay_controllers[i] for i in _command_locals["__WRITABLE_NODES__"]]
            map( make_all_readonly, nodes )
    return should_continue

def check_wp_at_proc( ctrl, wp ):
    """Helper for run_hooks().  Handles a single watchpoint.

    First we check whether the value has actually changed.  If so, we
    run the user-specified hook.  We also reset the watchpoint, as any
    modification to a strict subexpression may have

    Returns (<should_continue>,<was_modified>).
    """
    # Save old value.
    old_value = wp.values[ctrl.index]
    debug( "Old value =", old_value )
    new_value = None
    # Find possibly-moved location and value(s)
    success = reset_watchpoint_on_proc( ctrl, wp )
    if success:
        new_value = wp.values[ctrl.index]
        debug( "New value =", new_value )
    else:
        debug( "No new value" )
    
    # Any change?
    if success and (old_value != new_value):
        # TODO: print out in real type, instead of raw bytes.
        if not wp.command or "silent" not in wp.command.flags:
            out( "Process #%d hit watchpoint %d: %s"%(ctrl.index,wp.index,wp.string))
            out( "Old value = " + str(old_value) )
            out( "New value = " + str(new_value) )
        wp.mods += 1
        was_modified = True
        should_continue = run_command( ctrl, wp )
    else:
        should_continue = True
        was_modified = False        
    return (should_continue,was_modified)

def copy_watchpoints( ctrl, child_pid ):
    """Sets all currently-active WatchPoints in new process.
    """
    #FIXME -- call in start_replay(), attach_to_children()
    for wp in _points:
        if isinstance(wp, WatchPoint):
            set_watchpoint_in_proc( ctrl, wp, child_pid )
    
def run_hooks( ctrl, fault_addr ):
    """Runs the hooks for each WatchPoint at address.

    Returns (True,True,) if no WatchPoints were triggered.
    Returns (True,False,X) if all triggered WatchPoint returned True.
    	X is True iff one of the WatchPoints was modified.
    else returns (False,False,True).
    """
    # for each ctrl? No.
    base_addr = Page.baseaddr(fault_addr)
    should_continue = True
    false_positive = True
    some_modified = False
    wp_indices = _pages_by_ctrl[ctrl.index][base_addr].watchpoints
    for wp_i in wp_indices:
        wp = _points[wp_i]
        debugf( "Checking %s for fault at 0x%x", wp, fault_addr )
        for exp,(addr,len) in wp.addrs[ctrl.index].items():
            # FIXME: what if addr is not word-aligned?  What is range
            # of faulting instruction?
            if addr <= fault_addr < addr+len:
                # This WatchPoint was watching fault_addr.
                debugf( "Hit expression '%s'", exp )
                wp.hits += 1
                false_positive = False
                # check value, run hooks and reset if necessary:
                (should_continue_wp,modified) = check_wp_at_proc( ctrl, wp )
                should_continue &= should_continue_wp
                some_modified |= modified
                break
        else:
            wp.false += 1
    assert( should_continue or ((not false_positive) and some_modified))
    return (should_continue, false_positive, some_modified)

def get_value( ctrl, name ):
    """Extracts state from a replay process.

    Currently assumes everything is an integer.
    """
    debug( "get_value:", ctrl, name )
    # Interpolate any pyhton variables in the predicate.
    vars = globals().copy()
    vars.update( _command_locals )
    debugf( "Interpolating name '%s'", name)
    name = name%vars
    debugf( "Final: '%s'", name )
	 
    if ( is_call( name )
         and (not _command_locals["__SAFE__"])
         and (ctrl.index not in _command_locals["__WRITABLE_NODES__"])):
        # This function call may write to watched page.  Temporarily unprotect.
        _command_locals["__WRITABLE_NODES__"].add( ctrl.index )
        make_all_writable( ctrl )
    # It would be nice if we could handle arbitrary types.  For now,
    #  be sure to handle strings and integer types (assume latter).
    type = main.get_type( ctrl, name )
    debug( "type:", type )
    value = None
    if _string_type_re.search( type ):
        value = main.get_string( ctrl, name )
    elif _integer_type_re.match( type ):
        value = main.get_long( ctrl, name )
    elif _pointer_type_re.match( type ):
        forced_cast_name = "(long)"+name
        print "FORCED CAST: ", forced_cast_name
        value = main.get_long( ctrl, forced_cast_name )
    else:
        value = byte_tuple_t(main.get_as_bytes( ctrl, name ))

    return value
    
def set_value( ctrl, name, value ):
    """Modifies state in a replay process.

    Currently assumes everything is an integer.
    """
    debug( "set_value:", ctrl, name )
    # Interpolate any python variables in the predicate.
    #  _command_locals overrides globals()
    vars = globals().copy()
    vars.update( _command_locals )
    debugf( "Interpolating name '%s'", name )
    name = name%vars
    debugf( "Interpolating value '%s'", value )
    value = value%vars
    cmd = "set %s=%s\n"%(name,value)
    debugf( "command: '%s'", cmd )
    return __main__.call_gdb( ctrl, cmd, action="discard",
                              may_hit_breakpoint=False )


def parse_state_ref( string ):
    """Parses a reference of the form @[<ctrl>](<expression>).

    Returns the ctrl, expression, and reference string length,
    or raises a ParseException.
    """
    debug( "parse_state_ref", string )
    assert string.startswith( '@' )
    left_p = string.find( '(' )
    if left_p < 1:
        raise ParseException( "Invalid reference: '%s'"%string)
    ctrl = string[1:left_p]
    exp_len = find_closing_char( string[left_p:], '(', ')' )
    end = left_p+exp_len
    exp = string[left_p+1:end-1]
    debug( "parsed:", ctrl, exp, end )
    return (ctrl, exp, end)

def interpolate_line( line ):
    """Replaces references to application state with accessor functions.
    """
    debug( "interpolating:", line )
    line = _continue_cmd_re.sub( "raise ShouldContinueException", line )
    line = line.replace( "__VCLOCK__", "get_value(__NODE__,'_shared_info->vclock')" )
    line = line.replace( "__LOGICALCLOCK__", "get_value(__NODE__,'_shared_info->vclock')" )
    while True:
        start = line.find( '@' )
        if start >= 0:
            ctrl, exp, len = parse_state_ref( line[start:] )
            if not ctrl:
                ctrl = "__NODE__"
            elif re.match( "\d+", ctrl ):
                ctrl = "main._replay_controllers[%s]"%ctrl
            if -1 < exp.find("="):
                lvalue, rvalue = exp.split( "=" )
		# quote rvalue carefully, in case it contains a string.
		assign_cmd = 'set_value(%s,"%s",""" %s """)'%(ctrl,lvalue,rvalue)
                line = line.replace(line[start:start+len], assign_cmd )
                                    
            else:
                line = line.replace(line[start:start+len],
                                    'get_value(%s,"%s")'%(ctrl,exp))
                
        else:
            break
    debug( "final:", line )    
    return line

def read_and_compile_command( input=[] ):
    """Reads function from input and compile into Python code.

    References to application state are detected (from @... syntax)
    and replaced with accessor functions.
    "end", "continue", "cont", "silent", and "safe" are keywords.
    """
    lines = []
    flags = set()
    while( True ):
        if input:
            line = input.pop(0)
        else:
            line = __main__.prompt( "...  " )
        debugf( "read: '%s'", line )
        if line.strip() == "end":
            break
        elif (not lines) and (line.strip() in ("silent","safe")):
            # flags must be at start of command. 
            flags.add( line.strip() )
        else:
            lines.append(interpolate_line(line))
    all = "\n".join(lines)
    debugf( "compiling '%s'", all )
    try:
        code = compile( all, "<console>", "exec" )
    except SyntaxError, se:
        raise InputException( str(se) )
    debug( "flags:", flags )
    return Command( code, flags )
    
    
############################
# Console-accessible methods

def print_info():
    """Print out status of all WatchPoints.
    """
    if not _points:
        out( "No distributed breakpoints or watchpoints." )
    else:
        out( "Num\tType\t\tEnb\tHit\tMod\tFP\tWhat" )
        for p in _points:
            p.print_info()
    return True

def watch( words ):
    """Set a distributed watchpoint.

    Argument should be a list of C expressions.  This method will
    break each into a set of subexpressions that must be watched in
    order to detect any possible change to the overall expression's
    value.
    We then set a watchpoint for each subexpression, mapping any
    subsequent triggering back to the high-level distributed
    watchpoint, and resetting the internal watchpoints when
    necessary.
    """
    if not words:
        usage()
        return -1
    exps = join_false_whitespace( words )
    debug ("watching:", exps)
    subexps = set()
    try:
        for exp in exps:
            subexps |= find_subexps(exp)
        wp = WatchPoint( exps, subexps )
        set_watchpoint( wp )
    except FridayException, fe:
        error( "Caught exception:", fe )
    else:
        out( "Distributed watchpoint %d: %s"%(wp.index,wp.string))
    return wp.index

def add_breakpoint( words ):
    """Sets and remembers distributed breakpoint.

    Passes command through to GDB(s), remembering number and address.
    """
    spec = " ".join(words)
    debugf( "Setting breakpoint at '%s'", spec )
    bp = BreakPoint( spec )
    try:
	set_breakpoint( bp )
    except FridayException, fe:
	error( "Caught exception:", fe )
    else:
	out( "Distributed breakpoint %d: %s"%(bp.index, bp.string) )
    return True

def parse_index( words ):
    """Helper for enable() and disable().
    """
    if len(words) != 1:
        usage()
        return None
    index = int(words[0])
    if 0 <= index < len(_points):
        return _points[index]
    else:
        out( "Invalid break/watchpoint: %d"%index )
        return None

def enable( words ):
    """Disables a distributed watchpoint.

    Re-enables a WatchPoint set earlier with the 'watch' command.
    """
    point = parse_index( words )
    if point:
        if point.enabled:
            error( "Distributed %s %d already enabled."%(point.type_name,point.index ))
        else:
            out( "Re-enabling %s %d: %s"%(point.type_name,
                                          point.index,point.string))
            if isinstance( point, WatchPoint ):
                set_watchpoint( point )
            else:
                enable_breakpoint( point )
    return True

def disable( words ):
    """Disables a distributed watchpoint.

    Disables a WatchPoint set with the 'watch' command.
    The WatchPoint will remain in the list, so we could add a
    re-enable command later.
    """
    point = parse_index( words )
    if point:
        if not point.enabled:
            error( "Distributed %s %d already disabled."%(point.type_name,point.index ))
        else:
            out( "Disabling %s %d: %s"%(point.type_name,point.index,point.string)) 
            if isinstance( point, WatchPoint ):
                remove_watchpoint( point )
            else:
                disable_breakpoint( point )
    return True
    
def add_hook( words ):
    """Attaches a command script to be executed when a watchpoint is triggered."""
    point = None
    if words:
        if len(words) > 2:
            usage()
            return True
        else:
            try:
                point = _points[int(words[0])]                
            except (IndexError, ValueError), err:
                debug("Caught:", er )
                error( "Invalid break/watchpoint specifier: '%s'"%words[0])
    else:
        point = _points[-1]
    # We know the Break/WatchPoint we want.  Now read commands.
    try:
        point.command = read_and_compile_command()
    except FridayException, fe:
        error( "Caught exception:", fe )
    return True

def set_command( text ):
    """Like add_hook, but callable from within a hook."""
    debugf( "adding hook to %s: '%s'", _points[-1], text )
    try:
        _points[-1].command = read_and_compile_command( text.splitlines() )
    except FridayException, fe:
        error( "Caught exception:", fe )
    return True
