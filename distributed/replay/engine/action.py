# author: Gautam Altekar
# $Id: probe.py,v 1.18 2010/07/09 11:48:16 galtekar Exp $
#
# vim:ts=4:sw=4:expandtab

import sys, re, traceback
import __main__, misc

##### Constants
#_stop_cmd_re = re.compile( r'c(o(nt?)?)?($|\s)' )
_stop_cmd_re = re.compile( r'stop($|\s)' )

##### Globals
_action_locals = {}

# Detects string types.
_string_type_re = re.compile( r'char\s*\*' )
# Detects some integer types.
_integer_type_re = re.compile( r'(u_?)?(int(8|16|32|64)?|long)(_?t)?' )
# Detects pointer types.
_pointer_type_re = re.compile( r'\*[\)\s]*$' )

##### Exceptions
class ActionException(Exception):
    pass

class InputException(ActionException):
    "Raised if user request is invalid."

class ParseException(ActionException):
    "Raised if input is unparseable."
    pass

class ShouldStopException(ActionException):
    "Raised by compiled action scripts if they want to continue execution."
    pass


##### Classes
class ProbeAction:
    """Simple (code,flags) struct."""
    def __init__(self,code,flags):
        self.code = code
        self.flags = flags

class byte_tuple_t(tuple):
    """Simple set of integers.  Prints as large hex."""
    def __repr__(self):
        return "(" + " ".join( ["%.2x"%n for n in self]) + ")"

##### Functions
def get_value( task, expr ):
    """Extracts state from a replay process.
    Currently assumes everything is an integer.
    """
    misc.debug( "get_value:", task, expr )
    # Interpolate any python variables in the action script.
    vars = globals().copy()
    vars.update( _action_locals )
    misc.debugf( "Interpolating expr '%s'", expr)
    expr = expr%vars
    misc.debugf( "Final expr: '%s'", expr )
	 
    # It would be nice if we could handle arbitrary types.  For now,
    # be sure to handle strings and integer types (assume latter).
    type = task.debugger.get_type( ctrl, expr )
    misc.debug( "type:", type )
    value = None
    if _string_type_re.search( type ):
        value = task.debugger.get_string( ctrl, expr )
    elif _integer_type_re.match( type ):
        value = task.debugger.get_long( ctrl, expr )
    elif _pointer_type_re.match( type ):
        value = task.debugger.get_long( ctrl, expr )
    else:
        value = byte_tuple_t(task.debugger.get_as_bytes( ctrl, expr ))
    return value

def parse_state_ref( string ):
    """Parses a reference of the form @[<task_index>](<expression>).

    Returns the task_index, expression, and reference string length,
    or raises a ParseException.
    """
    misc.debug( "parse_state_ref", string )
    assert string.startswith( '@' )
    left_p = string.find( '(' )
    if left_p < 1:
        raise ParseException( "Invalid reference: '%s'"%string)
    task_index = string[1:left_p]
    exp_len = find_closing_char( string[left_p:], '(', ')' )
    end = left_p+exp_len
    exp = string[left_p+1:end-1]
    misc.debug( "parsed:", task_index, exp, end )
    return (task_index, exp, end)

def interpolate_line( line ):
    """Replaces references to application state with accessor functions.
    """
    misc.debug( "interpolating:", line )
    line = _stop_cmd_re.sub( "raise ShouldStopException", line )
    for str in [ "__VCLOCK__", "__LOGICALCLOCK__" ]:
        line = line.replace( str, "__TASK__.ctrl.get_vclock()" )
    while True:
        start = line.find( '@' )
        if start >= 0:
            task_index, exp, len = parse_state_ref( line[start:] )
            if not task_index:
                task_varname = "__TASK__"
            elif re.match( "\d+", task_index ):
                task_varname = "group._master.replay_tasks[%s]"%task_index
            if -1 < exp.find("="):
                # Assignment not permitted
                raise ParseException( "Assignment not permitted" )
            else:
                line = line.replace(line[start:start+len],
                                    'get_value(%s,"%s")'%(task_varname,exp))
        else:
            break
    misc.debug( "final:", line )    
    return line

def read_and_compile( input=[] ):
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
        misc.debugf( "read: '%s'", line )
        if line.strip() == "end":
            break
        elif (not lines) and (line.strip() in ("silent","safe")):
            # flags must be at start of action script
            flags.add( line.strip() )
        else:
            lines.append(interpolate_line(line))
    all = "\n".join(lines + [ "\n" ]) # ensure newline after last line
    misc.debugf( "compiling '%s'", all )
    try:
        code = compile( all, "<console>", "exec" )
    except SyntaxError, se:
        raise InputException( str(se) )
    misc.debug( "flags:", flags )
    return ProbeAction( code, flags )

def file_print( *args, **kwargs ):
    string = ' '.join( map(str, args) )
    sys.stdout.write("cool")
    

def run( pr, event ):
    """Run the action attached to a break/watchpoint.
    Returns False iff the code raised a ShouldStopException.
    """

    # Keep going even if there is hit, unless the action explicitly tells
    # us to stop
    should_continue = True
    if pr.action_func:
        pr.action_func(event.task, event)
    elif pr.action:
        # XXX: needs to be fixed
        assert(0)
        # galtekar: Allows handler to get info about the watchpoint
        # it is stopped on. Useful for retrieving aux info associated
        # with the watchpoint index.
        action_globals = globals()
        #action_globals["current_probe"] = pr

        _action_locals.update(pr.action_locals)
        #print action_globals
        #assert("print" in action_globals.keys())
        #action_globals["print"] = file_print
        #del action_globals["print"]
        #del _action_locals["print"]
        #print "AFTER:", action_globals
        try:
            exec pr.action.code in action_globals, _action_locals
        except ShouldStopException, sce:
            misc.debug( "caught stop exception" )
            should_continue = False
        except Exception, e:
            misc.error( "Caught exception in user-provided action:", e )
            misc.error( traceback.format_exc() )
    return should_continue
