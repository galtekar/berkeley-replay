# author: Gautam Altekar
# $Id: debugger.py,v 1.18 2010/07/09 11:48:16 galtekar Exp $
#
# vim:ts=4:sw=4:expandtab

import re, select
import misc

_gdb_prompt = "(gdb) "	# Used by gdb mode and to parse gdb output
gdb_print_string_re = re.compile( r'"(?P<var>.*)"', re.DOTALL )
gdb_type_re = re.compile( r'type = (?P<type>.*)' )
gdb_bytes_re = re.compile( r'.*:(?P<bytes>.*)' )
gdb_print_bytes_re = re.compile( r'\$\d+ = {(?P<bytes>.*)}', re.DOTALL )
gdb_print_re = re.compile( r'\$\d+ = (?P<var>.*)', re.DOTALL )

class GnuDebugger:
    def __init__( self ):
        pass

    #############################
    # Private functions
    def _drain_app( self, pipe ):
        """Read everything from an application pipe."""
        while select.select( [pipe],[],[],0 )[0]:
            text = pipe.read()
            if not text:
                debug( " EOF! " * 8 )
                break
            for line in text.splitlines(True):
                print_in_color( line, _output_app )


    def _read_output( self, ctrl, action="print", wait_for_prompt=True, 
            child_pid=None, may_hit_breakpoint=True ):
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
            if misc.ECHO_DEBUG:
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
                if misc.ECHO_DEBUG: debug("*", color=_output_echo_debug )
                continue
            #output = remove_extra_warnings( output )
            # Check for end of output
            should_break = False
            if output.endswith( _gdb_prompt ):
                if action != "discard":
                    if misc.ECHO_DEBUG:
                        debugf("removing: '%s'", _gdb_prompt,
                               color=_output_echo_debug)
                    output = output[:0-len(_gdb_prompt)]
                should_break = True	# break out of select loop
            # Now deal with output text:
            if action == "print":
                print_in_color( output, _output_from_gdb )
            elif misc.ECHO_DEBUG:
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

    def _write_command( self, ctrl, s, child_pid=None ):
        """Feeds a string to gdb's stdin.

        If child_pid is None, the currently active child is called.
        Overriding this default is risky, because inactive children may be
          blocked in the application, limiting their actions."""
        debug( "to gdb(", child_pid, "):", s, color=_output_to_gdb )
        ctrl.gdb(child_pid).stdin.write(s)
        if s[-1:] != "\n":
            ctrl.gdb(child_pid).stdin.write("\n")
        ctrl.gdb(child_pid).stdin.flush()


    def _call_gdb( self, ctrl, cmd, child=None, action="print",
              may_hit_breakpoint=True ):
        "Passes a command to gdb."
        write_command( ctrl, cmd, child )
        text, ignore = read_output( ctrl, action=action, child_pid=child,
                                    may_hit_breakpoint=may_hit_breakpoint )
        return text

    #############################
    # Public functions
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
