# vim:ts=4:sw=4:expandtab

import os, sys, fcntl, subprocess, time, re, ConfigParser

# Globals
LOG_OUTPUT = True
DEBUG = False
ECHO_DEBUG = False
VERBOSE_DEBUG = False
QUIET = True

unknowns = "data"

exe_path = os.path.dirname(sys.argv[0])
my_name = os.path.basename(sys.argv[0])
app_base_dir = "/tmp/bdr-" + os.environ["USER"]
_config_parser = None
_section_name = None

def out( *args, **kwargs ):
    """Prints and logs notable output.
    Calls through to main colorized output functions."""
    string = ' '.join( map( str, args ) )
    print( string )

def log( *args, **kwargs ):
    """Prints and logs notable output.
    Calls through to main colorized output functions."""

    if QUIET == False:
        string = my_name + ": " + ' '.join( map( str, args ) )
        print( string )

def die( *args, **kwargs ):
    string = my_name + ": " + ' '.join( map( str, args ) )
    print( string )
    sys.exit(-1)

def debug( *args, **kwargs ):
    """Prints and logs debug output.
    
    Calls through to main colorized output functions."""
    if DEBUG:
        string = " ".join( map( str, args ) )
        print( string )

def debugf( *args, **kwargs ):
    """Prints and logs debug output (format string version).    
    
    Calls through to main colorized output functions."""
    if DEBUG:
        string = args[0]%args[1:]
        print( string )

def error( *args ):
    """Prints an error message.

    Calls through to main colorized output functions."""
    string = " ".join( map( str, args ) )    
    print( string )

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

def make_non_blocking( fd ):
    "fcntl wrapper"
    flags = fcntl.fcntl( fd, fcntl.F_GETFL )
    fcntl.fcntl( fd, fcntl.F_SETFL, (flags|os.O_NDELAY) )


def start_child( command, should_block=True, out_file=subprocess.PIPE ):
    "Runs the command in a subprocess."
    debug( "Starting", command )
    assert(out_file)
    child = subprocess.Popen( command, stdin=subprocess.PIPE,
                          stdout=out_file,
                          stderr=out_file )
    if should_block == False:
        make_non_blocking( child.stdout.fileno() )
        make_non_blocking( child.stderr.fileno() )
    debug( "subprocess", child, child.pid )
    return child

def abspath( p ):
    "Returns an absolute version of path p."
    return os.path.abspath(os.path.expanduser(p))

#####
# Added config file support:
def load_preferences( section_name, default_prefs=None ):
    """Reads in the configuration files. 
    Reads 'bdr.cfg', '.bdrrc', and '~/.bdrrc',
    with the the first occurrence of duplicate keys overriding any
    later ones.  It then reads the protocol-specific configuration
    file, determined by the 'protocol' variable.
    """
    global _config_parser
    global _section_name

    _section_name = section_name
    _config_parser = ConfigParser.SafeConfigParser()
    # Put defaults into "main", rather than as ConfigParser defaults,
    # because we want to be able to detect when an option is overridden: 
    _config_parser.add_section("main")
    _config_parser.add_section(section_name)
    if default_prefs:
        for opt,val in default_prefs.items():
            _config_parser.set(section_name,opt,val)
    script_path = os.path.dirname(sys.argv[0])
    read_one = False
    for cfg in [abspath("~/.bdrrc"),".bdrrc",script_path+"/bdr.cfg",exe_path+"/../conf/bdr.cfg" ]:
        read_list = _config_parser.read( [cfg] )
        if len(read_list) > 0:
            read_one = True
            break
    if not read_one:
        die("Missing config file.")

    #if ((not _config_parser.has_option(section_name, "remote_user")) and
    #    ("USER" in os.environ)):
    #    _config_parser.set("replay","remote_user",os.environ["USER"])
    debug( "Preferences:", _config_parser.items(section_name))
    return _config_parser

def get_conf( name, host=None ):
    """Reads a config file variable.

    If "host" is set, this method searches for a matching section name
    before falling back to default value."""
    global _config_parser
    
    assert( _config_parser )
    matching_sections = set()
    if host:
        for section in _config_parser.sections():
            # TODO: quote "."?
            if re.match( section, host ):
                matching_sections.add( section )
    # Check all matching sections, starting with longest name.
    #   This will approximate a "most specific" regex order.
    #   Could also try ignoring regex syntactic variables, or parsing
    #    out section name clues (like hostname dots).
    for section in sorted( matching_sections,
                          key=lambda n: -1*len(n) ):
        if VERBOSE_DEBUG: debugf( "looking for %s in %s", name, section )
        if _config_parser.has_option( section, name ):
            return _config_parser.get( section, name )
    else:
        # Fall back on default section, and if that fails, "main"
        if VERBOSE_DEBUG: debug( "looking for default", name )
        try:
            return _config_parser.get( _section_name, name )
        except ConfigParser.NoOptionError:
            return _config_parser.get( "main", name )


class SockDisconnectException(Exception):
    pass

def recvall( sock_obj, num_bytes ):
    data = ""

    while len( data ) < num_bytes:
        #debug( len( data ), "of total", num_bytes, "received" )
        tmp_data = sock_obj.recv( num_bytes - len( data ) )
        if not tmp_data:
            raise SockDisconnectException
        data += tmp_data
    #debug( "got all", num_bytes, "bytes" )
    return data

def find_file(filename, search_path):
    """Given a search path, find file
    """
    paths = search_path.split(os.pathsep)
    #print paths
    for path in paths:
        abspath = os.path.join(path, filename)
        #print "Testing for:", abspath
        if os.path.exists(abspath):
            return os.path.abspath(abspath)
            break
    return None


#def is_known_control( rec_name ):
#    #print rec_name
#    if ( rec_name.find("chunk") != -1 or rec_name.find("cptokfs") != -1 ):
#        #print "DCGEN:", DCGEN
#        return DCGEN
#    else:
#        return False
#
