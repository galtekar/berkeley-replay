# vim:ts=4:sw=4:expandtab

import os, subprocess, shutil
import urlparse_custom, urlparse
import misc
        
hadoop_bin = "/home/galtekar/src/hadoop-0.20.1/bin/hadoop"


def start_child( command, quiet=True ):
    "Runs the command in a subprocess."
    #print command
    if quiet:
        child = subprocess.Popen( command, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE )
    else:
        child = subprocess.Popen( command )
    return child

class File:
    pass

class LocalFile(File):
    def __init__( self, path ):
        self.file = open( path, "r" )

    def __del__( self ):
        self.file.close()

    def read( self ):
        return self.file.read()

    def readline( self ):
        return self.file.readline()

    def close( self ):
        self.file.close()

class HdfsFile(File):
    def __init__( self, child ):
        self.child = child

    def __del__( self ):
        self.close()

    def read( self ):
        return self.child.stdout.read()
    
    def readline( self ):
        return self.child.stdout.readline()

    def close( self ):
        try:
            self.child.kill()
        except OSError:
            pass

        self.child.wait()

class FsException(Exception):
    pass

class Fs:
    def __init__( self ):
        pass


class Hdfs(Fs):
    def __init__( self, hostname, port ):
        Fs.__init__( self )
        if "hdfs" not in urlparse.uses_netloc:
            urlparse.uses_netloc.append("hdfs")
        if "hdfs" not in urlparse.uses_relative:
            urlparse.uses_relative.append("hdfs")

        if not hostname:
            raise Exception, "Invalid hostname"
        self.hostname = hostname

        if port:
            self.port = port
        else:
            self.port = 9000

        self.url = urlparse.urlparse( "hdfs://%s:%d/"%(self.hostname,\
            self.port) )

        assert( self.url.scheme == "hdfs" )
        assert( self.url.port == self.port )

    def _get_url_path( self, path ):
        return urlparse.urljoin( self.url.geturl(), path )

    def _dfs_cmd( self, arg_list ):
        return start_child( [ hadoop_bin, "fs" ] + arg_list )

    def _dfs_cmd_wait( self, arg_list ):
        child = self._dfs_cmd( arg_list )
        child.wait()
        return child

    def get( self, dst_path, src_path ):
        assert( 0 )

    def put( self, dst_path, src_path ):
        child = self._dfs_cmd_wait( [ "-copyFromLocal", src_path,\
                    self._get_url_path( dst_path ) ] )
        if child.returncode == 0:
            return
        else:
            raise Exception, "Upload failed"

    def mkdir( self, path ):
        child = self._dfs_cmd_wait( [ "-mkdir", \
                self._get_url_path( path ) ] )
        if child.returncode == 0:
            return
        else:
            raise Exception, "Mkdir failed"
        
    def test( self, path ):
        child = self._dfs_cmd_wait( [ "-test", "-e",
            "%s"%(self._get_url_path( path) ) ] )
        return child.returncode == 0

    def open( self, path ):
        child = self._dfs_cmd( [ "-cat", "%s"%( \
            self._get_url_path( path ) ) ] )
        return HdfsFile( child )

    def list( self, path ):
        child = self._dfs_cmd_wait( [ "-ls", \
            "%s"%( self._get_url_path( path ) ) ] )
        #print "returncode:",child.returncode
        if child.returncode == 0:
            list_str = child.stdout.read()
            entry_list = list_str.split('\n')
            res_list = []
            for entry_str in entry_list:
                columns = entry_str.split()
                if len(columns) == 8:
                    res_list.append((columns[0], os.path.basename(columns[-1])))
            return res_list
        else:
            raise Exception, "List failed"
        return

    def listdirs( self, path ):
        return [ name for (perms, name) in self.list( path ) \
                if perms[0] == 'd' ]

class LocalFs(Fs):
    def __init__( self ):
        Fs.__init__( self )

    def open( self, path ):
        return LocalFile( path )

    def put( self, dst_path, src_path ):
        shutil.copytree( src_path, dst_path )

    def list( self, path ):
        try: 
            os.listdir( path )
        except:
            raise FsException("Cannot list dir")

    def listdirs( self, path ):
        res = []
        try:
            dir_list = os.listdir( path )
        except:
            raise FsException("Cannot list dir")

        for entry in dir_list:
            misc.debug( "entry:", path + entry )
            if os.path.isdir( path + entry ):
                res.append( entry )
        return res

#class SshFs(Fs):
#    def __init__( self, hostname, port ):
#        Fs.__init__( self )
#        self.hostname = hostname
#        self.port = port
#
#    def _ssh_cmd( self, arg_list ):
#        return start_child( [ ssh_bin ] + arg_list )
#
#    def _ssh_cmd_wait( self, arg_list ):
#        child = self._ssh_cmd( arg_list )
#        child.wait()
#        return child
#
#    def open( self, path )
#        return SshFile( path )
#
#    def put( self, dst_path, src_path ):
#        assert( 0 )
#        child = self._ssh_cmd_wait( [ src_path, "%s:%s" ] )
#        if child.returncode == 0:
#            return
#        else:
#            raise Exception, "Upload failed"


def urlopen( url ):
    if url.scheme == 'file':
        return LocalFs( )
    elif url.scheme == 'hdfs':
        return Hdfs( url.hostname, url.port )
    else:
        raise FsException('unsupported url scheme')
