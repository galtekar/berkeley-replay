# vim:ts=4:sw=4:expandtab

import urlparse

protocols = [ "hdfs", "ssh" ]
urlparse.uses_netloc.extend( protocols )
urlparse.uses_relative.extend( protocols )
