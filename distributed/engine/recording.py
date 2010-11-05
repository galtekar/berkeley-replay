#!/usr/bin/env python2.6
#
# author: Gautam Altekar
# $Id: replay_console.py,v 1.54 2006/10/04 04:10:31 galtekar Exp $
#
# vim:ts=4:sw=4:expandtab

import urlparse_custom, urlparse
import dfs
import ConfigParser

class Recording:
    def __init__( self, url ):
        self.url = url
        fs = dfs.urlopen( self.url )
        f = fs.open( self.url.path + "/rec.bdx" )

        config = ConfigParser.SafeConfigParser()
        config.readfp(f)
        self.uuid = config.get('main', 'session_id')
        self.node_uuid = config.get('main', 'node_id')
        self.vkernel_bin = config.get('main', 'vkernel_bin')
        f.close()

        assert(len(self.uuid) > 0)
        assert(len(self.node_uuid) > 0)
        assert(len(self.vkernel_bin) > 0)

    def __repr__( self ):
        return self.uuid
