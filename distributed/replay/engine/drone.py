#!/usr/bin/env python2.6
#
# Copyright (C) 2010 Regents of the University of California
# All rights reserved.
#
# Author: Gautam Altekar
#
# vim:ts=4:sw=4:expandtab

from SimpleXMLRPCServer import SimpleXMLRPCServer
import xmlrpclib
import os, urlparse_custom, urlparse
import misc, socket, sys, getopt, dfs, formdb, recording

env = os.environ
_cache_base_dir = misc.app_base_dir + "/replay-cache/"
my_name = os.path.basename(sys.argv[0])
_db_map = {}


#def get_uuid( path ):
#    f = open(path + "/uuid", "r")
#    uuid_str = f.readline()
#    f.close()
#    misc.debug( "uuid:", uuid_str )
#    return uuid_str.strip()


def cache_recording( rec_uuid, home_url_str ):
    if not os.path.exists(_cache_base_dir):
        os.makedirs(_cache_base_dir)

    cache_manifest_list = os.listdir(_cache_base_dir)
    cache_dir = _cache_base_dir + rec_uuid
    misc.debug( cache_manifest_list, rec_uuid )

    if rec_uuid not in cache_manifest_list:
        assert(len(cache_dir) > 0)
        misc.debug("cache_dir:", cache_dir, "url_str:", home_url_str)
        home_url = urlparse.urlparse(home_url_str)
        misc.debug( "src:", home_url.path, "link: ", cache_dir )

        # No need to download if it's local
        should_download_rec = True
        try:
            local_dir = 'file:/%s'%(home_url.path)
            print local_dir
            rec = recording.Recording( urlparse.urlparse(local_dir) )
            if rec.uuid == rec_uuid:
                should_download_rec = False
                # Just symlink to the recording dir
                if home_url.path != cache_dir:
                    os.symlink(home_url.path, cache_dir)
        except:
            pass

        if should_download_rec == True:
            fs = dfs.urlopen(home_url)
            fs.get(cache_dir, home_url)

    assert(cache_dir)
    return cache_dir

def lookup_var( rec_uuid_str, var_name_list ):
    misc.debug("Lookup var(%s, %s)"%(rec_uuid_str, var_name_list))
    if rec_uuid_str not in _db_map:
        db = formdb.FormDB(rec_uuid_str)
        _db_map[rec_uuid_str] = db
    else:
        db = _db_map[rec_uuid_str]

    return db.lookup_list(var_name_list)

def ping():
    print "Got ping."
    return True


def usage():
    print "Usage: %s [options]"%(my_name)

def read_args():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "d", \
                ["--debug"])
    except getopt.GetoptError, ge:
        misc.die( "Option error: " + str(ge) )

    for opt, arg in opts:
        if opt in ("-d", "--debug"):
            misc.DEBUG = True
#        else:
#            usage()
#            sys.exit(-1)
    return

def read_config():
    pref = misc.load_preferences("replay", None)
    if not pref:
        misc.die("ERROR: Problem with configuration files\n")

if __name__ == "__main__":
    read_args()
    read_config()

    # For testing...
    if False:
        loc = "1d585c2a-8920-4cfd-af7b-42e74363bdd8"
        print lookup_var( loc, "COOL" )
        sys.exit(0)

    server = SimpleXMLRPCServer(("localhost", 8000))
    misc.log ("Listening on port 8000...")
    server.register_function(cache_recording, "cache_recording")
    server.register_function(ping, "ping")
    server.register_function(lookup_var, "lookup_var")

    server.serve_forever()
