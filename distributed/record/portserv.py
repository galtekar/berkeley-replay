#!/usr/bin/env python
# Copyright (C) 2010 Regents of the University of California
# All rights reserved.
#
# Author: Gautam Altekar

import os, sys, socket, select, struct, time, uuid
sys.path.append(os.path.dirname(sys.argv[0])+"/../common")
import misc

_reg_sock = None
_query_sock = None
_reg_sock_list = []
_query_sock_list = []

# Should be sets
_reg_set = set()
_client_reg_map = {}
me = os.path.basename(sys.argv[0])
my_uuid = uuid.uuid4()

def out( *args ):
    print "(%s):\t"%me, " ".join(map( str, args ))

def usage():
    print( "USAGE: %s <reg_port> <rpc_port>"%sys.argv[0] )

def handle_reg_request( sock ):
   fd = sock.fileno()
   fmt_str = '!cccL'
   msg = misc.recvall( sock, struct.calcsize(fmt_str) )

   # The incoming message should be in network byte order, hence the
   # ! in the format string.
   (req_kind, family, protocol, port_addr_len) = struct.unpack( fmt_str, msg )
   #print "Waiting for <%s,%s,%s,%d> length port address"%(req_kind, family, protocol, port_addr_len)
   port_addr = misc.recvall( sock, port_addr_len )
   #print "Got port address:", port_addr

   tuple = (family, protocol, port_addr)

   was_success = False
   if req_kind == 'R':
      print "Registering:", tuple
      if fd not in _client_reg_map:
         _client_reg_map[fd] = set([tuple])
      else:
         if tuple in _client_reg_map[fd]:
            print "Warning:", tuple, "is already in set."
         else:
            _client_reg_map[fd].add(tuple)
      _reg_set.add(tuple)
      was_success = True
   elif req_kind == 'U':
      print "Unregistering:", tuple
      try:
         _reg_set.remove(tuple)
         was_success = True
      except KeyError:
         print "Port and protocol not registered:", tuple

      try:
         _client_reg_map[fd].remove(tuple)
         was_success = True
      except (KeyError, ValueError):
         print "Can't unregister before registering:", tuple
   else:
      print "Unsupported request kind", req_kind

   rep_msg = struct.pack( '!c', 'S' if was_success else 'F' )
   sock.sendall(rep_msg)

   print "Members:", _reg_set


def handle_query_request( sock ):
   fmt_str = '!c'
   msg = misc.recvall( sock, struct.calcsize(fmt_str) )
   (req_kind, ) = struct.unpack( fmt_str, msg )

   if req_kind == 'P':
      fmt_str = '!ccL'
      msg = misc.recvall( sock, struct.calcsize(fmt_str) )
      (family, protocol, port_addr_len) = struct.unpack( fmt_str, msg )
      #print "Got query: <%s,%s,%d>"%(family, protocol, port_addr_len)
      port_addr = misc.recvall( sock, port_addr_len )
      #print "Got port addr:", port_addr

      tuple = (family, protocol, port_addr)
      # Port query
      found = 'F'
      if tuple in _reg_set:
         found = 'T'

      print "Responding to query:", (tuple, found)

      rep_msg = struct.pack( '!c', found[0] ) 
      sock.sendall( rep_msg )
   elif req_kind == 'U':
      elapsed_time = int(time.time() - start_time)
      print "Responding to uptime query:", elapsed_time
      sock.sendall( "Portserv uptime resp: %s %s"%(str(elapsed_time), str(my_uuid)) )
   else:
      print "Unsupported request kind", req_kind

def server_setup( port ):
   # Listen on all interfaces
   host = ''
   sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
   sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
   sock.bind( (host, port) )
   sock.listen( 10 )
   return sock

def client_disconnect( sock ):
   fd = sock.fileno()
   if fd in _client_reg_map:
      for tuple in _client_reg_map[fd]:
         _reg_set.remove(tuple)
      del _client_reg_map[fd]

   if sock in _reg_sock_list:
      _reg_sock_list.remove( sock )
   elif sock in _query_sock_list:
      _query_sock_list.remove( sock )
   else:
      assert( 0 )

   print "Disconnected client", sock.getpeername()
   sock.close()


def start_work( reg_port, query_port ):
   _reg_sock = server_setup( reg_port )
   _query_sock = server_setup( query_port )
   assert( _reg_sock and _query_sock )

   print "Registration server started on port %d."%(reg_port)
   print "Query server started on port %d."%(query_port)
   while True:
      client_sock_list = _reg_sock_list + _query_sock_list
      socks_to_monitor = [ _reg_sock, _query_sock ] + client_sock_list
      (read_list, write_list, except_list) = \
            select.select( socks_to_monitor, [], client_sock_list )
      for sock in read_list:
         if sock == _reg_sock or sock == _query_sock:
            client_sock, client_addr = sock.accept()
            if sock == _reg_sock:
               print "Got vkernel client from", client_addr
               _reg_sock_list.append( client_sock )
            elif sock == _query_sock:
               print "Got query client from", client_addr
               _query_sock_list.append( client_sock )
         else:
            if sock in _reg_sock_list:
               try:
                  handle_reg_request( sock )
               except misc.SockDisconnectException:
                  client_disconnect( sock )
            elif sock in _query_sock_list:
               try:
                  handle_query_request( sock )
               except misc.SockDisconnectException:
                  client_disconnect( sock )
            else:
               assert( 0 )

      for sock in except_list:
         client_disconnect( sock )

######################################################################
# Main Script
#
if __name__ == "__main__":
   out( "*"*60 )
   out( "Running at", time.ctime())
   if len(sys.argv) != 3:
      usage()
      sys.exit(0)

   start_time = time.time()
   try:
      start_work(int(sys.argv[1]), int(sys.argv[2]))
   except KeyboardInterrupt:
      print "Shutting down."
      client_sock_list = _reg_sock_list + _query_sock_list
      for sock in client_sock_list:
         sock.close()
      #_reg_sock.close()
      #_query_sock.close()
      sys.exit(0)
