#! /usr/bin/env python

"""Invoke it to toggle whether data read from network is considered sensitive or not. 
     Default dir for recordings is /tmp/bdr-X where X is username; if this is not directory, pass -dir parameter
     session-id is compulsory parameter following the options
   './lt-sensitive.py [-dir|d path-to-recordings] [-begin|-b] session-id'   to mark beginning of sensitive data 
   './lt-sensitive.py [-dir|d path-to-recordings] [-end|-e]   session-id'   to mark end of sensitive data  
"""

import cStringIO
import getopt
import os
import random
import re
import sys
import subprocess
import time
import traceback
import warnings
import tempfile
import socket
from struct import *
import glob
import shutil
import commands

def usage(code, msg=''):
   print __doc__
   if msg: print msg
   sys.exit(code)

def getbrcnt(s):
   statusreq = pack('i', 0)
   s.send(statusreq)
   data = s.recv(8)
   (brCnt,) = unpack('Q', data)
   return brCnt

def connect_to_vkernel(session_sock,begin_or_end):

   try:
      time.sleep(1)
      print "Connecting to vkernel at ", session_sock
      s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
      s.connect(session_sock)
      s.settimeout(5)

      print "successfully connected socket"

      lastbrcnt = -1
      cnt = 0
      while (cnt<10):
          time.sleep(1)
          brcnt = getbrcnt(s)
          print "brcnt =", brcnt
          #if brcnt == lastbrcnt:
          #   break
          lastbrcnt = brcnt
          cnt = cnt+1    

   except socket.error, msg:
      print msg

   s.close()


def main(session_id="",dir="", begin_or_end=0):

   dir = "/tmp/bdr-" + commands.getoutput("whoami") + "/"

   try:
      opts, args = getopt.getopt(sys.argv[1:], 'd:be',
            [
               'dir',
               'begin',
               'end'])
   except getopt.error, msg:
      usage(2, msg)

   for o, a in opts:
      if o in ('-d', '--dir'):
         dir = a
      if o in ('-b', '--begin'):
         begin_or_end = 0
      if o in ('-e', '--end'):
         begin_or_end = 1;

   if len(args) == 0:
      usage('Must specify session-id to connect to.')

   session_id = args[0];
   vsock_file = dir + session_id + "/vk.sock";

   print "input: vsock_file " , vsock_file , " begin_or_end " , begin_or_end  
   connect_to_vkernel(vsock_file,begin_or_end);

   sys.exit(0);


main()
