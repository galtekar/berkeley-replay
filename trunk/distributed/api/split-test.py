#!/usr/bin/env python2.5

"""
usage: split-test <formula dir>
"""

import os
import re
import sys
import getopt
import gdbm
import glob
import cPickle as pickle
import marshal
import split

from progressbar import *
from subprocess import *
from select import *
from collections import deque

def usage(code, msg=''):
   print __doc__
   if msg: print msg
   sys.exit(code)

def main():

   try:
      opts, args = getopt.getopt(sys.argv[1:], 'v',
            [
               'verify'])
   except getopt.error, msg:
      usage(2, msg)

   optVerify = 0
   for o, a in opts:
      if o in ('-v', '--verify'):
         optVerify = 1

   if len(args) == 0:
      usage('Must specify a directory containing formulas to split.')

   recordDir = args[0]

   if optVerify:
      VerifyDb(recordDir)
   else:
      split.split(recordDir)      


main()
