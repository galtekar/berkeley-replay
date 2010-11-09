#! /usr/bin/env python3

"""Regression testing.
Usage: test [OPTIONS] ... <actfile> <bdr-binary>

Command line options:

-b: basedir    -- top-level dir to place per-session logs
-f: fromfile   -- read names of tests to run from a file
-o: outdir     -- directory to place regression test files
"""

import io
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
from string import Template

flagMonitorActivity = 1
flagRemoveSuccessfulRuns = 1
flagPutInSubdir = 1

vkbin = "bin/bdr-dbg"

def usage(code, msg=''):
   print(__doc__)
   if msg: print(msg)
   sys.exit(code)

def count(n, word):
   if n == 1:
      return "%d %s" % (n, word)
   else:
      return "%d %ss" % (n, word)

def printlist(x):
   for item in x:
      print(item)

def nukedir(top):
   try:
      for root, dirs, files in os.walk(top, topdown=False):
         for name in files:
            os.remove(os.path.join(root, name))
         for name in dirs:
            os.rmdir(os.path.join(root, name))

      os.rmdir(top)
   except:
      pass

def getbrcnt(s):
   statusreq = pack('i', 0)
   s.send(statusreq)
   print("Awaiting reply...")
   data = s.recv(8)
   (brCnt,) = unpack('Q', data)

   return brCnt

def monitor_activity(p, sessiondir):
   sessionsock = sessiondir+"/bdr.sock"

   try:
      time.sleep(1)
      print("Connecting to BDR at ", sessionsock)
      s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
      s.connect(sessionsock)
      s.settimeout(5)

      lastbrcnt = 0
      while not p.poll():
         time.sleep(1)
         brcnt = getbrcnt(s)
         print("brcnt =", brcnt)
         if brcnt == lastbrcnt:
            return False
         lastbrcnt = brcnt

   except socket.error as msg:
      print(msg)

   s.close()

   return True


def runscene(sceneid, testcmd, scene, sessiondir, dbglvl):

   t = Template(scene)
   cmdstr = t.substitute(cmd=testcmd, sessiondir=sessiondir)

   print("Scene", cmdstr)

   if flagMonitorActivity:
      serverstr = "server -w"
   else:
      serverstr = "server"

   #cmdlist = ["/usr/bin/gdb", "--eval-command=run", "--args", vkbin, serverstr, cmdstr]
   cmdlist = [vkbin, serverstr, cmdstr]

   print(cmdlist)

   p = subprocess.Popen(cmdlist)

   if flagMonitorActivity:
      if monitor_activity(p, sessiondir) == False:
         # Child doesn't seem to be making any progress.
         p.kill()

   retcode = p.wait()

   # Careful: we may accidentally nuke unrelated tasks
   # XXX: try searching for the session directory instead ...
   #subprocess.call(["killall -9 -r -w log: rep:"], shell=True)

   return retcode


def runact(tstid, test, act, outdir):
   print("Act", act)

   if flagPutInSubdir:
      sessiondir = tempfile.mkdtemp(dir=outdir, prefix="%d-"%(tstid))
   else:
      sessiondir = outdir

   failure = False
   scenecount = 0

   for scene in act:
      if failure:
         break

      dbglvl = 0
      while True:
         retcode = runscene(scenecount, test, scene, sessiondir, dbglvl)
   
         if retcode != 0:
            print(test, "at", sessiondir, "failed.\n")
            if dbglvl == 5 or True:
               failure = True
               break
            else:
               # XXX: if logging fails, then retry won't work.
               # Must get rid of original log file first.
               print("Trying agin with full debugging info.")
               dbglvl = 5
         else:
            break
      scenecount = scenecount + 1

   if not failure and flagRemoveSuccessfulRuns:
      nukedir(sessiondir)

   return failure



def runtest(tstid, testcmd, actlist, outdir):

   print("---------------------------------------------------------------------")
   print("Test", testcmd)
   print("---------------------------------------------------------------------")

   #olddir = os.path.abspath(os.curdir)
   #os.chdir(testdir)

   failure = []

   for act in actlist:
      failure = runact(tstid, testcmd, act, outdir)

      if failure:
         print(testcmd, "act", act, "failed.")

   #os.chdir(olddir)

   return failure


def init_python_tests(tests):
   pydir = "../python-2.6.1"
   testfile = pydir + "/gtests"

   fp = open(testfile)
   for line in fp:
      if not line[0] == '#':
         tests.append((pydir, "/usr/local/bin/python " + line.strip()))

   fp.close()

def init_acts(actfile):

   actlist = []
   act = []
   fp = open(actfile)
   for line in fp:
      if len(line) == 0:
         if len(act):
            actlist.append(act)
            act = []
      elif not line[0] == '#':
         act.append(line.strip())

   if len(act):
      actlist.append(act)
   fp.close()

   return actlist

def init_tests(testfile):

   list = []

   if testfile:
      fp = open(testfile)
   else:
      fp = sys.stdin

   for line in fp:
      if not line[0] == '#':
         list.append(line.strip())
   fp.close()

   return list


def main(tests=None, actfile=None, fromfile=None, outdir="/tmp/bdr-galtekar/regress"):
   global vkbin, flagPutInSubdir

   try:
      opts, args = getopt.getopt(sys.argv[1:], 'f:o:b:',
            [
               'basedir',
               'fromfile',
               'outdir'])
   except getopt.error as msg:
      usage(2, msg)

   for o, a in opts:
      if o in ('-f', '--fromfile'):
         fromfile = a
      if o in ('-o', '--outdir'):
         outdir = a
         flagPutInSubdir = 0
      if o in ('-b', '--basedir'):
         outdir = a

   if len(args) != 2:
      usage('regrtest: invalid usage')

   actfile = args[0]
   vkbin = args[1]

   tests = init_tests(fromfile)
   actlist = init_acts(actfile)

   outdir = os.path.abspath(outdir)
   nukedir(outdir)
   os.mkdir(outdir)
   #shutil.copy2(vkbin, outdir)

   good = []
   bad = []
   testcnt = 0


   for testcmd in tests:
      try:
         failure = runtest(testcnt, testcmd, actlist, outdir)
         testcnt = testcnt + 1
      except KeyboardInterrupt:
         print()
         break
      except:
         raise

      if failure:
         bad.append(testcmd)
      else:
         good.append(testcmd)

   good.sort()
   bad.sort()

   if good:
      if len(bad) == 0 and len(good) > 0:
         print("All", count(len(good), "test(s)"), "OK.")

   if bad:
      print(count(len(bad), "test(s)"), "failed:")
      printlist(bad)

   sys.exit(len(bad) > 0)


main()
