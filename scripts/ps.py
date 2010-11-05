#! /usr/bin/env python

"""Path selection.
Usage: path-select [OPTIONS] <BIN>

Command line options:

-s,--session-dir=<PATH>       where to dump/find recording
"""

import subprocess
import os
import shutil
import glob
import tempfile
import sys
import getopt
import time

appcmd = "/bin/sh"
vkbin="/home/galtekar/src/logreplay/trunk/vkernel/vk-dbg"

rd_config_str = """
analysis:
{
   enabled = true;

   stage = 0;

   # Stage 0.
   race_detection:
   {
      memtrace_only = false;
   };
};

execution:
{
   mode = 1;
   de_enabled = false;
   //de_enabled = true;

   direct_execution :
   {
   };

   binary_translation :
   {
      # Self-modifying code check: 0=none  1=check stack  2=check all
      smc_check = 1;
   };
};

debug:
{
   segments:
   {
      by_task_id = (
            { id = 0; /* use default level */ }
            );
   };
};
"""

taint_config_str = """
analysis:
{
   enabled = true;

   stage = 1;

   # Stage 0.
   race_detection:
   {
   };

   # Stage 1.
   formula_generation:
   {
      # 0 = none, 1 = file, 2 = all loads, 3 = all loads from shared memory
      origin_src = 1;
   };
};

execution:
{
   mode = 1;
   de_enabled = false;

   direct_execution :
   {
   };

   binary_translation :
   {
      # Self-modifying code check: 0=none  1=check stack  2=check all
      smc_check = 0;
   };
};

debug:
{
   segments:
   {
      by_task_id = (
            { id = 0; /* use default level */ }
            );
   };
};
"""


def replay(sessiondir, config_str):

   f = tempfile.NamedTemporaryFile(delete=False)
   f.write(config_str)
   f.flush()
   #time.sleep(1000)
   print "Config file: ", f.name
   print config_str


   cmdlist = [vkbin, "--config-file=" + f.name,
         "--session-dir=%s"%(sessiondir),
         "--debug=%d"%(5),
         ] + appcmd.split()

   retcode = subprocess.call(cmdlist)
   f.close()

   return retcode


def create_rd_check_str(id, rtb):

   if rtb:
      (tid, eip, ecx, brcnt) = rtb
   else:
      # start logging at beginning
      (tid, eip, ecx, brcnt) = (0, 0, 0, 0)

   ep_str = "(%d, 0x%x, 0x%x, %lu)"%(tid, eip, ecx, brcnt)

   check_str = """
         check : 
         {
            id = %d;
            start_logging_at = %s;

            branches :
            {
               enforce_branches = true;
               flip_at = %s;
            };
         };
   """%(id, ep_str, ep_str)

   return check_str


def copy_previous_check_logs(sessiondir, id):
   previous_check_logs = glob.glob(sessiondir + "/vcpu-check-%d.*"%(id-1))
   for log in previous_check_logs:
      suffix = log.split('.')[-1]
      shutil.copy(log, sessiondir + "/vcpu-check-%d.%s"%(id, suffix))


def replay_rd(sessiondir, id, rtb):

   if id != 0:
      copy_previous_check_logs(sessiondir, id)

   check_str = create_rd_check_str(id, rtb)

   return replay(sessiondir, rd_config_str+check_str)


def create_taint_check_str(id):
   check_str = """
      check : 
      {
         # 0xFFFFFFFF means don't log at all, just replay
         start_logging_at = (0, 0xFFFFFFFF, 0, 0);

         branches :
         {
            id = %d;
            enforce_branches = true;
         };
      };
      """%(id)

   return check_str


def compute_rtb_set(sessiondir, id):
   check_str = create_taint_check_str(id)

   replay(sessiondir, taint_config_str+check_str)

   # XXX: gather the tainted branches and return them
   # as a list of execution-point tuples.
   return []


def path_select(sessiondir, id=0, rtb=None):

   print "path_select: starting depth %d"%(id)

   retcode = replay_rd(sessiondir, id, rtb)

   if retcode == 0:
      return id
   elif retcode == 1:
      rtb_set = compute_rtb_set(sessiondir, id)
      for rtb in rtb_set:
         id_prime = path_select(sessiondir, id+1, rtb)
         if id_prime:
            return id_prime

      return None
   else:
      print "path_select: error, retcode=%d"%(retcode)
      sys.exit(3)


def usage(code, msg=''):
   print __doc__
   if msg: print msg
   sys.exit(code)


def main(sessiondir="/tmp/replay-session"):

   try:
      opts, args = getopt.getopt(sys.argv[1:], 's:', ['session-dir'])
   except getopt.error, msg:
      usage(2, msg)

   for o, a in opts:
      if o in ('-s', '--session-dir'):
         sessiondir = a


   #if len(args) == 0:
   #   usage("Must specify vkernel binary to use.")


   old_check_logs = glob.glob(sessiondir + "/vcpu-check*")
   for log in old_check_logs:
      os.remove(log)

   id = path_select(sessiondir)

   print "finished: id=%d"%(id)

main()
