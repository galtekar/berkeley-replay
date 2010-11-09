#!/usr/bin/env python2.5

import os
import re
import sys
import getopt
import glob

from subprocess import *
from os.path import join

def RunCmd(cmdStr, envMap, f):

   p = Popen(cmdStr, stdout=f, stdin=PIPE, stderr=f, shell=True, env=envMap)
   try:
      p.wait()
   except KeyboardInterrupt:
      p.kill()
      p.wait()
      return


def DoRecord(dirBenchRoot, dirResults):

   for root, dirs, files in os.walk(dirBenchRoot):
      if "run.sh" in files:
         print root
         compList = root.split("/")
         strAppName = compList[-2]
         strJobName = compList[-1]

         envMap = {}
         resultsDir = join(join(dirResults, strAppName), strJobName)
         envMap["RECORD_BASEDIR"] = resultsDir
         envMap["RECORD_CMD"] = os.environ["DCR_BIN"] + " --mod=Record,DRec --opts=Sys.Env.Inherit=1;Sys.Debug.Level=0;Record.MaxRate=max;Sys.Classifier.UseAnnotations=0"
         print envMap

         if not os.path.exists(resultsDir):
            os.mkdir(resultsDir)
         f = open(join(resultsDir,"log"), "w+")
         RunCmd(root + "/run.sh", envMap, f)
         f.close()

def DoReplay(dirResults):
   for root, dirs, files in os.walk(dirResults):
      if "saved-env" in files:
         cmdStr = os.environ["DCR_BIN"] + "--modules=Replay,DCGen --opts=Sys.Debug.Level=0;Record.Classifier.UseAnnotations=1;DCGen.OutputFormula=false;DCGen.AssumeUnknown=data -- " + root

         RunCmd(cmdStr, None)




def __main__():
   #dirBenchRoot = os.path.join(os.environ["LOGREPLAY_ROOT"], "bench")

   targetDir = "./jobs"
   DoRecord(targetDir, join(os.getcwd(), "results"))

   #DoReplay(os.path.join(os.getcwd(), "results"))

__main__()
