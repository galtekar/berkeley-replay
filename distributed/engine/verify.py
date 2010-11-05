#!/usr/bin/env python2.5

"""
usage: verify <formula dir>
"""

import os
import re
import sys
import getopt
import gdbm
import glob
import cPickle as pickle
import marshal
import dbhash as bsddb
import time
import numpy

from progressbar import *
from subprocess import *
from select import *
from collections import deque
from operator import itemgetter



patStpInvalid = re.compile("Invalid.")

def solveWork(formula):
   cmdStr = "stp -p"
   #print cmdStr

   p = Popen(cmdStr, stdout=PIPE, stdin=PIPE, stderr=PIPE, shell=True)
   try:
      p.stdin.writelines(formula)
      p.stdin.close()
      outData = p.stdout.read()
      p.wait()

      #print outData

      match = patStpInvalid.search(outData)
      if not match:
         print outData
         return False
   except KeyboardInterrupt:
      p.kill()
      p.wait()
      return False
   

   return True


def solveComponents(compList, formDb):
   print "Solving all", len(formDb), "sub-formula(s)."

   timeMap = {}


   widgets = ['Solve:', Percentage(), ' ', Bar(marker=RotatingMarker()), ' ']
   pbar = ProgressBar(widgets=widgets, maxval=len(formDb)).start()
   i = 0
   for k in compList:
      v = formDb[k]
      startTime = time.time()
      solveSuccess = solveWork(v + "QUERY(FALSE);")
      endTime = time.time()

      runTime = endTime-startTime

      if not solveSuccess:
         print "Formula for component", k, "failed:"
         f = open("failed-" + k, 'w')
         f.write(v)
         f.close()
         #print v
         #sys.exit(-1)
      else:
         timeMap[k] = runTime

      i = i + 1
      pbar.update(i)
   pbar.finish()


   return timeMap

def showSolveStats(timeMap):

   timeList = timeMap.values()
   #sortedTimes = sorted(timeMap.values())

   print "Solving time stats:"
   print "Min:", min(timeList), " Max:", max(timeList), " Median:", numpy.median(timeList), " Avg:", numpy.mean(timeList), " Var:", numpy.var(timeList)




def checkConsistency(varDb, formDb):

   print "VarDB has", len(varDb), "entries."
   print "FormDB has", len(formDb), "entries."

   widgets = ['Cross-Check:', Percentage(), ' ', Bar(marker=RotatingMarker()), ' ']
   pbar = ProgressBar(widgets=widgets, maxval=len(varDb)).start()
   i = 0
   for k, v in varDb.iteritems():
      if v in formDb:
         i = i + 1
      else:
         print "Inconsistency: component", v, "not found in FormDB."
         sys.exit(-1)
      pbar.update(i)
   pbar.finish()


def listComponents(formDb, isDescending):
   lenMap = {}

   for k, v in formDb.iteritems():
      if v not in lenMap:
         lenMap[k] = len(v)

   print "Total of", len(lenMap), "component(s)."
   
   return sorted(lenMap.iteritems(), key=itemgetter(1), reverse=isDescending)

def printComponent(compNr, formDb):
   k = str(compNr)

   if k in formDb:
      print formDb[k] + "QUERY(FALSE);"
   else:
      print "Component", k, "not found."



def usage(code, msg=''):
   print __doc__
   if msg: print msg
   sys.exit(code)

def main():
   try:
      opts, args = getopt.getopt(sys.argv[1:], 'd:',
            ["--dir="])
   except getopt.error, msg:
      usage(2, msg)

   for o, a in opts:
      if o in ("-d", "--dir"):
         recordDir = a
         #if o in ("-l", "--list"):
      else:
         assert False, "unhandled option"

   #if len(args) != 2:
   #   usage('Must specify a directory containing formula DBs.')

   cmd = args[0]

   formPath = recordDir + "/comp-subform.bdb"
   varPath = recordDir + "/var-comp.bdb"

   formDb = bsddb.hashopen(formPath, 'r')
   varDb = bsddb.hashopen(varPath, 'r')

   if cmd == "list":
      print listComponents(formDb, True)
   if cmd == "print":
      printComponent(args[1], formDb)
   elif cmd == "check":
      checkConsistency(varDb, formDb)
   elif cmd == "solve-all":
      #print listComponents(formDb, False)
      timeMap = solveComponents(formDb.keys(), formDb)
      showSolveStats(timeMap)
      pickle.dump(timeMap, open('solve-times.pkl', 'wb'))


   formDb.close()
   varDb.close()

if __name__ == "__main__":
   main()
