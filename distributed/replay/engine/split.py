#!/usr/bin/env python2.6
#
# author: Gautam Altekar
# $Id: split.py,v 1.54 2006/10/04 04:10:31 galtekar Exp $
#
# vim:ts=4:sw=4:expandtab

"""
Usage: split <recording>
"""

import os, re, sys, getopt, glob, marshal, dbhash, misc
import cPickle as pickle

from progressbar import *
from subprocess import *
from select import *
from collections import deque
from cStringIO import StringIO


#cvPat = re.compile('(CV\w+|AV\w+|JV\w+|LV\w+|TV\w+|OV\w+|BC\w+|ParTab\w*)')
cvPat = re.compile('(CVv|AVv|JVv|LVv|TVv|OVv|BCv|ParTab)\w+')
defPat = re.compile('(.*BITVECTOR.*)|(.*BOOLEAN.*)')
assertPat = re.compile('ASSERT')



def DumpMap(map, fileName):
   marshal.dump(map, open(fileName, 'wb'))

def LoadMap(fileName):
   return marshal.load(open(fileName, 'rb'))


def ConnectNodes(adjMap, a, b):
   #print "Connecting", a.var, "and", b.var

   if a in adjMap:
      adjMap[a].add(b)
   else:
      adjMap[a] = set([b])

   if b in adjMap:
      adjMap[b].add(a)
   else:
      adjMap[b] = set([a])


def CreateGraph(formFile):
   widgets = ['Graph:', Percentage(), ' ', Bar(marker=RotatingMarker()), ' ']
   pbar = ProgressBar(widgets=widgets, maxval=os.path.getsize(formFile)).start()

   adjMap = {}
   f = open(formFile, 'r')
   for line in f:
      m = assertPat.match(line)
      if m:
         #print line

         count = 0
         for m in cvPat.finditer(line):
            nodeName = m.group()
            if count == 0:
               lhsName = nodeName
            else:
               rhsName = nodeName

               #print lhsName, rhsName
               # Graph is undirected, so we need to cover both dirs
               ConnectNodes(adjMap, lhsName, rhsName)

            count = count + 1
         assert(count > 0)
      pbar.update(f.tell())
   f.close()
   pbar.finish()

   misc.out("Loaded ", len(adjMap), " nodes.")

   return adjMap

# Does DFS, but iteratively on a heap allocated stack -- avoids
# the stack overflow problem.
def LabelComponentIter(adjMap, stack, nr, varMap):
   while len(stack) > 0:
      nodeName = stack.pop()

      if nodeName in varMap:
         # already visited and labeled
         # XXX: should we ever reach here?
         continue
      else:
         varMap[nodeName] = nr
         for neighborName in adjMap[nodeName]:
            stack.append(neighborName)



def FindConnectedComponents(adjMap):
   widgets = ['Components:', Percentage(), ' ', Bar(marker=RotatingMarker()), ' ']
   pbar = ProgressBar(widgets=widgets, maxval=len(adjMap)+1).start()

   varMap = {}
   nr = 0
   count = 0
   for nodeName in adjMap:
      #print count
      if nodeName not in varMap:
         # Hasn't been visited yet, so fill all connected components.
         nr = nr + 1
         #print nr
         #print adjMap[node]
         #LabelComponentRec(adjMap, node, nr)

         LabelComponentIter(adjMap, [ nodeName ], nr, varMap)
     
      count = count + 1
      pbar.update(count)
   pbar.finish()

   return nr, varMap


def generate_subformulas_work(varMap, formFileName, db):
   widgets = ['Split:', Percentage(), ' ', Bar(marker=RotatingMarker()), ' ']
   pbar = ProgressBar(widgets=widgets, maxval=os.path.getsize(formFileName)).start()

   formMap = {}

   f = open(formFileName, 'r')
   for line in f:
      #print line
      if line[0] == '%':
         continue

      var = None
      for m in cvPat.finditer(line):
         var = m.group()
         #print id(map[var])
         break;

      if not var: # empty line
         continue

      if var not in varMap:
         # unused variable
         misc.out("Warning: unused variable", var)
         continue

      compNr = varMap[var]
      assert(compNr > 0)

      if 1:
         if 0:
            if compNr in formMap:
               # String concat is slow, so we switched to append -- much
               # faster.
               formMap[compNr].append(line)
            else:
               formMap[compNr] = [line]
         elif 1:
            # StringIO() is supposed to be even faster for concats.
            if compNr in formMap:
               formMap[compNr].write(line)
            else:
               formMap[compNr] = StringIO()
               formMap[compNr].write(line)
         else:
            # This is slow as hell, especially when the db gets large
            if str(compNr) in db:
               db[str(compNr)] = db[str(compNr)] + line
            else:
               db[str(compNr)] = line


      pbar.update(f.tell())
   f.close()

   pbar.finish()

   return formMap

def generate_subformulas(record_dir):
   formDb = dbhash.open(record_dir + "/comp-subform.db", 'c')
   varDb = dbhash.open(record_dir + "/var-comp.db", 'c')

   for fileName in sorted(glob.iglob(record_dir + "/*.dc")):
      misc.out("Splitting", fileName)
      varMap = LoadMap(fileName + ".pkl")
      formMap = generate_subformulas_work(varMap, fileName, formDb)
      misc.out("Split into", len(formMap), "formula(s), writing...")

      for k, v in varMap.iteritems():
         strK = str(k)
         varDb[strK] = str(v)

      # Write the formMap to the DB, so that our debugger module can
      # look it up later.
      for k, v in formMap.iteritems():
         if str(k) not in formDb:
            #formDb[str(k)] = ''.join(v)
            formDb[str(k)] = v.getvalue()
         else:
            formDb[str(k)] = formDb[str(k)] + v.getvalue()

   formDb.close()
   varDb.close()



def Map(record_dir):

   idx = 0
   for fileName in sorted(glob.iglob(record_dir + "/*.dc")):
      misc.out("Processing", fileName)
      adjMap = CreateGraph(fileName)

      nr, varMap = FindConnectedComponents(adjMap)
      misc.out("Found", nr, "components, saving...")
      pklName = fileName + ".pkl"
      DumpMap(varMap, pklName)
      idx = idx + 1


def RelabelComponents(varMap, compNr, compMap, id):

   for nodeName in varMap:
      nr = varMap[nodeName]
      if (id, nr) in compMap:
         varMap[nodeName] = compMap[(id, nr)]
      else:
         varMap[nodeName] = compNr
         # Make sure other nodes in the same component get the same nr
         compMap[(id, nr)] = compNr
         compNr = compNr + 1

   return compNr


def RelabelFileList(fileList, compNr, compMap, id):

   for fileName in fileList:
      varMap = LoadMap(fileName)
      compNr = RelabelComponents(varMap, compNr, compMap, id)
      #print varMap
      DumpMap(varMap, fileName)

   return compNr



def BuildComponentGraph(fileList1, fileList2):
   compGraph = {}

   for fileName1 in fileList1:
      varMap1 = LoadMap(fileName1)
      for fileName2 in fileList2:
         varMap2 = LoadMap(fileName2)
         
         for key in varMap1:
            if key in varMap2:
               a = varMap1[key]
               b = varMap2[key]

               ConnectNodes(compGraph, (1,a), (2,b))


   return compGraph

def Merge(fileList1, fileList2):
   compGraph = BuildComponentGraph(fileList1, fileList2)

   if len(compGraph):
      nr, compMap = FindConnectedComponents(compGraph)
      #print compMap
   else:
      nr = 0
      compMap = {}

   misc.out("Found", nr, "mergeable component(s).")

   nrCmps = RelabelFileList(fileList1, nr+1, compMap, 1)
   nrCmps = RelabelFileList(fileList2, nrCmps, compMap, 2)
   misc.out("Merge resulted in", nrCmps-1, "component(s).")

   l = []
   l.extend(fileList1)
   l.extend(fileList2)
   return l

def Reduce(record_dir):

   stack = []
   for fileName in sorted(glob.iglob(record_dir + "*.dc")):
      stack.append([fileName + ".pkl"])

   while len(stack) > 1:
      print stack
      fileList1 = stack.pop()
      fileList2 = stack.pop()

      misc.out("Merging", fileList1, "and", fileList2)
      mergedFileList = Merge(fileList1, fileList2)
      stack.append(mergedFileList)

   return True

def compute_components(record_dir):
   Map(record_dir)
   Reduce(record_dir)

def split(record_dir):
   compute_components(record_dir)
   generate_subformulas(record_dir)

   return True

def usage(code, msg=''):
   print __doc__
   if msg: print msg
   sys.exit(code)


if __name__ == "__main__":
   misc.log( "Berkeley Deterministic Replay: Formula Splitter" )
   misc.log( "Copyright 2005-2010 University of California. All rights reserved." )
   try:
      opts, args = getopt.getopt(sys.argv[1:], 'v', ['verify'])
   except getopt.error, msg:
      usage(2, msg)
   opt_verify = 0
   for o, a in opts:
      if o in ('-v', '--verify'):
         opt_verify = 1

   if len(args) != 1:
      misc.die('Must specify a directory containing formulas to split.')

   record_dir = args[0]
   split( record_dir )
