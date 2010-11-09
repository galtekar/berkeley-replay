import matplotlib
import timing, os
import pickle, re

from pylab import *

class MispredictStats:
   def __init__(self):
      self.totalBytesList = []
      self.condMpList = []
      self.btbMpList = []
      self.rsbMpList = []

class ExecClass:
   def __init__(self):
      self.bareTimes = []
      self.noInstrTimes = []
      self.btbTimes = []
      self.btbRsbTimes = []
      self.btbMp = MispredictStats()
      self.btbRsbMp = MispredictStats()

execHash = {}

def saveData(execObj, filename):
   output = open(filename, 'wb')

   pickle.dump(execObj, output)

   output.close()


def loadData(fileList):
   global execHash

   for filename in fileList:
      input = open(filename, 'rb')

      execObj = pickle.load(input)

      input.close()

      execHash[filename] = execObj


def fileSize(filename):
   statinfo = os.stat(filename)

   return statinfo.st_size

totalBytesRe = re.compile(r'totalBytes=(?P<num>\d+)')
condMpRe = re.compile(r'condMispredicts=(?P<num>\d+)')
btbMpRe = re.compile(r'btbMispredicts=(?P<num>\d+)')
rsbMpRe = re.compile(r'rsbMispredicts=(?P<num>\d+)')
def readStats(statGroup):
   f = open("out.bin", 'rb')
   lines = f.readlines()
   f.close()

   mTotalBytes = None
   mCondMp = None
   mBtbMp = None
   mRsbMp = None
   for line in lines:
      if not mTotalBytes:
         mTotalBytes = totalBytesRe.search(line)
      if not mCondMp:
         mCondMp = condMpRe.search(line)
      if not mBtbMp:
         mBtbMp = btbMpRe.search(line)
      if not mRsbMp:
         mRsbMp = rsbMpRe.search(line)

   if not mTotalBytes:
      return 0

   assert(mCondMp and mBtbMp and mRsbMp)
   statGroup.totalBytesList.append(int(mTotalBytes.group("num")))
   statGroup.condMpList.append(int(mCondMp.group("num")))
   statGroup.btbMpList.append(int(mBtbMp.group("num")))
   statGroup.rsbMpList.append(int(mRsbMp.group("num")))

   return 1

def timingRun(execStr, cleanupStr, outputFilename):
   ex = ExecClass()
   desRuns = 1

   print "execStr:", execStr

   # Bare
   nRuns = 0
   while nRuns < desRuns:
      os.system(cleanupStr)
      timing.start()
      os.system(execStr);
      timing.finish()
      ex.bareTimes.append(float(timing.milli()) / 1000)
      nRuns = nRuns + 1
   print "."



   # Noinst
   nRuns = 0
   while nRuns < desRuns:
      os.system(cleanupStr)
      timing.start()
      os.system("pin -mt -t /home/galtekar/src/pin-2.0-10520-gcc.4.0.0-ia32-linux/Tests/noinstrum -- " + execStr);
      timing.finish()
      ex.noInstrTimes.append(float(timing.milli()) / 1000)
      nRuns = nRuns + 1
   print "."

   # BTB
   nRuns = 0
   while nRuns < desRuns:
      os.system(cleanupStr)
      timing.start()
      os.system("pin -mt -t /home/galtekar/src/pin-2.0-10520-gcc.4.0.0-ia32-linux/Tests/2lev_btb -- " + execStr);
      timing.finish()
      if fileSize("out.bin") != 0:
         ex.btbTimes.append(float(timing.milli()) / 1000)
         nRuns = nRuns + 1
   print "."

   # BTB stats
   nRuns = 0
   while nRuns < 1:
      os.system(cleanupStr)
      timing.start()
      os.system("pin -mt -t /home/galtekar/src/pin-2.0-10520-gcc.4.0.0-ia32-linux/Tests/2lev_btb_stats -- " + execStr);
      timing.finish()
      if readStats(ex.btbMp):
         nRuns = nRuns + 1
   print "."

   # BTB+RSB
   nRuns = 0
   while nRuns < desRuns:
      os.system(cleanupStr)
      timing.start()
      os.system("pin -mt -t /home/galtekar/src/pin-2.0-10520-gcc.4.0.0-ia32-linux/Tests/2lev_btb_rsb -- " + execStr);
      timing.finish()
      if fileSize("out.bin") != 0:
         ex.btbRsbTimes.append(float(timing.milli()) / 1000)
         nRuns = nRuns + 1
   print "."

   # BTB+RSB stats
   nRuns = 0
   while nRuns < 1:
      os.system(cleanupStr)
      timing.start()
      os.system("pin -mt -t /home/galtekar/src/pin-2.0-10520-gcc.4.0.0-ia32-linux/Tests/2lev_btb_rsb_stats -- " + execStr);
      timing.finish()
      if readStats(ex.btbRsbMp):
         nRuns = nRuns + 1
   print "."

   saveData(ex, outputFilename)


def generateData():
   gimpExecStr = "gimp -i -b '(batch-unsharp-mask \"*.jpg\" 5.0 0.5 0)' -b '(gimp-quit 0)'"

   #timingRun("ls", "killall ls; rm out.bin", "ls.pkl")
   #timingRun("ps", "killall ps; rm out.bin", "ps.pkl")
   #timingRun(gimpExecStr, "killall gimp; rm out.bin", "gimp.pkl")
   #timingRun("scp -r i3.millennium.berkeley.edu:/work/matei /tmp", "killall scp; rm out.bin", "scp.pkl")
   #timingRun("bzip2 -f -k ~/tmp.tar", "killall bzip2; rm ~/tmp.tar.bz2; rm out.bin", "bzip2.pkl")
   timingRun("tar -cf tmp.tar /tmp", "killall tar; rm tmp.tar; rm out.bin", "tar.pkl")


def generateGraph():
   global execHash

   N = len(execHash.keys())

   bareTimes = []
   noInstrTimes = []
   btbTimes = []
   btbRsbTimes = []

   for (key, ex) in execHash.items():
      norm = mean(ex.noInstrTimes)
      bareTimes.append(mean(ex.bareTimes) / norm)
      noInstrTimes.append(mean(ex.noInstrTimes) / norm)
      btbTimes.append(mean(ex.btbTimes) / norm)
      btbRsbTimes.append(mean(ex.btbRsbTimes) / norm)

   # Graph - Int/Unint Runtimes
   barList = []
   ind = arange(N)
   width = 0.1
   colors = ['r', 'g', 'y', 'c']
   for (c, times) in [('r', bareTimes), ('g', noInstrTimes), ('y', btbTimes), ('c', btbRsbTimes)]:
      yoff = array([0] * N)
      b = bar(ind, times, width, bottom=yoff, color=c)

      ind = ind + width
      barList.append(b[0])

   title('Branch-Tracing Overhead vs. Application')
   xlabel('Application')
   ylabel('Normalized Execution Slowdown (x)')
   xticks(arange(N)+width+0.1, ("Gimp", "ps", "ls"))
   xlim(-width, len(arange(N)))
   legend(barList, ('Native', 'Pin', 'Pin 2-lvl BTB', 'Pin 2-lvl BTB+RSB'), loc=2, shadow=True)
   show()

   condBytes = []
   btbBytes = []
   rsbBytes = []
   for (key, ex) in execHash.items():
      condBytes.append(mean(ex.btbMp.condMpList) * 4 / 1000000)
      btbBytes.append(mean(ex.btbMp.btbMpList) * 8 / 1000000)
      rsbBytes.append(mean(ex.btbMp.rsbMpList) * 8/ 1000000)
   btbTuple = (condBytes, btbBytes, rsbBytes)

   condBytes2 = []
   btbBytes2 = []
   rsbBytes2 = []
   for (key, ex) in execHash.items():
      condBytes2.append(mean(ex.btbRsbMp.condMpList) * 4 / 1000000)
      btbBytes2.append(mean(ex.btbRsbMp.btbMpList) * 8 / 1000000)
      rsbBytes2.append(mean(ex.btbRsbMp.rsbMpList) * 8 / 1000000)
   btbRsbTuple = (condBytes2, btbBytes2, rsbBytes2)

   # Graph - Log sizes
   barList = []
   ind = arange(N)
   width = 0.1
   colors = ['r', 'g', 'y']
   for tuple in [btbTuple, btbRsbTuple]:
      print tuple
      (condBytesV, btbBytesV, rsbBytesV) = tuple
      yoff = array([0] * N)
      b = bar(ind, condBytesV, width, bottom=yoff, color='r')
      barList.append(b[0])
      yoff = yoff + condBytesV
      b = bar(ind, btbBytesV, width, bottom=yoff, color='g')
      barList.append(b[0])
      yoff = yoff + btbBytesV
      b = bar(ind, rsbBytesV, width, bottom=yoff, color='b')
      barList.append(b[0])

      ind = ind + width

   title('Log Size vs. Application')
   xlabel('Application')
   ylabel('Log Size (MB)')
   xticks(arange(N)+width, ("Gimp", "ps", "ls"))
   xlim(-width, len(arange(N)))
   legend(barList, ('Conditional Mispredicts', 'BTB Mispredicts', 'RSB Mispredicts'), loc=2, shadow=True)
   show()

assert(len(sys.argv) == 2)

# figure out if user wants to load/generate data
if sys.argv[1] == "data":
   generateData()
elif sys.argv[1] == "graph":
   loadData(["gimp.pkl", "ps.pkl", "ls.pkl"])
   generateGraph()
else:
   print "Unrecognized command."
