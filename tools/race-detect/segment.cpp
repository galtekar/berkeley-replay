#include "segment.h"
#include "misc.h"

#include "debug.h"
#include "raceinfo.h"
#include "syncops.h"
#include "fdops.h"

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

SHAREDAREA struct SynchLock raceTableLock;
//SHAREDAREA char * raceFilePos = NULL;
SHAREDAREA int raceFd = -1;

void Segment::intersection(const AccessMap &m1, const AccessMap &m2, AddrSet &outSet) const {
   AddrSet s1, s2;

   AccessMap::const_iterator it, it_end;

   for (it = m1.begin(); it != m1.end(); it++) {
      s1.insert(it->first);
   }

   for (it = m2.begin(); it != m2.end(); it++) {
      s2.insert(it->first);
   }

   set_intersection(s1.begin(), s1.end(), s2.begin(), s2.end(),
         insert_iterator<AddrSet>(outSet, outSet.begin())
         );
}


void Segment::printAccessVec(const ADDRINT addr, const AccessMap &m, 
      int raceType, int accessType) const {

   pair<AccessMap::const_iterator, AccessMap::const_iterator> ret;
   AccessMap::const_iterator it;
   char buf[2048], *bufPtr;
   INT32 column, line;
   string name;

   ret = m.equal_range(addr);
   for (it = ret.first; it != ret.second; it++) {
      Race r;
      Access a = it->second;
      bufPtr = use_xed(a.pc, buf, sizeof(buf));
      column = line = 0;
      PIN_LockClient();
      PIN_GetSourceLocation(a.pc, &column, &line, &name);
      PIN_UnlockClient();

      ASSERT(bufPtr);
      DLOG("%d: EIP: 0x%8.8lx ECX: 0x%8.8lx BRCNT: %8lu INS: %30s -- %3.3d:%3.3d:%30s\n", a.tid, a.pc, a.ecx, a.brCnt, bufPtr,
            line, column, name.c_str());

      r.raceType = raceType;
      r.accessType = accessType;
      r.tid = a.tid;
      r.eip = a.pc;
      r.ecx = a.ecx;
      r.brCnt = a.brCnt;

      int res = safe_write(raceFd, &r, sizeof(r));
      ASSERT(res != -1);
   }
}

void Segment::printRaces(const AddrSet &raceSet, const AccessMap &m1, 
      const AccessMap &m2, int raceType) const {

   AddrSet::const_iterator it;

   for (it = raceSet.begin(); it != raceSet.end(); it++) {

      DLOG("Address: 0x%x\n", *it);

      printAccessVec(*it, m1, raceType, 
            (raceType == RACE_RAW) ? RACE_READ : RACE_WRITE);
      printAccessVec(*it, m2, raceType, RACE_WRITE);
   }
}

void Segment::racesWith(const Segment &rhs) const {
   AddrSet raw, war, waw;

   Synch_Lock(&raceTableLock);

   /* RAW */
   intersection(readMap, rhs.writeMap, raw);
   printRaces(raw, readMap, rhs.writeMap, RACE_RAW);

   /* WAR */
   intersection(writeMap, rhs.readMap, war);
   printRaces(war, rhs.readMap, writeMap, RACE_RAW);

   /* WAW */
   intersection(writeMap, rhs.writeMap, waw);
   printRaces(waw, writeMap, rhs.writeMap, RACE_WAW);

   Synch_Unlock(&raceTableLock);
}

#if 0
void Segment::update(const VectorClock &rhs) {
   VectorClock::update(rhs);

#if 0
   DLOG("Updated to: %s\n", toStr().c_str());
#endif
}


void Segment::advance() {
   VectorClock::advance();

#if 0
   DLOG("Advanced to: %s\n", toStr().c_str());
#endif
}
#endif


Segment::Segment(ThreadId _id) : VectorClock(_id) {
}

Segment::~Segment() {
   /* No need to readMap.clear() amd writeMap.clear() --
    * their destructors should take care of it. */
}

void Segment::addRead(ADDRINT addr, Access &a) {
   readMap.insert(pair<ADDRINT, Access>(addr, a));
}

void Segment::addWrite(ADDRINT addr, Access &a) {
   writeMap.insert(pair<ADDRINT, Access>(addr, a));
}

void Segment::racesWith(SegmentVec &rhsVec) const {
   SegmentVec::const_iterator it;

   DLOG("Computing races.\n");
   for (it = rhsVec.begin(); it != rhsVec.end(); it++) {
#if 0
      DLOG("%s || %s\n", this->toStr().c_str(),
            (**it).toStr().c_str());
#endif
      Segment *segPtr = *it;

      ASSERT(segPtr);

      /* rhsVec should only contain parallel segments. */
      ASSERT(*this || *segPtr);
      this->racesWith(*segPtr);
   }
}

void
Segment_Init()
{
#if 0
#define RACE_FILE_SIZE (1 << 20)
#endif
   char fileStr[] = "/tmp/races";
   int fd;
#if 0
   int res, dummy = 0;
#endif

   raceFd = fd = open(fileStr,
         O_RDWR | O_CREAT, S_IWUSR | S_IRUSR);
   if (fd == -1) {
      FATAL("Can't open race file ``%s''.\n", fileStr);
   }

#if 0
   res = lseek(fd, RACE_FILE_SIZE-sizeof(dummy), SEEK_SET);
   res = write(fd, &dummy, sizeof(dummy));
   ASSERT(res == sizeof(dummy));


   int prot = PROT_READ | PROT_WRITE;

   void *mmapres = (void*)mmap(NULL, RACE_FILE_SIZE+PAGE_SIZE, prot, MAP_SHARED, fd, 0);
   DEBUG_MSG(5, "Race file: fd=%d start=0x%x\n", fd, mmapres);
   ASSERT(mmapres != MAP_FAILED);

   char *guardPage = (char*)mmapres + RACE_FILE_SIZE;
   int mprotres = mprotect(guardPage, PAGE_SIZE, PROT_NONE);
   ASSERT(mprotres == 0);

   raceFilePos = (char*)mmapres;
#endif

   Synch_LockInit(&raceTableLock);
}
