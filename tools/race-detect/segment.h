#pragma once

#include <set>
#include <map>

#include "sharedheap.h"
#include "vectorclock.h"
#include "misc.h"

typedef set<ADDRINT> AddrSet;

typedef struct AccessStruct {
   ulong pc;
   ulong ecx;
   ulong brCnt;
   THREADID tid;
   ADDRINT vaddr;
} Access;

typedef pair<const ADDRINT, Access> AccessPair;

/* Must be on the shared heap, since a thread needs to compare accesses in 
 * his segment with accesses in others. */
class AccessMap : public multimap<ADDRINT, Access, less<ADDRINT>, SharedHeapAllocator<AccessPair> >, public SharedHeap {
};

class Segment;
typedef vector<Segment *> SegmentVec;
class Segment : public VectorClock, public SharedHeap {
private:
      AccessMap readMap, writeMap;

      void intersection(const AccessMap &m1, const AccessMap &m2, 
                        AddrSet &outSet) const;

      void printAccessVec(const ADDRINT addr, const AccessMap &m, int raceType, int accessType) const;

      void printRaces(const AddrSet &raceSet, const AccessMap &m1, 
                      const AccessMap &m2, int raceType) const;

      void racesWith(const Segment &rhs) const;

public:
      Segment(ThreadId _id);

      /* Segment's should not be copied! It will copy the
       * access map as well!. */
      Segment(const Segment &rhs);

      ~Segment();

#if 0
      virtual void update(const VectorClock &rhs);

      virtual void advance();
#endif

      void addRead(ADDRINT addr, Access &a);

      void addWrite(ADDRINT addr, Access &a);

      /* XXX: SegmentVec --> vector<VectorClock*> */
      void racesWith(SegmentVec &rhsVec) const;
};
