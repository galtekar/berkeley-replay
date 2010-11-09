#pragma once

#include <map>

#include "sharedheap.h"
#include "misc.h"

typedef uint LogicalClock;

/* XXX: not all dynamically allocated vector clocks belong on the shared heap... */
class VectorClock {
protected:
   LogicalClock vc[MAX_THREADS];
   ThreadId id;

public:
   VectorClock(ThreadId _id);

   VectorClock(const VectorClock &rhs);

   virtual ~VectorClock() { }

   LogicalClock operator[](const int index) const;

   void reset();

   /*
    * O(n) vector clock update.
    */
   virtual void update(const VectorClock &rhs);

   virtual void advance();

   ThreadId getId() const;

   bool operator<<(const VectorClock &rhs) const;

   bool operator>>(const VectorClock &rhs) const;

   /* isParallelWith (could be equal) */
   bool operator|(const VectorClock &rhs) const;

   /* isStrictlyParallelWith */
   bool operator||(const VectorClock &rhs) const;

   bool operator==(const VectorClock &rhs) const;

   bool operator!=(const VectorClock &rhs) const;

   /* Must be totally ordered for comparators to work
    * properly -- use thread id to break ties. */
   bool operator<(const VectorClock &rhs) const;

   /* Replaces vc with component-wise minimum
    * of it and rhs. */
   void minimize(const VectorClock &rhs);

   string toStr() const;
};

class MaxVectorClock : public VectorClock {
public:
   MaxVectorClock();
};
