#include <sstream>

#include "vectorclock.h"

#include "debug.h"

VectorClock::VectorClock(ThreadId _id) {
   id = _id;
   reset();
}

VectorClock::VectorClock(const VectorClock &rhs) {
   id = rhs.id;
   reset();
   update(rhs);
}

LogicalClock VectorClock::operator[](const int index) const {
   ASSERT(index < MAX_THREADS);

   return vc[index];
}

void VectorClock::reset() {
   for (int k = 0; k < MAX_THREADS; k++) {
      vc[k] = 0;
   }
}

/*
 * O(n) vector clock update.
 */
void VectorClock::update(const VectorClock &rhs) {

   /* Careful: don't copy rhs's id as well. That would
    * make this a copy operation rather than an
    * update operation. */

   for (int k = 0; k < MAX_THREADS; k++) {
      vc[k] = MAX(vc[k], rhs.vc[k]);
   }
}

void VectorClock::advance() {
   vc[id]++;
   ASSERT(vc[id] > 0);
}

ThreadId VectorClock::getId() const {
   return id;
}

/* Happens-before operator. */
bool VectorClock::operator<<(const VectorClock& rhs) const {
   bool strictlyLess = false;

   for (int k = 0; k < MAX_THREADS; k++) {

      if (rhs.vc[k] < vc[k]) {
         return false;
      }

      if (rhs.vc[k] > vc[k]) {
         strictlyLess = true;
      }
   }

   return strictlyLess;
}

bool VectorClock::operator>>(const VectorClock& rhs) const {
   return (rhs << *this);
}

/* isParallelWith (could be equal) */
bool VectorClock::operator|(const VectorClock &rhs) const {
   return !(*this << rhs) && !(rhs << *this);
}

/* isStrictlyParallelWith */
bool VectorClock::operator||(const VectorClock &rhs) const {
   return (*this | rhs) && (*this != rhs);
}

bool VectorClock::operator==(const VectorClock &rhs) const {

   for (int k = 0; k < MAX_THREADS; k++) {

      if (vc[k] != rhs.vc[k]) {
         return false;
      }
   }

   return true;
}

bool VectorClock::operator!=(const VectorClock &rhs) const {
   return !(*this == rhs);
}

/* Must be totally ordered for comparators to work
 * properly -- use thread id to break ties. */
bool VectorClock::operator<(const VectorClock& rhs) const {
   if (*this || rhs) {
      return (this->id < rhs.id);
   }

   return *this << rhs;
}

void VectorClock::minimize(const VectorClock& rhs) {
   for (int k = 0; k < MAX_THREADS; k++) {
      vc[k] = MIN(vc[k], rhs.vc[k]);
   }
}

string VectorClock::toStr() const {
   stringstream out;

   out << id << ".(";
   int k;
   for (k = 0; k < MAX_THREADS-1; k++) {
      out << vc[k] << ",";
   }
   out << vc[k] << ")";

   return out.str();
}

MaxVectorClock::MaxVectorClock() : VectorClock(0) {
   for (int k = 0; k < MAX_THREADS; k++) {
      vc[k] = UINT_MAX;
   }
}
