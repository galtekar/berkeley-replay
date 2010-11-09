#pragma once

#include <map>
#include <list>

#include "sharedheap.h"
#include "vectorclock.h"
#include "pagetable.h"
#include "thread.h"

class Message : public VectorClock, public SharedHeap {
public:
   Message(VectorClock &rhs);
};

class Channel : public list<Message*, SharedHeapAllocator<Message*> >, public VectorClock, public SharedHeap {
public:
   Channel();

   void send(Message *msg);

   Message* receive();
};

const ADDRINT MAX_USER_ADDR = 0xC0000000; /* Linux kernel begins here */
class ChannelKey {
private:
   ADDRINT key;

public:

   ChannelKey(ADDRINT k, const bool isTid) {
      if (isTid) {
         /* Make sure the tid key doesn't conflict
          * with that of a mutex key. */
         k = MAX_USER_ADDR + k;
      }

      key = k;
   }

   bool operator<(const ChannelKey &rhs) const {
      return key < rhs.key;
   }

   operator ADDRINT() {
      return key;
   }
};

typedef vector<ChannelKey> ChannelKeyVec;

typedef pair<const ChannelKey, Channel*> ChannelPair;

class ChannelMap : public map<ChannelKey, Channel*, less<ChannelKey>, SharedHeapAllocator<ChannelPair> >, public SharedHeap {
public:

   Channel* lookupCreate(ChannelKey key);

   Channel* lookup(ChannelKey key);
};
