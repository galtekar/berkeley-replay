#include "channel.h"

#include "debug.h"

Message::Message(VectorClock &rhs) : VectorClock(rhs) {
}

void Channel::send(Message *msg) {
#if 0
   DLOG("Sending: %s\n", msg->toStr().c_str());
#endif
   /* Update the channel's VC. */
   update(*msg);

   push_back(msg);
}

Message* Channel::receive() {
   Message *frontMsg = NULL;

   if (size() > 0) {
      frontMsg = front();
#if 0
      DLOG("Received: %s from %d\n", frontMsg->toStr().c_str(),
            frontMsg->getId());
#endif
      pop_front();
   }

   return frontMsg;
}

Channel::Channel() : VectorClock(0) {
}

#if 0
void free(ADDRINT mutex) {
   iterator im = find(mutex);

   ASSERT(im != end());

   delete im->second;

   erase(mutex);
}
#endif

Channel* ChannelMap::lookupCreate(ChannelKey key) {
   Channel *chnPtr = NULL;

   iterator im = find(key);

   if (im == end()) {
      chnPtr = new Channel();
      (*this)[key] = chnPtr;
   } else {
      chnPtr = im->second;
   }

   return chnPtr;
}

Channel* ChannelMap::lookup(ChannelKey key) {
   Channel *chnPtr = NULL;

   iterator im = find(key);

   if (im != end()) {
      chnPtr = im->second;
   }

   return chnPtr;
}
