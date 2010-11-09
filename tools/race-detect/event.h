#pragma once

#include "sharedheap.h"

/*************************************************************/
/* Pin seems to have its own heap, so it seems safe to dynamically
 * allocate events...*/
class Event {
public:
   virtual void before()=0;

   virtual void after()=0;

   virtual string toStr() const=0;

   virtual ~Event() { }
};

const int MAX_SYSARGS = 6;

class SyscallEvent : public Event {
private:
   /* Shouldn't be changed by derived classes. */
   ADDRINT *regsPtrArray[MAX_SYSARGS];
   ADDRINT regsValArray[MAX_SYSARGS];

protected:
   //ADDRINT regsValArray[MAX_SYSARGS];
   INT32 sysno;
   INT32 retVal;

   /* Why do we need postbefore? So that sysargs are available
    * to post-syscall handlers. */
   void postBefore() {
      /* Update syscall args. We expect some of them
       * to change after the beforeEvent handler
       * gets called. */
      for (int i = 0; i < MAX_SYSARGS; i++) {
         *(regsPtrArray[i]) = regsValArray[i];
      }
   }

   inline ADDRINT& arg(const int i) {
      return regsValArray[i];
   }

   inline ADDRINT argv(const int i) const {
      return regsValArray[i];
   }

public:
   SyscallEvent() {
      retVal = -1;
   }

   void setArgs(UINT32 _sysno, ADDRINT *regPtrs[MAX_SYSARGS]) {
      sysno = _sysno;

      for (int i = 0; i < MAX_SYSARGS; i++) {
         regsPtrArray[i] = regPtrs[i];
         regsValArray[i] = *(regPtrs[i]);
      }
   }

   string argsToStr() const {
      string str;
      stringstream out;

      out << hex << argv(0) << " " << hex << argv(1) << " " << hex << argv(2) 
         << " " << hex << argv(3) << " " << hex << argv(4) << " " 
         << hex << argv(5);

      str = out.str();

      return str;
   }

   void setReturnValue(INT32 ret) {
      retVal = ret;
   }

   virtual void before() {
   };

   virtual void after()=0;
};

class NonSyscallEvent : public Event {
protected:
   void postBefore() {
      /* Do nothing. */
   };

public:
   virtual void before()=0;

   virtual void after()=0;

   virtual string toStr() const=0;
};
