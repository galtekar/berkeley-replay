#pragma once

#include "event.h"

#include "framepool.h"
#include "shmsegmap.h"
#include "syscall.h"

#include "debug.h"

extern FramePool *framePool;
extern ShmSegMap *shmMap;

class MemSyscallEvent : public SyscallEvent {
protected:
   inline bool is_backed_shm(UINT32 flags)
   {
      /* returns true iff file-backed shared memory */
      return (flags & MAP_SHARED && !(flags & MAP_ANONYMOUS));
   }

   virtual void beforeEvent() {
      /* Default: do nothing. */
   }

   virtual void afterEvent()=0;

public:

   void before() {
      framePool->lock();

      DLOG("----------------------------------------\n");
      DLOG("MemEvent: %s\n", toStr().c_str());
      DLOG("PreArgs: %s\n", argsToStr().c_str());

      beforeEvent();

      SyscallEvent::postBefore();
   }


   void after() {
      afterEvent();

      DLOG("PostArgs: %s = 0x%x\n", argsToStr().c_str(), retVal);

      framePool->unlock();
   }
};

class MmapEvent : public MemSyscallEvent {
private:
   enum {START, LEN, PROT, FLAGS, FD, PGOFF};

protected:
   void mmapBefore(ADDRINT &start, size_t len, UINT32 &flags) {
      len = PAGE_ALIGN(len);

      ASSERT(PAGE_ALIGNED(start));
      if ((start == 0) ||
            (!current->getPt()->is_region_free(PAGE_NUM(start), 
                                               PAGE_NUM(len)) &&
             !(flags & MAP_FIXED))) {

         /* find a spot */
         start = current->getPt()->find_free_block(len);

      } else {
         /* call insists on specified start; be preparted to replace
          * the existing mapping */
         DLOG("MmapBefore: insists on replace\n");
      }

      flags |= MAP_FIXED;

      ASSERT(start);
   }

   void mmapAfter(const ADDRINT start, size_t len, const UINT32 flags, const int fd, Page pgoff) {
      ASSERT(start);
      ASSERT(flags & MAP_FIXED);
      len = PAGE_ALIGN(len);

      if (!SYSERR(retVal)) {
         ASSERT((ADDRINT)retVal == start);

         ShmId shmid = 0;
         if (is_backed_shm(flags)) {
            /* file-backed shared memory */
            struct stat sbuf;
            int ret = fstat(fd, &sbuf);
            ASSERT(ret == 0);
            shmid = sbuf.st_ino;
         }

         if (flags & MAP_ANONYMOUS) {
            pgoff = OFFSET_INVALID;
         }

         current->getPt()->allocate(start, len, pgoff, flags & MAP_SHARED, shmid);
      }
   }

   void beforeEvent() {
      mmapBefore(arg(START), arg(LEN), arg(FLAGS));
   }

   void afterEvent() {
      mmapAfter(arg(START), arg(LEN), arg(FLAGS), arg(FD), arg(PGOFF));
   }

   string toStr() const {
      return "MmapEvent";
   }
};


class OldMmapEvent : public MmapEvent {
private:
   struct mmap_arg_struct {
      ADDRINT addr;
      size_t len;
      unsigned long prot;
      UINT32 flags;
      int fd;
      ADDRINT offset;
   };

protected:
   void beforeEvent() {
      struct mmap_arg_struct *argp = 
         reinterpret_cast<struct mmap_arg_struct*>(arg(0));

      mmapBefore(argp->addr, argp->len, argp->flags);
   }

   void afterEvent() {
      struct mmap_arg_struct *argp = 
         reinterpret_cast<struct mmap_arg_struct*>(arg(0));

      mmapAfter(argp->addr, argp->len, argp->flags, argp->fd, PAGE_NUM(argp->offset)); 
   }

public:
   string toStr() const {
      return "OldMmapEvent";
   }
};


class MunmapEvent : public MemSyscallEvent {
private:
   enum {START, LEN};

protected:
   void munmapAfter(const ADDRINT start, size_t len) {
      len = PAGE_ALIGN(len);

      if (!SYSERR(retVal)) {
         current->getPt()->deallocate(start, len);
      }
   }

   void afterEvent() {
      munmapAfter(arg(START), arg(LEN));
   }

public:
   string toStr() const {
      return "MunmapEvent";
   }
};

#if 1
class BrkEvent : public MemSyscallEvent {
private:
   enum {NEWBRK};
   ADDRINT old_brk;

protected:
   void beforeEvent() {
      old_brk = syscall(SYS_brk, 0);
      ASSERT(old_brk > 0);
      ASSERT(PAGE_ALIGNED(old_brk));
   }

   void afterEvent() {
      ASSERT(PAGE_ALIGNED(retVal));
      if ((ADDRINT)retVal > old_brk) {
         /* Allocate pages. */

         current->getPt()->allocate(old_brk, retVal - old_brk, 0, 0, 0);
         //mmapAfter(old_brk, retVal - old_brk, 
          //     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
      } else if ((ADDRINT)retVal < old_brk) {
         /* Deallocate pages. */
         size_t len = PAGE_ALIGN(old_brk - retVal);

         current->getPt()->deallocate(retVal, len);

      } else {
         /* Pages were neither allocated nor deallocated. 
          * Do nothing. */
      }
   }

public:
   string toStr() const {
      return "BrkEvent";
   }
};
#endif


class ShmatEvent : public MemSyscallEvent {
private:
   enum {CALL, SHMID, SHMFLG, THIRD, SHMADDR};
   SharedSegment *ssp;

protected:
   void beforeEvent() {
      ssp = shmMap->lookup(arg(SHMID));

      if (ssp) {

         if (arg(SHMADDR) == 0 /* NULL starting address */) {
            arg(SHMADDR) = current->getPt()->find_free_block(ssp->size_bytes());
         }

         ASSERT(arg(SHMADDR));
      }
   }

   void afterEvent() {
      ASSERT(arg(SHMADDR));
#if 0
      /* XXX: implement on demand */
      //ASSERT(!(arg(SHMFLG) & SHM_REMAP));
#endif

      if (ssp) {

         if (!SYSERR(retVal)) {
            current->getPt()->allocate(arg(SHMADDR), ssp->size_bytes(), 
                  0, true, arg(SHMID));
         } 

      } else {
         /* If we didn't find it, then the segment was never allocated
          * via shmget, in which case, the syscall should fail. */
         ASSERT(SYSERR(retVal));
      }
   }

public:
   string toStr() const {
      return "ShmatEvent";
   }
};

class ShmdtEvent : public MemSyscallEvent {
private:
   enum {CALL, SHMID, SECOND, THIRD, SHMADDR};
   SharedSegment *ssp;

protected:
   void afterEvent() {
      PtEntry pte = current->getPt()->lookup(arg(SHMADDR));
      ssp = shmMap->lookup(pte.shmid);

      if (ssp) {
         if (!SYSERR(retVal)) {
            current->getPt()->deallocate(arg(SHMADDR), ssp->size_bytes());
         }

      } else {
         ASSERT(SYSERR(retVal));
      }
   }

public:
   string toStr() const {
      return "ShmdtEvent";
   }
};

class ShmgetEvent : public MemSyscallEvent {
private:
   enum {CALL, KEY, LEN, SHMFLG};

protected:
   void afterEvent() {
      if (!SYSERR(retVal)) {
         /* arg(LEN) may be less than the actual size of the segment if
          * the app is attaching to an existing segment, so
          * we must obtain the actual size from the kernel. */
         struct shmid_ds buf;
         int res;

         res = shmctl(retVal /* shmid */, IPC_STAT, &buf);
         ASSERT(res != -1);

         /* Linux allows arg(LEN) to be less than the actual size. */
         ASSERT(buf.shm_segsz >= arg(LEN));

         const SharedSegment *ssp = shmMap->get(retVal, 0, buf.shm_segsz);
         ASSERT(ssp);
      }
   }
public:
   string toStr() const {
      return "ShmgetEvent";
   }
};

class ShmctlEvent : public MemSyscallEvent {
private:
   enum {CALL, SHMID, CMD};

protected:
   void afterEvent() {
      if (!SYSERR(retVal)) {
         if (arg(CMD) == IPC_RMID) {
            const SharedSegment *ssp = shmMap->lookup(arg(SHMID));
            ASSERT(ssp);
            shmMap->put(arg(SHMID), 0, ssp->size_bytes());
         }
      }
   }
public:
   string toStr() const {
      return "ShmctlEvent";
   }
};
