/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "vkernel/public.h"

/* Must NOT be in the SHAREDAREA -- we need this to be local
 * to the address space, since log mappings are per-address space
 * as well. */
static uint replayLogLocalRotationGeneration[MAX_NR_VCPU] = { 0 };

static char *
LogMap(const struct Log *logp, ulong pgoff)
{
   int prot, res, fd;
   ulong logStart;
   ulong dummyStart;

   logStart = Log_LogStart(logp);
   dummyStart = logStart + LOGFSZ;

   prot = PROT_READ | (logp->isLogging || 
         !logp->isProtectedInReplay ? PROT_WRITE : 0);

   fd = logp->fd;
   ASSERT(fd >= 0);
   res = syscall(SYS_mmap2, logStart, LOGFSZ_INC_DUMMY,
           prot, MAP_FIXED | MAP_SHARED,
           fd, pgoff);
   ASSERT(!SYSERR(res));

   /* This should catch any overflows to the log dummy. */
   res = syscall(SYS_mprotect, dummyStart, PAGE_SIZE, PROT_NONE);
   ASSERT(!SYSERR(res));

   return (char*) logStart;
}

void
Log_Close(struct Log * logP)
{
#if PRODUCT
#error "XXX: should close all logs before shutdown"
#endif

   ASSERT(logP->fd >= 0);

   /* We don't want to see the junk (zeroes) at the end of the sparse file
    * so truncate. */
   if (logP->isLogging) {
      loff_t endOffset = logP->endOff;
      UNUSED loff_t pos = (size_t) logP->pos;
      UNUSED loff_t logStart = logP->logStart;

      ASSERT(pos >= logStart);
      loff_t logOff = (size_t)(logP->pos - (char*)logP->logStart);

      loff_t finalLength = (endOffset - LOGFSZ) + logOff;
      DEBUG_MSG(0, "eo=%llu off=%llu finalLength=%llu\n", 
            endOffset, logOff, finalLength);

      UNUSED int err = ftruncate64(logP->fd, finalLength);
      ASSERT(!err);
   }

   close(logP->fd);
   logP->fd = -1;
}


static void
LogOpen(struct Log *logp)
{
   int res;
   char *filename;

   //LOG("log open: global=%d\n", Log_GetLocalRotGen(logp), logp->nrRotations);

   filename = SharedArea_Malloc(PATH_MAX);

   res = snprintf(filename, PATH_MAX, "%s/vcpu-%.4lu-%.2d.%s", 
                  session.dir, logp->nrRotations, logp->vcpu->id, 
                  logp->idstr);
   ASSERT(res < PATH_MAX);

   logp->fd = SysOps_Open(filename, 
         (logp->isLogging ? 
            (O_RDWR | O_CREAT | O_TRUNC) 
            : (logp->isProtectedInReplay ? O_RDONLY : O_RDWR)) |
         O_LARGEFILE,
         S_IRUSR | (logp->isProtectedInReplay ? 0 : S_IWUSR));

   if (logp->fd < 0) {
      FATAL("Can't open log file %s: %s\n", 
            filename, strerror(SYSERR_ERRNO(logp->fd)));
   }

   SharedArea_Free(filename, PATH_MAX);
}

void
Log_CatchupOnRotations(struct Log *logp)
{
   loff_t logCurrFileOffset;

   ASSERT(logp);
   ASSERT(logp->hasBeenInitialized);
   ASSERT(logp->vcpu);
   ASSERT(PAGE_ALIGNED(LOGFSZ));
   ASSERT(PAGE_ALIGNED(logp->endOff));
   ASSERT(Log_GetLocalRotGen(logp) < logp->nrRotations);

   DEBUG_MSG(5, "local=%d global=%d\n",
         Log_GetLocalRotGen(logp), logp->nrRotations);

   /* Play catchup. */
   DEBUG_MSG(5, "Rotating to catch up with most recent rotation in "
         "other address space.\n");

   logCurrFileOffset = logp->endOff - LOGFSZ;
   ASSERT(logp->endOff >= LOGFSZ);
   ASSERT(PAGE_ALIGNED(logCurrFileOffset));
   LogMap(logp, PAGE_NUM(logCurrFileOffset));

   /* vcpu->pos is already pointing to the right spot, so don't
    * reset it. */

   DEBUG_MSG(5, "mapped pos=0x%x start=0x%x:0x%x offset=%llu\n", 
         logp->pos, Log_LogStart(logp), Log_LogEnd(logp),
         logCurrFileOffset);

   Log_UpdateLocalRotGen(logp);
}


void
Log_Rotate(struct Log *logp)
{
#if 0
   LOG("local=%d global=%d\n",
         Log_GetLocalRotGen(logp), logp->nrRotations);
#endif
#if DEBUG
   ASSERT_KPTR(logp);
   ASSERT(logp->hasBeenInitialized);
   ASSERT(logp->vcpu);
   ASSERT(PAGE_ALIGNED(LOGFSZ));
   ASSERT(PAGE_ALIGNED(logp->endOff));
   ASSERT(Log_GetLocalRotGen(logp) == logp->nrRotations);
   DEBUG_MSG(5, "local=%d global=%d\n",
         Log_GetLocalRotGen(logp), logp->nrRotations);
   ASSERT(Log_GetLocalRotGen(logp) == logp->nrRotations);
#endif

   const int wantsChunkedFiles = 1;

   if (wantsChunkedFiles) {
      if (logp->pos) {
         Log_Close(logp);
      } else {
         /* Not mapped; initial rotation. */
      }

      logp->endOff = LOGFSZ;
   } else {
      /* Just keep extending the current log file. */
      logp->endOff += LOGFSZ;
   }


   if (logp->fd == -1) {
      LogOpen(logp);
   }

   if (logp->isLogging) {
      /* Extend the file to an mmap'able size. The file should be sparse
       * and hence won't consume all of the space until written. */
      int dummy = 0, fd = logp->fd;
      loff_t err, off = logp->endOff-sizeof(dummy);

      ASSERT(fd >= 0);

      DEBUG_MSG(5, "off=%lu\n", off);
      err = lseek64(fd, off, SEEK_SET);
      ASSERT(err == off);

      UNUSED int res = write(fd, &dummy, sizeof(dummy));
      ASSERT(res == sizeof(dummy));
   }

   const loff_t logCurrFileOffset = logp->endOff - LOGFSZ;
   ASSERT(logCurrFileOffset >= 0);
   logp->pos = LogMap(logp, PAGE_NUM(logCurrFileOffset));

   DEBUG_MSG(5, "mapped pos=0x%x start=0x%x:0x%x offset=%llu\n", 
         logp->pos, Log_LogStart(logp), Log_LogEnd(logp),
         logCurrFileOffset);

   logp->nrRotations++;
   Log_UpdateLocalRotGen(logp);
}

static int nextLogSlot = 0;
#define MAX_LOG_SLOTS ((__VCPU_LOGS_END - __VCPU_LOGS_START) / LOGFSZ_INC_DUMMY)

/* Init the log and bind it to @vcpu. */
void
Log_Setup(struct Log * logp, const char *idstr, struct VCPU * vcpu,
      uint * localRotGenArray, const int isLogging, 
      const int isProtectedInReplay)
{
   DEBUG_MSG(5, "Initializing '%s' log, vcpu %d, isLogging %d, "
         "isProtectedInReplay %d\n", 
         idstr, vcpu->id, isLogging, isProtectedInReplay);

   /* Total log lengths may exceed 4GB. */
   ASSERT(sizeof(logp->size) == sizeof(loff_t));

   logp->fd = -1;
   logp->endOff = 0;
   logp->pos = NULL;
   logp->nrRotations = 0;
   logp->logLocalRotationGeneration = localRotGenArray;
   logp->isProtectedInReplay = isProtectedInReplay;
   logp->vcpu = vcpu;
   logp->size = 0;
   logp->isLogging = isLogging;

   if (isLogging) {
      TokenBucket_Init(&logp->tokenBucket, session.optRecSpec);
   }
   strncpy(logp->idstr, idstr, sizeof(logp->idstr));
   STATS_ONLY(memset(logp->stats, 0, sizeof(logp->stats));)

      logp->logStart = __VCPU_LOGS_START + (nextLogSlot * LOGFSZ_INC_DUMMY);
   ASSERT(logp->logStart >= __VCPU_LOGS_START);
   ASSERT((logp->logStart+LOGFSZ_INC_DUMMY) <= __VCPU_LOGS_END);

   nextLogSlot++;

   DEBUG_ONLY(logp->hasBeenInitialized = 1;)

      /* Initial rotation maps the log files into the
       * address space. */
   Log_Rotate(logp);
}


#undef LOGENTRYDEF
#define LOGENTRYDEF(name, ...) int LogEntryId_##name;
#include "entries.h"

#define MAX_ENTRY_LEN 256
char entryId2Str[MAX_ENTRY_TYPES][MAX_ENTRY_LEN];

/* Expected to be called by the initial task. */
int
Log_Init()
{
   int i, id = 0;

   /* Times 2, because, in check mode, we need address-space for the check 
    * log files in addition to the standard log files. */
#if PRODUCT
#error "XXX: reenable checks log: MAX_NR_VCPU*2"
#endif
   ASSERT_MSG(MAX_LOG_SLOTS >= MAX_NR_VCPU*1, 
         "Probably not enough address space for all VCPUS. "
         "Lower the number of VCPUs or the size of each in-memory log.");
#if MAX_LOG_SLOTS < MAX_NR_VCPU
#error "Not enough logmap space for all VCPUs, lower MAX_NR_VCPU or log size"
#endif

#undef LOGENTRYDEF
#define LOGENTRYDEF(name, ...) \
   LogEntryId_##name = id;  \
   ASSERT(strlen(#name) < MAX_ENTRY_LEN); \
   strncpy(entryId2Str[id], #name, sizeof(entryId2Str[id])); \
   id++; \
   ASSERT(id < MAX_ENTRY_TYPES);
#include "entries.h"

   ASSERT(NR_VCPU > 0 && NR_VCPU <= MAX_NR_VCPU);

   DEBUG_MSG(5, "Initializing the logs.\n");

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpu = VCPU_Ptr(i); 
      Log_Setup(&vcpu->replayLog, "log", vcpu, 
            replayLogLocalRotationGeneration, VCPU_IsLogging(), 1);
   }

   return 0;
}
