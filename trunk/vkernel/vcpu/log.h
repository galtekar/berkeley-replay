#pragma once

#include "libcommon/misc.h"

/* The size of each log file. */
#define LOGFSZ (1 << 24)

/* The size of each log file, including dummy page size. */
#define LOGFSZ_INC_DUMMY (LOGFSZ+PAGE_SIZE)

/* We want the entry type to fit into 1-byte to reduce log size. */
#define MAX_ENTRY_TYPES 256

#define TYPE_EXPANDED(type) struct type##EntryStruct
#define DECLARE_LOG_ENTRY_POINTER(type, name)   TYPE_EXPANDED(type) *name = NULL


extern void                Log_Rotate(struct Log *);
extern void                Log_CatchupOnRotations(struct Log *);


#if DEBUG
#define ENTRY_MAGIC 0xc0011dea

struct DebugHeader {
   uint magic;
   ullong brCnt;
   int taskId;
};
#endif

struct EntryHeader {
   /* We need the id for debug and release builds. Without it,
    * we can't do look-ahead, which is important for setting up
    * preemptions. */
   char id;
   ulong eip;

   DEBUG_ONLY(struct DebugHeader dbg;)
};


#undef LOGENTRYDEF
#define LOGENTRYDEF(name, ...) \
   struct name##EntryStruct { \
      struct EntryHeader hdr; \
      __VA_ARGS__ \
   };

#include "entries.h"

#undef LOGENTRYDEF
#define LOGENTRYDEF(name, ...) extern int LogEntryId_##name;
#include "entries.h"
extern char entryId2Str[MAX_ENTRY_TYPES][256];

static INLINE ulong
Log_LogStart(const struct Log *logp)
{
   ulong logStart = logp->logStart;

   ASSERT(logStart >= __VCPU_LOGS_START);
   ASSERT_MSG((logStart+LOGFSZ_INC_DUMMY) <= __VCPU_LOGS_END,
         "logStart=0x%x LOGFZ_INC_DUMMY=%d VCPU_LOG_END=0x%x\n",
         logStart, LOGFSZ_INC_DUMMY, __VCPU_LOGS_END);

   return logStart;
}

static INLINE ulong
Log_LogEnd(const struct Log *logp)
{
   ulong logEnd;

   logEnd = Log_LogStart(logp) + LOGFSZ;

   ASSERT(logEnd < __VCPU_LOGS_END);

   return logEnd;
}

static INLINE void
LogSanityCheck(const struct Log *logp)
{
   ulong pos;

   pos = (ulong) logp->pos;

   ASSERT(pos >= Log_LogStart(logp));
   ASSERT(pos < Log_LogEnd(logp));
}

static INLINE void
LogPrintEntryInfo(struct EntryHeader *hdrp, TaskRegs *regs, u64 brCnt,
                  int entryType)
{
   DEBUG_MSG(7, "Logged: %s:0x%x:%llu Replay: %s:0x%x:%llu\n", 
         entryId2Str[(int)hdrp->id], hdrp->eip, hdrp->dbg.brCnt,
         entryId2Str[(int)entryType], regs->R(eip), brCnt);
}

static INLINE void
LogPrepHeader(struct EntryHeader *hdrp, TaskRegs *regs, u64 brCnt, 
      int entryType, int isPeek, int isLogging)
{
   DEBUG_MSG(8, "hdrp=0x%x\n", hdrp);

   if (isLogging) {
      hdrp->id = entryType;
      hdrp->eip = regs->R(eip);
#if DEBUG
      hdrp->dbg.magic = ENTRY_MAGIC;
      hdrp->dbg.brCnt = brCnt;
      hdrp->dbg.taskId = current->id;

      DEBUG_MSG(7, "Logged: %s:0x%x:%llu\n",
            entryId2Str[(int)hdrp->id], hdrp->eip, hdrp->dbg.brCnt);
#endif
   } else {
#if DEBUG
      int match = 1;
      /* Some rudimentary checks. */
      LogPrintEntryInfo(hdrp, regs, brCnt, entryType);
#endif

      if (hdrp->id != entryType && !isPeek) {
#if !DEBUG
         /* Debug logs and ASSERT macros are disabled in release builds. */
         LOG("hrdp->id=%d:%s entryType=%d:%s\n", 
               hdrp->id, entryId2Str[(int)hdrp->id], 
               entryType, entryId2Str[(int)entryType]);
         sleep(1000);
         FATAL("Divergence.\n");
#endif
      }

#if DEBUG
      if (!isPeek) {
#define VERIFY(var, correct_val, fmt) \
      match &= (var == correct_val); \
      if (!match) { \
         DEBUG_MSG(0, #var "=" fmt ", expected " fmt "\n", var, correct_val); \
      }

         VERIFY(hdrp->dbg.magic, ENTRY_MAGIC, "0x%x");
         VERIFY(hdrp->dbg.taskId, current->id, "%d");
         VERIFY(hdrp->eip, regs->R(eip), "0x%x");
         VERIFY(hdrp->dbg.brCnt, brCnt, "%llu");
         VERIFY(hdrp->id, entryType, "%d");

      } else {
         /* Register state needn't match for peeks, since
          * the peek may not happen at the same execution point
          * as which the peeked-event took place. */
         DEBUG_MSG(5, "Peek, so skipping determinism checks.\n");
      }

      ASSERT(match);
#endif
   } 
}

static INLINE uint
Log_GetLocalRotGen(const struct Log *logp)
{
   return logp->logLocalRotationGeneration[logp->vcpu->id];
}

static INLINE void
Log_UpdateLocalRotGen(const struct Log *logp)
{
   logp->logLocalRotationGeneration[logp->vcpu->id] = logp->nrRotations;
}

static INLINE int
LogIsTimeToCatchup(const struct Log *logp)
{
   /* The VCPU log may have been rotated in a different address space.
    * In that case, it wouldn't have been rotated in this address space.
    * And we definitely don't want to write over existing entries. 
    * So rotate to catchup. */
   int isBehindOnRotations = (Log_GetLocalRotGen(logp) < 
         logp->nrRotations);

   ASSERT(Log_GetLocalRotGen(logp) <= logp->nrRotations);

   return isBehindOnRotations;
}

static INLINE int
LogIsTimeToRotate(const struct Log *logp, size_t entrySize, 
      size_t dataSize)
{
   ulong pos = (ulong) logp->pos;
   ulong logEnd = Log_LogEnd(logp);

   if (logp->isLogging) {
      int isEnoughRoomForRotateEntryAfterWritingCurrentEntry =
         ((pos + entrySize + dataSize) <= 
          logEnd-sizeof(TYPE_EXPANDED(Rotate)));

      return !isEnoughRoomForRotateEntryAfterWritingCurrentEntry;
   } else {
      struct EntryHeader *hdrp = (struct EntryHeader*)pos;

      /* We don't know how long the entry is (the data component is variable
       * sized -- the length of the entry is stored in the fixed-length
       * component somewhere, we don't know where), so we must look for the
       * RotateEntry entry to tell us when we should rotate. */
      return (hdrp->id == LogEntryId_Rotate);
   }
}


static INLINE void
LogRotateIfNecessary(struct Log *logp, TaskRegs *regs, u64 brCnt,
      size_t entrySize, size_t dataSize)
{
   struct EntryHeader *hdrp;
#if DEBUG
   struct VCPU *vcpu = logp->vcpu;

   /* Must have exclusive access to the VCPU to rotate. */
   ASSERT(VCPU_IsLocked(vcpu));
#endif
   const int isLogging = logp->isLogging;


   if (LogIsTimeToCatchup(logp)) {
      Log_CatchupOnRotations(logp);

      /* pos needn't be exactly at the start of the
       * log mapping if we are rotating to catch-up with
       * a VCPU rotation performed in another address space. */
      ASSERT((ulong)logp->pos >= Log_LogStart(logp));
   } 

   /* It's possible that right after we catchup on rotations,
    * we won't have enough room to make a log entry and
    * so we must perform a real rotation. Hence this should
    * not be an ``else if'' of the previous conditional. */
   
   if (LogIsTimeToRotate(logp, entrySize, dataSize)) {
      hdrp = (struct EntryHeader*)logp->pos;
      LogPrepHeader(hdrp, regs, brCnt, LogEntryId_Rotate, 1, isLogging);
      Log_Rotate(logp);
      ASSERT((ulong)logp->pos == Log_LogStart(logp));
   }
}

static INLINE void
Log_Advance(struct Log *logP, const size_t nrBytes)
{
   logP->pos += nrBytes;
   logP->size += nrBytes;
}

static INLINE void
Log_AdvanceToNextEntry(struct Log *logp, TaskRegs *regs, 
      const u64 brCnt, const int id, 
      const size_t entrySize, 
      const ssize_t dataSize, void **entryp, void **datap, 
      struct EntryHeader **hdrp, const int isReserve) {

   const int isLogging = logp->isLogging;
   DEBUG_ONLY(const ulong totalEntrySize = entrySize+dataSize;)

   ASSERT(logp->hasBeenInitialized);
   DEBUG_ONLY(LogSanityCheck(logp);)
   ASSERT(totalEntrySize < LOGFSZ); /* otherwise, rotation is ineffective */
   /* Must have exclusive access to the VCPU to make a log entry. */
   ASSERT(VCPU_IsLocked(logp->vcpu));

   DEBUG_MSG(7, "Log: idstr=%s entry_idstr=%s\n", 
         logp->idstr,entryId2Str[(int)id]);
   LogRotateIfNecessary(logp, regs, brCnt, entrySize, dataSize);
   ASSERT(Log_GetLocalRotGen(logp) == logp->nrRotations);

   /* CAREFUL: vcpu->pos will have changed after a rotation,
    * but not on a catchup rotation. */
   *hdrp = (struct EntryHeader*)logp->pos;
   LogPrepHeader(*hdrp, regs, brCnt, id, 0, isLogging);

   *entryp = logp->pos;
   Log_Advance(logp, entrySize);
   if (isLogging) {
      TokenBucket_Consume(&logp->tokenBucket, entrySize);
   }

   *datap = logp->pos;
   if (!isReserve) {
      Log_Advance(logp, dataSize);
      if (isLogging) {
         TokenBucket_Consume(&logp->tokenBucket, dataSize);
      }
   } else {
      /* Update the pos only after we know how much of the
       * reservation was used. */
   }
}


static INLINE int
Log_EntryIsType(struct Log *logp, const int type)
{
   struct EntryHeader *hdrp;

   hdrp = (struct EntryHeader*)logp->pos;

   return hdrp->id == type;
}

static INLINE void*
Log_EntrySafeCast(struct Log *logp, int type)
{
   if (Log_EntryIsType(logp, type)) {
      return logp->pos;
   }

   return NULL;
}

#if STATS
static INLINE void
Log_CollectStats(struct Log * logp, int id, size_t entrySize, size_t dataSize)
{
   ASSERT(id >=0 && id < MAX_ENTRY_TYPES);
   logp->stats[id] += (entrySize + dataSize);
}
#endif


#define DO_WITH_LOG_ENTRY_DATA_GENERIC(log_ptr, type, dataSz, isReserve, wantsRateLimiting) { \
   DECLARE_LOG_ENTRY_POINTER(type, entryp); \
   void * datap = NULL; \
   struct EntryHeader * hdrp = NULL; \
   struct Log * logp = log_ptr; \
   ssize_t __dataSz = dataSz; \
   int should_prevent_data_logging = FALSE; \
   if (logp->isLogging) { \
      TokenBucket_Fill(&logp->tokenBucket); \
      if (wantsRateLimiting && !TokenBucket_IsConsumable(&logp->tokenBucket, dataSz)) { \
         should_prevent_data_logging = TRUE; \
         __dataSz = 0; \
      } \
   } \
   Log_AdvanceToNextEntry(logp, curr_regs, BrCnt_Get(), \
         LogEntryId_##type, sizeof(TYPE_EXPANDED(type)), \
         (__dataSz), \
         (void**)&entryp, &datap, &hdrp, isReserve); \
   STATS_ONLY(Log_CollectStats(logp, LogEntryId_##type, \
            sizeof(TYPE_EXPANDED(type)), (__dataSz));) \
   if (should_prevent_data_logging) { \
      datap = NULL; \
   }

#define DO_WITH_LOG_ENTRY_DATA(type, dataSz) \
   DO_WITH_LOG_ENTRY_DATA_GENERIC(&curr_vcpu->replayLog, type, \
         dataSz, 0, 0)

#define DO_WITH_LOG_ENTRY_DATA_RESERVE(type, dataSz, wantsRateLimiting) \
   DO_WITH_LOG_ENTRY_DATA_GENERIC(&curr_vcpu->replayLog, type, \
         VCPU_IsLogging() ? dataSz : 0, VCPU_IsLogging(), \
         wantsRateLimiting)

#define DO_WITH_LOG_ENTRY(type) \
   DO_WITH_LOG_ENTRY_DATA_GENERIC(&curr_vcpu->replayLog, type, 0, \
         0, 0)

#define CHECK_DO_WITH_LOG_ENTRY(type) \
   DO_WITH_LOG_ENTRY_DATA_GENERIC(&curr_vcpu->checkLog, type, 0, \
         0, 0)

/* During replay, you don't know what the size of the data is
 * until we've read the entry. Once you know how big the data
 * is, though, you have to advance the log entry past it. 
 * The @dataSz argument lets you do that. */
#define END_WITH_LOG_ENTRY(dataSz) \
   { \
      Log_Advance(logp, dataSz); \
      if (logp->isLogging) { \
         TokenBucket_Consume(&logp->tokenBucket, dataSz); \
      } \
   } \
}

/* Look at the current log entry without advancing the entry position 
 * pointer. Be mindful that the current entry could be a rotation
 * entry. */
#define PEEK_LOG_ENTRY(type, name) ({ \
   ASSERT(VCPU_IsReplaying()); \
   LogRotateIfNecessary(&curr_vcpu->replayLog,curr_regs,BrCnt_Get(),0,0); \
   name = (TYPE_EXPANDED(type)*) \
      Log_EntrySafeCast(&curr_vcpu->replayLog, LogEntryId_##type); \
   name; })

#define PEEK_LOG_ENTRY_HEADER(logP) ({ \
   struct EntryHeader *__hdrP = NULL; \
   ASSERT(VCPU_IsReplaying()); \
   LogRotateIfNecessary(logP,curr_regs,BrCnt_Get(),0,0); \
   __hdrP = (struct EntryHeader*)((logP)->pos); \
   __hdrP; })

/* XXX: duplicate code; try to merge this with the above. */
#define CHECK_PEEK_LOG_ENTRY(type, name) ({ \
   ASSERT(Check_IsReplaying()); \
   LogRotateIfNecessary(&curr_vcpu->checkLog,curr_regs,BrCnt_Get(),0,0); \
   name = (TYPE_EXPANDED(type)*) \
      Log_EntrySafeCast(&curr_vcpu->checkLog, LogEntryId_##type); \
   name; })


static INLINE int
Log_IsAddrInLogDummy(struct Log *logp, ulong addr)
{
   ulong dummy_start, dummy_end;

   dummy_start = Log_LogEnd(logp);
   ASSERT(PAGE_ALIGNED(dummy_start));
   dummy_end = dummy_start + PAGE_SIZE;

   return (dummy_start <= addr && addr < dummy_end);
}

extern void Log_Setup(struct Log * logp, const char *idstr, 
      struct VCPU *vcpu, uint * localRotGenArray, const int isLogging, 
      const int isProtectedInReplay);

extern void Log_Close(struct Log * logP);

extern int  Log_Init();


static INLINE void
Log_ReplayInt(uint *ptr)
{
   ASSERT_KPTR(ptr);

   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY(ValInt) {
         entryp->val = *ptr;
      } END_WITH_LOG_ENTRY(0);
   } else if (VCPU_IsReplaying()) {
      DO_WITH_LOG_ENTRY(ValInt) {
         *ptr = entryp->val;
      } END_WITH_LOG_ENTRY(0);
   }
}

static INLINE void
Log_ReplayLong(ulong *ptr)
{
   ASSERT_KPTR(ptr);

   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY(ValLong) {
         entryp->val = *ptr;
      } END_WITH_LOG_ENTRY(0);
   } else if (VCPU_IsReplaying()) {
      DO_WITH_LOG_ENTRY(ValLong) {
         *ptr = entryp->val;
      } END_WITH_LOG_ENTRY(0);
   }
}

static INLINE void
Log_ReplayLongLong(ullong *ptr)
{
   ASSERT_KPTR(ptr);

   if (VCPU_IsLogging()) {
      DO_WITH_LOG_ENTRY(ValLongLong) {
         entryp->val = *ptr;
      } END_WITH_LOG_ENTRY(0);
   } else if (VCPU_IsReplaying()) {
      DO_WITH_LOG_ENTRY(ValLongLong) {
         *ptr = entryp->val;
      } END_WITH_LOG_ENTRY(0);
   }
}
