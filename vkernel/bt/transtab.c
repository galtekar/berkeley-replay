/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"


/* May or may not be necessary, depending on BT instrumentatino
 * performed. If thread/process specific arguments are burned
 * into helper call arguments, then this must be turned on. */
#define TRNSTAB_FLUSH_ON_FORK 0

/* Number of sectors the TC is divided into.  If you need a larger
   overall translation cache, increase this value. */
#define N_SECTORS 1

/* Default value for avg_translations_sizeB (in bytes), indicating typical
   code expansion of about 6:1. */
#define VK_DEFAULT_TRANS_SIZEB   172

/* Number of TC entries in each sector.  This needs to be a prime
   number to work properly, it must be <= 65535 (so that a TT index
   fits in a UShort, leaving room for 0xFFFF(EC2TTE_DELETED) to denote
   'deleted') and it is strongly recommended not to change this.
   65521 is the largest prime <= 65535. */
#define N_TTES_PER_SECTOR /*30011*/ /*40009*/ 65521

/* Because each sector contains a hash table of TTEntries, we need to
   specify the maximum allowable loading, after which the sector is
   deemed full. */
#define SECTOR_TT_LIMIT_PERCENT 80

/* The sector is deemed full when this many entries are in it. */
#define N_TTES_PER_SECTOR_USABLE \
           ((N_TTES_PER_SECTOR * SECTOR_TT_LIMIT_PERCENT) / 100)

/* The fast-cache for tt-lookup, and for finding counters.  Unused
   entries are denoted by .guest == 1, which is assumed to be a bogus
   address for all guest code. */
typedef struct { 
   ulong guest;
   ulong host;
} FastCacheEntry;

/* A translation-table entry.  This indicates precisely which areas of
   guest code are included in the translation, and contains all other
   auxiliary info too.  */
typedef struct {
   /* Status of the slot.  Note, we need to be able to do lazy
      deletion, hence the Deleted state. */
   enum { InUse, Deleted, Empty } status;

   /* This is the original guest address that purportedly is the
      entry point of the translation.  You might think that .entry
      should be the same as .vge->base[0], and most of the time it
      is.  However, when doing redirections, that is not the case.
      .vge must always correctly describe the guest code sections
      from which this translation was made.  However, .entry may or
      may not be a lie, depending on whether or not we're doing
      redirection. */
   ulong entry;

   /* 64-bit aligned pointer to one or more 64-bit words containing
      the corresponding host code (must be in the same sector!)
      This is a pointer into the sector's tc (code) area. */
   u64* tcptr;


   /* This structure describes precisely what ranges of guest code
      the translation covers, so we can decide whether or not to
      delete it when translations of a given address range are
      invalidated. */
   VexGuestExtents vge;
} TrnsTabEntry;

typedef struct {
   /* The TCEntry area.  Size of this depends on the average
      translation size.  We try and size it so it becomes full
      precisely when this sector's translation table (tt) reaches
      its load limit (SECTOR_TT_LIMIT_PERCENT). */
   u64* tc;

   /* The TrnsTabEntry array.  This is a fixed size, always containing
      exactly N_TTES_PER_SECTOR entries. */
   TrnsTabEntry tt[N_TTES_PER_SECTOR];

   /* This points to the current allocation point in tc. */
   u64* tc_next;

   /* The count of tt entries with state InUse. */
   int tt_n_inuse;
} Sector;

/* The root data structure is an array of sectors.  The index of the
   youngest sector is recorded, and new translations are put into that
   sector.  When it fills up, we move along to the next sector and
   start to fill that up, wrapping around at the end of the array.
   That way, once all N_TC_SECTORS have been bought into use for the
   first time, and are full, we then re-use the oldest sector,
   endlessly. 

   When running, youngest sector should be between >= 0 and <
   N_TC_SECTORS.  The initial -1 value indicates the TT/TC system is
   not yet initialised. 
*/
static Sector sectors[N_SECTORS];
static int    youngest_sector = -1;

/* The number of u64s in each TCEntry area.  This is computed once
   at startup and does not change. */
static size_t  tc_sector_szQ;
static size_t  tc_sector_szQ_bytes;

/* Fast helper for the TC.  A direct-mapped cache which holds a set of
   recently used (guest address, host address) pairs.  This array is
   referred to directly from m_dispatch/dispatch-<platform>.S.

   Entries in tt_fast may refer to any valid TC entry, regardless of
   which sector it's in.  Consequently we must be very careful to
   invalidate this cache when TC entries are changed or disappear.

   A special .guest address - TRANSTAB_BOGUS_GUEST_ADDR -- must be
   pointed at to cause that cache entry to miss.  This relies on the
   assumption that no guest code actually has that address, hence a
   value 0x1 seems good.  m_translate gives the client a synthetic
   segfault if it tries to execute at this address.
*/
/*
typedef
   struct { 
      Addr guest;
      Addr host;
   }
   FastCacheEntry;
*/
/*global*/ 
__attribute__((aligned(16))) FastCacheEntry tt_fast[TT_FAST_SIZE];

/* Reader/writer lock used to protect translation table
 * and cache, and VEX internal buffers against concurrent
 * thread access while performing translation. */
volatile int tt_lock = RW_LOCK_INIT;

#define VEX_CODE_BUFSZ 60000

/* Where we hold translated code before copying it into
 * the translation cache. Necessary b/c we need to determine
 * the size of the code block before placing the translated
 * code in the code cache (otherwise we must assume some
 * large upper bound and that's wastefull of memory) */
static uchar tc_staging_buf[VEX_CODE_BUFSZ];
static u64 n_disc_count = 0;
static int initDone = 0;

#if DEBUG
uint nrFlushes = 0;
uint order = 0;
#endif

#define TRANSTAB_BOGUS_GUEST_ADDR ((ulong)1)

static void
TrnsTabInvalidateFastCache()
{
   int j;

   DEBUG_MSG(4, "Flushing fast cache.\n");

   for (j = 0; j < TT_FAST_SIZE; j++) {
      tt_fast[j].guest = TRANSTAB_BOGUS_GUEST_ADDR;
   }

   DEBUG_ONLY(nrFlushes++;)
}

static void 
TrnsTabSetFastCache(ulong key, u64* tcptr)
{
   uint cno = (uint) TT_FAST_HASH(key);

   ASSERT(cno >= 0 && cno < TT_FAST_SIZE);

   tt_fast[cno].guest = (ulong) key;
   tt_fast[cno].host  = (ulong) tcptr;

   ASSERT(Task_IsAddrInUser(tt_fast[cno].guest));
}

#if DEBUG
static int 
isValidSector(int sector)
{
   if (sector < 0 || sector >= N_SECTORS)
      return 0;
   return 1;
}
#endif

static INLINE
uint HASH_TT ( u64 key )
{
   uint kHi = (uint)(key >> 32);
   uint kLo = (uint)key;
   uint k32 = kHi ^ kLo;
   uint ror = 7;
   if (ror > 0)
      k32 = (k32 >> ror) | (k32 << (32-ror));
   return k32 % N_TTES_PER_SECTOR;
}

static void
TrnsTabInitSector(int sno)
{
   int i;
   Sector* sec;

   ASSERT(isValidSector(sno));

   sec = &sectors[sno];

   if (sec->tc == NULL) {
      /* Sector has never been used before.  Need to allocate tt and
         tc. */
      ulong tcStart;
      int err;

      ASSERT(sec->tc_next == NULL);
      ASSERT(sec->tt_n_inuse == 0);

      ASSERT(tc_sector_szQ_bytes > 0);
      ASSERT(PAGE_ALIGNED(tc_sector_szQ_bytes));

      tcStart = __TC_START + tc_sector_szQ_bytes*sno;
      DEBUG_MSG(5, "tc start=0x%x size=%d\n", tcStart, tc_sector_szQ_bytes);
      err = syscall(SYS_mmap2, tcStart, tc_sector_szQ_bytes,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      ASSERT(!SYSERR(err));


      sec->tc = (u64*) tcStart;
      /* XXX: Put this on the dynamic heap rather than the static heap,
       * so we can be memory efficient. */
#if 0
      sec->tt = HeapArea_Malloc(N_TTES_PER_SECTOR * sizeof(TrnsTabEntry));
#endif

      for (i = 0; i < N_TTES_PER_SECTOR; i++) {
         sec->tt[i].status = Empty;
      }
   } else {
      /* Sector has been used before.  Dump the old contents. */
      DEBUG_MSG(4, "recycling sector %d\n", sno);
      ASSERT(sec->tt != NULL);
      ASSERT(sec->tc_next != NULL);

      /* Visit each just-about-to-be-abandoned translation. */
      for (i = 0; i < N_TTES_PER_SECTOR; i++) {
         sec->tt[i].status   = Empty;
      }
   }

   sec->tc_next = sec->tc;
   sec->tt_n_inuse = 0;

   /* XXX: why flush for newly allocated, non-recycled sectors? */
   TrnsTabInvalidateFastCache();
}

static void
TrnsTabAdd(VexGuestExtents* vge,
      ulong           entry,
      uchar*           code,
      int             code_len)
{
   int tcAvailQ, reqdQ, y, i;
   u64 *tcptr, *tcptr2;
   uchar *srcP, *dstP;

   DEBUG_MSG(5, "adding translation: entry=0x%x code_len=%d gen=%d\n", 
         entry, code_len, nrFlushes);

   ASSERT(Task_IsAddrInUser(entry));
   ASSERT(vge->n_used >=1 && vge->n_used <= 3);
   ASSERT(code_len > 0 && code_len <= VEX_CODE_BUFSZ);

   y = youngest_sector;
   ASSERT(isValidSector(y));

   if (sectors[y].tc == NULL) {
      TrnsTabInitSector(y);
   }

   /* Try putting the translation in this sector. */

   /* This is equivalent to: ciel(code_len / 8) . */
   reqdQ = (code_len + 7) >> 3;

   /* Will it fit in tc? */
   tcAvailQ = ((u64*)(&sectors[y].tc[tc_sector_szQ]))
      - ((u64*)(sectors[y].tc_next));
   ASSERT(tcAvailQ >= 0);
   ASSERT(tcAvailQ <= tc_sector_szQ);

   if (tcAvailQ < reqdQ 
         || sectors[y].tt_n_inuse >= N_TTES_PER_SECTOR_USABLE) {
      /* No.  So move on to the next sector.  Either it's never been
         used before, in which case it will get its tt/tc allocated
         now, or it has been used before, in which case it is set to be
         empty, hence throwing out the oldest sector. */
      ASSERT(tc_sector_szQ > 0);
      DEBUG_MSG(4,
            "declare sector %d full "
            "(TT loading %2d%%, TC loading %2d%%)\n",
            y,
            (100 * sectors[y].tt_n_inuse) 
            / N_TTES_PER_SECTOR,
            (100 * (tc_sector_szQ - tcAvailQ)) 
            / tc_sector_szQ);
      youngest_sector++;
      if (youngest_sector >= N_SECTORS) {
         youngest_sector = 0;
      }
      y = youngest_sector;
      TrnsTabInitSector(y);
   }

   /* Be sure ... */
   tcAvailQ = ((u64*)(&sectors[y].tc[tc_sector_szQ]))
      - ((u64*)(sectors[y].tc_next));
   ASSERT(tcAvailQ >= 0);
   ASSERT(tcAvailQ <= tc_sector_szQ);
   ASSERT(tcAvailQ >= reqdQ);
   ASSERT(sectors[y].tt_n_inuse < N_TTES_PER_SECTOR_USABLE);
   ASSERT(sectors[y].tt_n_inuse >= 0);

   /* Copy into tc. */
   tcptr = sectors[y].tc_next;
   ASSERT(tcptr >= &sectors[y].tc[0]);
   ASSERT(tcptr <= &sectors[y].tc[tc_sector_szQ]);

   dstP = (uchar*)tcptr;
   srcP = (uchar*)code;
   for (i = 0; i < code_len; i++)
      dstP[i] = srcP[i];
   sectors[y].tc_next += reqdQ;
   sectors[y].tt_n_inuse++;

   /* more paranoia */
   tcptr2 = sectors[y].tc_next;
   ASSERT(tcptr2 >= &sectors[y].tc[0]);
   ASSERT(tcptr2 <= &sectors[y].tc[tc_sector_szQ]);

   /* Find an empty tt slot, and use it.  There must be such a slot
      since tt is never allowed to get completely full. */
   i = HASH_TT(entry);
   ASSERT(i >= 0 && i < N_TTES_PER_SECTOR);
   while (1) {
      if (sectors[y].tt[i].status == Empty
            || sectors[y].tt[i].status == Deleted) {
         break;
      }
      i++;
      if (i >= N_TTES_PER_SECTOR) {
         i = 0;
      }
   }

   sectors[y].tt[i].status = InUse;
   sectors[y].tt[i].tcptr  = tcptr;
   sectors[y].tt[i].vge    = *vge;
   sectors[y].tt[i].entry  = entry;

   TrnsTabSetFastCache(entry, tcptr);
}

/* Search for the translation of the given guest address.  If
   requested, a successful search can also cause the fast-caches to be
   updated.  
   */
static int 
TrnsTabSearch( /*OUT*/ ulong* result,
      ulong        guest_addr, 
      int          upd_cache )
{
   int i, j, k, kstart, sno;

   ASSERT(youngest_sector >= 0);

   /* Find the initial probe point just once.  It will be the same in
      all sectors and avoids multiple expensive % operations. */
   k      = -1;
   kstart = HASH_TT(guest_addr);
   ASSERT(kstart >= 0 && kstart < N_TTES_PER_SECTOR);

   /* Search in all the sectors.  Although the order should not matter,
      it might be most efficient to search in the order youngest to
      oldest. */
   sno = youngest_sector;
   for (i = 0; i < N_SECTORS; i++) {

      if (sectors[sno].tc == NULL)
         goto notfound; /* sector not in use. */

      k = kstart;
      for (j = 0; j < N_TTES_PER_SECTOR; j++) {
         if (sectors[sno].tt[k].status == InUse
               && sectors[sno].tt[k].entry == guest_addr) {
            /* found it */
            if (upd_cache)
               TrnsTabSetFastCache(guest_addr, sectors[sno].tt[k].tcptr);
            if (result)
               *result = (ulong) sectors[sno].tt[k].tcptr;
            return 1;
         }
         if (sectors[sno].tt[k].status == Empty)
            break; /* not found in this sector */
         k++;
         if (k == N_TTES_PER_SECTOR)
            k = 0;
      }

      /* If we fall off the end, all entries are InUse and not
         matching, or Deleted.  In any case we did not find it in this
         sector. */

notfound:
      /* move to the next oldest sector */
      sno = sno==0 ? (N_SECTORS-1) : (sno-1);
   }

   /* Not found in any sector. */
   return 0;
}

void
TrnsTab_HandleFastMiss()
{
   int found, codeLen;
   TaskRegs *regs = Task_GetCurrentRegs();
   VexGuestExtents vge;

   ulong entry = regs->R(eip);

   ASSERT(initDone);

   Spin_WriteLock(&tt_lock);

   DEBUG_ONLY(order++;)

   found = TrnsTabSearch(NULL, entry, 1 /* update fast cache */);

   if (!found) {
      DEBUG_MSG(6, "0x%x: Missed in translation table (order=%d)\n", entry, 
            order);

      /* Must first translate into staging buffer to determine
       * size of translated code block. Then we can efficiently
       * pack the translation into the TC.
       *
       * XXX: Slow -- requires copying from staging buf to TC. Problem
       * is that we don't know length of x86 instructions until we
       * finish decoding them...but perhaps we can establish a tight
       * upper-bound somehow? */
      BT_TranslateBlock(entry, tc_staging_buf,
            VEX_CODE_BUFSZ, &codeLen, &vge);

      TrnsTabAdd(&vge, entry, tc_staging_buf, codeLen);

#if DEBUG
      found = TrnsTabSearch(NULL, entry, 0);
      ASSERT(found);
#endif
   } else {
      DEBUG_MSG(6, "0x%x: Hit in translation table (order=%d)\n", entry, 
            order);
   }

   Spin_WriteUnlock(&tt_lock);
}

static INLINE int 
overlap1(ulong s1, ulong r1, ulong s2, ulong r2)
{
   ulong e1 = s1 + r1 - 1ULL;
   ulong e2 = s2 + r2 - 1ULL;
   if (e1 < s2 || e2 < s1) 
      return 0;

   return 1;
}

static INLINE int
TrnsTabOverlaps(ulong start, ulong range, VexGuestExtents* vge)
{
   if (overlap1(start, range, (ulong)vge->base[0], (ulong)vge->len[0]))
      return 1;
   if (vge->n_used < 2)
      return 0;
   if (overlap1(start, range, (ulong)vge->base[1], (ulong)vge->len[1]))
      return 1;
   if (vge->n_used < 3)
      return 0;
   if (overlap1(start, range, (ulong)vge->base[2], (ulong)vge->len[2]))
      return 1;
   return 0;
}

/* Delete a tt entry, and update all the eclass data accordingly. */

static void 
TrnsTabDeleteTte( /*MOD*/Sector* sec, int tteno )
{
   TrnsTabEntry* tte;

   ASSERT(tteno >= 0 && tteno < N_TTES_PER_SECTOR);
   tte = &sec->tt[tteno];
   ASSERT(tte->status == InUse);

   /* Now fix up this TrnsTabEntry. */
   tte->status   = Deleted;

   n_disc_count++;

   /* Stats .. */
   sec->tt_n_inuse--;
}

/* Delete translations from sec which intersect specified range, the
   slow way, by inspecting all translations in sec. */

static int
TrnsTabDeleteInSector( /*MOD*/Sector* sec, 
      ulong guest_start, size_t range )
{
   int  i;
   int anyDeld = 0;

   for (i = 0; i < N_TTES_PER_SECTOR; i++) {
      if (sec->tt[i].status == InUse
          && TrnsTabOverlaps( guest_start, range, &sec->tt[i].vge)) {
         anyDeld = 1;
         TrnsTabDeleteTte( sec, i );
      }
   }

   return anyDeld;
} 

void
TrnsTab_Invalidate(ulong guest_start, size_t range)
{
   Sector* sec;
   int     sno;
   int    anyDeleted = 0;


   ASSERT(initDone);
   ASSERT(range > 0);
#ifdef YOU_WANT_THIS_TO_TRIGGER_BECAUSE_IT_DEFINITELY_WILL_FOR_BASH
   ASSERT(!MemOps_Intersects(guest_start, range, __IMAGE_START,
            __IMAGE_LEN, NULL, NULL));
#endif

   ASSERT_MSG(!current->is_in_code_cache, 
         "Don't invalidate when executing translated "
         "code. Because doing so risks invalidating the currently "
         "executing translation. That would be akin to using a freed "
         "object, and horrible things may happen.\n");

#if 0
   /* Pre-deletion sanity check */
   if (VG_(clo_sanity_level >= 4)) {
      int sane = sanity_check_all_sectors();
      vg_assert(sane);
   }
#endif

   Spin_WriteLock(&tt_lock);

   DEBUG_ONLY(order++;)

   DEBUG_MSG(4, "discard_translations(0x%lx, %lu) (order=%d)\n",
         guest_start, range, order);

   
   for (sno = 0; sno < N_SECTORS; sno++) {
      sec = &sectors[sno];
      if (sec->tc == NULL)
         continue;
      anyDeleted |= TrnsTabDeleteInSector( sec, guest_start, range );
   }

   
   if (anyDeleted) {
      TrnsTabInvalidateFastCache(); 
   }

   Spin_WriteUnlock(&tt_lock);
}

void
TrnsTab_InvalidateAll()
{
   TrnsTab_Invalidate(0, __IMAGE_START);
} 

void
TrnsTab_OnVmaUnmap(const struct VmaStruct *vma, ulong istart, size_t ilen)
{
   /* We don't have the ability to invalidate a translation in another
    * addresspace, so we must make the assumption that the vma is
    * from our address space. */
   ASSERT(vma->mm);
   ASSERT(vma->mm == current->mm);

   TrnsTab_Invalidate(istart, ilen);
}


void
TrnsTab_Fork(struct Task *tsk)
{
   if (Task_IsThread(tsk)) {
      return;
   }

   /* Sectors, TT, and TC are in private, copy on write region. 
    * So nothing to do here. */
}

void
TrnsTab_SelfInit()
{
   if (Task_IsThread(current)) {
      return;
   }

   tt_lock = RW_LOCK_INIT;

#if TRNSTAB_FLUSH_ON_FORK
   /* Wipe out all cached translations. */
   TrnsTab_Invalidate(0, __LINUX_KERNEL_START);
#endif

#if DEBUG
   nrFlushes = 0;
   order = 0;
#endif
   tt_lock = RW_LOCK_INIT;
}

int
TrnsTab_Init()
{
   int i;
   size_t avg_codeszQ;

   ASSERT(tt_lock == RW_LOCK_BIAS);
   ASSERT(sizeof(FastCacheEntry) == 2 * sizeof(void*));
   ASSERT(TT_FAST_SIZE > 0 && (TT_FAST_SIZE % 4) == 0);

   /* Figure out how big each tc area should be.  */
   avg_codeszQ   = (VK_DEFAULT_TRANS_SIZEB + 7) / 8;
   tc_sector_szQ = N_TTES_PER_SECTOR_USABLE * (1 + avg_codeszQ);
   tc_sector_szQ_bytes = PAGE_ALIGN(tc_sector_szQ * 8);
#define MAX_TC_SIZE (__TC_END - __TC_START)
   ASSERT(tc_sector_szQ_bytes > 0 && tc_sector_szQ_bytes <= MAX_TC_SIZE);
   ASSERT(__TC_START + N_SECTORS*tc_sector_szQ_bytes <= __TC_END);

   /* Ensure the calculated value is not way crazy. */
   ASSERT(tc_sector_szQ >= 2 * N_TTES_PER_SECTOR_USABLE);
   ASSERT(tc_sector_szQ <= 80 * N_TTES_PER_SECTOR_USABLE);
   ASSERT(PAGE_ALIGNED(tc_sector_szQ_bytes));

   DEBUG_MSG(5, "avg_codesz=%d bytes  tc size=%d bytes\n", 
         avg_codeszQ * 8, tc_sector_szQ_bytes);

   /* Initialise the sectors */
   youngest_sector = 0;
   for (i = 0; i < N_SECTORS; i++) {
      sectors[i].tc = NULL;
#if 0
      sectors[i].tt = NULL;
#endif
      sectors[i].tc_next = NULL;
      sectors[i].tt_n_inuse = 0;
   }

   TrnsTabInvalidateFastCache();

   initDone = 1;
   ASSERT(tt_lock == RW_LOCK_BIAS);

   return 0;
}
