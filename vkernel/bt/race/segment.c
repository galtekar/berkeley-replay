/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

#define EXPECTED_MAX_ACCESS_SECTORS 200
#define EXPECTED_MAX_EP_SECTORS     (EXPECTED_MAX_ACCESS_SECTORS*2)

static const size_t ep_table_sz = sizeof(struct ExecPoint) * N_EP_PER_SECTOR;
static const size_t access_table_sz = sizeof(struct Access) * 
                        N_ACCESS_PER_SECTOR;

static struct ExecPointSector *
SegmentInsnInitSector(struct Segment *seg, int sno)
{
   struct ExecPointSector *sec;

   if (sno >= EXPECTED_MAX_EP_SECTORS) {
      LOG("WARNING: sno=%d, exceed max expected. \n", sno);
   } else {
      DEBUG_MSG(5, "Allocating insn sec %d, %d bytes\n",
            sno, ep_table_sz);
   }

   sec = SharedArea_Malloc(sizeof(*sec));
   ASSERT(sec);
   List_AddTail(&sec->list, &seg->ep_sec_list);

   sec->t = SharedArea_Malloc(ep_table_sz);
   ASSERT(sec->t);

   sec->t_n_inuse = 0;

   return sec;
}

static INLINE struct ExecPointSector *
SegmentGetExecPointTail(struct ListHead *secHead)
{
   struct ExecPointSector * sec;

   if (List_IsEmpty(secHead)) {
      sec = NULL;
   } else {
      sec = list_entry(secHead->prev, struct ExecPointSector, list);
   }

   return sec;
}

/*
 * Returns pointer to instruction descriptor in segment storage. 
 */
static INLINE struct ExecPoint *
SegmentInsnInsert(struct Segment *seg, struct ExecPoint *in_ep)
{
   ASSERT(seg);

   int sno = seg->idx_ep_sec;
   struct ExecPointSector *sec = SegmentGetExecPointTail(&seg->ep_sec_list);
   struct ExecPoint *ep;

   if (!sec) {
      sec = SegmentInsnInitSector(seg, sno);
   }

   if (sec->t_n_inuse >= N_EP_PER_SECTOR) {
      sno = ++seg->idx_ep_sec;
      ASSERT(sno == seg->idx_ep_sec);
      sec = SegmentInsnInitSector(seg, sno);
   }

   ASSERT(sec);
   ASSERT(sec->t);

   ep = &sec->t[sec->t_n_inuse];
   *ep = *in_ep;
   sec->t_n_inuse++;

   return ep;
}

static INLINE
uint HASH ( u64 key )
{
   uint kHi = (uint)(key >> 32);
   uint kLo = (uint)key;
   uint k32 = kHi ^ kLo;
   uint ror = 7;
   if (ror > 0)
      k32 = (k32 >> ror) | (k32 << (32-ror));
   return k32 % N_ACCESS_PER_SECTOR;
}

static struct AccessSector *
SegmentHashInitSector(struct ListHead *secHead, int sno)
{
   int i;
   struct AccessSector *sec;

   if (sno >= EXPECTED_MAX_ACCESS_SECTORS) {
      LOG("WARNING: sno=%d, exceed max expected. \n", sno);
   } else {
      DEBUG_MSG(5, "Allocating hash sno %d, %d bytes\n",
            sno, access_table_sz);
   }

   sec = SharedArea_Malloc(sizeof(*sec));
   ASSERT(sec);
   memset(sec, 0, sizeof(*sec));
   List_AddTail(&sec->list, secHead);


   sec->t = SharedArea_Malloc(access_table_sz);
   ASSERT(sec->t);

   for (i = 0; i < N_ACCESS_PER_SECTOR; i++) {
      sec->t[i].status = Empty;
   }

   sec->t_n_inuse = 0;

   return sec;
}

static INLINE struct AccessSector *
SegmentGetAccessTail(struct ListHead *secHead)
{
   struct AccessSector * sec;

   if (List_IsEmpty(secHead)) {
      sec = NULL;
   } else {
      sec = list_entry(secHead->prev, struct AccessSector, list);
   }

   return sec;
}

static INLINE void
SegmentInsertHash(struct ListHead *secHead, ushort *idx_sec, u64 gaddr, 
                  struct ExecPoint *ep)
{
   int sno = *idx_sec, i;
   struct AccessSector *sec = SegmentGetAccessTail(secHead);

   if (!sec) {
      sec = SegmentHashInitSector(secHead, sno);
   }


   if (sec->t_n_inuse >= N_ACCESS_PER_SECTOR) {
      sno = ++(*idx_sec);
      ASSERT(sno == *idx_sec);
      sec = SegmentHashInitSector(secHead, sno);
   }

   ASSERT(sec);
   ASSERT(sec->t);

   sec->t_n_inuse++;

   i = HASH(gaddr);
   ASSERT(i >= 0 && i < N_ACCESS_PER_SECTOR);

   /* There must be a spot, otherwise sec->t_n_inuse
    * would be >= N_ACCESS_PER_SECTOR and we would've
    * rotated to a new sector already. */
   while (1) {
      if (sec->t[i].status == Empty) {
         break;
      }
      i++;
      if (i >= N_ACCESS_PER_SECTOR) {
         i = 0;
      }
   }

   sec->t[i].status = InUse;
   sec->t[i].gaddr = gaddr;
   sec->t[i].ep = ep;
}

#define STRICT 1

static INLINE void
SegmentAddAccess(const int isRead, struct ListHead *secHead, ushort *idx_sec, 
                 struct ExecPoint *in_ep, const ulong vaddr, 
                 const uint accessLen)
{
   struct Segment *seg = curr_vcpu->segment;
#if STRICT
   u64 gaddr[ARCH_MAX_ACCESS_LEN];
   int i;
#else
   u64 gaddr;
#endif
   int accessesAtLeastOneFileByte = 0;


   ASSERT(accessLen > 0 && accessLen <= ARCH_MAX_ACCESS_LEN);
   ASSERT(current->mm->users > 0);
   ASSERT(seg);


#if STRICT
   /* The access may straddle multiple vmas -- e.g.,
    * first 2 bytes to shared memory, but last 2 bytes
    * to non-shared memory. This is rare, but we must
    * check for it. */
   for (i = 0; i < accessLen; i++) {
      gaddr[i] = GlobalAddr_FromVirt(current->mm, vaddr+i, isRead);
      if (GlobalAddr_IsFileAddr(gaddr[i])) {
         accessesAtLeastOneFileByte = 1;
      }
   }
#else
   /* Assume that access doesn't straddle multiple objects
    * (memory/file or file/file). */
   gaddr = GlobalAddr_FromVirt(vaddr, isRead);
   if (GlobalAddr_IsFileAddr(gaddr)) {
      accessesAtLeastOneFileByte = 1;
   }
#endif


   /* Optimization: Don't add the access to the segment if it isn't
    * to a file or if this is the only thread in the address space.
    *
    * XXX: rethink this carefully...
    *
    * No need to worry about mm->users changing if mm->users == 1,
    * since only this thread can change it. If mm->users > 1, of course
    * it may concurrently change -- if it decrements such that 
    * mm->users == 1, then we may race and add the access, but no harm 
    * done. */
   if (accessesAtLeastOneFileByte || current->mm->users > 1) {
      int j;
      struct ExecPoint *ep;

      ep = SegmentInsnInsert(seg, in_ep);
      ASSERT(ep);
      ASSERT(ep != in_ep);

      if (isRead) {
         seg->numReads++;
      } else {
         seg->numWrites++;
      }

      for (j = 0; j < accessLen; j++) {
#if STRICT
         SegmentInsertHash(secHead, idx_sec, gaddr[j], ep);
#else
         SegmentInsertHash(secHead, idx_sec, gaddr+j, ep);
#endif
      }
   }
}

void
Segment_AddRead(struct ExecPoint *in_ep, ulong vaddr, uint accessLen)
{
   struct Segment *seg = curr_vcpu->segment;

   SegmentAddAccess(1, &seg->read_sec_list, &seg->idx_read_sec, in_ep, vaddr, 
         accessLen);
}

void
Segment_AddWrite(struct ExecPoint *in_ep, ulong vaddr, uint accessLen)
{
   struct Segment *seg = curr_vcpu->segment;

   SegmentAddAccess(0, &seg->write_sec_list, &seg->idx_write_sec, in_ep, vaddr, 
         accessLen);
}


static struct ExecPoint *
SegmentLookupAccess(u64 gaddr, const struct ListHead *secHead)
{
   int j, k, kstart;
   struct AccessSector *sec;

   /* Find the initial probe point just once.  It will be the same in
      all sectors and avoids multiple expensive % operations. */
   k      = -1;
   kstart = HASH(gaddr);
   ASSERT(kstart >= 0 && kstart < N_ACCESS_PER_SECTOR);

   list_for_each_entry(sec, secHead, list) {

      if (sec->t == NULL) {
         goto notfound;
      }
  
      k = kstart;
      for (j = 0; j < N_ACCESS_PER_SECTOR; j++) {
         if (sec->t[k].status == InUse &&
             sec->t[k].gaddr == gaddr) {
            /* found it */

            return sec->t[k].ep;
         }

         if (sec->t[k].status == Empty) {
            break; /* not found in this sector */
         }
         k++;
         if (k == N_ACCESS_PER_SECTOR) {
            k = 0;
         }
      }
   }

notfound:
   return NULL;
}

static void
SegmentWriteRacePair(int raceFd, u64 gaddr, const struct RaceAccess *r1,
                       const struct RaceAccess *r2)
{
   int res;
   struct RacePair rr;

   ASSERT(raceFd >= 0);

   rr.gaddr = gaddr;
   rr.access1 = *r1;
   rr.access2 = *r2;

   Race_PrintRecord(&rr);

   res = write(raceFd, (void*)&rr, sizeof(rr));
   ASSERT(res == sizeof(rr));
}

/*
 * Note that if multiple bytes of instruction access intersect,
 * then we record the execution point of that access for each
 * byte. Hence the race output list is likely to have duplicates.
 */
static void
SegmentFindIntersection(const struct Segment *a_seg, 
                        const struct ListHead *a_sectors,
                        const struct Segment *b_seg, 
                        const struct ListHead *b_sectors)
{
   int j;
   struct AccessSector *sec;

   ASSERT(a_sectors == &a_seg->read_sec_list ||
          a_sectors == &a_seg->write_sec_list);
   ASSERT(b_sectors == &b_seg->read_sec_list ||
          b_sectors == &b_seg->write_sec_list);

   list_for_each_entry(sec, a_sectors, list) {
      if (sec->t == NULL) {
         return;
      }

      for (j = 0; j < N_ACCESS_PER_SECTOR; j++) {
         struct Access *a = &sec->t[j];

         if (a->status == InUse) {
            struct ExecPoint * b_ep;

            b_ep = SegmentLookupAccess(a->gaddr, b_sectors);

            if (b_ep) {
               ASSERT(VCPU_GetMode() & VCPU_MODE_RACEDETECT);
               ASSERT(NR_VCPU > 1);


               {
                  struct RaceAccess r_a, r_b;

                  r_a.loc.ep = *(a->ep);
                  r_b.loc.ep = *b_ep;
                  r_a.loc.task_id = a_seg->task_id;
                  r_b.loc.task_id = b_seg->task_id;
                  r_a.loc.vcpu_id = Segment_VCPU(a_seg)->id;
                  r_b.loc.vcpu_id = Segment_VCPU(b_seg)->id;
                  r_a.loc.vc = a_seg->vc;
                  r_b.loc.vc = b_seg->vc;
                  r_a.isRead = (a_sectors == &a_seg->read_sec_list);
                  r_b.isRead = (b_sectors == &b_seg->read_sec_list);


                  /* Found intersecting access. Write it to the race
                   * file. Here we assume that a_seg is the current
                   * task's segment. */
                  SegmentWriteRacePair(
                        Segment_VCPU(a_seg)->raceFd, a->gaddr, &r_a, &r_b);
                  //SegmentWriteRacePair(b_seg->fd, a->gaddr, &r_b, &r_a);
               }
            }
         }
      }
   }
}

void
Segment_DetectRaces(const struct Segment *a_seg, const struct Segment *b_seg)
{
   ASSERT(NR_VCPU > 1);

#define DETECT(x, y) \
   SegmentFindIntersection(a_seg, &a_seg->x, b_seg, &b_seg->y)

   /* Read-Write races. */
   DETECT(read_sec_list, write_sec_list);
   DETECT(write_sec_list, read_sec_list);

   /* Write-Write races. */
   DETECT(write_sec_list, write_sec_list);
}

struct Segment *
Segment_Alloc()
{
   struct Segment *seg;

   seg = SharedArea_Malloc(sizeof(*seg));
   memset(seg, 0, sizeof(*seg));

   List_Init(&seg->list);
   List_Init(&seg->ep_sec_list);
   List_Init(&seg->read_sec_list);
   List_Init(&seg->write_sec_list);

   seg->vcpu = curr_vcpu;
   seg->task_id = current->id;

   return seg;
}

static int
SegmentFreeAccessSectors(struct ListHead *secHead)
{
   int numSecsDeleted = 0;

   struct AccessSector *asp, *as_dummy;
   list_for_each_entry_safe(asp, as_dummy, secHead, list) {
      ASSERT(asp->t);
      DEBUG_MSG(5, "Freeing access sector: in_use=%d, max=%d\n", 
            asp->t_n_inuse, N_ACCESS_PER_SECTOR);
      SharedArea_Free(asp->t, access_table_sz);
      asp->t = NULL;
      List_Del(&asp->list);
      SharedArea_Free(asp, sizeof(*asp));
      numSecsDeleted++;
   }

   return numSecsDeleted;
}

void
Segment_Free(struct Segment *seg)
{
#if DEBUG
   int vcpu_id = Segment_VCPU(seg)->id;
#endif
   int numEpSecsDeleted = 0, numReadSecsDeleted = 0, numWriteSecsDeleted = 0;
   struct ExecPointSector *exp, *ex_dummy;
   ASSERT(vcpu_id >= 0 && vcpu_id < NR_VCPU);
   ASSERT(curr_vcpu->id == vcpu_id ||
          curr_vcpu->id != vcpu_id);

   list_for_each_entry_safe(exp, ex_dummy, &seg->ep_sec_list, list) {
      ASSERT(exp->t);
      DEBUG_MSG(5, "Freeing ep sector: in_use=%d, max=%d\n", 
            exp->t_n_inuse, N_EP_PER_SECTOR);
      SharedArea_Free(exp->t, ep_table_sz);
      exp->t = NULL;
      List_Del(&exp->list);
      SharedArea_Free(exp, sizeof(*exp));
      numEpSecsDeleted++;
   }

   numReadSecsDeleted = SegmentFreeAccessSectors(&seg->read_sec_list);
   numWriteSecsDeleted = SegmentFreeAccessSectors(&seg->write_sec_list);

#if DEBUG
   if (seg->numReads || seg->numWrites) {
      ASSERT(numEpSecsDeleted > 0);
   } else {
      ASSERT(numEpSecsDeleted == 0);
   }

   if (seg->numReads) {
      ASSERT(numReadSecsDeleted > 0);
   } else {
      ASSERT(numReadSecsDeleted == 0);
   }

   if (seg->numWrites) {
      ASSERT(numWriteSecsDeleted > 0);
   } else {
      ASSERT(numWriteSecsDeleted == 0);
   }
#endif

   SharedArea_Free(seg, sizeof(*seg));
   seg = NULL;
}

void
Segment_OpenRaceLog(struct VCPU *vcpu, int isCreate)
{
   int res;
   char *filename;

   filename = SharedArea_Malloc(PATH_MAX);

   res = snprintf(filename, PATH_MAX, "%s/vcpu-races.%d", 
                  session.dir, vcpu->id);
   ASSERT(res < PATH_MAX);

   vcpu->raceFd = syscall(SYS_open, filename, 
         isCreate ? (O_CREAT | O_RDWR | O_TRUNC) : O_RDONLY, S_IRUSR | S_IWUSR);

   if (vcpu->raceFd < 0) {
      FATAL("can't open race log file ``%s''.\n", filename);
   }

   SharedArea_Free(filename, PATH_MAX);
   filename = NULL;
}

void
Segment_CloseRaceLog(struct VCPU *vcpu)
{
   ASSERT(vcpu->raceFd >= 0);
   SysOps_Close(vcpu->raceFd);
   vcpu->raceFd = -1;
}

int
Segment_Init()
{
   int i;

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpu = VCPU_Ptr(i);

      if (VCPU_TestMode(VCPU_MODE_RACEDETECT)) {
         Segment_OpenRaceLog(vcpu, 1);
      } else {
         vcpu->raceFd = -1;
      }
   }

   ASSERT(0 < N_EP_PER_SECTOR && N_EP_PER_SECTOR <= USHRT_MAX);
   ASSERT(0 < N_ACCESS_PER_SECTOR && N_ACCESS_PER_SECTOR <= USHRT_MAX);

   return 0;
}
