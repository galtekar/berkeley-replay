#pragma once

#include "../private.h"


extern int  SegEvent_Init();

#define N_EP_PER_SECTOR    100

/* Number of read OR write (not both) accesses in each sector. 
 * Since each entry corresponds to an access of one byte,
 * this should be larger than the N_EP_PER_SECTOR.
 * Since most accesses are word-sized, it makes sense
 * to multiply by 4. But note that this needs to be a prime
 * number in order for hashing to work effectively. 
 * Also, must be <= 2^16 so it can fit in a ushort. */
#define N_ACCESS_PER_SECTOR  401

struct Access {
   /* The global-address of the memory access target location. */
   u64 gaddr;

   /* Pointer to instruction descriptor of instruction that
    * made the access. */
   struct ExecPoint *ep;

   /* Status of the hashtable slot. */
   enum { InUse, Empty } status;
};


struct ExecPointSector {
   struct ExecPoint *t;
   ushort            t_n_inuse;
   struct ListHead   list;
};

struct AccessSector {
   struct Access     *t;
   ushort            t_n_inuse;
   struct ListHead   list;
};

struct Segment {
   /* VCPU from which this segment originated -- we shouldn't
    * hold a struct Task * reference since it may not always be
    * valid -- the segment may endure even after the corresponding
    * task terminates. . */
   struct VCPU * vcpu;

   /* XXX: once perfctrs are made per-vcpu rather than per-task,
    * we won't need this anymore -- we won't need to know from
    * which task the race came from. */
   int task_id;

   struct VectorClock vc;

   uint numReads, numWrites;

   /* Counts the number (actually, the index) of sectors. */
   ushort idx_ep_sec, idx_read_sec, idx_write_sec;

   /* Linked-lists of sectors. */
   struct ListHead ep_sec_list, read_sec_list, write_sec_list;

   /* Links segment to the global segment list, once inserted there. */
   struct ListHead list;
};

static INLINE struct VCPU *
Segment_VCPU(const struct Segment *segp)
{
   return segp->vcpu;
}

static INLINE void
Segment_Print(const struct Segment *segp)
{
   DEBUG_ONLY(DECLARE_VCSTR(s1);)

   DEBUG_MSG(5, "Segment: %d.%s\n",
         Segment_VCPU(segp)->id, 
         VectorClock_ToStr(s1, &segp->vc));
}

static INLINE void
Segment_PrintWithStats(const struct Segment *segp)
{
   DEBUG_ONLY(DECLARE_VCSTR(s1);)

   DEBUG_MSG(5, "Segment: %d.%s -- %6d, %6d\n", 
         Segment_VCPU(segp)->id, 
         VectorClock_ToStr(s1, &segp->vc),
         segp->numReads, segp->numWrites);
}

static INLINE int
Segment_IsEmpty(const struct Segment *segp)
{
   return !(segp->numReads || segp->numWrites);
}

extern struct Segment * Segment_Alloc();
extern void             Segment_Free(struct Segment *);
extern void             Segment_DetectRaces(const struct Segment *a_seg, 
                                            const struct Segment *b_seg);

extern int              Segment_Init();

extern int              MemTrace_Init();

STATS_ONLY(extern int statsTraceButDontAddToSegment;)
