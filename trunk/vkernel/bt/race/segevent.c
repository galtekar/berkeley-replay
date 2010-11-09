#include "vkernel/public.h"
#include "private.h"

/*
 * Vector clocks are transmiatted through channels.
 * There is one channel for each lock, stored in
 * a hash map keyed by the lock's address.
 *
 * XXX: when are channels deallocated? 
 *
 */
static SHAREDAREA struct MapStruct * channelMap = NULL;

/* 
 * Protects access to channel map and segment queue.
 * The VCPU lock is insufficient to protect those since
 * different threads in the same address space may belong
 * to different VCPUs. 
 */
SYNCH_DECL_INIT(static SHAREDAREA, evLock);

/*
 * Where we store all completed segments. Segments in this
 * list are eventually garbage collected.
 */
static SHAREDAREA LIST_HEAD(segList);


struct ChannelStruct {
   struct MapField addrMap;
   struct VectorClock vc;
};

static struct ChannelStruct *
ChannelAlloc(ulong key)
{
   struct ChannelStruct *chnp;

   chnp = SharedArea_Malloc(sizeof(*chnp));
   memset(chnp, 0, sizeof(*chnp));

   chnp->addrMap.keyLong = key;

   return chnp;
} 

struct ChannelStruct *
ChannelLookupCreate(ulong key)
{
   struct ChannelStruct *chnp;

   ASSERT(key > 0);
   ASSERT(channelMap);

   Map_Find(channelMap, addrMap, key, chnp);

   if (!chnp) {
      chnp = ChannelAlloc(key);
      Map_Insert(channelMap, addrMap, key, chnp);
   }

   ASSERT(chnp);

   return chnp;
}

void
ChannelUpdate(struct ChannelStruct *chnp, struct VectorClock *vcp)
{
   VectorClock_Update(&chnp->vc, vcp);
}


static void
SegEventSend(ulong key, struct Segment *seg)
{
   struct ChannelStruct *chnp;
#if DEBUG
   DECLARE_VCSTR(s1);
   DECLARE_VCSTR(s2);
   DECLARE_VCSTR(s3);
   struct VectorClock old_cvc;
#endif

   ASSERT(seg);

   chnp = ChannelLookupCreate(key);
 
   DEBUG_ONLY(old_cvc = chnp->vc;)

   ChannelUpdate(chnp, &seg->vc);

   DEBUG_MSG(5, "0x%x: %s <-- %s.update(%s)\n",
         key, VectorClock_ToStr(s1, &chnp->vc),
         VectorClock_ToStr(s2, &old_cvc),
         VectorClock_ToStr(s3, &seg->vc));
}

static void
SegEventRecv(ulong key, struct Segment *seg)
{
   struct ChannelStruct *chnp;
#if DEBUG
   DECLARE_VCSTR(s1);
   DECLARE_VCSTR(s2);
   DECLARE_VCSTR(s3);
   struct VectorClock old_vc = seg->vc;
#endif

   ASSERT(seg);

   chnp = ChannelLookupCreate(key);

   VectorClock_Update(&seg->vc, &chnp->vc);
   DEBUG_MSG(5, "%s <-- %s.update(0x%x: %s)\n",
         VectorClock_ToStr(s1, &seg->vc),
         VectorClock_ToStr(s2, &old_vc),
         key,
         VectorClock_ToStr(s3, &chnp->vc));
}

/*
 * Protects the global segment list. 
 */
static void
SegEventLock()
{
   SYNCH_LOCK(&evLock);
}

static void
SegEventUnlock()
{
   SYNCH_UNLOCK(&evLock);
}

#if DEBUG
static int
SegEventIsLocked()
{
   return SYNCH_IS_LOCKED(&evLock);
}
#endif


static void
SegmentAdvance(struct Segment *seg)
{
   struct VCPU *vcpu = Task_GetVCPU(current);

   ASSERT(vcpu->id >= 0 && vcpu->id < NR_VCPU);

   VectorClock_Increment(&seg->vc, vcpu->id);
}



/*
 * Here we look at the vector clocks of all VCPUs to figure
 * out what everyone knows. */
static void
SegEventComputeCommonKnowledge(struct VectorClock *commonVec)
{
   int i;

   ASSERT(SegEventIsLocked());
   ASSERT(VCPU_IsLocked(curr_vcpu));
   DEBUG_ONLY(DECLARE_VCSTR(s1);)

   VectorClock_InitWithMax(commonVec);

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpu = VCPU_Ptr(i);

      /* You could use VCPU_IsActive() here -- but you don't
       * have @vcpu's lock --- that may be okay ... */
      if (vcpu->segment) {
         VectorClock_Minimize(commonVec, &vcpu->segment->vc);
      } else {
         /* 
          * VCPU is inactive -- perhaps because all tasks
          * on it have been suspended, are in waitqueues,
          * blocked, or a combination of these. Or simply 
          * because there are no tasks scheduled on it yet. 
          */
      }
   }

   DEBUG_MSG(5, "Common knowledge: %s\n", 
         VectorClock_ToStr(s1, commonVec));
}

static void
SegEventGarbageCollect()
{
   struct VectorClock commonVec;
   struct Segment *seg, *tmp;
   int numSegs = 0, numDeleted = 0;

   ASSERT(SegEventIsLocked());

   SegEventComputeCommonKnowledge(&commonVec);

   DEBUG_MSG(5, "Garbage collecting segments:\n");

   list_for_each_entry_safe(seg, tmp, &segList, list) {
      int id = seg->vcpu->id;

      //Segment_PrintWithStats(seg);

      /* Will there be any future segments (on any VCPU)
       * that will be parallel to the segment pointed to by @seg?
       * If so, we cannot garbage collect @seg, since those
       * future parallel segments will need to check with seg
       * for intersections. */
      if (VectorClock_GetElem(&seg->vc, id) <=
          VectorClock_GetElem(&commonVec, id)) {


         /* Looks like everyone knows about this segment,
          * and hence seg happens-before any current segment
          * on any VCPU, and hence any current or future
          * segments will never be parallel to seg.
          * Thus it's safe to delete seg. */

         //DEBUG_MSG(5, "Deleting.\n");

         List_DelInit(&seg->list);
         Segment_Free(seg);
         seg = NULL;

         numDeleted++;
      }
      numSegs++;
   }

#if DEBUG
   if (NR_VCPU == 1) {
      int val;

      seg = curr_vcpu->segment;
      /* VCPU may no longer be active. */
      ASSERT(seg || !seg);

      if (seg) {
         ASSERT(seg->vcpu == curr_vcpu);

         val = VectorClock_GetElem(&seg->vc, seg->vcpu->id);
         ASSERT(val >= 1);

         if (val != 1) {
            ASSERT(SegEventIsLocked());

            /* Should've deleted the previous segment. */
            ASSERT(numDeleted <= 1);
         }
      }

      /* There should be nothing to garbage collect. */
      ASSERT(List_IsEmpty(&segList));
   }

   DEBUG_MSG(5, "%d of %d segments deleted.\n", numDeleted, numSegs);
#endif
}

static void
SegEventDetectRaces(struct Segment *curr_seg)
{
   struct Segment *seg;

   ASSERT(SegEventIsLocked());

   list_for_each_entry(seg, &segList, list) {
      if (VectorClock_IsParallel(&curr_seg->vc, &seg->vc)) {
         /* Since we insert curr_seg into seglist after detecting
          * races... */
         ASSERT(VectorClock_IsStrictlyParallel(&curr_seg->vc, &seg->vc));

         /* Shouldn't be any empty segments in the seg list. */
         ASSERT(!Segment_IsEmpty(curr_seg));
         ASSERT(!Segment_IsEmpty(seg));
         Segment_DetectRaces(curr_seg, seg);
      }
   }
}

static void
SegEventWork(ulong key, int isSend)
{
   struct Segment *seg, *nseg;

   ASSERT(curr_vcpu);
   ASSERT(VCPU_IsLocked(curr_vcpu));

   nseg = Segment_Alloc();

   seg = curr_vcpu->segment;

   SegEventLock();

   if (seg) {
      VectorClock_Update(&nseg->vc, &seg->vc);

      if (!Segment_IsEmpty(seg)) {
         ASSERT(SegEventIsLocked());
         SegEventDetectRaces(seg);

         List_AddTail(&seg->list, &segList);
      } else {
         /* Can't possibly intersect with any concurrent segment,
          * so get rid of it now. */
         Segment_Free(seg);
      }
      /* Pointer is read when garbage collecting -- to
       * determine if VCPU is active or not. */
      curr_vcpu->segment = seg = NULL;
   } else {
      DEBUG_MSG(5, "No existing segment.\n");

      /* @current should be coming back online. */
      ASSERT(VCPU_IsActive(curr_vcpu));
   }

   if (isSend) {
      SegEventSend(key, nseg);
   } else {
      SegEventRecv(key, nseg);
   }

   /* Must advance before GC to compute an up-to-date
    * garbage vector. */
   SegmentAdvance(nseg);

   if (VCPU_IsActive(curr_vcpu)) {
      /* Begin a new segment. */
      Segment_Print(nseg);
      curr_vcpu->segment = nseg;
   } else {
      ASSERT(!curr_vcpu->segment);
      DEBUG_MSG(5, "VCPU is inactive.\n");
      Segment_Free(nseg);
      nseg = NULL;
   }


   SegEventGarbageCollect();

   SegEventUnlock();

   ASSERT(VCPU_IsLocked(curr_vcpu));
}

void
SegEvent_Send(ulong key, void *data)
{
   SegEventWork(key, 1);
}

void
SegEvent_Recv(ulong key, void *data)
{
   SegEventWork(key, 0);
}

int
SegEvent_Init()
{
   int i;

   channelMap = Map_Create(0);

   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpu = VCPU_Ptr(i);

      ASSERT(vcpu);
      vcpu->segment = NULL;
   }

   return 0;
}
