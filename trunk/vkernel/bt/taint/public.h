#pragma once

#if STATS
enum {
   TTOK_STAT_PTR_LOAD,
   TTOK_STAT_PTR_STORE,
   TTOK_STAT_EXIT,
   TTOK_STAT_COPY,
   TTOK_STAT_INT_UNOP,
   TTOK_STAT_INT_BINOP,
   TTOK_STAT_FP_UNOP,
   TTOK_STAT_FP_BINOP,
   TTOK_STAT_FP_TRIOP,
   TTOK_STAT_REF,
   TTOK_STAT_MAXREF,
   TTOK_STAT_BIRTH,
   TTOK_STAT_DEATH,
   TTOK_NUM_STATS
};
#endif

struct TaintToken {
   void * data;

#if STATS
   struct SynchLock statsLock;
   u64 stat[TTOK_NUM_STATS];
#endif
};

static INLINE void
TaintToken_Init(struct TaintToken *tok)
{
   memset(tok, 0, sizeof(*tok));

   STATS_ONLY(Synch_LockInit(&tok->statsLock);)
}

#if STATS
typedef enum { StatOp_Inc, StatOp_Dec } StatOp;
static INLINE void
TaintToken_StatOp(struct TaintToken *tok, StatOp op, int statIdx)
{
   u64 *p;

   ASSERT(statIdx < TTOK_NUM_STATS);

   SYNCH_LOCK(&tok->statsLock);

   p = &tok->stat[statIdx];

   switch (op) {
   case StatOp_Inc:
      if (statIdx == TTOK_STAT_REF) {
         /* Can't propage a race that is supposed to be dead! */
         //ASSERT(!tok->stat[TTOK_STAT_DEATH]);

         if (*p == 0) {
            tok->stat[TTOK_STAT_BIRTH] = BrCnt_Get();
         }
      }

      (*p)++;
      if (statIdx == TTOK_STAT_REF) {
         if (tok->stat[TTOK_STAT_MAXREF] < *p) {
            tok->stat[TTOK_STAT_MAXREF] = *p;
         }
      }
      break;
   case StatOp_Dec:
      (*p)--;
      if (statIdx == TTOK_STAT_REF) {
         if (*p == 0) {
            tok->stat[TTOK_STAT_DEATH] = BrCnt_Get();
         }
      }
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   SYNCH_UNLOCK(&tok->statsLock);
}

static INLINE const char *
TaintToken_StatIdxToStr(int statIdx)
{
   switch (statIdx) {
   case TTOK_STAT_PTR_LOAD:
      return "#PTR_LOAD";
   case TTOK_STAT_PTR_STORE:
      return "#PTR_STORE";
   case TTOK_STAT_EXIT:
      return "#EXIT";
   case TTOK_STAT_COPY:
      return "#COPY";
   case TTOK_STAT_INT_UNOP:
      return "#INT_UNOP";
   case TTOK_STAT_INT_BINOP:
      return "#INT_BINOP";
   case TTOK_STAT_FP_UNOP:
      return "#FP_UNOP";
   case TTOK_STAT_FP_BINOP:
      return "#FP_BINOP";
   case TTOK_STAT_FP_TRIOP:
      return "#FP_TRIOP";
   case TTOK_STAT_REF:
      return "#REF";
   case TTOK_STAT_MAXREF:
      return "MAXREF";
   case TTOK_STAT_BIRTH:
      return "BIRTH_BRCNT";
   case TTOK_STAT_DEATH:
      return "DEATH_BRCNT";
   default:
      ASSERT_UNIMPLEMENTED(0);
      return "Unknown";
      break;
   };

   return NULL;
}
#endif

/* We represent taint as the set of origin instructions that influence
 * a particular piece of data. Multiple instructions may influence
 * a peice of data after a join point (e.g., a binary operation such
 * as Add32 that adds two datums, each influenced by a different
 * instruction). */
struct TaintSet {
   /* XXX: When the taint-set is large, this may need to be
    * a size-bounded linked list. */
#define MAX_TAINT_SET_SIZE 4
   struct TaintToken * origin[MAX_TAINT_SET_SIZE];
   int size;
};

static INLINE void
TaintSet_Init(struct TaintSet *set)
{
   set->size = 0;
}

static INLINE void
TaintSet_Add(struct TaintSet *set, struct TaintToken * origin)
{
   ASSERT(set->size >= 0);
   ASSERT(set->size < MAX_TAINT_SET_SIZE);

   ASSERT(origin);

   set->origin[set->size] = origin;
   set->size++;
}

static INLINE int
TaintSet_Find(const struct TaintSet *dst, const struct TaintToken * origin)
{
   int i;

   ASSERT(dst->size >= 0);
   ASSERT(dst->size <= MAX_TAINT_SET_SIZE);

   for (i = 0; i < dst->size; i++) {
      if (dst->origin[i] == origin) {
         return 1;
      }
   }

   return 0;
}

static INLINE void
TaintSet_Union(struct TaintSet *dst, const struct TaintSet *src)
{
   int i;

   for (i = 0; i < src->size; i++) {
      if (!TaintSet_Find(dst, src->origin[i])) {
         TaintSet_Add(dst, src->origin[i]);
      }
   }
}

static INLINE void
TaintSet_Copy(struct TaintSet *dst, const struct TaintSet *src)
{
   int i;

   ASSERT(src->size <= MAX_TAINT_SET_SIZE);

   TaintSet_Init(dst);
   for (i = 0; i < src->size; i++) {
      TaintSet_Add(dst, src->origin[i]);
   }
}

static INLINE int
TaintSet_IsEmpty(const struct TaintSet *set)
{
   return set->size == 0;
}

static INLINE int
TaintSet_GetSize(const struct TaintSet *set)
{
   return set->size;
}

static INLINE void *
TaintSet_Get(const struct TaintSet *set, int i)
{
   ASSERT(i < set->size);

   return set->origin[i];
}

#if STATS
static INLINE void
TaintSet_StatOp(struct TaintSet *set, StatOp op, int statIdx)
{
   int j;

   for (j = 0; j < set->size; j++) {
      TaintToken_StatOp(set->origin[j], op, statIdx);
   }
}
#endif

/* Lists the origins influencing a @len-byte datum. */
struct TaintExtent {
   /* At most X86_MAX_ACCESS_LEN bytes. */
   size_t len;

   /* Set of all origins that influence each byte of the access
    * for the @len bytes. */
   struct TaintSet set[X86_MAX_ACCESS_LEN];

   void * dataSet[X86_MAX_ACCESS_LEN];
};

static INLINE void
TaintExtent_Init(struct TaintExtent *ext, size_t len)
{
   int i;

   ext->len = len;

   for (i = 0; i < len; i++) {
      TaintSet_Init(&ext->set[i]);
      ext->dataSet[i] = NULL;
   }
}

static INLINE void
TaintExtent_Join(struct TaintExtent *joinExt, const struct TaintExtent *srcExt)
{
   int i, j;

   ASSERT(joinExt->len > 0);
   ASSERT(srcExt->len > 0);

   for (i = 0; i < joinExt->len; i++) {
      for (j = 0; j < srcExt->len; j++) {
         TaintSet_Union(&joinExt->set[i], &srcExt->set[j]);
      }
   }
}

static INLINE void
TaintExtent_ToSet(struct TaintSet *set, const struct TaintExtent *ext)
{
   int i;

   TaintSet_Init(set);

   ASSERT(ext->len);

   for (i = 0; i < ext->len; i++) {
      TaintSet_Union(set, &ext->set[i]);
   }
}

#if STATS
/*
 * Update a stat for each unique token in the extent.
 */
static INLINE void
TaintExtent_UnionStatOp(struct TaintExtent *ext, StatOp op, int statIdx)
{
   int i;
   struct TaintSet tset;

   TaintExtent_ToSet(&tset, ext);

   /* Must be tainted by at least one token, otherwise we
    * wouldn't be here. */
   ASSERT(tset.size > 0);

   for (i = 0; i < tset.size; i++) {
      struct TaintToken *tok;

      tok = TaintSet_Get(&tset, i);

      TaintToken_StatOp(tok, op, statIdx);
   }
}

/*
 * Update a stat for each taint set in each byte in the extent.
 */
static INLINE void
TaintExtent_StatOp(struct TaintExtent *ext, StatOp op, int statIdx)
{
   int i;

   for (i = 0; i < ext->len; i++) {
      TaintSet_StatOp(&ext->set[i], op, statIdx);
   }
}
#endif


typedef enum {
   MemLoc,    /* Location is a memory address */
   RegLoc,    /* Location is a register name */
   TmpLoc,    /* Location is a temporary */
} LocType;


enum {
   Key_RegStart     = 0,
   Key_MemStart     = PAGE_SIZE,
   /* IRSBs may contain well over 256 tmps, which is more than we
    * can fit in 4K, so we map the temp keys over the Linux address
    * space. But we are careful not to map over the VDSO blackhole
    * to which accesses are legal memory accesses (even if there
    * is not VDSO mapping visible there). */
   Key_TmpStart     = __LINUX_KERNEL_START,
   Key_TmpEnd       = __LINUX_VDSO_START,
   Key_VDSO_End   = __LINUX_VDSO_START + __LINUX_VDSO_SIZE,
   Key_Origin       = 0xFFFFFFFEUL,
   Key_Const        = 0xFFFFFFFFUL,
};

static INLINE int
TaintMap_IsKeyReg(const HWord key)
{
   return (key >= Key_RegStart && key < Key_MemStart);
}

static INLINE int
TaintMap_IsKeyTmp(const HWord key)
{
   return (Key_TmpStart <= key) && (key < Key_TmpEnd);
}

static INLINE int
TaintMap_IsKeyConst(const HWord key)
{
   return key == Key_Const;
}

static INLINE int
TaintMap_IsKeyMem(const HWord key)
{
   /* Accesses to the VDSO blackhole are legal. */
   return ((Key_MemStart <= key) && (key < Key_TmpStart)) ||
          ((Key_TmpEnd <= key) && (key < Key_VDSO_End));
}

static INLINE int
TaintMap_IsKeyOrigin(const HWord key)
{
   return (key == Key_Origin);
}


static INLINE HWord
TaintMap_Loc2Key(const HWord loc, LocType ltype)
{
   HWord key;

   switch (ltype) {
   case MemLoc:
      ASSERT(TaintMap_IsKeyMem(loc));
      return loc;
   case RegLoc:
      ASSERT(TaintMap_IsKeyReg(loc));
      return loc;
   case TmpLoc:
      key = Key_TmpStart + loc * X86_MAX_ACCESS_LEN;
      ASSERT_MSG(TaintMap_IsKeyTmp(key), "key=%d/0x%x loc=%d\n", key, key, loc);
      return key;
   default:
      ASSERT(0);
      return 0;
   }
   return 0;
}

static INLINE HWord
TaintMap_Key2Loc(const HWord key)
{
   if (TaintMap_IsKeyMem(key)) {
      return key;
   } else if (TaintMap_IsKeyReg(key)) {
      return key;
   } else if (TaintMap_IsKeyTmp(key)) {
      ASSERT(key % X86_MAX_ACCESS_LEN == 0);
      return (key - Key_TmpStart) / X86_MAX_ACCESS_LEN;
   } else if (TaintMap_IsKeyConst(key)) {
      return Key_Const;
   } else if (TaintMap_IsKeyOrigin(key)) {
      return Key_Origin;
   } else {
      DEBUG_MSG(5, "Unknown key: %d/0x%x\n", key, key)
      ASSERT(0);
      return 0;
   }
}


extern int  TaintMap_Init();
extern void TaintMap_TaintKey(HWord dstKey, struct TaintExtent *srcExt);
extern int  TaintMap_GetRangeExtent(HWord key, size_t len, struct TaintExtent *ext);
extern int  TaintMap_IsRangeTainted(HWord key, size_t len);

static INLINE int
TaintMap_IsTmpTainted(const HWord tmp, IRType ty)
{
   return TaintMap_IsRangeTainted(TaintMap_Loc2Key(tmp, TmpLoc),
                                  ty == Ity_I1 ? 1 : sizeofIRType(ty));
}

static INLINE int
TaintMap_IsMemTainted(HWord addr, size_t len)
{
   return TaintMap_IsRangeTainted(TaintMap_Loc2Key(addr, MemLoc),
         len);
}
