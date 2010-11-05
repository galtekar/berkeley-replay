#pragma once

#include "debug.h"
#include "listops.h"

#include <string.h>

/* 
 * Convenience functions for dealing with maps (i.e., one-to-one hash tables). 
 *
 * They are macros and not functions so that we can get type-checking and 
 * polymorphism.
 */

/* XXX: we expect user to override malloc() with appropriate
 * allocator. But this results in ``implicit definition''
 * compiler warning. */
extern void* malloc(size_t size);
extern void free(void *ptr);

#define MAP_MAGIC 0xdeaddeed

struct MapField {
   ulong keyLong;
   ulong magic;
   struct ListHead list;
   struct HListNode chain;
};

struct MapField64 {
   u64 key64;
   ulong magic;
   struct ListHead list;
   struct HListNode chain;
};

#define MapKey MapField
#define MapKey64 MapField64

#define Map_FindCommon(map, field, keyv, node, HSFX) \
({ \
   typeof(*node)* tmpnode; \
   struct HListNode *elem; \
   node = NULL; \
   hlist_for_each_entry(tmpnode, elem, &(map->hash[Hash_##HSFX(keyv, map->shift)]), field.chain) { \
      ASSERT(tmpnode->field.magic == MAP_MAGIC); \
      if (tmpnode->field.key##HSFX == keyv) { \
         node = tmpnode; \
         break; \
      } \
   } \
   node; \
})

#define Map_Find(map, field, keyv, node) \
   Map_FindCommon(map, field, keyv, node, Long)

#define Map_Find64(map, field, keyv, node) \
   Map_FindCommon(map, field, keyv, node, 64)

//#error "XXX: won't work with 64 bit keys"
#define MAP_FOR_EACH_KEY_ENTRY_DO_COMMON(map, field, keyv, ent, HSFX) \
{ \
   struct HListNode *elem, *dummy; \
   hlist_for_each_entry_safe(ent, elem, dummy, &(map->hash[Hash_##HSFX(keyv, map->shift)]), field.chain) { \
      ASSERT(ent->field.magic == MAP_MAGIC); \
      if (ent->field.key##HSFX == keyv) {

#define MAP_FOR_EACH_KEY_ENTRY_DO_64(map, field, keyv, ent) \
         MAP_FOR_EACH_KEY_ENTRY_DO_COMMON(map, field, keyv, ent, 64)

#define MAP_FOR_EACH_KEY_ENTRY_DO(map, field, keyv, ent) \
         MAP_FOR_EACH_KEY_ENTRY_DO_COMMON(map, field, keyv, ent, Long)


#define END_MAP_FOR_EACH_KEY_ENTRY } } }

#define MAP_FOR_EACH_ENTRY_DO(map, field, ent) \
{ \
   list_for_each_entry(ent, Map_GetList(map), field.list) {


#define MAP_FOR_EACH_ENTRY_SAFE_DO(map, field, ent) \
{ \
   typeof(*ent)* map_for_each_tmp; \
   list_for_each_entry_safe(ent, map_for_each_tmp, Map_GetList(map), field.list) {

#define END_MAP_FOR_EACH_ENTRY_SAFE } }

/* 
 * Removes node from map, but does not free the object.
 * That's left to the caller -- this behavior is neeeded
 * in some situations (e.g., inode cache removal). */
#define Map_Remove(map, field, node) \
{ \
   ASSERT(node); \
   ASSERT(node->field.magic == MAP_MAGIC); \
   HList_Del(&node->field.chain); \
   ASSERT(HList_IsUnlinked(&node->field.chain)); \
   List_DelInit(&node->field.list); \
   ASSERT(List_IsEmpty(&node->field.list)); \
   map->size--; \
}

#define Map_InsertCommon(map, field, keyv, newNode, sortCb, HSFX) \
{ \
   struct ListHead *targetHead = &map->list; \
   int (*cbFn)(typeof(*newNode)*, typeof(*newNode)*) = sortCb; \
   typeof(*newNode)* tmpNode; \
   ASSERT(newNode); \
   ASSERT(newNode->field.key##HSFX == keyv); \
   newNode->field.magic = MAP_MAGIC; \
   ASSERT(HList_IsUnlinked(&newNode->field.chain)); \
   HList_AddHead(&newNode->field.chain, \
         &map->hash[Hash_##HSFX(keyv, map->shift)]); \
   if (cbFn) { \
      list_for_each_entry(tmpNode, &map->list, field.list) { \
         if (cbFn(newNode, tmpNode)) { \
            targetHead = &tmpNode->field.list; \
            break; \
         } \
      } \
   } \
   ASSERT(List_IsEmpty(&newNode->field.list)); \
   List_AddTail(&newNode->field.list, targetHead); \
   map->size++; \
}


#define Map_InsertSorted(map, field, keyv, newNode, sortCb) \
   Map_InsertCommon(map, field, keyv, newNode, sortCb, Long)

#define Map_Insert(map, field, keyv, newNode) \
   Map_InsertCommon(map, field, keyv, newNode, NULL, Long)

#define Map_Insert64(map, field, keyv, newNode) \
   Map_InsertCommon(map, field, keyv, newNode, NULL, 64)

#define Set_Add64(map, field, keyv, newNode) \
({ \
   int set_add_res = 0; \
   typeof(*newNode)* nP; \
   if (!Map_Find64(map, field, keyv, nP)) { \
      Map_Insert64(map, field, keyv, newNode) \
      set_add_res = 1; \
   } \
   set_add_res; \
})



struct MapStruct {
   uint shift;
   struct HListHead *hash;
   struct ListHead list;
   int size; /* number of elements */
};

static INLINE struct MapStruct*
Map_Create(uint shift) 
{
   ulong numBuckets;
   struct MapStruct *map;
   uint i;

   if (!shift) {
      shift = DEFAULT_HASH_SHIFT;
   }

   map = (struct MapStruct *)malloc(sizeof(*map));
   map->shift = shift;
   map->size = 0;

   numBuckets = 1 << shift;
   map->hash = (struct HListHead *) 
      malloc(numBuckets * sizeof(struct HListHead));

   for (i = 0; i < numBuckets; i++) {
      HList_HeadInit(&map->hash[i]);
   }

   List_Init(&map->list);

   return map;
}

static INLINE void
MapDestroy(struct MapStruct *mapP)
{
   ASSERT(mapP->hash);

   free(mapP->hash);
   mapP->hash = NULL;

   mapP->size = 0;
}

static INLINE void
Map_NodeInit(struct MapField *fP, const ulong key)
{
   fP->keyLong = key;
   List_Init(&fP->list);
   HList_NodeInit(&fP->chain);
}

static INLINE void
Map_NodeInit64(struct MapField64 *fP, const u64 key)
{
   fP->key64 = key;
   List_Init(&fP->list);
   HList_NodeInit(&fP->chain);
}

static INLINE struct HListHead *
Map_GetHashList(const struct MapStruct *mapP)
{
   return mapP->hash;
}

static INLINE struct ListHead *
Map_GetList(struct MapStruct *mapP)
{
   return &mapP->list;
}

static INLINE int
Map_GetSize(const struct MapStruct *mapP)
{
   ASSERT(mapP->size >= 0);

   return mapP->size;
}


/*
 * Deallocates map metadata and objects within. */
#define Map_Destroy(map, field, node) \
{ \
   typeof(node) safety; \
   /* Destroy all elements first. */ \
   list_for_each_entry_safe(node, safety, &map->list, field.list) { \
      Map_Remove(map, field, node); \
      free(node); \
   } \
   MapDestroy(map); \
   map = NULL; \
}

/* ---------- Direct mapped hashtable (no hashing required) ---------- */

typedef struct {
   void **array;
   uint size;
   uint maxSize;
} FastMap;

static INLINE void
FastMap_Clear(FastMap *fmP)
{
   ASSERT(fmP->maxSize > 0);

   const size_t arrSz = sizeof(void*) * fmP->maxSize;

   memset(fmP->array, 0, arrSz);
   fmP->size = 0;
}

static INLINE FastMap*
FastMap_Create(int maxSize)
{
   FastMap *fmP;
   const size_t arrSz = sizeof(void*) * maxSize;

   ASSERT(maxSize > 0);
   /* Wasn't meant for very large maps. */
   ASSERT_MSG(maxSize <= 4096, "maxSize=%d; max is 4096\n", maxSize);

   fmP = (FastMap *) malloc(sizeof(*fmP));
   fmP->array = (void**) malloc(arrSz);
   fmP->maxSize = maxSize;

   FastMap_Clear(fmP);

   return fmP;
}

static INLINE void
FastMap_Destroy(FastMap *fmP)
{
   free(fmP->array);
   memset(fmP, 0, sizeof(*fmP));
   free(fmP);
}

static INLINE void *
FastMap_Find(FastMap *fmP, uint idx)
{
   ASSERT(fmP->array);
   ASSERT_MSG(idx < fmP->maxSize, "idx=%d maxSize=%d\n", idx, fmP->maxSize);

   return fmP->array[idx];
}

static INLINE void
FastMap_Insert(FastMap *fmP, uint idx, void *data)
{
   ASSERT(fmP->array);
   ASSERT(idx < fmP->maxSize);
   ASSERT(data);

   fmP->array[idx] = data;
   fmP->size++;
}

static INLINE void *
FastMap_Remove(FastMap *fmP, uint idx)
{
   ASSERT(fmP->array);
   ASSERT(idx < fmP->maxSize);

   void *data = fmP->array[idx];

   if (data) {
      fmP->array[idx] = NULL;
      fmP->size--;
   }

   return data;
}


/* ---------- Statically allocated map/hashtable ---------- */

typedef enum { SMapEntry_Empty, SMapEntry_InUse } SMapEntryStatus;
typedef struct {
   u64 key;
   SMapEntryStatus status;
} SMapHdr;

typedef struct {
   uint size;
   size_t entry_size;
   uint max_nr_entries;
   char *array;
} SMap;

static INLINE void
SMap_Init(SMap *mapP)
{
   ASSERT(mapP->entry_size > 0);
   ASSERT(mapP->max_nr_entries > 0);
   ASSERT(mapP->array);
   ASSERT(mapP->size == 0);

   memset(mapP->array, 0, mapP->entry_size*mapP->max_nr_entries);
}

static INLINE uint 
SMap_Hash ( const u64 key, const uint max_nr_entries )
{
   uint kHi = (uint)(key >> 32);
   uint kLo = (uint)key;
   uint k32 = kHi ^ kLo;
   uint ror = 7;
   if (ror > 0)
      k32 = (k32 >> ror) | (k32 << (32-ror));
   return k32 % max_nr_entries;
}

static INLINE SMapHdr *
SMap_FindEmpty(const SMap *mapP, const u64 key)
{
   SMapHdr *hdrP;

   uint j;
   uint k = SMap_Hash(key, mapP->max_nr_entries);

   for (j = 0; j < mapP->max_nr_entries; j++) {
      hdrP = (SMapHdr*) (mapP->array + (mapP->entry_size*k));
      if (hdrP->status == SMapEntry_Empty) {
         return hdrP;
      }
      k++;
      if (k == mapP->max_nr_entries) {
         k = 0;
      }
   }

   return NULL;
}

static INLINE SMapHdr *
SMap_Lookup(const SMap *mapP, const u64 key)
{
   uint kstart = SMap_Hash(key, mapP->max_nr_entries);
   SMapHdr *hdrP;

   uint k = kstart;
   uint j;
   for (j = 0; j < mapP->max_nr_entries; j++) {
      hdrP = (SMapHdr*) (mapP->array + (mapP->entry_size*k));
      if (hdrP->status == SMapEntry_InUse && hdrP->key == key) {
         /* Found it. */
         return hdrP;
      }
      if (hdrP->status == SMapEntry_Empty) {
         /* Not in table. */
         return NULL;
      }
      k++;
      if (k == mapP->max_nr_entries) {
         k = 0;
      }
   }

   return NULL;
}

static INLINE SMapHdr *
SMap_Insert(SMap *mapP, const u64 key)
{
   SMapHdr *hdrP = SMap_FindEmpty(mapP, key);

   if (hdrP) {
      hdrP->key = key;
      hdrP->status = SMapEntry_InUse;
      mapP->size++;
   } else {
      ASSERT_UNIMPLEMENTED_MSG(0, "size=%d; map size too small\n",
            mapP->size);
   }

   return hdrP;
}

static INLINE SMapHdr *
SMap_Remove(SMap *mapP, const u64 key)
{
   SMapHdr *hdrP = SMap_Lookup(mapP, key);

   if (hdrP) {
      hdrP->status = SMapEntry_Empty;
      mapP->size--;
   }

   return hdrP;
}

static INLINE void
SMap_RemoveRange(SMap *mapP, const u64 key, const size_t len)
{
   u64 i;

   for (i = key; i < key+len; i++) {
      SMap_Remove(mapP, i);
   }
}
