#ifndef _TrigBinHeap_H
#define _TrigBinHeap_H

#include "../utils/utils.h"
#include "i3.h"
#include "i3_id.h"

/* For maintaining the list of measurements that are started
 * but waiting for reply and those which need to be initiated
 * IMPLEMENTATION: Sorted array */
enum {
  REFRESH_TO_SEND = 0x10,
  REFRESH_TO_CHECK = 0x20
};
typedef struct TrigInsertNode {
    uint64_t	time;	// when this times out
    i3_trigger	*t;	// trigger that needs to be refreshed
    char	state;
} TrigInsertNode;

typedef TrigInsertNode *TrigElementType;

struct TrigHeapStruct;
typedef struct TrigHeapStruct *TrigPriorityQueue;

TrigPriorityQueue TrigInitialize( int MaxElements );
void TrigDestroy( TrigPriorityQueue H );
void TrigMakeEmpty( TrigPriorityQueue H );
void TrigInsert( TrigElementType X, TrigPriorityQueue H );
TrigElementType TrigDeleteMin( TrigPriorityQueue H );
TrigElementType TrigFindMin( TrigPriorityQueue H );
int TrigIsEmpty( TrigPriorityQueue H );
int TrigIsFull( TrigPriorityQueue H );
void TrigRemoveAddr(TrigPriorityQueue *H);

#endif

/* END */
