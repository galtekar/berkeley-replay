#include "trig_binheap.h"
#include <stdlib.h>

#define TrigMinPQSize (10)
#define TrigMinData (-32767)

struct TrigHeapStruct
{
    int Capacity;
    int Size;
    TrigElementType *Elements;
};


TrigPriorityQueue TrigInitialize(int MaxElements)
{
    TrigPriorityQueue H;
    
    if( MaxElements < TrigMinPQSize )
	weprintf( "Priority queue size is too small" );
    
    H = emalloc( sizeof( struct TrigHeapStruct ) );
    if (H == NULL)
	eprintf( "Out of space!!!" );
    
    /* Allocate the array plus one extra for sentinel */
    H->Elements = emalloc( ( MaxElements + 1 ) * sizeof( TrigElementType ) );
    if( H->Elements == NULL )
	eprintf( "Out of space!" );

    H->Capacity = MaxElements;
    H->Size = 0;
    
    H->Elements[0] = (TrigElementType) emalloc(sizeof(TrigInsertNode));
    H->Elements[0]->time = wall_time();
    
    return H;
}

void TrigMakeEmpty(TrigPriorityQueue H)
{
    H->Size = 0;
}


void TrigInsert(TrigElementType X, TrigPriorityQueue H)
{
    int i;
    
    if( TrigIsFull(H)) {
	eprintf("Priority queue is full\n");
	return;
    }

    for( i = ++H->Size; H->Elements[i/2]->time > X->time; i /= 2 )
	H->Elements[i] = H->Elements[i/2];
    H->Elements[i] = X;
}

TrigElementType TrigDeleteMin(TrigPriorityQueue H)
{
    int i, Child;
    TrigElementType MinElement, LastElement;
    
    if( TrigIsEmpty(H)) {
	eprintf( "Priority queue is empty" );
	return H->Elements[0];
    }
    
    MinElement = H->Elements[1];
    LastElement = H->Elements[H->Size--];
    for( i = 1; i * 2 <= H->Size; i = Child ) {
	/* Find smaller child */
	Child = i * 2;
	if( Child != H->Size && 
		H->Elements[Child + 1]->time < H->Elements[Child]->time )
	    Child++;
	
	/* Percolate one level */
	if( LastElement->time > H->Elements[ Child ]->time )
	    H->Elements[ i ] = H->Elements[ Child ];
	else
	    break;
    }

    H->Elements[ i ] = LastElement;
    return MinElement;
}


TrigElementType TrigFindMin(TrigPriorityQueue H)
{
    if (!TrigIsEmpty(H))
	return H->Elements[1];
    eprintf( "Priority Queue is Empty" );
    return H->Elements[0];    
}


int TrigIsEmpty(TrigPriorityQueue H)
{
    return H->Size == 0;
}


int TrigIsFull(TrigPriorityQueue H)
{
    return H->Size == H->Capacity;
}

void TrigDestroy(TrigPriorityQueue H)
{
    free(H->Elements);
    free(H);
}

void TrigRemoveAddr(TrigPriorityQueue *H)
{
    TrigPriorityQueue temp = TrigInitialize((*H)->Capacity);
	    
    fprintf(stderr, "Triggers deleted due to address change:\n");
    while (!TrigIsEmpty(*H)) {
	TrigElementType et = TrigDeleteMin(*H);
	if (I3_ADDR_TYPE_IPv4 == et->t->to->type) {
	    printf_i3_id(&(et->t->id), 4);
	    free(et->t);
	    free(et);
	} else {
	    TrigInsert(et, temp);
	}
    }

    TrigDestroy(*H);
    *H = temp;
}
