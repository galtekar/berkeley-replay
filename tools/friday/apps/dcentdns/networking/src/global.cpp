#include <stdlib.h>
#include <assert.h>
#include "global.h"
#include <stdio.h>

unsigned char* new_char(int size){
	unsigned char* tmp=(unsigned char*)malloc(size);
	assert(tmp!=NULL);
	return tmp;
}

int* new_int(){
	int* tmp=(int *)malloc(sizeof(int));
	assert(tmp!=NULL);
	return tmp;
}



