#ifndef ALLOC_H
#define ALLOC_H

extern /*@null@*//*@out@*/char *alloc(unsigned int);
extern void alloc_free(char*);
extern int alloc_re();
extern char *alloc_channel(unsigned int, int);
extern void alloc_free_channel(char *, int);
extern void printAllocStats(int);

#endif
