#ifndef _BYTE_ORDER_H
#define _BYTE_ORDER_H

#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

/***************************************************************************
 * Purpose:     Wrapper functions for byte order conversion
 **************************************************************************/

void hnputl(void *p, uint32_t v);
void hnputs(void *p, uint16_t v);
void hnput64(void *p, uint64_t v);
uint32_t nhgetl(void *p);
uint16_t nhgets(void *p);
uint64_t nhget64(void *p);

#endif
