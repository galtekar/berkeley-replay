#ifndef _INET_FNS_H
#define _INET_FNS_H

#include <netinet/in.h>

/* Get address of local machine */
uint32_t get_local_addr_eth();
uint32_t name_to_addr(const char *);
uint32_t get_local_addr_uname();
uint32_t get_local_addr();

#endif
