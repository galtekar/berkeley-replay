#ifndef _I3SERVER_INFO_H
#define _I3SERVER_INFO_H

#include "i3.h"
#include <netdb.h>

typedef struct I3ServerInfo {
    ID		id;	// ID of the server
    uint32_t	addr;	// address of the server (in host byteorder)
    uint16_t	port;	// port of the server (in host byteorder)
} I3ServerInfo;

int pack_i3_server_info(char *p, I3ServerInfo *i3_server_info);
int unpack_i3_server_info(char *p, I3ServerInfo *info);
void print_i3_server_info(I3ServerInfo *i3server_info);

#endif
