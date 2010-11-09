#include "i3_server_info.h"
#include "i3_id.h"
#include "../utils/utils.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/***************************************************************************
 * Purpose: Pack/Unpack i3 server info into/from packet
 *
 * Format: total length = 38 bytes
 * [	addr (4) | port (2) | ID (32)	]
 **************************************************************************/
int pack_i3_server_info(char *p, I3ServerInfo *i3_server_info)
{
    int info_len = 0;
    
    hnputl((void *) p, i3_server_info->addr);
    p += sizeof(uint32_t);
    info_len += sizeof(uint32_t);

    hnputs((void *) p, i3_server_info->port);
    p += sizeof(uint16_t);
    info_len += sizeof(uint16_t);

    memcpy((void *) p, i3_server_info->id.x, ID_LEN);
    info_len += ID_LEN;

    return info_len;
}

int unpack_i3_server_info(char *p, I3ServerInfo *i3_server_info)
{
    int len = 0;

    i3_server_info->addr = nhgetl((void *) p);
    p += sizeof(uint32_t);
    len += sizeof(uint32_t);
    
    i3_server_info->port = nhgets((void *) p);
    p += sizeof(uint16_t);
    len += sizeof(uint16_t);

    memcpy((void *) i3_server_info->id.x, p, ID_LEN);
    len += ID_LEN;

    return len;
}

void print_i3_server_info(I3ServerInfo *i3server_info)
{
    struct in_addr ia;
    ia.s_addr = htonl(i3server_info->addr);
	
    printf("Node:   addr= %s, port = %d, ID = ",
	    		inet_ntoa(ia), i3server_info->port);
    printf_i3_id(&i3server_info->id, 0);
}
