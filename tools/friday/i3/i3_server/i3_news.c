#include "i3_news_instrument.h"
#include "i3_server_info.h"
#include "../utils/utils.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/***************************************************************************
 * Purpose: Pack/Unpack node info into/from packet
 *
 * Format: total length = 14 bytes
 * [	addr (4) | port (2) | TS (8)	]
 **************************************************************************/
int pack_node_info(char *p, NodeInfo *info)
{
    hnputl((void *) get_nodeinfo_addr(p), info->addr);
    hnputs((void *) get_nodeinfo_port(p), info->port);
    hnput64((void *) get_nodeinfo_ts(p), info->local_ts);

    return NODE_INFO_SIZE;
}

int unpack_node_info(char *p, NodeInfo *info)
{
    info->addr = nhgetl((void *) get_nodeinfo_addr(p));
    info->port = nhgets((void *) get_nodeinfo_port(p));
    info->local_ts   = nhget64((void *) get_nodeinfo_ts(p));

    return NODE_INFO_SIZE;
}

int validate_node_info(NodeInfo *info, I3ServerInfo *i3server_info)
{
    if (info->addr == i3server_info->addr &&
	    info->port == i3server_info->port) {
	return TRUE;
    } else {
	return FALSE;
    }
}

void printf_node_info(NodeInfo *info, int indent)
{
    char		buf[INDENT_BUF_LEN];
    struct in_addr	ia;

    assert(indent < INDENT_BUF_LEN);
    
    memset(buf, ' ', indent);
    buf[indent] = 0;

    ia.s_addr = htonl(info->addr);
    printf("%sNodeInfo: [%s:%d] %Ld\n",
	    buf, inet_ntoa(ia), info->port, info->local_ts);
}

/***************************************************************************
 * Purpose: allocate and initialize news_header fields
 **************************************************************************/
NewsHeader *alloc_news_header()
{
    NewsHeader *n_hdr = (NewsHeader *) emalloc(sizeof(NewsHeader));
    return n_hdr;
}
    
void init_news_header(NewsHeader *n_hdr)
{
    n_hdr->magic = NEWS_MAGIC;
    n_hdr->version = NEWS_VERSION;
}

/***************************************************************************
 * Purpose: allocate and initialize news_header fields
 **************************************************************************/
void printf_news_header(NewsHeader *n, int indent)
{
    char	buf[INDENT_BUF_LEN];
    struct in_addr ia1, ia2;

    assert(indent < INDENT_BUF_LEN);
    
    memset(buf, ' ', indent);
    buf[indent] = 0;

    ia1.s_addr = htonl(n->s1->addr);
    ia2.s_addr = htonl(n->s2->addr);

    printf("%sNews header: [magic:%d], [ver:%d], [type:%d], [nhops:%d]\n",
	    	buf, n->magic, n->version, n->type, n->nhops);
    printf("%s             [header_len:%d], [pinfo_len: %d], ",
	    	buf, n->n_hdr_len, n->pinfo_len);
    printf("[major_seq:%d], [minor_seq:%d]\n", n->major_seq, n->minor_seq);
    printf("%s             [%s:%d] to ", buf, inet_ntoa(ia1), n->s1->port);
    printf("[%s:%d]\n", inet_ntoa(ia2), n->s2->port);
}

/***************************************************************************
 * Purpose: Pack/unpack News header info into/from packet
 *
 * Format: total length = 96 bytes
 * [	magic (1) | version (1) | nhops (1) | type (1) |
 * 	n_hdr_len (4) | pinfo_len (4)
 * 	addr_1 (4) | port_1 (2) | ID_1 (32) |
 * 	addr_2 (4) | port_2 (2) | ID_2 (32) |
 * 	major_seq (4) | minor_seq (4)
 * ]
 **************************************************************************/
uint8_t extract_news_hdr_magic(char *p)
{
    return *p;
}

uint8_t extract_increment_news_header_nhops(char *p)
{
    uint8_t retval;
    
    p += 3 * sizeof(uint8_t);
    retval = *p;
    (*p)++;

    return retval;
}

uint32_t extract_news_header_pinfo_len(char *p)
{
    return nhgetl((void *) (p + 4 * sizeof(uint8_t) + sizeof(uint32_t)));
}

uint32_t extract_news_header_hdr_len(char *p)
{
    return nhgetl((void *) (p + 4 * sizeof(uint8_t)));

}

void add_news_header_pinfo_len(char *p, int added_len)
{
    char *off = p + 4 * sizeof(uint8_t) + sizeof(uint32_t);
    uint32_t temp = nhgetl((void *) off);
    temp += added_len;
    hnputl((void *) off, temp);
}

void add_news_header_hdr_len(char *p, int added_len)
{
    char *off = p + 4 * sizeof(uint8_t);
    uint32_t temp = nhgetl((void *) off);
    temp += added_len;
    hnputl((void *) off, temp);
}

int pack_news_header(char *p, NewsHeader *n_hdr)
{
    int hdr_len = 0, temp_len = 0;
    
    *p = n_hdr->magic;
    p++;
    hdr_len += sizeof(uint8_t);

    *p = n_hdr->version;
    p++;
    hdr_len += sizeof(uint8_t);
    
    *p = n_hdr->type;
    p++;
    hdr_len += sizeof(uint8_t);
    
    *p = n_hdr->nhops;
    p++;
    hdr_len += sizeof(uint8_t);

    hnputl((void *) p, n_hdr->n_hdr_len);
    p += sizeof(uint32_t);
    hdr_len += sizeof(uint32_t);

    hnputl((void *) p, n_hdr->pinfo_len);
    p += sizeof(uint32_t);
    hdr_len += sizeof(uint32_t);
    
    temp_len = pack_i3_server_info(p, n_hdr->s1);
    p += temp_len;
    hdr_len += temp_len;
        
    temp_len = pack_i3_server_info(p, n_hdr->s2);
    p += temp_len;
    hdr_len += temp_len;
        
    hnputl((void *) p, n_hdr->major_seq);
    p += sizeof(uint32_t);
    hdr_len += sizeof(uint32_t);
    
    hnputl((void *) p, n_hdr->minor_seq);
    p += sizeof(uint32_t);
    hdr_len += sizeof(uint32_t);

    return hdr_len;
}

int unpack_news_header(char *p, NewsHeader *n_hdr)
{
    int hdr_len = 0, temp_len;
    
    n_hdr->magic = *p; p++; hdr_len++;
    n_hdr->version = *p; p++; hdr_len++;
    n_hdr->type = *p; p++; hdr_len++;
    n_hdr->nhops = *p; p++; hdr_len++;
    
    n_hdr->n_hdr_len = nhgetl((void *)p);
    p += sizeof(uint32_t);
    hdr_len += sizeof(uint32_t);
    
    n_hdr->pinfo_len = nhgetl((void *)p);
    p += sizeof(uint32_t);
    hdr_len += sizeof(uint32_t);
    
    temp_len = unpack_i3_server_info(p, n_hdr->s1);
    p += temp_len;
    hdr_len += temp_len;

    temp_len = unpack_i3_server_info(p, n_hdr->s2);
    p += temp_len;
    hdr_len += temp_len;

    n_hdr->major_seq = nhgetl((void *)p);
    p += sizeof(uint32_t);
    hdr_len += sizeof(uint32_t);
    
    n_hdr->minor_seq = nhgetl((void *)p);
    p += sizeof(uint32_t);
    hdr_len += sizeof(uint32_t);

    return hdr_len;
}
