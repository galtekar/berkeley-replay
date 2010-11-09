#ifndef _I3_NEWS_H
#define _I3_NEWS_H

#include <netdb.h>
#include "i3_server_info.h"

/* random magic number that must be sent as the first byte
 * for the i3 server to process any nonlocal options */
#define NEWS_VERSION 0
#define NEWS_MAGIC 0x18
#define NEWS_MAX_HOPS 10

/* Local information that i3 server tags on to a payload
 * if instructed to do so by a measurement service.
 * Use: Instrumentation to compare measured and actual numbers */

#define get_nodeinfo_addr(p)	(p)
#define get_nodeinfo_port(p) 	(p + sizeof(uint32_t))
#define get_nodeinfo_ts(ps)	(p + sizeof(uint32_t) + sizeof(uint16_t))
#define NODE_INFO_SIZE		(sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint64_t))

typedef struct NodeInfo {
    uint32_t	addr;		// local address, port of the i3-server
    uint16_t	port;		// 	where a trigger is matched
    uint64_t	local_ts;	// local timestamp when packet is matched
} NodeInfo;

// packet pack/unpack functions
int pack_node_info(char *p, NodeInfo *info);
int unpack_node_info(char *p, NodeInfo *info);
void printf_node_info(NodeInfo *info, int indent);


/* Header of the measurement payload */
typedef struct NewsHeader {
    uint8_t	magic;		// magic number to be filled in by NEWS agent
    uint8_t	version;	// version number
    uint8_t	type;		// type of measurement
    uint8_t	nhops;		// number of i3-hops packet has taken
    uint32_t	n_hdr_len;	// length of header alone
    uint32_t	pinfo_len;	// total length of path_info (now, should be
    				// nhops * nodeinfo_len, but might
				// change in the future)
    				// note: there might be an empty
				// payload following the news header
    I3ServerInfo *s1;		// i3 servers between which characteristics
    I3ServerInfo *s2;		// 	are measured
    uint32_t	major_seq;	// major/minor sequence number
    uint32_t	minor_seq;	// 	of the measurement
} NewsHeader;

// allocate news header
NewsHeader *alloc_news_header();
void init_news_header(NewsHeader *);
void printf_news_header(NewsHeader *n, int indent);

// packet pack/unpack functions
int pack_news_header(char *p, NewsHeader *n_hdr);
int unpack_news_header(char *p, NewsHeader *n_hdr);
uint8_t extract_news_hdr_magic(char *p);
uint8_t extract_increment_news_header_nhops(char *p);
uint32_t extract_news_header_pinfo_len(char *p);
uint32_t extract_news_header_hdr_len(char *p);
void add_news_header_pinfo_len(char *p, int added_len);
void add_news_header_hdr_len(char *p, int added_len);

int validate_node_info(NodeInfo *, I3ServerInfo *);

#endif
