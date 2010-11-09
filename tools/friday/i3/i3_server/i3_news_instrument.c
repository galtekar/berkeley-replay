/***************************************************************************
 * 			i3_news_instrument.c
 * 
 * Purpose: 	Contains methods that are created to instrument i3
 *	 	to perform action for the news agent.
 *
 * 		i) Append local node info at the end of the payload
 * 		ii) Log packet to a local file
 *
 * Contributors:
 * 		Karthik Lakshminarayanan (karthik AT cs berkeley edu)
 *
 **************************************************************************/

#include "i3_news_instrument.h"
#include "../utils/utils.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/***************************************************************************
 * Purpose: Initialize/update node info
 **************************************************************************/
static NodeInfo *init_node_info(srv_context *ctx)
{
    NodeInfo *info = (NodeInfo *) emalloc(sizeof(NodeInfo));

    info->addr = ctx->local_ip_addr.s_addr;
    info->port = ntohs(ctx->local.sin_port);
    info->local_ts = wall_time();

    return info;
}

static void update_node_info(NodeInfo *info)
{
    info->local_ts = wall_time();
}


/***************************************************************************
 * Purpose: Append local time stamp at the end of payload.
 * 	Also modify all the fields in the header that get affected
 **************************************************************************/
void append_local_ts(srv_context *ctx, char *payload, int *payload_len)
{
    uint8_t	nhops;
    int		added_len;
    uint32_t	offset;
    static NodeInfo *info = NULL;
    
    /* init static vars during first invocation */
    if (NULL == info)	info = init_node_info(ctx);
    else		update_node_info(info);

    /* check if magic is satisfied */
    assert(extract_news_hdr_magic(payload) == NEWS_MAGIC);
   
    /* extract and increment number of hops */
    nhops = extract_increment_news_header_nhops(payload);
    assert(nhops < NEWS_MAX_HOPS);

    /* pack local info */
    offset = extract_news_header_pinfo_len(payload) +
		extract_news_header_hdr_len(payload);
    added_len = pack_node_info(payload + offset, info);
    // TODO - before appending check if there is space at the end
    //		by default, should be there as header sizes are small
    //		and allocated packet size is ~4KB
    add_news_header_pinfo_len(payload, added_len);
    *payload_len = max(*payload_len, (int)(offset + added_len));
}


/***************************************************************************
 * Purpose: Perform (un)buffered fprintf to file
 **************************************************************************/
#define LOG_FILE	"news.log"
#define BUFFER_SIZE	1024
#define BUFFER_THRES	800

#define IS_BUFFERED	1
#define UNBUFFERED_LOG	0
#define BUFFERED_LOG	1
#define UNINITIALIZED	2

static FILE	*log_fp = NULL;
static int	buf_len = 0; 
static char 	file_buffer[BUFFER_SIZE];
static char	write_lock = UNINITIALIZED;


static void init_log_file()
{
    log_fp = fopen(LOG_FILE, "a");
    buf_len	= 0;
    memset(file_buffer, BUFFER_SIZE, 0);
}

static void unbuffered_printf_log(char *fmt, ...)
{
    va_list args;

    /* Initialize output file during the first call */
    if (NULL == log_fp) {
	assert(UNINITIALIZED == write_lock);
	write_lock = UNBUFFERED_LOG;
	init_log_file();
    }

    /* write contents to buffer */
    va_start(args, fmt);
    buf_len += vfprintf(log_fp, fmt, args);
    fflush(log_fp);
    va_end(args);
}

static void buffered_printf_log(char *fmt, ...)
{
    va_list args;

    /* Initialize output file during the first call */
    if (NULL == log_fp) {
	assert(UNINITIALIZED == write_lock);
	write_lock = BUFFERED_LOG;
	init_log_file();
    }    

    /* If buffer more than THRES, write to file */
    if (buf_len > BUFFER_THRES) {
        file_buffer[buf_len] = 0;
        fputs(file_buffer, log_fp);
        fflush(log_fp);
        buf_len = 0;
    }
    
    /* write contents to buffer */
    va_start(args, fmt);
    buf_len += vsprintf((char *) (file_buffer + buf_len), fmt, args);
    va_end(args);
}

/***************************************************************************
 * Purpose: Log the information of a news header onto a file
 * 
 * Notes: The information is printed into a buffer, which
 * 	is in turn spewed out to a file whenever its size > threshild 
 **************************************************************************/
typedef void	(*PrintfLogFnPtr)(char *fmt, ...);
static const	PrintfLogFnPtr printf_log_fn_ptrs[2] =
		{&unbuffered_printf_log, &buffered_printf_log};

void log_news_pkt(char *p, int payload_len)
{
    struct timeval 	tv;
    time_t		clock_time;
    struct tm		calendar_time;
    struct in_addr	ia;
    int			nhdr_len;
    static NewsHeader	*n_hdr = NULL;
    PrintfLogFnPtr	printf_log;
    
    /* init static vars during first invocation */
    if (NULL == n_hdr) {
	n_hdr = (NewsHeader *) emalloc(sizeof(NewsHeader));
        n_hdr->s1 = (I3ServerInfo *) emalloc(sizeof(I3ServerInfo));
        n_hdr->s2 = (I3ServerInfo *) emalloc(sizeof(I3ServerInfo));
    }

    /* init print_log fn pointer */
    assert (0 <= IS_BUFFERED && 1 >= IS_BUFFERED);
    printf_log = printf_log_fn_ptrs[IS_BUFFERED];
    
    /* print time */
    gettimeofday(&tv, NULL);
    clock_time = tv.tv_sec;
    if (NULL == localtime_r(&clock_time, &calendar_time)) {
	printf_log("ERR_TIME ");
    } else {
	printf_log("%d.%02d.%02d.%02d ", calendar_time.tm_mday, 
			calendar_time.tm_hour, calendar_time.tm_min,
			calendar_time.tm_sec);
    }

    /* unpack header of packet */
    nhdr_len = unpack_news_header(p, n_hdr);
    assert(nhdr_len <= payload_len);

    /* print from/to addresses */
    ia.s_addr = htonl(n_hdr->s1->addr);
    printf_log("%s:%d ", inet_ntoa(ia), n_hdr->s1->port);
    ia.s_addr = htonl(n_hdr->s2->addr);
    printf_log("%s:%d ", inet_ntoa(ia), n_hdr->s2->port);

    /* print necessary part of the remaining header */
    printf_log("%d %d %d %d\n",
	    n_hdr->type, n_hdr->nhops, n_hdr->major_seq, n_hdr->minor_seq);
}
