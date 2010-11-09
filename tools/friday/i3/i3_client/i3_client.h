#ifndef I3_CLIENT_H
#define I3_CLIENT_H

#include "i3server_list.h"

#define TRIGGER_REFRESH_PERIOD	30
#define ACK_TIMEOUT		2
#define ID_REFRESH_PERIOD	30
#define MAX_NUM_TRIG_RETRIES	6
#define MAX_NUM_ID_RETRIES	3

#define CL_CBK_TRIGGER_INSERTED       1        
#define CL_CBK_TRIGGER_REFRESH_FAILED 2        
#define CL_CBK_TRIGGER_NOT_FOUND      3
#define CL_CBK_PATH_ID_NOT_FOUND CL_CBK_TRIGGER_NOT_FOUND
#define CL_CBK_RECEIVE_PACKET         4
#define CL_CBK_RECEIVE_PAYLOAD        5
#define CL_CBK_SERVER_DOWN            6
#define CL_CBK_TRIGGER_CONSTRAINT_FAILED 7
#define CL_CBK_ROUTE_BROKEN	      8

#define CL_CBK_PATH_INSERTED        100
#define CL_CBK_PATH_REFRESH_FAILED  101   
#define CL_CBK_PATH_RECEIVE         102  

#define CL_RET_OK                      0
#define CL_RET_TRIGGER_ALREADY_CREATED 1
#define CL_RET_TRIGGER_NOT_FOUND       2
#define CL_RET_IGNORE_CBK_RECEIVE_PAYLOAD 3   
#define CL_RET_DUP_CONTEXT             4
#define CL_RET_NO_CONTEXT              5
#define CL_RET_NO_TRIGGER              6
#define CL_RET_PATH_INVALID_MASK       7
#define CL_RET_PATH_TOO_LONG           8
#define CL_RET_PATH_TOO_SHORT          9
#define CL_RET_PATH_CREATE_FAILED     10
#define CL_RET_TRIGGER_ALREADY_EXISTS 11
#define CL_RET_NO_AUTO_SERVER_SELECT  12

#define CL_TRIGGER_STATUS_IDLE   0
#define CL_TRIGGER_STATUS_PENDING  1
#define CL_TRIGGER_STATUS_INSERTED 2

#define CL_PATH_STATUS_IDLE   CL_TRIGGER_STATUS_IDLE
#define CL_PATH_STATUS_PENDING  CL_TRIGGER_STATUS_PENDING
#define CL_PATH_STATUS_INSERTED CL_TRIGGER_STATUS_INSERTED


#define EOL          0xa
#define MAX_BUF_SIZE 2048

#define CL_HTABLE_SIZE 1024*64


/****************************************************************************
 *  Macro definitions
 ****************************************************************************/

#define CL_HASH_ID(id) (((*(uint32_t *)&(id)->x[0])^(*(uint32_t *)&(id)->x[4]) ^ (*(uint32_t *)&(id)->x[8]) ^ (*(uint32_t *)&(id)->x[12]))% CL_HTABLE_SIZE)

#define CL_HASH_TRIG(id) (((*(uint32_t *)&(id)->x[0])^(*(uint32_t *)&(id)->x[4])^ (*(uint32_t *)&(id)->x[8]) ^ (*(uint32_t *)&(id)->x[12]))% CL_HTABLE_SIZE)

/* #define CL_HASH_TRIG(id) (((*(uint32_t *)&(id)->x[0])^(*(uint32_t *)&(id)->x[4])^ (*(uint32_t *)&(id)->x[8]) ^ (*(uint32_t *)&(id)->x[12]) ^ (*(uint32_t *)&(id)->x[16]) ^ (*(uint32_t *)&(id)->x[20]) ^ (*(uint32_t *)&(id)->x[24]) ^ (*(uint32_t *)&(id)->x[28]))% CL_HTABLE_SIZE) */

/* macros used to set/check bits in cl_path's tmask filed */
#define is_mask_bit_set(mask, i) \
    (((0x1 << (CL_MAX_PATH_LEN - (i) -1)) & mask) ? TRUE : FALSE)
#define set_mask_bit(mask, i) (mask = (0x1 << (CL_MAX_PATH_LEN - (i) - 1)) | mask)


/****************************************************************************
 *  Data structures
 ****************************************************************************/

typedef struct buf_struct {
  unsigned short  len;
  char *p;
} buf_struct;

#ifndef CCURED
typedef struct cl_cbk {
  void (*fun)();  /* pointer to callbcak function */
  void *data;     /* pointer to client data associated with this callback */ 
		     
} cl_cbk;
#else
#ifndef __RTTI
  #define __RTTI
#endif
typedef struct cl_cbk {
  void (*fun)(i3_trigger*, void * __RTTI);  /* pointer to callbcak function */
  void * __RTTI data;     /* pointer to client data associated with this callback */
} cl_cbk;
#endif
		     




typedef struct cl_trigger {
  i3_trigger *t;
  buf_struct precomputed_pkt;
#define CL_OPT_NO_REFRESH 0x1
  char		     is_queued; /* True when it is inserted in PRIORITY QUEUE */
  uint16_t           status; /* possible status: CL_TRIGGER_STATUS_PENDING, 
			      * CL_TRIGGER_STATUS_INSERTED 
			      * CL_TRIGGER_STATUS_IDLE */
  int                retries_cnt;
  struct timeval     last_sent; /* time when latest refresh msg was sent */
  struct timeval     last_ack;  /* time when latest ack was received for 
				 * a refresh message */
  void *path;                   /* if the trigger is part of a path,
                                 * point to that path; otherwise NULL */
  cl_cbk cbk_trigger_inserted; /* callback confirming that the trigger
				* has been inserted */
  cl_cbk cbk_trigger_refresh_failed;/* trigger cannot be inserted 
				     * or trigger couldn't be refreshed */
  cl_cbk cbk_trigger_constraint_failed; /* constraint fails at server */
  cl_cbk cbk_receive_packet;    /* callback triggered when a packet 
				 * arrives to this trigger */
  cl_cbk cbk_receive_payload;   /* callback triggered when a packet 
				 * arrives to this trigger
				 * NOTE 1: cbk_receive_packet has a higher
				 * precedence than cbk_receive_data; if both
				 * of these callbacks are specified, only 
				 * cbk_receive_data will called
				 * NOTE 2: the only difference between 
				 * cbk_receive_data and cbk_receive_packet
				 * is that cbk_receive_packet returns
                                 * the packet's header (hdr) in addition */
  cl_cbk cbk_path_receive;      /* XXX */
  cl_cbk cbk_route_broken;	/* triggered when an i3_server when
				   attempting to forward a packet
				   along this trigger discovers that
				   the i3_server corres to the next
				   hop is down */
				   
  struct cl_trigger *next;
  struct cl_trigger *prev;
} cl_trigger;


typedef struct cl_id {
  ID                 id;
  struct sockaddr_in i3_srv; /* i3 server where packets with the
			      * the identifier "id" are sent;
                              * data is stored in network format 
			      */
  int            retries_cnt;
  struct timeval last_ack;  /* time when last request for ack 
			       has been sent */
  cl_cbk cbk_no_trigger;    /* callback invoked when no trigger
                             * matchin the "id" filed was found 
			     */
#if NEWS_INSTRUMENT
  int		opt_log_pkt;
  int		opt_add_ts;
#endif
  struct cl_id *next;
  struct cl_id *prev;
} cl_id;


/* define path abstraction */
typedef struct cl_path {
  int     status; /* possible status: CL_TRIGGER_STATUS_PENDING, 
		   * CL_TRIGGER_STATUS_INSERTED 
		   * CL_TRIGGER_STATUS_IDLE
		   */
  ID      *path; /* path expressed as an array of IDs */
#define CL_MAX_PATH_LEN 32
  uint16_t path_len; /* path length */
  uint32_t tmask;    /* mask associated with the path; if the i-th
		      * bit in the mask is 1 then the corresponding 
                      * ID in the path (i.e., path[i]) is a transient 
		      * or bridge ID that usually identifies a service.
		      * the first and the last bit in the mask SHOULD
                      * always be 0.
		      */
  cl_trigger   **triggers; /* list of triggers used to construct the path */
  uint16_t       trigger_num; /* number of triggers used to construct 
			       * the path 
                               */
  cl_cbk cbk_path_inserted; /* callback confirming that the path
			     * has been inserted. a path is assumed to be
                             * inserted if and only if all its triggers
                             * were successfully inserted */
  cl_cbk cbk_path_refresh_failed;/* path cannot be inserted 
				  * or path couldn't be refreshed.
				  * a path is assumed to fail if at least 
				  * one of its triggers failed to be 
				  * refreshed/inserted */
  cl_cbk cbk_trigger_constraint_failed; /* constraint fails at server */
  cl_cbk cbk_route_broken;	/* Unimplemented TODO */
  struct cl_path *next;
} cl_path;


/* maintain the list of i3 servers read from the configuration file */
 #define MAX_NUM_SRV 20
typedef struct srv_address {
  struct in_addr addr;
  uint16_t port;
  ID id;
#define ID_EMPTY 0
#define ID_UP    1
#define ID_DOWN  2
  char     status;
} srv_address;

/* Maintain array of precomputed options */
#define MAX_OPTS_MASK_SIZE (1 << 3) + 1
#define REFRESH_MASK (1 << 0)
#define LOG_PKT_MASK (1 << 1)
#define APP_TS_MASK  (1 << 2)

typedef struct {
  int                fd;    /* file descriptor for i3 packets */
  struct sockaddr_in local; /* local address, used to receive i3 traffic 
			     * (in network format)
			     */
  struct in_addr local_ip_addr; /* local IP address; this field is
				 * needed because the IP address in 
				 * "local" data structure is set to
				 * INADDR_ANY (host format)
				 */
  uint16_t        local_port; /* local port number (host format) */           
  struct timeval  now; /* updated every time cl_refresh_context 
			* is invoked */

  int		tcp_fd;		/* Filedes for TCP connection */
  char		is_tcp;		/* 1 if tcp connection is used */
  
  cl_cbk cbk_trigger_not_found;  /* callback invoked when there is no trigger
                                  * matching the ID of the transmitted 
                                  * packet */ 
  cl_cbk cbk_server_down;        /* callback invoked when an i3 server
				  * couldn't be contacted */ 
  /* following callbacks are called when the corresponding callbacks 
   * associated with the trigger are not defined */
  cl_cbk cbk_trigger_inserted; /* callback confirming that the trigger
				* has been inserted 
				*/
  cl_cbk cbk_trigger_refresh_failed;/* trigger cannot be inserted 
				     * or trigger couldn't be refreshed */
  cl_cbk cbk_trigger_constraint_failed; /* constraint fails at server */
    
  cl_cbk cbk_receive_packet;    /* callback triggered when a packet 
				 * arrives to this trigger */
  cl_cbk cbk_receive_payload;   /* callback triggered when a packet 
				 * arrives to this trigger
				 * NOTE 1: cbk_receive_packet has a higher
				 * precedence than cbk_receive_data; if both
				 * of these callbacks are specified, only 
				 * cbk_receive_data will called
				 * NOTE 2: the only difference between 
				 * cbk_receive_data and cbk_receive_packet
				 * is that cbk_receive_packet returns
                                 * the packet's header (hdr) in addition */
  cl_cbk cbk_path_inserted; /* callback confirming that the path
			     * has been inserted. */
  cl_cbk cbk_path_refresh_failed;/* path cannot be inserted 
				  * or path couldn't be refreshed.*/
  cl_cbk cbk_route_broken;	/* triggered when an i3_server when
				   attempting to forward a packet
				   along this trigger discovers that
				   the i3_server corres to the next
				   hop is down */
  
  cl_trigger      *trigger_htable[CL_HTABLE_SIZE];
  TrigPriorityQueue trig_refresh_queue;
  
  cl_id           *id_htable[CL_HTABLE_SIZE];
  cl_path         *path_list;
  srv_address     *s_array;
  int		  num_servers;
  buf_struct	  precomputed_opt[MAX_OPTS_MASK_SIZE];
  //buf_struct       precomputed_opt_sender;
  //buf_struct       precomputed_opt_all;
  I3ServerList	*list;
  uint64_t *ping_start_time;
} cl_context;


/* this data structure is used to send/receive data while eliminating 
 * an extra memory copy
 */
typedef struct cl_buf {
#define CL_PREFIX_LEN   512
  char *data;            /* pointer to the payload */
  unsigned int data_len; /* length of the payload */
  unsigned int max_len;  /* maximum length that can be used for payload */
  char *internal_buf;    /* pointer to the allocated buffer. the size of 
                          * this buffer is max_len + 2*CL_PREFIX_LEN.
			  * the "data" pointer is between (internal_buf + 
			  * CL_PREFIX_LEN) and (internal_buf + 2*CL_PREFIX_LEN)
			  */
} cl_buf;


#endif // I3_CLIENT_H
