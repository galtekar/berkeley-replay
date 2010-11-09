#ifndef LOGGER_H
#define LOGGER_H

#include "logreplay.h"

#define DEFAULT_LOGGER_PORT 7777

/* Create a new log if no log exists, or rotate to a new
 * log if one already exists. */
#define MSG_LOG_CREATE 0

/* Make an entry to an open log. */
#define MSG_LOG_ENTRY 1

/* Close a process's log. */
#define MSG_LOG_CLOSE 2

/* Shared memory message. This is no longer used. */
#define MSG_LOG_MULTIWRITE_ENTRY 3

/* Flushes all entries in shared memory to disk. */
#define MSG_LOG_FLUSH 4

/* Registers a port for listening or receiving. */
#define MSG_PORT_REGISTER 5

/* Unregisters a registered port. */
#define MSG_PORT_UNREGISTER 6

typedef struct log_msg_hdr {
	/* Type of message, as defined above. */
	int type;

	/* Group id of the sending process. */
	int src_pgid;

	/* Pid of the sending process. */
	int src_pid;

	/* Vector clock associated with log event. */
	int64_t vclock;

	/* The size of the following data payload. */
	ssize_t data_size;
} LogMsgHdr;

/* Format for data in MSG_PORT_(UN)REGISTER msg. */
#define PORT_PROT_FMT	"%d/%s"
#define PROT_STR_UDP	"udp"
#define PROT_STR_TCP	"tcp"
#define MAX_PROT_STR_LEN 3

/* Use a human-readable query format for remote queries. */

/* Fields are: <ip>,<port> / (udp|tcp).
   We include the IP address in the query in case the logger is
   responsible for multiple independent addresses. */
#define PORT_QUERY_MSG_FMT "Liblog port query: %s %d / %s"
/* conservative bound: */
#define MAX_PORT_QUERY_MSG_LEN 60
/* string arg is either "TRUE" or "FALSE". */
#define PORT_QUERY_REP_FMT "Liblog port resp: %s"
#define MAX_PORT_QUERY_REP_LEN 24

#define UPTIME_QUERY_MSG_FMT "Liblog uptime query"
#define MAX_UPTIME_QUERY_MSG_LEN 20
/* int arg is uptime in seconds */
#define UPTIME_QUERY_REP_FMT "Liblog uptime resp: %d"
/* conservative bound: */
#define MAX_UPTIME_QUERY_REP_LEN 30

#define MAX_QUERY_MSG_LEN MAX_PORT_QUERY_MSG_LEN
#define MAX_QUERY_REP_LEN MAX_UPTIME_QUERY_REP_LEN


#endif
