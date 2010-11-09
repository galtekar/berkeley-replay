#ifndef SEND_LOG_H
#define SEND_LOG_H

extern void send_new_log_msg(int64_t vclock);

extern void send_log_entry_msg(char *log_str, int64_t vclock);

extern void send_log_close_msg(char* log_str, int64_t vclock);

extern void send_log_flush_msg();

extern int connect_to_logger(in_addr_t logger_addr, int logger_port);

/** Informs the local logger that we are ready for tagged messages on
    a specified port. 
*/
extern void register_port( int port, char* protocol );

/** Informs the local logger that we have closed a registered socket.
*/
extern void unregister_port( int port, char* protocol );


/** Queries a remote logger regarding the status of a port on that
    machine.
    Returns TRUE iff the RPC succeeds and returns TRUE.
    Currently does not cache results.
    The port argument should be the port in question; the remote
      logger is assumed to be listening on a globally known port.
    Only logger_addr should use network byte order.
*/
extern int query_remote_logger( const struct in_addr logger_addr,
				int port, char* protocol );


#endif
