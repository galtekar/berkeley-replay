#ifndef NETOPS_H
#define NETOPS_H

/* Sends a message to the log server. Work like send(), but ensures
 * that all LEN bytes are sent. */
extern ssize_t barf(int network, void* buf, size_t len);

/* Reads LEN bytes from socket NETWORK info BUF. It works just like
 * recv() except that it ensures that you get all LEN bytes. */
extern ssize_t snarf(int network, void* buf, size_t len, int flags);

#endif
