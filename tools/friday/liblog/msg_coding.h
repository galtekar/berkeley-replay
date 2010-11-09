/**
 * $Id: msg_coding.h,v 1.4 2005/12/29 18:49:14 geels Exp $
 *
 * Copyright (c) 2005 Regents of the University of California.  All
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. Neither the name of the University nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Encoding/Decoding methods for application messages.
 *
 * ASSUMPTIONS:
 * All messages are sent with either UDP or TCP
 *      (local socketpair() close enough to TCP).
 * The ancillary/OOB funcionality is not used by the application.
 * The recv*() libc calls never return more than one datagram on a UDP
 *   socket.
 * The recv*() libc calls never return more bytes than requested.
 * TCP sockets really are lossless.
 * Extra metadata will not push datagrams over MTU.
 *
 */

#include "logreplay.h"	// MSG_TAG_LEN
#include "gcc.h"	// HIDDEN

/************************************************************
 * Constants and Types
 ************************************************************/

#define LIBLOG_MAX_TAG_LEN 	MSG_TAG_LEN	// 56
#define LIBLOG_MAGIC_CODE_WORD	0x444D4721UL	// random bytes
#define LIBLOG_MIN_METADATA_LEN (sizeof(uint32_t)+sizeof(uint64_t)+sizeof(uint32_t)+1)  // No tag
#define LIBLOG_MAX_METADATA_LEN (LIBLOG_MIN_METADATA_LEN+LIBLOG_MAX_TAG_LEN)
#define LIBLOG_MAX_DATAGRAM_LEN 	65536	// UDP maximum
#define LIBLOG_MAX_FD	1024	// Highest possible fd.
#define LIBLOG_UNKNOWN_TAG	"UNKNOWN"

// Error return codes for read_metadata:
#define LL_MD_NOT_MAGIC	-1	
#define LL_MD_TRUNCATED	-2
#define LL_MD_INVALID	-3

typedef struct liblog_msg_metadata {
  uint64_t vclock;		// sender vclock at send time (host byte order)
  size_t msg_len;	// Length of original message, in bytes.
  char tag[LIBLOG_MAX_TAG_LEN+1];	// sender tag
} liblog_msg_metadata;

typedef enum {	// Socket type for a file descriptor.
  LIBLOG_SOCKET_OTHER = 1,	// Unused, File, Closed, etc.
  LIBLOG_SOCKET_UDP = 2,	// Created with SOCK_DGRAM
  LIBLOG_SOCKET_TCP = 3,	// Created with SOCK_STREAM
  LIBLOG_SOCKET_PIPE_DGRAM = 4,	// Created with socketpair()
  LIBLOG_SOCKET_PIPE_STREAM = 5,
  LIBLOG_SOCKET_RAW = 6,	// Created with SOCK_RAW
} liblog_socket_state_t;

typedef enum {	// Is remote peer also logging?
  LIBLOG_PEER_UNKNOWN = 1,	// Unconnected/no info
  LIBLOG_PEER_TAGS = 2,		// Should send/expect tags
  LIBLOG_PEER_NO_TAGS = 3,	// Should NOT send/expect tags
} liblog_peer_info_t;

typedef struct liblog_tcp_state {
  /* This struct stores embedded metadata for a TCP socket in between
     reads.  If the next byte on the socket is application data from a
     send chunk, bytes_left is nonzero and md is valid.  Otherwise we
     are in the middle of reading metadata, or have just finished the
     last chunk, and we use the last two fields to store any partial
     metadata we've read.
  */
  size_t bytes_left;	// (TCP) Bytes left unread from current
			// send chunk
  liblog_msg_metadata md;	// (TCP) Metadata from current send chunk
  size_t md_len;	// (TCP) Number of bytes read into md_buf
  char md_buf[LIBLOG_MAX_METADATA_LEN];	// (TCP) Parial metadata read
  int refs;	// Simple reference counter
} liblog_tcp_state;

typedef struct liblog_registered_port_info {
  /* The information passed to register_port for this socket. */
  int port;
  char * protocol;	// Only use literals here, so we don't have to
			// worry about memory management.
  int refs;	// Simple reference counter  
} liblog_registered_port_info;

typedef struct liblog_socket_info {
  liblog_socket_state_t state;
  liblog_peer_info_t peer_info;	// Should we send or expect tags?
  
  /* If state == LIBLOG_SOCKET_TCP, tcp_state points to a
     liblog_tcp_state struct.  Else is NULL. */
  liblog_tcp_state * tcp_state;
  /* If we register a port, set this field. */
  liblog_registered_port_info * registered_info;
  
} liblog_socket_info;

/************************************************************
 * Methods
 ************************************************************/

/**
 * Initializes the liblog_socket_info array.
 */
HIDDEN void init_socket_info();

/**
 * Calls through to register_port().
 * Semantics depend on whether function is called from log_listen() or
 * log_bind(), so we just pass in the caller function name.
 */
HIDDEN void register_socket( int fd, char *caller );

/**
 * Returns TRUE iff fd is a valid UDP or TCP socket and the remote
 * peer is a logging process that understands msg tags.
 *
 * Functions that operate on a connected socket and do not provide an
 *  explicit remote address (e.g. send,write) should provide to=NULL,
 * to_len = 0.
 */
HIDDEN int should_send_tagged( int fd, const struct sockaddr *to,
			       int to_len );

/**
 * Returns TRUE iff fd is a valid UDP or TCP socket and the sender may
 * have added a tag to the message.
 */
HIDDEN int should_recv_tagged( int fd );

/**
 * Called from log_socket() to mark network sockets.
 * protocol argument should be one of LIBLOG_SOCKET_*
 */
HIDDEN void set_socket_state( int fd, int protocol );

/**
 * Copies internal state from one socket to another.
 * Called from log_dup(), etc.
 */
HIDDEN void dup_socket_state( int old_fd, int new_fd );

/**
 * Called from log_*close().
 */
HIDDEN void clear_socket_state( int fd );

/**
 * Tags and sends a message.
 * Prepends up to LIBLOG_MAX_METADATA bytes; This should lower
 *   effective MTU for UDP sockets.
 * Returns the number of bytes from the original message that are sent.
 */
HIDDEN ssize_t send_wrapped_msg( int fd, char const * buf,
				 size_t buf_len, int flags,
				 struct sockaddr const * to,
				 socklen_t to_len,
				 char const * tag, uint64_t vclock );

/**
 * Receives and decodes a single message from a stream.
 * Assumes that fd is a UDP or TCP socket.
 * Sets tag and vclock to metadata from message, or something
 *   reasonable if that fails.
 * Returns the length of the decoded message.
 */
HIDDEN ssize_t recv_wrapped_msg( int fd, char * buf, size_t buf_len,
				 int flags, struct sockaddr *from,
				 socklen_t *from_len,
				 char * tag, uint64_t * vclock );
