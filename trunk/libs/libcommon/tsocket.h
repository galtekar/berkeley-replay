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

/************************************************************
 * Constants and Types
 ************************************************************/

#define TSOCK_MAX_TAG_LEN 	56
#define TSOCK_MAGIC_CODE_WORD	0x444D4721UL	// random bytes
/* Magic + Original Message Length + 1 byte tag length field */
#define TSOCK_MIN_METADATA_LEN (sizeof(uint32_t)+sizeof(size_t)+1)  // No tag
#define TSOCK_MAX_METADATA_LEN (TSOCK_MIN_METADATA_LEN+TSOCK_MAX_TAG_LEN)
#define TSOCK_MAX_DATAGRAM_LEN 	65536	// UDP maximum

// Error return codes for read_metadata:
#define LL_MD_NOT_MAGIC	-1	
#define LL_MD_TRUNCATED	-2
#define LL_MD_INVALID	-3

typedef struct tsock_msg_metadata {
  size_t msg_len;	// Length of original message, in bytes.
  size_t tag_len;
  char tag[TSOCK_MAX_TAG_LEN];	// sender tag
} tsock_msg_metadata;

typedef struct {
   int data_off; /* offset into buffer at which chunk starts. */
   char tag_buf[TSOCK_MAX_TAG_LEN];
   size_t tag_len;
} tsock_chunk_t;

// We need to distinguish in order to determine what syscall to
// invoke--can't invoke sys_sendmsg on pipe fds.
typedef enum {
   TSOCK_FAMILY_PIPE = 1, // just pipes (XXX: fifos?)
   TSOCK_FAMILY_SOCKET, // includes unix domain, socketpair, sockets
} tsock_family_t;

typedef enum {	// Socket type for a file descriptor.
  TSOCK_PROTOCOL_UDP = 1,	// Created with SOCK_DGRAM
  TSOCK_PROTOCOL_TCP,	// Created with SOCK_STREAM
  TSOCK_PROTOCOL_RAW,	// Created with SOCK_RAW
  TSOCK_PROTOCOL_RDM,	// Created with SOCK_RDM
  TSOCK_PROTOCOL_SEQPACKET,	// Created with SOCK_SEQPACKET
  TSOCK_PROTOCOL_PACKET,	// Created with SOCK_PACKET
} tsock_protocol_t;

typedef enum {	// Is remote peer also logging?
  TSOCK_PEER_UNKNOWN = 1,	// Unconnected/no info
  TSOCK_PEER_TAGS = 2,		// Should send/expect tags
  TSOCK_PEER_NO_TAGS = 3,	// Should NOT send/expect tags
} tsock_peer_info_t;

typedef struct tsock_tcp_state {
  /* This struct stores embedded metadata for a TCP socket in between
     reads.  If the next byte on the socket is application data from a
     send chunk, bytes_left is nonzero and md is valid.  Otherwise we
     are in the middle of reading metadata, or have just finished the
     last chunk, and we use the last two fields to store any partial
     metadata we've read.
  */
  size_t bytes_left;	// (TCP) Bytes left unread from current
			// send chunk
  tsock_msg_metadata md;	// (TCP) Metadata from current send chunk
  size_t md_len;	// (TCP) Number of bytes read into md_buf
  char md_buf[TSOCK_MAX_METADATA_LEN];	// (TCP) Parial metadata read
} tsock_tcp_state_t;

#define UNIX_PATH_MAX 108
typedef struct tsock_port_info {
  /* The information passed to register_port for this socket. */
  char family;
  char protocol;
  char port_addr[UNIX_PATH_MAX];
  int port_addr_len;
} tsock_port_info_t;

typedef struct tsock_socket_info {
  int fd;
  tsock_family_t family;
  tsock_protocol_t protocol;
  tsock_peer_info_t peer_info;	// Should we send or expect tags?
  
  /* If state == TSOCK_PROTOCOL_TCP, tcp_state points to a
     tsock_tcp_state struct.  Else is NULL. */
  tsock_tcp_state_t * tcp_state;
  /* If we register a port, set this field. */
  tsock_port_info_t * registered_info;

  // For our userspace receive buffer, needed for MSG_PEEK
  // support
  ring_buffer_t *peek_buf; 
  int nr_b2b_peeks;
} tsock_socket_info_t;

/************************************************************
 * Methods
 ************************************************************/

extern void
TSock_Open( tsock_socket_info_t *s_info, const int fd, 
            const tsock_family_t family, const tsock_protocol_t protocol, 
            const tsock_peer_info_t peer_info );
extern void 
TSock_Close( tsock_socket_info_t *s_info );

extern ssize_t 
TSock_Recv( tsock_socket_info_t * s_info, struct msghdr * msg_ptr,
      const int flags, tsock_chunk_t *chunk_buf, int *buf_len_ptr );

extern ssize_t 
TSock_Send( tsock_socket_info_t *s_info, const struct msghdr *msg_ptr,
            const int flags, void * tag, size_t *tag_len_ptr );

extern int
TSock_Pselect(const tsock_socket_info_t *s_info, 
             const int is_read, struct timeval *timeout_p, 
             sigset_t *mask_p);
extern int
TSock_Connect(tsock_socket_info_t *s_info, const struct sockaddr *servaddr, 
              const int addr_len);

extern int
TSock_Bind(tsock_socket_info_t *s_info, const struct sockaddr *addr, 
      const int addr_len);

extern void
TSock_Init(int is_enabled);

//extern int
//TSock_IsDataAvailable( const tsock_socket_info_t *s_info );
