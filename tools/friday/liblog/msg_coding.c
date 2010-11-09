/**
 * $Id: msg_coding.c,v 1.17 2006/07/15 01:24:42 geels Exp $
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
 * Encoding/Decoding methods for application-layer network messages.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "logreplay.h"
#include "libc_pointers.h"
#include "msg_coding.h"
#include "sendlog.h"
#include "logger.h"
#include "errops.h"
#include "tmalloc.h"

#define DEBUG 0

#if DEBUG
#include "hexops.h"
#endif

// Defined in log.c:
extern void write_errno_log_entry();

/************************************************************
 * Variables
 ************************************************************/
static liblog_socket_info _socket_info[LIBLOG_MAX_FD+1];

/************************************************************
 * Methods
 ************************************************************/

static void print_buf( char const * prefix, char const * buf, size_t buf_len )
{
#if DEBUG  
  char hex_buf[2*MAX(0,buf_len)];
  if( buf_len <= 0 ) {
    hex_buf[0] = '\0';
  } else {
    hex_encode((void*)buf, hex_buf, buf_len );
  }
  lprintf( "%s[%d]: <%s>\n", prefix, buf_len, hex_buf );
#endif
}

/**
 * Creates a liblog_registered_port_info struct.
 */
static liblog_registered_port_info * new_registered_info( int port,
							  char * protocol )
{
  liblog_registered_port_info * rp =
    (liblog_registered_port_info*)tmalloc(sizeof(liblog_registered_port_info));
  rp->port = port;
  rp->protocol = protocol;
  rp->refs = 1;
  return rp;
}

/**
 * Calls through to register_port().
 * Semantics depend on whether function is called from log_listen() or
 * log_bind(), so we just pass in the caller function name.
 */
HIDDEN void register_socket( int fd, char *caller )
{
  struct sockaddr_in sin;	// Assume this socket is INET.
  socklen_t sock_len;
  int port;
  
  assert( fd >= 0 );
  assert( fd <= LIBLOG_MAX_FD );

  sock_len = sizeof(sin);
  assert( 0 == getsockname( fd, (struct sockaddr*)&sin, &sock_len));
  port = ntohs(sin.sin_port);

  if( DEBUG ) lprintf( "Registering port %d, caller %s, socket type %d\n",
		       port, caller, _socket_info[fd].state );

  switch( _socket_info[fd].state ) {
  case LIBLOG_SOCKET_UDP:
    assert( 0 == strcmp( caller, "bind" ) );
    register_port( port, PROT_STR_UDP );
    _socket_info->registered_info =
      new_registered_info( port, PROT_STR_UDP );
    break;
  case LIBLOG_SOCKET_TCP:
    // Do nothing on bind.
    if( 0 == strcmp( caller, "listen" ) ) {
      register_port( port, PROT_STR_TCP );
      _socket_info->registered_info =
	new_registered_info( port, PROT_STR_TCP );
    }
    break;
  case LIBLOG_SOCKET_RAW:
    assert( 0 == strcmp( caller, "bind" ) );
    // For now, assume raw sockets are untagged.
    break;
  default:
    if( DEBUG ) lprintf( "Cannot register socket type %d\n",
			 _socket_info[fd].state );
    assert( FALSE );
  }
  return;
}


/**
 * Returns TRUE iff fd is a valid UDP or TCP socket and the remote
 * peer is a logging process that understands msg tags.
 *
 * Functions that operate on a connected socket and do not provide an
 *  explicit remote address (e.g. send,write) should provide to=NULL,
 * to_len = 0.
 */
HIDDEN int should_send_tagged( int fd, const struct sockaddr *to,
		int to_len )
{
	int remote_accepts_tags = FALSE;
	char *prot = NULL;

	assert( fd >= 0 );
	assert( fd <= LIBLOG_MAX_FD );
	if (DEBUG) lprintf( "should_send_tagged( %d ) <%d,%d>\n", fd,
			_socket_info[fd].state, _socket_info[fd].peer_info );

	switch( _socket_info[fd].state ) {
		case LIBLOG_SOCKET_UDP:
			prot = PROT_STR_UDP;	// Fall through.
		case LIBLOG_SOCKET_TCP:
			if( !prot ) prot = PROT_STR_TCP;	// Check for fall through.

			// Network message.  Is it a connected socket?
			if( to==NULL ) {	// Then we already have the answer.
				assert( to_len == 0 );
				if( _socket_info[fd].peer_info == LIBLOG_PEER_TAGS ) {
					remote_accepts_tags = TRUE;
				}
				// If peer_info==LIBLOG_PEER_UNKNOWN, we must have an unconnected
				// socket.  send call should fail.
			} else {
				// New destination; find out whether it accepts tags.
				const struct sockaddr_in *sin = (const struct sockaddr_in*)to;
				if( sin->sin_family != AF_INET ) {
					fatal( "sin->sin_family: %d\n", sin->sin_family );
				}
				assert( sin->sin_family == AF_INET );

				remote_accepts_tags =
					query_remote_logger( sin->sin_addr, ntohs(sin->sin_port), prot );

				// Save for duration of connection.
				_socket_info[fd].peer_info =
					(remote_accepts_tags ? LIBLOG_PEER_TAGS : LIBLOG_PEER_NO_TAGS );
			}
		default:
			// RAW, or not an internet socket.
			break;
	}
	if (DEBUG) lprintf( "should_send_tagged( %d ): %d\n", fd,
			remote_accepts_tags );

	return remote_accepts_tags;
}


/**
 * Returns TRUE iff fd is a valid UDP or TCP socket and the sender may
 * have added a tag to the message.
 */
HIDDEN int should_recv_tagged( int fd )
{
	assert( fd >= 0 );
	assert( fd <= LIBLOG_MAX_FD );
	if (DEBUG) lprintf( "should_recv_tagged( %d ) <%d,%d>\n", fd,
			_socket_info[fd].state, _socket_info[fd].peer_info );

	switch( _socket_info[fd].state ) {
		case LIBLOG_SOCKET_UDP:
			// No way to know sender in advance.  Look for tag.
			return TRUE;
		case LIBLOG_SOCKET_TCP:
			return( (_socket_info[fd].peer_info == LIBLOG_PEER_UNKNOWN) ||
					(_socket_info[fd].peer_info == LIBLOG_PEER_TAGS) );
		default:
			if (DEBUG) lprintf( "should_recv_tagged: NO\n" );

			return FALSE;
	}     
}


/**
 * Resets a metadata struct.
 */
static void erase_md( liblog_msg_metadata * md )
{
	md->vclock = 0;
	md->msg_len = 0;
	strncpy( md->tag, LIBLOG_UNKNOWN_TAG, LIBLOG_MAX_TAG_LEN );
}

/**
 * Creates a liblog_tcp_state struct.
 */
static liblog_tcp_state * new_tcp_info()
{
	liblog_tcp_state * ts = (liblog_tcp_state*)tmalloc(sizeof(liblog_tcp_state));
	ts->bytes_left = 0;
	erase_md( &(ts->md) );
	ts->md_len = 0;
	memset( ts->md_buf, 0, LIBLOG_MAX_METADATA_LEN );
	ts->refs = 1;
	return ts;
}

/**
 * Called from log_socket(), etc. to mark UDP/TCP sockets.
 */
HIDDEN void set_socket_state( int fd, int state )
{
	assert( fd >= 0 );
	assert( fd <= LIBLOG_MAX_FD );
	if (DEBUG) lprintf( "set_socket_state( %d, %d )\n", fd, state );
	//  if (DEBUG) lprintf( "old state[%d]: %d\n", fd, _socket_info[fd].state );
	clear_socket_state( fd );	// First erase current state.

	if( state == LIBLOG_SOCKET_PIPE_DGRAM ) {
		// For now, treat it like a UDP connection
		_socket_info[fd].state = LIBLOG_SOCKET_UDP;
		_socket_info[fd].peer_info = LIBLOG_PEER_TAGS;
	} else if( state == LIBLOG_SOCKET_PIPE_STREAM ) {
		// For now, treat it like a TCP connection
		_socket_info[fd].state = LIBLOG_SOCKET_TCP;
		_socket_info[fd].peer_info = LIBLOG_PEER_TAGS;
	} else {
		// Just use the provided state, and clear peer_info.
		_socket_info[fd].state = state;
		_socket_info[fd].peer_info = LIBLOG_PEER_UNKNOWN;
	}

	if( _socket_info[fd].state == LIBLOG_SOCKET_TCP ) {
		// Need extra struct for tracking stream metadata:
		_socket_info[fd].tcp_state = new_tcp_info();
	}

	if (DEBUG) lprintf( "new state[%d]: <%d,%d,%p>\n", fd,
			_socket_info[fd].state,
			_socket_info[fd].peer_info,
			_socket_info[fd].tcp_state );
}


/**
 * Copies internal state from one socket to another.
 * Called from log_dup(), etc.
 */
HIDDEN void dup_socket_state( int old_fd, int new_fd )
{
	assert( old_fd >= 0 );
	assert( old_fd <= LIBLOG_MAX_FD );
	assert( new_fd >= 0 );
	assert( new_fd <= LIBLOG_MAX_FD );
	if (DEBUG) lprintf( "dup_socket_state( %d, %d )\n", old_fd, new_fd );

	_socket_info[new_fd] = _socket_info[old_fd];  
	if( _socket_info[old_fd].tcp_state ) {
		// Increment reference counter on tcp_state struct.
		_socket_info[old_fd].tcp_state->refs++;
	}
	if( _socket_info[old_fd].registered_info ) {
		// Increment reference counter on tcp_state struct.
		_socket_info[old_fd].registered_info->refs++;
	}

	if (DEBUG) {
		lprintf( "old: <%d,%d,%p>\n", _socket_info[old_fd].state,
				_socket_info[old_fd].peer_info, _socket_info[old_fd].tcp_state);  
		lprintf( "new: <%d,%d,%p>\n", _socket_info[new_fd].state,
				_socket_info[new_fd].peer_info, _socket_info[new_fd].tcp_state);
	}
}

/**
 * initializes a single liblog_socket_info.
 */
static void init_socket_state( int fd )
{
	_socket_info[fd].state = LIBLOG_SOCKET_OTHER;
	_socket_info[fd].peer_info = LIBLOG_PEER_UNKNOWN;
	_socket_info[fd].tcp_state = NULL;
	_socket_info[fd].registered_info = NULL;
}


/**
 * Called from log_*close().
 * Resets a single liblog_socket_info.
 */
HIDDEN void clear_socket_state( int fd )
{
	liblog_tcp_state * ts;
	liblog_registered_port_info * rp;

	if (DEBUG) lprintf( "clear_socket_state( %d )\n", fd );  
	assert( fd >= 0 );
	assert( fd <= LIBLOG_MAX_FD );
	// clean up tcp_state
	if( NULL != (ts = _socket_info[fd].tcp_state) ) {
		assert( ts->refs > 0 );
		ts->refs--;
		if( ts->refs == 0 ) {	// No more references.
			tfree( ts );
		}
	}
	// then clean up port info
	if( NULL != (rp = _socket_info[fd].registered_info) ) {
		assert( rp->refs > 0 );
		rp->refs--;
		if( rp->refs == 0 ) {	// No more references.
			unregister_port( rp->port, rp->protocol );
			tfree( rp );
		}
	}
	// then reset everything.  
	init_socket_state( fd );
}

/**
 * Initializes the _socket_info array.
 */
HIDDEN void init_socket_info()
{
	int i;
	for( i=0; i<LIBLOG_MAX_FD+1; ++i ) {
		init_socket_state( i );
	}
	if (DEBUG) lprintf( "Finished init_socket_info().\n" );

	//print_buf( "socket_info", (char const *)_socket_info,
	//	     2*sizeof(_socket_info));	// Just print a few.
}
/**
 * Pack metadata into a byte array.
 * Returns the number of bytes written.
 *
 * Metadata Format:
 * 4B Magic (Mostly a sanity check)
 * 8B Vclock (scalar Lamport clock)
 * 4B Message Length (does not include metadata length)
 * 1B Tag length
 * *B Tag (No NUL termination, truncated at LIBLOG_MAX_TAG_LEN)
 */
static size_t write_metadata( char * buf, size_t buf_len,
		char const * tag, uint64_t vclock,
		size_t data_len )
{
	uint8_t tag_len;
	char *buf_p = buf;

	assert( buf_len >= LIBLOG_MAX_METADATA_LEN );

	// First add the Magic
	// TODO: consider replacing magic with checksum.
	*(uint32_t*)buf_p = htonl(LIBLOG_MAGIC_CODE_WORD);
	buf_p += sizeof(uint32_t);

	// Next, the vclock.
	*(uint64_t*)buf_p = htonll(vclock);
	buf_p += sizeof(uint64_t);

	// Then the original message length (4-byte field).
	*(uint32_t*)buf_p = htonl(data_len);
	buf_p += sizeof(uint32_t);

	// Now add the tag, with 1-byte length field.
	tag_len = (uint8_t)MIN(LIBLOG_MAX_TAG_LEN,strlen(tag));
	*buf_p++ = tag_len;
	strncpy( buf_p, tag, tag_len );
	buf_p += tag_len;

	if (DEBUG) print_buf( "metadata", buf, buf_p-buf );
	return (buf_p - buf);
}

/**
 * Reads metadata from byte array into metadata struct.
 * May not read tag if provided array is too short.
 * If at least core metadata (all but tag) was read successfully,
 * return the length of the entire metadata, including tag.
 * Otherwise, return one of the LL_MD_* codes on failure.
 */
static int read_metadata( liblog_msg_metadata *md,
		char const * buf, size_t buf_len )
{
	uint8_t tag_len;
	size_t md_len;
	uint32_t net_magic = htonl(LIBLOG_MAGIC_CODE_WORD);
	char const *buf_p = buf;
	assert( md != NULL );

	if (DEBUG) print_buf( "reading metadata", buf, buf_len );

	// Check magic word (or as many bytes as are available).
	if (DEBUG) lprintf( "Magic: 0x%x vs. 0x%x\n",
			*((uint32_t*)buf_p), net_magic );
	if( 0 != memcmp( buf_p, &net_magic, MIN(buf_len, sizeof(uint32_t)) ) ) {
		return LL_MD_NOT_MAGIC;
	}

	// LL_MD_NOT_MAGIC takes precedence over LL_MD_TRUNCATED.
	if( buf_len < sizeof(uint32_t) ) return LL_MD_TRUNCATED;
	buf_p += sizeof(uint32_t);

	// Now check for rest of core metadata (all but tag)
	if( buf_len < LIBLOG_MIN_METADATA_LEN ) return LL_MD_TRUNCATED;

	// Next, the vclock.
	md->vclock = ntohll(*(uint64_t*)buf_p);
	buf_p += sizeof(uint64_t);

	// Then the original message length (4-byte field).
	md->msg_len = ntohl(*(uint32_t*)buf_p);
	buf_p += sizeof(uint32_t);

	// Now the tag length.
	tag_len = *(uint8_t*)buf_p;
	if( tag_len > LIBLOG_MAX_TAG_LEN ) return LL_MD_INVALID;
	++buf_p;

	// Compute total metadata length.
	md_len = LIBLOG_MIN_METADATA_LEN + tag_len;

	if (DEBUG) lprintf( "read_metadata: md_len=%d, buf_len=%d\n",
			md_len, buf_len );
	// Read the tag in, if available. Otherwise, wait for later.
	if( md_len <= buf_len ) {
		strncpy( md->tag, buf_p, tag_len );
		md->tag[tag_len] = '\0';
		buf_p += tag_len;
	}
	assert( (buf_p - buf) <= buf_len );
	return md_len;
}

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
		char const * tag, uint64_t vclock )
{
	char metadata_buf[LIBLOG_MAX_METADATA_LEN];
	size_t metadata_len;
	struct msghdr msg_hdr;
	struct iovec iov[2];	// Always one for metadata, one for original msg.
	ssize_t bytes_sent;
	if (DEBUG) lprintf( "send_wrapped_msg( %d, ..., %s, %llu )\n",
			fd, tag, vclock );  

	assert( fd >= 0 );

	// Have not tested flags:
	assert( (flags == 0) || (flags == MSG_DONTWAIT) );

	// FIXME: for connected TCP sockets, skip tag, magic, compress vclock.
	// For all, drop tag?  How is it helping?  Pull peer IP from socket.
	// For UDP, do we use length?
	
	// First write metadata into second buffer.
	metadata_len = write_metadata( metadata_buf, LIBLOG_MAX_METADATA_LEN,
			tag, vclock, buf_len );
	// Would be nice to check this for UDP sockets:
	//assert( metadata_len + buf_len <= LIBLOG_MAX_DATAGRAM_LEN );

	// Next assemble the iovec for a gather.
	iov[0].iov_base = metadata_buf;
	iov[0].iov_len = metadata_len;
	iov[1].iov_base = (char*)buf;	// Discard const
	iov[1].iov_len = buf_len;  

	// Finally build the msghdr struct.
	memset( &msg_hdr, 0, sizeof(msg_hdr) );
	msg_hdr.msg_name = (void*)to;
	msg_hdr.msg_namelen = to_len;
	msg_hdr.msg_iov = iov;
	msg_hdr.msg_iovlen = 2;

	/* FIXME: eventually, use __INTERNAL_CALL_LIBC_2() macro here. */
	bytes_sent = sendmsg( fd, &msg_hdr, flags );
	write_errno_log_entry(errno);

	if (DEBUG) lprintf( "Sent %d (%d) bytes\n", bytes_sent, MAX( 0, (bytes_sent-metadata_len) ));
	if( bytes_sent < 0 ) {
		return bytes_sent;	// Failure.
	} else {
		// Hide metadata from app.
		return MAX( 0, (bytes_sent-metadata_len) );
	}
}

/**
 * Receives and decodes a single datagram.
 * Assumes that fd is a UDP socket.
 * Returns the length of the decoded message.
 */
static ssize_t recv_wrapped_datagram( int fd, char * buf, size_t buf_len,
		int flags, struct sockaddr *from,
		socklen_t *from_len,
		char * tag, uint64_t * vclock )
{
	char wrapped_buf[LIBLOG_MAX_DATAGRAM_LEN];
	size_t to_read;
	ssize_t bytes_read;
	liblog_msg_metadata md;
	size_t md_len;
	if (DEBUG) lprintf( "recv_wrapped_datagram( %d )\n", fd );

	assert( fd >= 0 );
	// Have not tested flags:
	assert( (flags == 0) || (flags == MSG_DONTWAIT) );
	to_read = MIN(LIBLOG_MAX_DATAGRAM_LEN,	// Do not read more than
			(buf_len+LIBLOG_MAX_METADATA_LEN));	// necessary.
	/* __INTERNAL_CALL_LIBC_2 prevents this call from recurring */
	__INTERNAL_CALL_LIBC_2( bytes_read, recvfrom, fd, wrapped_buf,
			to_read, flags, from, from_len );
	write_errno_log_entry(errno);
	if (DEBUG) lprintf( "recvfrom returned %d\n", bytes_read );  
	assert( (bytes_read < 0) || ((size_t)bytes_read <= to_read) );

	if( bytes_read < 0 ) {
		// recv failed.  Pass error back up.
		strncpy( tag, LIBLOG_UNKNOWN_TAG, LIBLOG_MAX_TAG_LEN );
		*vclock = 0;

	} else {
		// Try to parse prepended metadata tag
		int rm_ret = read_metadata( &md, wrapped_buf, bytes_read );
		if (DEBUG) lprintf( "read_metadata(1) returned %d\n", rm_ret );        
		switch( rm_ret ) {
			case LL_MD_NOT_MAGIC:
			case LL_MD_TRUNCATED:
			case LL_MD_INVALID:
				// Any failure to parse metadata is assumed to mean that the
				// message is not tagged.  This assumption fails if the metadata
				// was merely truncated; we hope that case is uncommon, and that
				// the application can handle the occasional gibberish packet.
				if (DEBUG) print_buf( "Assuming not tagged:", wrapped_buf, bytes_read );
				strncpy( tag, LIBLOG_UNKNOWN_TAG, LIBLOG_MAX_TAG_LEN );
				*vclock = 0;
				// TODO: postpone this copy until we have the global scheduler
				// lock, to avoid race conditions.
				memcpy( buf, wrapped_buf, bytes_read );      
				break;

			default:
				// Valid metadata.  Return value is length.
				md_len = rm_ret;
				*vclock = md.vclock;
				if( md_len > bytes_read ) {	// Tag truncated, no app data.
					bytes_read = 0;
					strncpy( tag, LIBLOG_UNKNOWN_TAG, LIBLOG_MAX_TAG_LEN );	
				} else {
					bytes_read -= md_len;	// Hide metadata from app.
					// TODO: We could avoid this copy if we fix the length of the tag
					// field, so we could use a fixed length iovec to read the metadata.
					memcpy( buf, &wrapped_buf[md_len], bytes_read );
					if (DEBUG) print_buf( "Decoded app msg", buf, bytes_read );    
					strcpy( tag, md.tag );
				}
				break;
		}
	}
	return bytes_read;
}

/**
 * Reads the next chunk of metadata from a TCP stream.
 * buf_len is the number of application bytes requested.  We should
 *   never read more than that from the stream until we are sure that
 *   the stream is tagged.
 * Returns 0 normally, < 0 on error.  If metadata is completely read
 * and parsed, s_info->bytes_left is set to nonzero.
 */
static ssize_t read_stream_metadata( int fd, int buf_len, int flags,
		liblog_socket_info *s_info )
{
	assert( s_info->tcp_state->bytes_left == 0 );	// Not in a data chunk.
	size_t to_read;  
	ssize_t bytes_read;
	size_t full_md_len;
	int rm_ret;
	liblog_msg_metadata scratch_md;	// Don't want to modify
	// s_info->tcp_state->md unless we're sure.

	if (DEBUG) lprintf( "read_stream_metadata( %d )\n", fd );
	assert (fd >= 0 );

	/* Phase 1: Make sure we can read the length fields. */
	// How much more to read?
	while( s_info->tcp_state->md_len < LIBLOG_MIN_METADATA_LEN ) {
		to_read = LIBLOG_MIN_METADATA_LEN-s_info->tcp_state->md_len;
		if( (s_info->peer_info == LIBLOG_PEER_UNKNOWN) &&
				(to_read > buf_len) ) {
			// The stream might not be tagged.  Be careful not to read too
			//  much.  We'll loop if necessary.

		  // FIXME -- if we loop here, we're assuming the tag
		  // exists.  Might as well kick to_read all the way
		  // up, right? 
			to_read = buf_len;
		} // else, read the whole tag.

		if (DEBUG) lprintf( " have %d/%d, need %d\n", s_info->tcp_state->md_len,
				LIBLOG_MIN_METADATA_LEN, to_read );
		// Don't bother with recvfrom() here.
		/* __INTERNAL_CALL_LIBC_2 prevents this call from recurring */
		__INTERNAL_CALL_LIBC_2( bytes_read, recv, fd, &(s_info->tcp_state->md_buf[s_info->tcp_state->md_len]),
				to_read, flags );
		write_errno_log_entry(errno);
		
		assert( (bytes_read < 0) || ((size_t)bytes_read <= to_read) );
		if( bytes_read < 0 ) {
			return bytes_read;	// socket failure, or empty.
		}
		// else, at least some read. 
		s_info->tcp_state->md_len += bytes_read;

		if( s_info->tcp_state->md_len < LIBLOG_MIN_METADATA_LEN ) {
			// Not done yet; check what we have so far.
			rm_ret = read_metadata( &scratch_md, s_info->tcp_state->md_buf, s_info->tcp_state->md_len );    
			if (DEBUG) lprintf( "read_metadata(2) returned %d\n", rm_ret );
			switch( rm_ret ) {
				case LL_MD_NOT_MAGIC:
				case LL_MD_INVALID:
					// As with datagrams, we assume that a parse failure means the
					// message is not tagged.
					assert( s_info->peer_info == LIBLOG_PEER_UNKNOWN );
					if (DEBUG) print_buf( "Assuming not tagged:", s_info->tcp_state->md_buf, s_info->tcp_state->md_len );      
					// Signal caller to recover read bytes, reset state:
					s_info->peer_info = LIBLOG_PEER_NO_TAGS;
					return 0;
					break;
				case LL_MD_TRUNCATED:
					if( bytes_read < to_read ) {
						return 0;	// No error, but drained for now
					} else {
						continue;	// Just a small buf_len.  Keep trying.
					}
					break;
				default:
					fatal( "Should not reach this case" );
			}
		}	// else, loop condition should drop out.
	}

	/* Phase 2: Finish reading (variable-length) tag */
	assert( s_info->tcp_state->md_len >= LIBLOG_MIN_METADATA_LEN );

	rm_ret = read_metadata( &scratch_md, s_info->tcp_state->md_buf, s_info->tcp_state->md_len );
	if (DEBUG) lprintf( "read_metadata(3) returned %d\n", rm_ret );          
	switch( rm_ret ) {
		case LL_MD_NOT_MAGIC:
		case LL_MD_INVALID:
			// As with datagrams, we assume that a parse failure means the
			// message is not tagged.
			assert( s_info->peer_info == LIBLOG_PEER_UNKNOWN );
			if (DEBUG) print_buf( "Assuming not tagged:", s_info->tcp_state->md_buf, s_info->tcp_state->md_len );      
			// Signal caller to recover read bytes, reset state:
			s_info->peer_info = LIBLOG_PEER_NO_TAGS;
			return 0;
			break;
		case LL_MD_TRUNCATED:
			fatal( "Should not reach this case." );
			return 0;	// To calm compiler warnings.
			break;

		default:
			// Valid metadata.  Return value is length.    
			full_md_len = rm_ret;
			// Mark this as known tagged.
			assert( s_info->peer_info != LIBLOG_PEER_NO_TAGS );
			// Or else why did we even check for tags?
			if( s_info->peer_info == LIBLOG_PEER_UNKNOWN ) {
				if( DEBUG ) lprintf( "Marking stream as tagged.\n" );
				s_info->peer_info = LIBLOG_PEER_TAGS;
			}

			to_read = (full_md_len - s_info->tcp_state->md_len);
			assert( to_read > 0 );	// Must still read tag.
			/* __INTERNAL_CALL_LIBC_2 prevents this call from recurring */
			__INTERNAL_CALL_LIBC_2( bytes_read, recv, fd, &(s_info->tcp_state->md_buf[s_info->tcp_state->md_len]),
					to_read, flags );
			write_errno_log_entry(errno);
			
			assert( (bytes_read < 0) || ((size_t)bytes_read <= to_read) );
			if( bytes_read < 0 ) {
				return bytes_read;	// socket failure
			}
			s_info->tcp_state->md_len += bytes_read;
			if( full_md_len == s_info->tcp_state->md_len ) {
				// Finally have full metadata in buffer.  
				// Read everything, including tag, into real struct.  Cannot fail:
				assert( full_md_len == read_metadata( &(s_info->tcp_state->md), s_info->tcp_state->md_buf,
							s_info->tcp_state->md_len ));
				// Reset counters, switch to phase 2.
				s_info->tcp_state->bytes_left = s_info->tcp_state->md.msg_len;
				s_info->tcp_state->md_len = 0;
			}	// else we'll try again later.
			return 0;
	}
}
/**
 * Reads application data from the TCP stream until buffer is full or
 * we hit next chunk of metadata.
 */
static ssize_t read_stream_data( int fd, char * buf, size_t buf_len,
		int flags, struct sockaddr *from,
		socklen_t *from_len,
		liblog_socket_info *s_info )
{
	size_t to_read;
	ssize_t bytes_read;
	assert( s_info->tcp_state->bytes_left > 0 );

	assert( fd >= 0 );

	if (DEBUG) lprintf( "read_stream_data( %d, %d )\n", fd, s_info->tcp_state->bytes_left );

	to_read = MIN(buf_len, s_info->tcp_state->bytes_left);	// Do not read more than necessary.
	/* __INTERNAL_CALL_LIBC_2 prevents this call from recurring */
	__INTERNAL_CALL_LIBC_2( bytes_read, recvfrom, fd, buf,
			to_read, flags, from, from_len );
	write_errno_log_entry(errno);
	assert( (bytes_read < 0) || ((size_t)bytes_read <= to_read) );

	if( bytes_read > 0 ) {
		s_info->tcp_state->bytes_left -= bytes_read;
	}    
	return bytes_read;
}


/**
 * Receives and decodes a single message from a stream.
 * Assumes that fd is a TCP socket.
 * Returns the length of the decoded message.
 */
static ssize_t recv_wrapped_stream( int fd, char * buf, size_t buf_len,
		int flags, struct sockaddr *from,
		socklen_t *from_len,
		char * tag, uint64_t * vclock )
{
	/*
	 * This message may consume bytes that were sent by multiple calls to
	 * send_wrapped_msg().  We therefore need to be careful about
	 * extracting the metadata.
	 */
	ssize_t bytes_read;
	ssize_t rsm_ret;
	size_t bytes_read_total;
	liblog_socket_info * s_info;

	if (DEBUG) lprintf( "recv_wrapped_stream( %d )[%d]\n", fd, buf_len );


	assert( fd >= 0 );
	assert( fd <= LIBLOG_MAX_FD );
	s_info = &(_socket_info[fd]);
	assert( s_info->state == LIBLOG_SOCKET_TCP );
	// Have not tested flags:
	assert( (flags == 0) || (flags == MSG_DONTWAIT) );

	strcpy( tag, s_info->tcp_state->md.tag );	// Same info as last time.
	*vclock = s_info->tcp_state->md.vclock;
	bytes_read_total = 0;

	/* The following loop should alternate phases.  Every other iteration,
	 * read_stream_metadata() should set bytes_left to the size of the
	 * next data chunk; on the following iteration read_stream_data()
	 * should empty that data and reset bytes_left.  If the phase does
	 * not switch after read_stream_*(), the underlying socket must be
	 * (possibly temporarily) drained; just return early.
	 */
	while( bytes_read_total < buf_len ) {

		if( s_info->tcp_state->bytes_left == 0 ) {	// Start new send() chunk.
			rsm_ret = read_stream_metadata( fd, (buf_len-bytes_read_total),
					flags, s_info );
			if( rsm_ret < 0 ) {
				// FIXME: Socket error, but perhaps some bytes already
				// received?  Should they be returned first?
				return rsm_ret;
			} else if( s_info->peer_info != LIBLOG_PEER_TAGS ) {
				// Stream is not tagged after all.
				assert( bytes_read_total == 0 );	// Should be first try.
				memcpy( &(buf[bytes_read_total]), s_info->tcp_state->md_buf,
						s_info->tcp_state->md_len );
				bytes_read_total = s_info->tcp_state->md_len;
				s_info->tcp_state->md_len = 0;	// Reset for possible reuse?

				return bytes_read_total;
			} else if( s_info->tcp_state->bytes_left == 0 ) {	// Stream drained.
				return bytes_read_total;
			} // else:
			// Metadata complete. Perform some sanity checks, then continue loop.
			// Make sure tags do not change in middle of stream.
			if( 0 != strncmp(tag, s_info->tcp_state->md.tag, LIBLOG_MAX_TAG_LEN)) {
				// Possible only if we just read the first tag.
				assert( 0 == strncmp(tag, LIBLOG_UNKNOWN_TAG, LIBLOG_MAX_TAG_LEN) );
				assert( bytes_read_total == 0 );
				strcpy( tag, s_info->tcp_state->md.tag );
			}
			assert( *vclock < s_info->tcp_state->md.vclock );	// strictly monotonic.
			*vclock = s_info->tcp_state->md.vclock;	// Update

		} else {	// Finish last send() chunk
			bytes_read =
				read_stream_data( fd, &(buf[bytes_read_total]),
						(buf_len-bytes_read_total), flags,
						from, from_len, s_info );

			if( bytes_read < 0 ) {
				return bytes_read;
			} else {
				bytes_read_total += bytes_read;
				if( s_info->tcp_state->bytes_left > 0 ) {	// recv() could not finish chunk.
					return bytes_read_total;
				}
			}
		}
	}
	assert( bytes_read_total <= buf_len );
	return bytes_read_total;
}

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
		char * tag, uint64_t * vclock )
{
	if (DEBUG) lprintf( "recv_wrapped_msg( %d )\n", fd );
	assert( fd >= 0 );
	assert( fd <= LIBLOG_MAX_FD );
	/* We use different methods for receiving messages on UDP and TCP
	 * sockets, because the operating system treats the buffer length
	 * field differently, and because TCP may require extra work to
	 * extract the message metadata.
	 */
	/* FIXME -- To allow for non-logged senders, include
	 * LIBLOG_SOCKET_*_NEW state, and revert to ..._OTHER state if first
	 * packet does not include MAGIC. */
	if( _socket_info[fd].state == LIBLOG_SOCKET_UDP ) {
		return recv_wrapped_datagram( fd, buf, buf_len, flags,
				from, from_len, tag, vclock );
	} else {
		assert( _socket_info[fd].state ==  LIBLOG_SOCKET_TCP );
		return recv_wrapped_stream( fd, buf, buf_len, flags,
				from, from_len, tag, vclock );    
	}
}
