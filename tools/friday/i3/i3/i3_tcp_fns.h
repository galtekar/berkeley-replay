#ifndef _I3_TCP_FNS_H
#define _I3_TCP_FNS_H

/*************************************************************
 *  Packet formats for TCP packets, pack/unpack
 ************************************************************/
/* Header = [ 1 byte: MAGIC | 2 bytes (packet length) ] */
#define TCP_I3_HEADER_SIZE 3
#define TCP_I3_HEADER_MAGIC 0x42
int send_tcp(char *p, int len, int fd);
int recv_tcp(char *p, int len, int fd);

#endif
