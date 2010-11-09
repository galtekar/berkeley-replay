#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include "chord.h"

/* pack: pack binary items into buf, return length */

int pack(uchar *buf, char *fmt, ...)
{
  va_list args;
  char *p;
  uchar *bp;
  chordID *id;
  ushort s;
  ulong l;

  bp = buf;
  va_start(args, fmt);
  for (p = fmt; *p != '\0'; p++) {
    switch (*p) {
    case 'c':   /* char */
      *bp++ = va_arg(args, int);
      break;
    case 's':   /* short */
      s = va_arg(args, int);
      s = htons(s);
      memmove(bp, (char *)&s, sizeof(int));
      bp += sizeof(ushort);
      break;
    case 'l':   /* long */
      l = va_arg(args, ulong);
      l = htonl(l);
      memmove(bp, (char *)&l, sizeof(ulong));
      bp += sizeof(ulong);
      break;
    case 'x':   /* id */
      id = va_arg(args, chordID *);
      memmove(bp, id->x, ID_LEN);
      bp += ID_LEN;
      break;
    default:   /* illegal type character */
      va_end(args);
      return -1;
    }
  }
  va_end(args);
  return bp - buf;
}

/**********************************************************************/

/* unpack: unpack binary items from buf, return length */
int unpack(uchar *buf, char *fmt, ...)
{
  va_list args;
  char *p;
  uchar *bp, *pc;
  chordID *id;
  ushort *ps;
  ulong *pl;
  
  bp = buf;  
  va_start(args, fmt);
  for (p = fmt; *p != '\0'; p++) {
    switch (*p) {
    case 'c':   /* char */
      pc = va_arg(args, uchar*);
      *pc = *bp++;
      break;
    case 's':   /* short */
      ps = va_arg(args, ushort*);
      *ps = ntohs(*(ushort*)bp);
      bp += sizeof(ushort);
      break;
    case 'l':   /* long */
      pl = va_arg(args, ulong*);
      *pl  = ntohl(*(ulong*)bp);
      bp += sizeof(ulong);
      break;
    case 'x':   /* id */
      id = va_arg(args, chordID *);
      memmove(id->x, bp, ID_LEN);
      bp += ID_LEN;
      break;
    default:   /* illegal type character */
      va_end(args);
      return -1;
    }
  }
  va_end(args);
  return bp - buf;
}

/**********************************************************************/

static int (*unpackfn[])(Server *, int, uchar *) = {
  unpack_data,
  unpack_fs,
  unpack_fs_repl,
  unpack_stab,
  unpack_stab_repl,
  unpack_notify,
  unpack_ping,
  unpack_pong,
  unpack_get_fingers,
  unpack_repl_fingers,
};

/* dispatch: unpack and process packet */
int dispatch(Server *srv, int n, uchar *buf)
{
  uchar type;
  int res;

  type = buf[0];
  
  if (type >= NELEMS(unpackfn))
    eprintf("bad packet type 0x%x", type);
  res = (*unpackfn[type])(srv, n, buf);
  if (res < 0)
    eprintf("protocol error, type %x length %d", type, n);
  return res;
}

/**********************************************************************/

/* pack_data: pack data packet */
int pack_data(uchar *buf, chordID *id, ushort len, uchar *data)
{
  int n;

  n = pack(buf, "cxs", CHORD_ROUTE, id, len);
  if (n >= 0) {
    memmove(buf + n, data, len);
    n += len;
  }
  return n;
}

/**********************************************************************/

/* unpack_data: unpack and process data packet */
int unpack_data(Server *srv, int n, uchar *buf)
{
  uchar type;
  int len;
  chordID id;
  ushort pkt_len;

  len = unpack(buf, "cxs", &type, id.x, &pkt_len);
  if (len < 0 || len + pkt_len != n)
    return -1;
  assert(type == CHORD_ROUTE);
  return process_data(srv, &id, pkt_len, buf + len);
}

/**********************************************************************/

/* pack_fs: pack find_successor packet */
int pack_fs(uchar *buf, chordID *id, ulong addr, ushort port)
{
  return pack(buf, "cxls", CHORD_FS, id, addr, port);
}

/**********************************************************************/

/* unpack_fs: unpack and process find_successor packet */
int unpack_fs(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  chordID id;

  if (unpack(buf, "cxls", &type, &id, &addr, &port) != n)
    return -1;
  assert(type == CHORD_FS);
  return process_fs(srv, &id, addr, port);
}

/**********************************************************************/

/* pack_fs_repl: pack find_successor reply packet */
int pack_fs_repl(uchar *buf, chordID *id, ulong addr, ushort port)
{
  return pack(buf, "cxls", CHORD_FS_REPL, id, addr, port);
}

/**********************************************************************/

/* unpack_fs_repl: unpack and process find_successor reply packet */
int unpack_fs_repl(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  chordID id;

  if (unpack(buf, "cxls", &type, &id, &addr, &port) != n)
    return -1;
  assert(type == CHORD_FS_REPL);
  return process_fs_repl(srv, &id, addr, port);
}

/**********************************************************************/

/* pack_stab: pack stabilize packet */
int pack_stab(uchar *buf, chordID *id, ulong addr, ushort port)
{
  return pack(buf, "cxls", CHORD_STAB, id, addr, port);
}

/**********************************************************************/

/* unpack_stab: unpack and process stabilize packet */
int unpack_stab(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  chordID id;

  if (unpack(buf, "cxls", &type, &id, &addr, &port) != n)
    return -1;
  assert(type == CHORD_STAB);
  return process_stab(srv, &id, addr, port);
}

/**********************************************************************/

/* pack_stab_repl: pack stabilize reply packet */
int pack_stab_repl(uchar *buf, chordID *id, ulong addr, ushort port)
{
  return pack(buf, "cxls", CHORD_STAB_REPL, id, addr, port);
}

/**********************************************************************/

/* unpack_stab_repl: unpack and process stabilize reply packet */
int unpack_stab_repl(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  chordID id;

  if (unpack(buf, "cxls", &type, &id, &addr, &port) != n)
    return -1;
  assert(type == CHORD_STAB_REPL);
  return process_stab_repl(srv, &id, addr, port);
}

/**********************************************************************/

/* pack_notify: pack notify packet */
int pack_notify(uchar *buf, chordID *id, ulong addr, ushort port)
{
  return pack(buf, "cxls", CHORD_NOTIFY, id, addr, port);
}

/**********************************************************************/

/* unpack_notify: unpack notify packet */
int unpack_notify(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  chordID id;

  if (unpack(buf, "cxls", &type, &id, &addr, &port) != n)
    return -1;
  assert(type == CHORD_NOTIFY);
  return process_notify(srv, &id, addr, port);
}

/**********************************************************************/

/* pack_ping: pack ping packet */
int pack_ping(uchar *buf, ulong addr, ushort port, ulong time)
{
  return pack(buf, "clsl", CHORD_PING, addr, port, time);
}

/**********************************************************************/

/* unpack_ping: unpack and process ping packet */
int unpack_ping(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  ulong time;

  if (unpack(buf, "clsl", &type, &addr, &port, &time) != n)
    return -1;
  assert(type == CHORD_PING);
  return process_ping(srv, addr, port, time);
}

/**********************************************************************/

/* pack_pong: pack pong packet */
int pack_pong(uchar *buf, chordID *id, ulong addr, ushort port, ulong time)
{
  return pack(buf, "cxlsl", CHORD_PONG, id, addr, port, time);
}

/**********************************************************************/

/* unpack_pong: unpack pong packet */
int unpack_pong(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  chordID id;
  ulong   time;

  if (unpack(buf, "cxlsl", &type, &id, &addr, &port, &time) != n)
    return -1;
  assert(type == CHORD_PONG);
  return process_pong(srv, &id, addr, port, time);
}

/**********************************************************************/
/**********************************************************************/

/* pack_get_fingers: pack get fingers packet */
int pack_get_fingers(uchar *buf, ulong addr, ushort port, ulong time)
{
  return pack(buf, "clsl", CHORD_GET_FINGERS, addr, port, time);
}

/**********************************************************************/

/* unpack_get_fingers: unpack and process get_fingers packet */
int unpack_get_fingers(Server *srv, int n, uchar *buf)
{
  uchar type;
  ulong addr;
  ushort port;
  ulong time;

  if (unpack(buf, "clsl", &type, &addr, &port, &time) != n)
    return -1;
  assert(type == CHORD_GET_FINGERS);
  return process_get_fingers(srv, addr, port, time);
}

#define INCOMPLETE_FINGER_LIST -1
#define END_FINGER_LIST 0

/* pack_repl_fingers: pack repl fingers packet */
int pack_repl_fingers(uchar *buf, Server *srv, ulong time)
{
  Finger *f;
  int len, l;

  assert(srv);
  len = pack(buf, "cxls", CHORD_REPL_FINGERS, &srv->node.id, 
	     srv->node.addr, srv->node.port);
  /* pack fingers */
  for (f = srv->head_flist; f; f = f->next) {
    l = pack(buf + len, "xls",
             &f->node.id, 
	     f->node.addr, f->node.port); 
    len += l;
    if (len + l + 1 > BUFSIZE) {
      len += pack(buf + len, "c", INCOMPLETE_FINGER_LIST);
      return len;
    }
  }
  len += pack(buf + len, "c", END_FINGER_LIST);
  return len;
}


/* unpack_repl_fingers: unpack and process repl_fingers packet */
int unpack_repl_fingers(Server *null, int n, uchar *buf)
{
  Server dummy_srv;
  chordID id;
  uchar type, ret_code;
  ulong addr;
  ushort port;
  ulong time;
  int len;

#ifndef CCURED  
  memset((char *)&dummy_srv, 0, sizeof(Server));
#else
  memset(&dummy_srv, 0, sizeof(Server));
#endif
  
  len = unpack(buf, "cxls", &type, &dummy_srv.node.id, 
	       (ulong*)&dummy_srv.node.addr, (ushort*)&dummy_srv.node.port);
  if (len >= n) 
    return -1;
  assert(type == CHORD_REPL_FINGERS);

  do {
    len += unpack(buf + len, "xls", &id, &addr, &port);
    insert_finger(&dummy_srv, &id, addr, port);
  } while (len + 1 < n);

  if (len+1 > n) return -1;
  
  unpack(buf + len, "c", &ret_code);

  return process_repl_fingers(&dummy_srv, ret_code, time);
}
