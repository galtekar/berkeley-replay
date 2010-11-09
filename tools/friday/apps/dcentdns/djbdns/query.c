#include <stdio.h>
#include "error.h"
#include "roots.h"
#include "log.h"
#include "case.h"
#include "cache.h"
#include "byte.h"
#include "dns.h"
#include "uint64.h"
#include "uint32.h"
#include "uint16.h"
#include "dd.h"
#include "alloc.h"
#include "response.h"
#include "query.h"

static int flagforwardonly = 0;
static int flaglog = 0;

void query_forwardonly(void)
{
  flagforwardonly = 1;
}

void query_log(void)
{
  flaglog = 1;
}

static void cachegeneric(const char type[2],const char *d,const char *data,unsigned int datalen,uint32 ttl)
{
  unsigned int len;
  char key[257];

  len = dns_domain_length(d);
  if (len > 255) return;

  byte_copy(key,2,type);
  byte_copy(key + 2,len,d);
  case_lowerb(key + 2,len);

  cache_set(key,len + 2,data,datalen,ttl);
}

static char save_buf[8192];
static unsigned int save_len;
static unsigned int save_ok;

static void save_start(void)
{
  save_len = 0;
  save_ok = 1;
}

static void save_data(const char *buf,unsigned int len)
{
  if (!save_ok) return;
  if (len > (sizeof save_buf) - save_len) { save_ok = 0; return; }
  byte_copy(save_buf + save_len,len,buf);
  save_len += len;
}

static void save_finish(const char type[2],const char *d,uint32 ttl)
{
  if (!save_ok) return;
  cachegeneric(type,d,save_buf,save_len,ttl);
}


static int typematch(const char rtype[2],const char qtype[2])
{
  return byte_equal(qtype,2,rtype) || byte_equal(qtype,2,DNS_T_ANY);
}

static uint32 ttlget(char buf[4])
{
  uint32 ttl;

  uint32_unpack_big(buf,&ttl);
  if (ttl > 1000000000) return 0;
  if (ttl > 604800) return 604800;
  return ttl;
}


static void cleanup(struct query *z)
{
  int j;
  int k;

  dns_transmit_free(&z->dt);
  for (j = 0;j < QUERY_MAXALIAS;++j)
    dns_domain_free(&z->alias[j]);
  for (j = 0;j < QUERY_MAXLEVEL;++j) {
    dns_domain_free(&z->name[j]);
    for (k = 0;k < QUERY_MAXNS;++k)
      dns_domain_free(&z->ns[j][k]);
  }
}

static int move_name_to_alias(struct query *z,uint32 ttl)
{
  int j ;
  
  if (z->alias[QUERY_MAXALIAS - 1]) return 0 ;
  for (j = QUERY_MAXALIAS - 1;j > 0;--j)
    z->alias[j] = z->alias[j - 1];
  for (j = QUERY_MAXALIAS - 1;j > 0;--j)
    z->aliasttl[j] = z->aliasttl[j - 1];
  z->alias[0] = z->name[0];
  z->aliasttl[0] = ttl;
  z->name[0] = 0;
  return 1 ;
}

static int rqa(struct query *z)
{
  int i;

  for (i = QUERY_MAXALIAS - 1;i >= 0;--i)
    if (z->alias[i]) {
      if (!response_query(z->alias[i],z->type,z->class)) return 0;
      while (i > 0) {
        if (!response_cname(z->alias[i],z->alias[i - 1],z->aliasttl[i])) return 0;
        --i;
      }
      if (!response_cname(z->alias[0],z->name[0],z->aliasttl[0])) return 0;
      return 1;
    }

  if (!response_query(z->name[0],z->type,z->class)) return 0;
  return 1;
}

static int globalip(char *d,char ip[4])
{
  if (dns_domain_equal(d,"\011localhost\0")) {
    byte_copy(ip,4,"\177\0\0\1");
    return 1;
  }
  if (dd(d,"",ip) == 4) return 1;
  return 0;
}

static char *t1 = 0;
static char *t2 = 0;
static char *t3 = 0;
//static char *cname = 0;
static char *referral = 0;
static unsigned int *records = 0;

static int smaller(char *buf,unsigned int len,unsigned int pos1,unsigned int pos2)
{
  char header1[12];
  char header2[12];
  int r;
  unsigned int len1;
  unsigned int len2;

  pos1 = dns_packet_getname(buf,len,pos1,&t1);
  dns_packet_copy(buf,len,pos1,header1,10);
  pos2 = dns_packet_getname(buf,len,pos2,&t2);
  dns_packet_copy(buf,len,pos2,header2,10);

  r = byte_diff(header1,4,header2);
  if (r < 0) return 1;
  if (r > 0) return 0;

  len1 = dns_domain_length(t1);
  len2 = dns_domain_length(t2);
  if (len1 < len2) return 1;
  if (len1 > len2) return 0;

  r = case_diffb(t1,len1,t2);
  if (r < 0) return 1;
  if (r > 0) return 0;

  if (pos1 < pos2) return 1;
  return 0;
}

static int doit(struct query *z,int state)
{
  char key[257];
  char *cached;
  unsigned int cachedlen;
  char *buf;
  unsigned int len;
  const char *whichserver;
  char header[12];
  char misc[20];
  unsigned int rcode;
  unsigned int posanswers;
  uint16 numanswers;
  unsigned int posauthority;
  uint16 numauthority;
  unsigned int posglue;
  uint16 numglue;
  unsigned int pos;
  unsigned int pos2;
  uint16 datalen;
  char *control;
  char *d;
  char *owner_name = 0;
  const char *dtype;
  unsigned int dlen;
  int flagout;
  //int flagcname;
  int flagreferral;
  int flagsoa;
  uint32 ttl;
  uint32 soattl;
  //uint32 cnamettl;
  int i;
  int j;
  int k;
  int p;
  int q;

  int dbglin = 0;
  errno = error_io;
  if (state == 1) goto HAVEPACKET;
  if (state == -1) {
    if (flaglog) log_servfail(z->name[z->level]);
    goto SERVFAIL;
  }


  NEWNAME:
  if (++z->loop == 200) { dbglin = 1; goto DIE; }
  d = z->name[z->level];
  dtype = z->level ? DNS_T_A : z->type;
  dlen = dns_domain_length(d);

  if (globalip(d,misc)) {
    if (z->level) {
      for (k = 0;k < 64;k += 4)
        if (byte_equal(z->servers[z->level - 1] + k,4,"\0\0\0\0")) {
	  byte_copy(z->servers[z->level - 1] + k,4,misc);
	  break;
	}
      goto LOWERLEVEL;
    }
    if (!rqa(z)) { dbglin = 2; goto DIE; }
    if (typematch(DNS_T_A,dtype)) {
      if (!response_rstart(d,DNS_T_A,655360)) { dbglin = 3; goto DIE; }
      if (!response_addbytes(misc,4)) { dbglin = 4; goto DIE; }
      response_rfinish(RESPONSE_ANSWER);
    }
    cleanup(z);
    return 1;
  }

  if (dns_domain_equal(d,"\0011\0010\0010\003127\7in-addr\4arpa\0")) {
    if (z->level) goto LOWERLEVEL;
    if (!rqa(z)) { dbglin = 5; goto DIE; }
    if (typematch(DNS_T_PTR,dtype)) {
      if (!response_rstart(d,DNS_T_PTR,655360)) { dbglin = 6; goto DIE; }
      if (!response_addname("\011localhost\0")) { dbglin = 7; goto DIE; }
      response_rfinish(RESPONSE_ANSWER);
    }
    cleanup(z);
    //if (flaglog) log_stats();
    return 1;
  }

  if (dlen <= 255) {
    byte_copy(key,2,DNS_T_ANY);
    byte_copy(key + 2,dlen,d);
    case_lowerb(key + 2,dlen);
    cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
    if (cached) {
      if (flaglog) log_cachednxdomain(d);
      goto NXDOMAIN;
    }

    byte_copy(key,2,DNS_T_CNAME);
    cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
    //if (cached) {
    /* A previous explicit query might have caused an empty RRSet to have been
     * cached.  Take care to ignore such a thing. 
     */
    if (cached && cachedlen) {
      if (typematch(DNS_T_CNAME,dtype)) {
        if (flaglog) log_cachedanswer(d,DNS_T_CNAME);
        if (!rqa(z)) { dbglin = 8; goto DIE; }
	if (!response_cname(z->name[0],cached,ttl)) { dbglin = 9; goto DIE; }
	cleanup(z);
	return 1;
      }
      if (flaglog) log_cachedcname(d,cached);
      //if (!dns_domain_copy(&cname,cached)) { dbglin = 10; goto DIE; }
      //goto CNAME;
      if (!z->level) {
	if (!move_name_to_alias(z,ttl)) { dbglin = 101; goto DIE ; }
      }
      if (!dns_domain_copy(&z->name[z->level],cached)) { dbglin = 102; goto DIE;
 }
      goto NEWNAME;
    }

    if (typematch(DNS_T_NS,dtype)) {
      byte_copy(key,2,DNS_T_NS);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
	if (flaglog) log_cachedanswer(d,DNS_T_NS);
	if (!rqa(z)) { dbglin = 11; goto DIE; }
	pos = 0;
	while (pos = dns_packet_getname(cached,cachedlen,pos,&t2)) {
	  if (!response_rstart(d,DNS_T_NS,ttl)) { dbglin = 12; goto DIE; }
	  if (!response_addname(t2)) { dbglin = 13; goto DIE; }
	  response_rfinish(RESPONSE_ANSWER);
	}
	cleanup(z);
	return 1;
      }
    }

    if (typematch(DNS_T_PTR,dtype)) {
      byte_copy(key,2,DNS_T_PTR);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
	if (flaglog) log_cachedanswer(d,DNS_T_PTR);
	if (!rqa(z)) { dbglin = 14; goto DIE; }
	pos = 0;
	while (pos = dns_packet_getname(cached,cachedlen,pos,&t2)) {
	  if (!response_rstart(d,DNS_T_PTR,ttl)) { dbglin = 15; goto DIE; }
	  if (!response_addname(t2)) { dbglin = 16; goto DIE; }
	  response_rfinish(RESPONSE_ANSWER);
	}
	cleanup(z);
	return 1;
      }
    }

    if (typematch(DNS_T_MX,dtype)) {
      byte_copy(key,2,DNS_T_MX);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
	if (flaglog) log_cachedanswer(d,DNS_T_MX);
	if (!rqa(z)) { dbglin = 17; goto DIE; }
	pos = 0;
	while (pos = dns_packet_copy(cached,cachedlen,pos,misc,2)) {
	  pos = dns_packet_getname(cached,cachedlen,pos,&t2);
	  if (!pos) break;
	  if (!response_rstart(d,DNS_T_MX,ttl)) { dbglin = 18; goto DIE; }
	  if (!response_addbytes(misc,2)) { dbglin = 19; goto DIE; }
	  if (!response_addname(t2)) { dbglin = 20; goto DIE; }
	  response_rfinish(RESPONSE_ANSWER);
	}
	cleanup(z);
	return 1;
      }
    }

    if (typematch(DNS_T_A,dtype)) {
      byte_copy(key,2,DNS_T_A);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
	if (z->level) {
	  if (flaglog) log_cachedanswer(d,DNS_T_A);
	  while (cachedlen >= 4) {
	    for (k = 0;k < 64;k += 4)
	      if (byte_equal(z->servers[z->level - 1] + k,4,"\0\0\0\0")) {
		byte_copy(z->servers[z->level - 1] + k,4,cached);
		break;
	      }
	    cached += 4;
	    cachedlen -= 4;
	  }
	  goto LOWERLEVEL;
	}

	if (flaglog) log_cachedanswer(d,DNS_T_A);
	if (!rqa(z)) { dbglin = 21; goto DIE; }
	while (cachedlen >= 4) {
	  if (!response_rstart(d,DNS_T_A,ttl)) { dbglin = 22; goto DIE; }
	  if (!response_addbytes(cached,4)) { dbglin = 23; goto DIE; }
	  response_rfinish(RESPONSE_ANSWER);
	  cached += 4;
	  cachedlen -= 4;
	}
	cleanup(z);
	return 1;
      }
    }

    //if (!typematch(DNS_T_ANY,dtype) && !typematch(DNS_T_AXFR,dtype) && !typematch(DNS_T_CNAME,dtype) && !typematch(DNS_T_NS,dtype) && !typematch(DNS_T_PTR,dtype) && !typematch(DNS_T_A,dtype) && !typematch(DNS_T_MX,dtype)) {
    if (!typematch(DNS_T_ANY,dtype) && !typematch(DNS_T_AXFR,dtype) && !typematch(DNS_T_NS,dtype) && !typematch(DNS_T_PTR,dtype) && !typematch(DNS_T_A,dtype) && !typematch(DNS_T_MX,dtype)) {
      byte_copy(key,2,dtype);
      cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
      if (cached && (cachedlen || byte_diff(dtype,2,DNS_T_ANY))) {
	if (flaglog) log_cachedanswer(d,dtype);
	if (!rqa(z)) { dbglin = 24; goto DIE; }
	while (cachedlen >= 2) {
	  uint16_unpack_big(cached,&datalen);
	  cached += 2;
	  cachedlen -= 2;
	  if (datalen > cachedlen) { dbglin = 25; goto DIE; }
	  if (!response_rstart(d,dtype,ttl)) { dbglin = 26; goto DIE; }
	  if (!response_addbytes(cached,datalen)) { dbglin = 27; goto DIE; }
	  response_rfinish(RESPONSE_ANSWER);
	  cached += datalen;
	  cachedlen -= datalen;
	}
	cleanup(z);
	return 1;
      }
    }
  }

  for (;;) {
    if (roots(z->servers[z->level],d)) {
      for (j = 0;j < QUERY_MAXNS;++j)
        dns_domain_free(&z->ns[z->level][j]);
      z->control[z->level] = d;
      break;
    }

    if (!flagforwardonly && (z->level < 2))
      if (dlen < 255) {
        byte_copy(key,2,DNS_T_NS);
        byte_copy(key + 2,dlen,d);
        case_lowerb(key + 2,dlen);
        cached = cache_get(key,dlen + 2,&cachedlen,&ttl);
        if (cached && cachedlen) {
	  z->control[z->level] = d;
          byte_zero(z->servers[z->level],64);
          for (j = 0;j < QUERY_MAXNS;++j)
            dns_domain_free(&z->ns[z->level][j]);
          pos = 0;
          j = 0;
          while (pos = dns_packet_getname(cached,cachedlen,pos,&t1)) {
	    if (flaglog) log_cachedns(d,t1);
            if (j < QUERY_MAXNS)
              if (!dns_domain_copy(&z->ns[z->level][j++],t1)) { dbglin = 28; goto DIE; }
	  }
          break;
        }
      }

    if (!*d) { dbglin = 29; goto DIE; }
    j = 1 + (unsigned int) (unsigned char) *d;
    dlen -= j;
    d += j;
  }


  HAVENS:
  for (j = 0;j < QUERY_MAXNS;++j)
    if (z->ns[z->level][j]) {
      if (z->level + 1 < QUERY_MAXLEVEL) {
        if (!dns_domain_copy(&z->name[z->level + 1],z->ns[z->level][j])) { dbglin = 30; goto DIE; }
        dns_domain_free(&z->ns[z->level][j]);
        ++z->level;
        goto NEWNAME;
      }
      dns_domain_free(&z->ns[z->level][j]);
    }

  for (j = 0;j < 64;j += 4)
    if (byte_diff(z->servers[z->level] + j,4,"\0\0\0\0"))
      break;
  if (j == 64) goto SERVFAIL;

  dns_sortip(z->servers[z->level],64);
  if (z->level) {
    if (flaglog) log_tx(z->name[z->level],DNS_T_A,z->control[z->level],z->servers[z->level],z->level);
    if (dns_transmit_start(&z->dt,z->servers[z->level],flagforwardonly,z->name[z->level],DNS_T_A,z->localip) == -1) { dbglin = 31; goto DIE; }
  }
  else {
    if (flaglog) log_tx(z->name[0],z->type,z->control[0],z->servers[0],0);
    if (dns_transmit_start(&z->dt,z->servers[0],flagforwardonly,z->name[0],z->type,z->localip) == -1) { dbglin = 97; goto DIE; }
  }
  return 0;


  LOWERLEVEL:
  dns_domain_free(&z->name[z->level]);
  for (j = 0;j < QUERY_MAXNS;++j)
    dns_domain_free(&z->ns[z->level][j]);
  --z->level;
  goto HAVENS;


  HAVEPACKET:
  if (++z->loop == 200) { dbglin = 32; goto DIE; }
  buf = z->dt.packet;
  len = z->dt.packetlen;

  whichserver = z->dt.servers + 4 * z->dt.curserver;
  control = z->control[z->level];
  d = z->name[z->level];
  dtype = z->level ? DNS_T_A : z->type;

  pos = dns_packet_copy(buf,len,0,header,12); if (!pos) { dbglin = 33; goto DIE; }
  pos = dns_packet_skipname(buf,len,pos); if (!pos) { dbglin = 34; goto DIE; }
  pos += 4;
  posanswers = pos;

  uint16_unpack_big(header + 6,&numanswers);
  uint16_unpack_big(header + 8,&numauthority);
  uint16_unpack_big(header + 10,&numglue);

  rcode = header[3] & 15;
  if (rcode && (rcode != 3)) { dbglin = 35; goto DIE; } /* impossible; see irrelevant() */

  flagout = 0;
  //flagcname = 0;
  flagreferral = 0;
  flagsoa = 0;
  soattl = 0;
  //cnamettl = 0;
  if (!dns_domain_copy(&owner_name,d)) { dbglin = 103; goto DIE; }
  /* This code assumes that the CNAME chain is presented in the correct 
  ** order.  The example algorithm in RFC 1034 will actually result in this
  ** being the case, but the words do not require it to be so.
  */

  for (j = 0;j < numanswers;++j) {
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) { dbglin = 36; goto DIE; }
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) { dbglin = 37; goto DIE; }

    //if (dns_domain_equal(t1,d))
    if (dns_domain_equal(t1,owner_name))
      if (byte_equal(header + 2,2,DNS_C_IN)) { /* should always be true */
        if (typematch(header,dtype))
          flagout = 1;
        else if (typematch(header,DNS_T_CNAME)) {
          //if (!dns_packet_getname(buf,len,pos,&cname)) { dbglin = 38; goto DIE; }
          //flagcname = 1;
	  //cnamettl = ttlget(header + 4);
          if (!dns_packet_getname(buf,len,pos,&owner_name)) { dbglin = 104; goto DIE; }
        }
      }
  
    uint16_unpack_big(header + 8,&datalen);
    pos += datalen;
  }
  dns_domain_free(&owner_name);
  posauthority = pos;

  for (j = 0;j < numauthority;++j) {
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) { dbglin = 39; goto DIE; }
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) { dbglin = 40; goto DIE; }

    if (typematch(header,DNS_T_SOA)) {
      flagsoa = 1;
      soattl = ttlget(header + 4);
      if (soattl > 3600) soattl = 3600;
    }
    else if (typematch(header,DNS_T_NS)) {
      flagreferral = 1;
      if (!dns_domain_copy(&referral,t1)) { dbglin = 41; goto DIE; }
    }

    uint16_unpack_big(header + 8,&datalen);
    pos += datalen;
  }
  posglue = pos;

  //if (!flagcname && !rcode && !flagout && flagreferral && !flagsoa)
  //if (dns_domain_equal(referral,control) || !dns_domain_suffix(referral,control)) {
  //if (flaglog) log_lame(whichserver,control,referral);
  //byte_zero(whichserver,4);
  //goto HAVENS;
  //}

  if (records) { alloc_free(records); records = 0; }

  k = numanswers + numauthority + numglue;
  records = (unsigned int *) alloc(k * sizeof(unsigned int));
  if (!records) { dbglin = 42; goto DIE; }

  pos = posanswers;
  for (j = 0;j < k;++j) {
    records[j] = pos;
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) { dbglin = 43; goto DIE; }
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) { dbglin = 44; goto DIE; }
    uint16_unpack_big(header + 8,&datalen);
    pos += datalen;
  }

  i = j = k;
  while (j > 1) {
    if (i > 1) { --i; pos = records[i - 1]; }
    else { pos = records[j - 1]; records[j - 1] = records[i - 1]; --j; }

    q = i;
    while ((p = q * 2) < j) {
      if (!smaller(buf,len,records[p],records[p - 1])) ++p;
      records[q - 1] = records[p - 1]; q = p;
    }
    if (p == j) {
      records[q - 1] = records[p - 1]; q = p;
    }
    while ((q > i) && smaller(buf,len,records[(p = q/2) - 1],pos)) {
      records[q - 1] = records[p - 1]; q = p;
    }
    records[q - 1] = pos;
  }

  i = 0;
  while (i < k) {
    char type[2];

    pos = dns_packet_getname(buf,len,records[i],&t1); if (!pos) { dbglin = 45; goto DIE; }
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) { dbglin = 46; goto DIE; }
    ttl = ttlget(header + 4);

    byte_copy(type,2,header);
    if (byte_diff(header + 2,2,DNS_C_IN)) { ++i; continue; }

    for (j = i + 1;j < k;++j) {
      pos = dns_packet_getname(buf,len,records[j],&t2); if (!pos) { dbglin = 47; goto DIE; }
      pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) { dbglin = 48; goto DIE; }
      if (!dns_domain_equal(t1,t2)) break;
      if (byte_diff(header,2,type)) break;
      if (byte_diff(header + 2,2,DNS_C_IN)) break;
    }

    if (!dns_domain_suffix(t1,control)) { i = j; continue; }
    if (!roots_same(t1,control)) { i = j; continue; }

    if (byte_equal(type,2,DNS_T_ANY))
      ;
    else if (byte_equal(type,2,DNS_T_AXFR))
      ;
    else if (byte_equal(type,2,DNS_T_SOA)) {
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) { dbglin = 49; goto DIE; }
        pos = dns_packet_getname(buf,len,pos + 10,&t2); if (!pos) { dbglin = 50; goto DIE; }
        pos = dns_packet_getname(buf,len,pos,&t3); if (!pos) { dbglin = 51; goto DIE; }
        pos = dns_packet_copy(buf,len,pos,misc,20); if (!pos) { dbglin = 52; goto DIE; }
        if (records[i] < posauthority)
          if (flaglog) log_rrsoa(whichserver,t1,t2,t3,misc,ttl);
        ++i;
      }
    }
    else if (byte_equal(type,2,DNS_T_CNAME)) {
      pos = dns_packet_skipname(buf,len,records[j - 1]); if (!pos) { dbglin = 53; goto DIE; }
      pos = dns_packet_getname(buf,len,pos + 10,&t2); if (!pos) { dbglin = 54; goto DIE; }
      if (flaglog) log_rrcname(whichserver,t1,t2,ttl);
      cachegeneric(DNS_T_CNAME,t1,t2,dns_domain_length(t2),ttl);
    }
    else if (byte_equal(type,2,DNS_T_PTR)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) { dbglin = 55; goto DIE; }
        pos = dns_packet_getname(buf,len,pos + 10,&t2); if (!pos) { dbglin = 56; goto DIE; }
        if (flaglog) log_rrptr(whichserver,t1,t2,ttl);
        save_data(t2,dns_domain_length(t2));
        ++i;
      }
      save_finish(DNS_T_PTR,t1,ttl);
    }
    else if (byte_equal(type,2,DNS_T_NS)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) { dbglin = 57; goto DIE; }
        pos = dns_packet_getname(buf,len,pos + 10,&t2); if (!pos) { dbglin = 58; goto DIE; }
        if (flaglog) log_rrns(whichserver,t1,t2,ttl);
        save_data(t2,dns_domain_length(t2));
        ++i;
      }
      save_finish(DNS_T_NS,t1,ttl);
    }
    else if (byte_equal(type,2,DNS_T_MX)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) { dbglin = 59; goto DIE; }
        pos = dns_packet_copy(buf,len,pos + 10,misc,2); if (!pos) { dbglin = 60; goto DIE; }
        pos = dns_packet_getname(buf,len,pos,&t2); if (!pos) { dbglin = 61; goto DIE; }
        if (flaglog) log_rrmx(whichserver,t1,t2,misc,ttl);
        save_data(misc,2);
        save_data(t2,dns_domain_length(t2));
        ++i;
      }
      save_finish(DNS_T_MX,t1,ttl);
    }
    else if (byte_equal(type,2,DNS_T_A)) {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) { dbglin = 62; goto DIE; }
        pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) { dbglin = 63; goto DIE; }
        if (byte_equal(header + 8,2,"\0\4")) {
          pos = dns_packet_copy(buf,len,pos,header,4); if (!pos) { dbglin = 64; goto DIE; }
          save_data(header,4);
          if (flaglog) log_rr(whichserver,t1,DNS_T_A,header,4,ttl);
        }
        ++i;
      }
      save_finish(DNS_T_A,t1,ttl);
    }
    else {
      save_start();
      while (i < j) {
        pos = dns_packet_skipname(buf,len,records[i]); if (!pos) { dbglin = 65; goto DIE; }
        pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) { dbglin = 66; goto DIE; }
        uint16_unpack_big(header + 8,&datalen);
        if (datalen > len - pos) { dbglin = 67; goto DIE; }
        save_data(header + 8,2);
        save_data(buf + pos,datalen);
        if (flaglog) log_rr(whichserver,t1,type,buf + pos,datalen,ttl);
        ++i;
      }
      save_finish(type,t1,ttl);
    }

    i = j;
  }

  alloc_free(records); records = 0;

  if (byte_diff(DNS_T_CNAME,2,dtype)) {
    /* This code assumes that the CNAME chain is presented in the correct 
    ** order.  The example algorithm in RFC 1034 will actually result in this
    ** being the case, but the words do not require it to be so.
    */
    pos = posanswers;
    for (j = 0;j < numanswers;++j) {
      pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) { dbglin = 105; goto DIE; }
      pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) { dbglin = 106; goto DIE; }

      if (dns_domain_equal(t1,d))
	if (byte_equal(header + 2,2,DNS_C_IN)) { /* should always be true */
	  if (typematch(header,DNS_T_CNAME)) {
	    ttl = ttlget(header + 4);
	    if (z->level == 0) {
	      if (!move_name_to_alias(z,ttl)) { dbglin = 107; goto DIE; }
	    }
	    if (!dns_packet_getname(buf,len,pos,&z->name[z->level])) { dbglin = 108; goto DIE; }
	    d = z->name[z->level];
	    if (!dns_domain_suffix(d,control) || !roots_same(d,control))
	      goto NEWNAME ;  /* Cannot trust the chain further - restart using current name */
	  }
	}
 

      //if (flagcname) {
      //ttl = cnamettl;
      //CNAME:
      //if (!z->level) {
      //if (z->alias[QUERY_MAXALIAS - 1]) { dbglin = 68; goto DIE; }
      //for (j = QUERY_MAXALIAS - 1;j > 0;--j)
      //z->alias[j] = z->alias[j - 1];
      //for (j = QUERY_MAXALIAS - 1;j > 0;--j)
      //z->aliasttl[j] = z->aliasttl[j - 1];
      //z->alias[0] = z->name[0];
      //z->aliasttl[0] = ttl;
      //z->name[0] = 0;
      uint16_unpack_big(header + 8,&datalen);
      pos += datalen;
    }
    //if (!dns_domain_copy(&z->name[z->level],cname)) { dbglin = 69; goto DIE; }
    //goto NEWNAME;
  }
  
  /* A "no such name" error applies to the end of any CNAME chain, not to the start. */
  if (rcode == 3) {
    if (flaglog) log_nxdomain(whichserver,d,soattl);
    cachegeneric(DNS_T_ANY,d,"",0,soattl);

    NXDOMAIN:
    if (z->level) goto LOWERLEVEL;
    if (!rqa(z)) { dbglin = 70; goto DIE; }
    response_nxdomain();
    cleanup(z);
    return 1;
  }

  /* We check for a lame server _after_ we have cached any records that it
  ** might have returned to us.  This copes better with the incorrect
  ** behaviour of one content DNS server software that doesn't return
  ** complete CNAME chains but instead returns only the first link in a
  ** chain followed by a lame delegation to the same server.
  ** Also: We check for a lame server _after_ following the CNAME chain.  The
  ** delegation in a referral answer applies to the _end_ of the chain, not
  ** to the beginning.
  */
  if (!rcode && !flagout && flagreferral && !flagsoa)
    if (dns_domain_equal(referral,control) || !dns_domain_suffix(referral,control)) {
      //log_lame(whichserver,control,referral);
      byte_zero(whichserver,4);
      goto HAVENS;
    }

  if (!flagout && flagsoa)
    /* Don't save empty RRSets for those types that we use as special markers. */
    if (byte_diff(DNS_T_ANY,2,dtype))
      //if (byte_diff(DNS_T_AXFR,2,dtype))
      //if (byte_diff(DNS_T_CNAME,2,dtype)) {
      if (byte_diff(DNS_T_AXFR,2,dtype)) {
          save_start();
          save_finish(dtype,d,soattl);
	  if (flaglog) log_nodata(whichserver,d,dtype,soattl);
      }

  //if (flaglog) log_stats();


  if (flagout || flagsoa || !flagreferral) {
    if (z->level) {
      pos = posanswers;
      for (j = 0;j < numanswers;++j) {
        pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) { dbglin = 71; goto DIE; }
        pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) { dbglin = 72; goto DIE; }
        uint16_unpack_big(header + 8,&datalen);
        if (dns_domain_equal(t1,d))
          if (typematch(header,DNS_T_A))
            if (byte_equal(header + 2,2,DNS_C_IN)) /* should always be true */
              if (datalen == 4)
                for (k = 0;k < 64;k += 4)
                  if (byte_equal(z->servers[z->level - 1] + k,4,"\0\0\0\0")) {
                    if (!dns_packet_copy(buf,len,pos,z->servers[z->level - 1] + k,4)) { dbglin = 73; goto DIE; }
                    break;
                  }
        pos += datalen;
      }
      goto LOWERLEVEL;
    }

    if (!rqa(z)) { dbglin = 74; goto DIE; }

    pos = posanswers;
    for (j = 0;j < numanswers;++j) {
      pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) { dbglin = 75; goto DIE; }
      pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) { dbglin = 76; goto DIE; }
      ttl = ttlget(header + 4);
      uint16_unpack_big(header + 8,&datalen);
      if (dns_domain_equal(t1,d))
        if (byte_equal(header + 2,2,DNS_C_IN)) /* should always be true */
          if (typematch(header,dtype)) {
            if (!response_rstart(t1,header,ttl)) { dbglin = 77; goto DIE; }
  
            if (typematch(header,DNS_T_NS) || typematch(header,DNS_T_CNAME) || typematch(header,DNS_T_PTR)) {
              if (!dns_packet_getname(buf,len,pos,&t2)) { dbglin = 78; goto DIE; }
              if (!response_addname(t2)) { dbglin = 79; goto DIE; }
            }
            else if (typematch(header,DNS_T_MX)) {
              pos2 = dns_packet_copy(buf,len,pos,misc,2); if (!pos2) { dbglin = 80; goto DIE; }
              if (!response_addbytes(misc,2)) { dbglin = 81; goto DIE; }
              if (!dns_packet_getname(buf,len,pos2,&t2)) { dbglin = 82; goto DIE; }
              if (!response_addname(t2)) { dbglin = 83; goto DIE; }
            }
            else if (typematch(header,DNS_T_SOA)) {
              pos2 = dns_packet_getname(buf,len,pos,&t2); if (!pos2) { dbglin = 84; goto DIE; }
              if (!response_addname(t2)) { dbglin = 85; goto DIE; }
              pos2 = dns_packet_getname(buf,len,pos2,&t3); if (!pos2) { dbglin = 86; goto DIE; }
              if (!response_addname(t3)) { dbglin = 87; goto DIE; }
              pos2 = dns_packet_copy(buf,len,pos2,misc,20); if (!pos2) { dbglin = 88; goto DIE; }
              if (!response_addbytes(misc,20)) { dbglin = 89; goto DIE; }
            }
            else {
              if (pos + datalen > len) { dbglin = 90; goto DIE; }
              if (!response_addbytes(buf + pos,datalen)) { dbglin = 91; goto DIE; }
            }
  
            response_rfinish(RESPONSE_ANSWER);
          }

      pos += datalen;
    }

    cleanup(z);
    return 1;
  }


  if (!dns_domain_suffix(d,referral)) { dbglin = 92; goto DIE; }
  control = d + dns_domain_suffixpos(d,referral);
  z->control[z->level] = control;
  byte_zero(z->servers[z->level],64);
  for (j = 0;j < QUERY_MAXNS;++j)
    dns_domain_free(&z->ns[z->level][j]);
  k = 0;

  pos = posauthority;
  for (j = 0;j < numauthority;++j) {
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) { dbglin = 93; goto DIE; }
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) { dbglin = 94; goto DIE; }
    uint16_unpack_big(header + 8,&datalen);
    if (dns_domain_equal(referral,t1)) /* should always be true */
      if (typematch(header,DNS_T_NS)) /* should always be true */
        if (byte_equal(header + 2,2,DNS_C_IN)) /* should always be true */
          if (k < QUERY_MAXNS)
            if (!dns_packet_getname(buf,len,pos,&z->ns[z->level][k++])) { dbglin = 95; goto DIE; }
    pos += datalen;
  }

  goto HAVENS;


  SERVFAIL:
  if (z->level) goto LOWERLEVEL;
  if (!rqa(z)) { dbglin = 96; goto DIE; }
  response_servfail();
  cleanup(z);
  return 1;


  DIE:
  fflush(stdout);
  cleanup(z);
  if (records) { alloc_free(records); records = 0; }
  dns_domain_free(&owner_name) ;
  return -1;
}

int query_start(struct query *z,char *dn,char type[2],char class[2],char localip[4])
{
  if (byte_equal(type,2,DNS_T_AXFR)) { errno = error_perm; return -1; }

  cleanup(z);
  z->level = 0;
  z->loop = 0;

  if (!dns_domain_copy(&z->name[0],dn)) return -1;
  byte_copy(z->type,2,type);
  byte_copy(z->class,2,class);
  byte_copy(z->localip,4,localip);

  return doit(z,0);
}

int query_get(struct query *z,iopause_fd *x,struct taia *stamp)
{
  switch(dns_transmit_get(&z->dt,x,stamp)) {
    case 1:
      return doit(z,1);
    case -1:
      return doit(z,-1);
  }
  return 0;
}

void query_io(struct query *z,iopause_fd *x,struct taia *deadline)
{
  dns_transmit_io(&z->dt,x,deadline);
}
