#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <sys/time.h>
#include "dns.h"
#include "uint16.h"
#include "uint32.h"
#include "byte.h"
#include "alloc.h"
#include "codonsutils.h"
#include "dnssecutils.h"
#include "error.h"

#include "logger.h"
#include <assert.h>

static char versionname[] = "\007version\006codons\000";
static char statsname[] = "\005stats\006codons\000";

unsigned short getshort(const char s[2]) {
  uint16 u;
  uint16_unpack_big(s, &u);
  return u;
}

unsigned int getint(const char s[4]) {
  uint32 u;

  uint32_unpack_big(s, &u);

  return u;
}

void getsha1hash(const char *name, unsigned char digest[20]) {
  char temp[256];

  int pos = 0;
  while(name[pos]) {
    int i;
    for (i=0; i<name[pos]; i++) {
      if (name[pos+1+i] >= 'A' && name[pos+1+i] <= 'Z') {
	temp[pos+i] = name[pos+1+i] - 'A' + 'a';
      }
      else {
	temp[pos+i] = name[pos+1+i];
      }
    }
    temp[pos+i] = '.';
    pos += name[pos]+1;
  }
  temp[pos] = 0;

  SHA1(temp, pos, digest);
}

int rdata_diff(register char *rr1, int len1, register char *rr2, int len2) {
  register int n = (len1 < len2) ? len1 : len2;

  for (;;) {
    if (!n) return len1-len2; if (*rr1 != *rr2) break; ++rr1; ++rr2; --n;
    if (!n) return len1-len2; if (*rr1 != *rr2) break; ++rr1; ++rr2; --n;
    if (!n) return len1-len2; if (*rr1 != *rr2) break; ++rr1; ++rr2; --n;
    if (!n) return len1-len2; if (*rr1 != *rr2) break; ++rr1; ++rr2; --n;
  }  
  return ((int)(unsigned int)(unsigned char) *rr1)
       - ((int)(unsigned int)(unsigned char) *rr2);
}

void printHeader(Header header) {
  Flags2 *flags2 = (Flags2 *)&header.flags2;
  Flags3 *flags3 = (Flags3 *)&header.flags3;
  printf("Id: %d, Flags: response %d, authoritative %d, truncation %d, recursion desired %d, recursion available %d, codons %d, authentic %d, checking disabled %d, rcode %d\n", getshort(header.id), flags2->response, flags2->authoritative, flags2->truncation, flags2->recurse, flags3->recurseavail, flags3->reserved, flags3->ad, flags3->cd, flags3->rcode);
  printf("RR Counts: query %d, answer %d, authoritative %d, additional %d\n", header.qdcount, header.ancount, header.nscount, header.arcount);
}

uint16 getLabels(const char *name) {
  uint16 labels = 0;
  int pos = 0;
  while(name[pos]) {
    labels += 1;
    pos += name[pos]+1;
  }
  return labels;
}

int printName(const char *name) {
  int i;
  int pos = 0;
  while(name[pos]) {
    for (i=0; i<name[pos]; i++) {
      printf("%c", name[pos+1+i]);
    }
    printf(".");
    pos += name[pos]+1;
  }
  return pos+1;
}

int printCharStrs(const char *text, int length) {
  int i;
  int pos = 0;
  while(pos < length) {
    for (i=0; i<text[pos]; i++) {
      printf("%c", text[pos+1+i]);
    }
    printf(" ");
    pos += text[pos]+1;
  }
  return pos+1;
}

int readDataFromQuery(char *pkt, int len, DNSQueryMsg **msgPtr) {
  *msgPtr = 0;

  DNSQueryMsg *msg;

  if (pkt == 0 || len < 12) {
    errno = error_proto;
    return 0; // no header
  }

  if (((uint8)pkt[2] & 0x80) || byte_diff(pkt+4, 8, "\0\1\0\0\0\0\0\0")) {
    errno = error_proto;
    return 0; // not a query
  }

  int pos = 12;
  pos = dns_packet_skipname(pkt, len, pos);
  if (pos == 0) {
    return 0; //bad name format;
  }
  if (pos+4 > len) {
    errno = error_proto;
    return 0; //short packet
  }

  int qdatalen = pos - 12 + 4;
  msg = (DNSQueryMsg *)alloc_channel(qdatalen + 14, 2);
  if (msg == 0) {
    errno = error_nomem;
    return 0;
  }
  
  byte_zero(msg, qdatalen + 14);

  msg->length = 12 + qdatalen;
  byte_copy(msg->header.id, 2, pkt);
  byte_copy(&msg->header.flags2, 1, pkt+2);
  byte_copy(&msg->header.flags3, 1, pkt+3);
  msg->header.qdcount = 1;
  byte_copy(msg->qdata, qdatalen, pkt+12);

  *msgPtr = msg;
  return 1;
} 

void printQueryMsg(const DNSQueryMsg *msg) {
  printHeader(msg->header);
  printName(msg->qdata);
  printf(" Type %d, Class %d Length %d\n", getshort(msg->qdata+msg->length-12-4), getshort(msg->qdata+msg->length-12-2), msg->length);
}

void printQueryData(QueryData qdata) {
  printName(qdata.qname);
  printf(" Type %d, Class %d Length %d\n", getshort(qdata.qtype), getshort(qdata.qclass), qdata.length);
}

void printRData(const char type[2], const char *rdata, int rdatalen) {
  if (byte_equal(type, 2, DNS_T_A) && rdatalen == 4) {
     printf("A: %d.%d.%d.%d\n", (unsigned char)rdata[0], (unsigned char)rdata[1], (unsigned char)rdata[2], (unsigned char)rdata[3]);
  }
  else if (byte_equal(type, 2, DNS_T_CNAME) || byte_equal(type, 2, DNS_T_NS) || byte_equal(type, 2, DNS_T_PTR)) {
     printf("Name ");
     printName(rdata);
     printf("\n");
  }
  else if (byte_equal(type, 2, DNS_T_MX)) {
     printf("MX: Pref %d, Exchange ", getshort(rdata));
     printName(rdata+2);
     printf("\n");
  }
  else if (byte_equal(type, 2, DNS_T_SOA)) {
    printf("SOA: MName ");
    int pos = printName(rdata);
    printf(" RName ");
    pos += printName(rdata+pos);
    printf(" serial %d, refresh %d, retry %d, expire %d, minimum %d\n", getint(rdata+pos), getint(rdata+pos+4), getint(rdata+pos+8), getint(rdata+pos+12), getint(rdata+pos+16));
  }
  else if (byte_equal(type, 2, DNS_T_KEY)) {
    uint16 fdata = getshort(rdata);
    KEYFlags *flags = (KEYFlags *)&fdata;
    printf("KEY: ac %d, xt %d, nametype %d, sig %d, protocol %d, algorithm %d\n", flags->ac, flags->xt, flags->nametype, flags->sig, rdata[2], rdata[3]);
  }
  else if (byte_equal(type, 2, DNS_T_SIG)) {
    printf("SIG: type %d, algorithm %d, labels %d, ttl %d, expiration %d, inception %d SNAME ", getshort(rdata), rdata[2], rdata[3], getint(rdata+4), getint(rdata+8), getint(rdata+12));
    printName(rdata+18);
    printf("\n");
  }
  else if (byte_equal(type, 2, DNS_T_NXT)) {
    printf("NXT: next domain name ");
    printName(rdata);
    printf("\n");
  }
  else if (byte_equal(type, 2, DNS_T_SRV)) {
    printf("SRV: priority %d, weight %d, port %d, target  ", getshort(rdata), getshort(rdata+2), getshort(rdata+4));
    printName(rdata+6);
    printf("\n");
  }
  else if (byte_equal(type, 2, DNS_T_TXT)) {
    printf("TXT: ");
    printCharStrs(rdata, rdatalen);
    printf("\n");
  }
  else {
  } 
}

int readRDataFromPacket(char *pkt, int len, int oldp, const char type[2], int oldrdatalen, char **rdataptr) {
  char *rdata = 0;
  int newrdatalen = 0;

  char *temp1 = 0;
  char *temp2 = 0;
  int temp1len = 0;
  int temp2len = 0;
  int pos = oldp;

  if (byte_equal(type, 2, DNS_T_CNAME) || byte_equal(type, 2, DNS_T_NS) || byte_equal(type, 2, DNS_T_PTR)) {
    pos = dns_packet_getname(pkt, len, pos, &temp1);
    alloc_channel(0, 3);
    if (pos == 0) {
      goto bad_return;
    } 

    newrdatalen = dns_domain_length(temp1);
    rdata = alloc_channel(newrdatalen, 1);
    if (rdata == 0) {
      errno = error_nomem;      
      goto bad_return;
    }

    byte_copy(rdata, newrdatalen, temp1);
  }
  else if (byte_equal(type, 2, DNS_T_MX)) {
    if (pos+2 > len) {
      errno = error_proto;
      goto bad_return;
    }
    
    pos = dns_packet_getname(pkt, len, pos+2, &temp1);
    alloc_channel(0, 3);
    if (pos == 0) {
      goto bad_return;
    }

    temp1len = dns_domain_length(temp1);
    newrdatalen = 2 + temp1len;

    rdata = alloc_channel(newrdatalen, 1);
    if (rdata == 0) {
      errno = error_nomem;      
      goto bad_return;
    }

    byte_copy(rdata, 2, pkt+oldp);
    byte_copy(rdata+2, temp1len, temp1);
  }
  else if (byte_equal(type, 2, DNS_T_SOA)) {
    pos = dns_packet_getname(pkt, len, pos, &temp1);
    alloc_channel(0, 3);
    if (pos == 0) {
      goto bad_return;
    }
    pos = dns_packet_getname(pkt, len, pos, &temp2);
    alloc_channel(0, 3);
    if (pos == 0) {
      goto bad_return;
    }
    if (pos+20 > len) {
      errno = error_proto;
      goto bad_return;
    }

    temp1len = dns_domain_length(temp1);
    temp2len = dns_domain_length(temp2);
    newrdatalen = temp1len + temp2len + 20;

    rdata = alloc_channel(newrdatalen, 1);
    if (rdata == 0) {
      errno = error_nomem;      
      goto bad_return;
    }

    byte_copy(rdata, temp1len, temp1);
    byte_copy(rdata+temp1len, temp2len, temp2);
    byte_copy(rdata+temp1len+temp2len, 20, pkt+pos);
  }
  else if (byte_equal(type, 2, DNS_T_SIG)) {
    if (pos+18 > len) {
      errno = error_proto;
      goto bad_return;
    }

    pos = dns_packet_getname(pkt, len, pos+18, &temp1);
    alloc_channel(0, 3);
    if (pos == 0) {
      goto bad_return;
    }

    if (pos > len) {
      errno = error_proto;
      goto bad_return;
    }

    temp1len = dns_domain_length(temp1);
    int siglen = len - pos;
    newrdatalen = 18 + temp1len + siglen;

    rdata = alloc_channel(newrdatalen, 1);
    if (rdata == 0) {
      errno = error_nomem;      
      goto bad_return;
    }    

    byte_copy(rdata, 18, pkt+oldp);
    byte_copy(rdata+18, temp1len, temp1);
    byte_copy(rdata+18+temp1len, siglen, pkt+pos);
  }
  else if (byte_equal(type, 2, DNS_T_NXT)) {
    pos = dns_packet_getname(pkt, len, pos, &temp1);
    alloc_channel(0, 3);
    if (pos == 0) {
      goto bad_return;
    }
    if (pos+2 > len) {
      errno = error_proto;
      goto bad_return;
    }
    
    temp1len = dns_domain_length(temp1);
    int maplen = len - pos;
    newrdatalen = temp1len + maplen;

    rdata = alloc_channel(newrdatalen, 1);
    if (rdata == 0) {
      errno = error_nomem;      
      goto bad_return;
    }    

    byte_copy(rdata, temp1len, temp1);
    byte_copy(rdata+temp1len, maplen, pkt+pos);
  }
  else {
    newrdatalen = oldrdatalen;
    rdata = pkt+oldp;
  }

 bad_return:	   
  if (temp1 != 0) alloc_free_channel(temp1, 3);
  if (temp2 != 0) alloc_free_channel(temp2, 3);
  *rdataptr = rdata;
  return newrdatalen;
}

void printResourceRecord(const ResourceRecord *rr) {
  printName(rr->oname);
  printf(" Type %d, Class %d, TTL %d Length %d\n", getshort(rr->type), getshort(rr->class), rr->ttl, rr->length);
  printRData(rr->type, rr->rdata, rr->rdatalen);
}

int readResourceRecordFromPacket(char *pkt, int len, int *pos, ResourceRecord *rr, int expand) {
  int p = *pos;

  byte_zero(rr, sizeof(ResourceRecord));

  if (expand) {
    p = dns_packet_getname(pkt, len, p, &rr->oname);
    alloc_channel(0, 3);
  }
  else {
    rr->oname = pkt+p;
    p = dns_packet_skipname(pkt, len, p);
  }

  if (p == 0) {
    *pos = len;
    errno = error_proto;
    return 0; //bad name format
  }
  rr->onamelen = dns_domain_length(rr->oname);

  if (p+10 > len) {
    *pos = len;
    errno = error_proto;
    return 0; //short packet
  }

  byte_copy(rr->type, 2, pkt+p);
  byte_copy(rr->class, 2, pkt+p+2);
  uint32_unpack_big(pkt+p+4, &rr->ttl);
  uint16 datalength;
  uint16_unpack_big(pkt+p+8, &datalength);
  p += 10;

  if (p + datalength > len) {
    *pos = len;
    errno = error_proto;
    return 0; //short packet
  }

  *pos = p + datalength;

  int rdatalen = 0;
  if (expand) {
    rdatalen = readRDataFromPacket(pkt, p+datalength, p, rr->type, datalength, &rr->rdata);
    if (rr->rdata == 0) {
      return 0; // rdata read failed
    }
  }
  else {
    rr->rdata = pkt+p;
    rdatalen = datalength;
  }
  rr->rdatalen = rdatalen;

  rr->length = rr->onamelen + 10 + rr->rdatalen;  
  return 1;
}

int packResourceRecord(ResourceRecord *rr, char *pkt, int *pos) {
  int p = *pos;

  strcpy(pkt+p, rr->oname);
  p += rr->onamelen;

  byte_copy(pkt+p, 2, rr->type);
  byte_copy(pkt+p+2, 2, rr->class);
  uint32_pack_big(pkt+p+4, rr->ttl);
  uint16_pack_big(pkt+p+8, rr->rdatalen);
  byte_copy(pkt+p+10, rr->rdatalen, rr->rdata);
  p += 10 + rr->rdatalen;

  *pos = p;
  return 1;
}

void freeResourceRecord(ResourceRecord *rr) {
  if (rr->oname != 0) {
    alloc_free_channel(rr->oname, 3);
    rr->oname = 0;
  }

  if (rr->rdata != 0) {
    if (byte_equal(rr->type, 2, DNS_T_CNAME) || byte_equal(rr->type, 2, DNS_T_NS) || byte_equal(rr->type, 2, DNS_T_PTR) || byte_equal(rr->type, 2, DNS_T_MX) || byte_equal(rr->type, 2, DNS_T_SOA) || byte_equal(rr->type, 2, DNS_T_SIG) || byte_equal(rr->type, 2, DNS_T_NXT)) {
      alloc_free_channel(rr->rdata, 1);
    }
    rr->rdata = 0;
  }
}

ResourceRecord *createSigRR(ResourceRecord **rrset, int rrcount, ResourceRecord *sigrr) {
  sigrr->oname = alloc_channel(rrset[0]->onamelen, 3);
  if (sigrr->oname == 0) {
    return 0;
  }

  strcpy(sigrr->oname, rrset[0]->oname);
  byte_copy(sigrr->type, 2, DNS_T_SIG);
  byte_copy(sigrr->class, 2, DNS_C_IN);
  sigrr->ttl = SIG_TTL;
    
  sigrr->rdatalen = 18 + CODONS_NAMELEN + getCoDoNSSize();
  sigrr->rdata = alloc_channel(sigrr->rdatalen, 1);
  if (sigrr->rdata == 0) {
    errno = error_nomem;
    return 0;
  }

  byte_copy(sigrr->rdata, 2, rrset[0]->type);
  sigrr->rdata[2] = DNSSEC_ALG;
  sigrr->rdata[3] = getLabels(rrset[0]->oname);
  uint32_pack_big(sigrr->rdata+4, SIG_TTL);
  struct timeval tv;
  if (gettimeofday(&tv, 0) < 0) {
    return 0;
  }
  uint32_pack_big(sigrr->rdata+8, tv.tv_sec + SIG_EXP);
  uint32_pack_big(sigrr->rdata+12, tv.tv_sec);
  byte_copy(sigrr->rdata+16, 2, getCoDoNSKeytag());
  strcpy(sigrr->rdata+18, CODONS_NAME);

  sigrr->onamelen = rrset[0]->onamelen;
  sigrr->length = sigrr->onamelen + 10 + sigrr->rdatalen;
  if (!sign(sigrr->rdata, sigrr->rdatalen, rrset, rrcount)) {
    return 0;
  }
  return sigrr;
}

/* assumes messages in canonical form */
int matchResourceRecord(ResourceRecord *rr1, ResourceRecord *rr2) {
  if (rr1 == rr2) {
    return 1; // same records
  }

  if (rr1 == 0 || rr2 == 0) {
    return 0; // sanity check
  }

  if (rr1->rdatalen != rr2->rdatalen || byte_diff(rr1->type, 2, rr2->type) || byte_diff(rr1->class, 2, rr2->class) || strcasecmp(rr1->oname, rr2->oname) != 0) {
    return 0;
  }

  int rdatalen = byte_equal(rr1->type, 2, DNS_T_SOA) ? (rr1->rdatalen - 4) : rr1->rdatalen; // don't compare minimum for soa records
  return byte_equal(rr1->rdata, rdatalen, rr2->rdata);
}

void orderResourceRecords(ResourceRecord **rrset, int rrcount, int space) {
  if (rrcount == 0) {
    return;
  }

  if (rrset == 0) {
    return; // sanity check
  }

  int i, j;
  int factor = space ? 2 : 1;

  for (i=0; i<rrcount; i+=factor) {
    if (rrset[i] == 0) {
      printf("Illegal i %d\n", i);
      return; // illegal state
    }
    for (j=0; j<i; j+=factor) {
      if (strcasecmp(rrset[i]->oname, rrset[j]->oname) == 0 && byte_equal(rrset[i]->type, 2, rrset[j]->type) && byte_equal(rrset[i]->class, 2, rrset[j]->class)) {
	break;
      }
    }
    for (; j<i; j+=factor) {
      if (strcasecmp(rrset[i]->oname, rrset[j]->oname) == 0 && byte_equal(rrset[i]->type, 2, rrset[j]->type) && byte_equal(rrset[i]->class, 2, rrset[j]->class) && rdata_diff(rrset[i]->rdata, rrset[i]->rdatalen, rrset[j]->rdata, rrset[j]->rdatalen) >= 0) {
	continue;
      }
      else {
	break;
      }
    }
    ResourceRecord *temp = rrset[i];
    int k;
    for (k=i; k>j; k-=factor) {
      rrset[k] = rrset[k-factor];
    }
    rrset[j] = temp;
  }
}

void printDNSMessage(const DNSMessage *msg) {
  int i;

  printHeader(msg->header);
  for (i=0; i<msg->header.qdcount; i++) {
    printQueryData(msg->qdata[i]);
  }
  for (i=0; i<msg->maxrr; i++) {
    if (msg->rrset[i] != 0) {
      printResourceRecord(msg->rrset[i]);
    }
  }
}

int readDataFromPacket(char *pkt, int len, DNSMessage **msgPtr, int space) {
  *msgPtr = 0;

  DNSMessage *msg;

  if (pkt == 0 || len < 12) {
    errno = error_proto;
    return 0; // no header
  }

  uint16 qdcount = 0;
  uint16 ancount = 0;
  uint16 nscount = 0;
  uint16 arcount = 0;

  uint16_unpack_big(pkt + 4, &qdcount);
  uint16_unpack_big(pkt + 6, &ancount);
  uint16_unpack_big(pkt + 8, &nscount);
  uint16_unpack_big(pkt + 10, &arcount);

  int expand = !((uint8)pkt[3] & 0x40);
  int factor = space ? 2 : 1;

  msg = (DNSMessage *)alloc_channel(sizeof(DNSMessage) + qdcount * sizeof(QueryData) + factor*(ancount + nscount + arcount)*(sizeof(ResourceRecord) + sizeof(ResourceRecord *)), 4);
  if (msg == 0) {
    errno = error_nomem;
    return 0;
  }

  byte_zero(msg, sizeof(DNSMessage));
  msg->freePtr = msg->data;

  /* read header */
  byte_copy(msg->header.id, 2, pkt);
  byte_copy(&msg->header.flags2, 1, pkt+2);
  byte_copy(&msg->header.flags3, 1, pkt+3);
  msg->header.qdcount = qdcount;
  msg->header.ancount = ancount;
  msg->header.nscount = nscount;
  msg->header.arcount = arcount;

  msg->length = 12;
  msg->expansive = expand;

  if (msg->header.qdcount > 0) {
    msg->qdata = (QueryData *)msg->freePtr;
    msg->freePtr += sizeof(QueryData) * msg->header.qdcount;
    byte_zero((char *)msg->qdata, sizeof(QueryData) * msg->header.qdcount);
  }

  int pos = 12;
  int i;

  for (i=0; i<msg->header.qdcount; i++) {
    if (expand) {
      pos = dns_packet_getname(pkt, len, pos, &msg->qdata[i].qname);
      alloc_channel(0, 3);
    }
    else {
      msg->qdata[i].qname = pkt+pos;
      pos = dns_packet_skipname(pkt, len, pos);
    }

    if (pos == 0) {
      errno = error_proto;
      freeDNSMessage(&msg);
      return 0; //bad name format;
    }
    if (pos+4 > len) {
      errno = error_proto;
      freeDNSMessage(&msg);
      return 0; //short packet
    }

    byte_copy(msg->qdata[i].qtype, 2, pkt+pos);
    byte_copy(msg->qdata[i].qclass, 2, pkt+pos+2);
    pos += 4;

    msg->qdata[i].length = dns_domain_length(msg->qdata[i].qname) + 4;
    msg->length += msg->qdata[i].length; 
  }

  int rrcount = ancount + nscount + arcount;
  msg->maxrr = factor * rrcount;

  if (rrcount > 0) {
    msg->rrset = (ResourceRecord **)msg->freePtr;
    msg->freePtr += sizeof(ResourceRecord *) * msg->maxrr;
    byte_zero((char *)msg->rrset, sizeof(ResourceRecord *) * msg->maxrr);
  }

  // read answers 
  // leave blank rrs for sig records if factor is 2
  for (i=0; i<msg->maxrr; i+=factor) {
    msg->rrset[i] = (ResourceRecord *)msg->freePtr;
    msg->freePtr += sizeof(ResourceRecord);
    if (readResourceRecordFromPacket(pkt, len, &pos, msg->rrset[i], expand) == 0) {
      freeDNSMessage(&msg);
      return 0;
    }
    msg->length += msg->rrset[i]->length;
  }

  *msgPtr = msg;
  return 1;
} 

int packDNSMessage(DNSMessage *msg, char **packet) {
  int i;

  char *pkt = (*packet == 0) ? alloc_channel(msg->length, 5) : (*packet);
  if (pkt == 0) {
    errno = error_nomem;
    return 0;
  }

  /* copy header */
  byte_copy(pkt, 2, msg->header.id);
  byte_copy(pkt+2, 1, &msg->header.flags2);
  byte_copy(pkt+3, 1, &msg->header.flags3);
  uint16_pack_big(pkt+4, msg->header.qdcount);
  uint16_pack_big(pkt+6, msg->header.ancount);
  uint16_pack_big(pkt+8, msg->header.nscount);
  uint16_pack_big(pkt+10, msg->header.arcount);

  int pos = 12;

  /* copy queries */
  for (i=0; i<msg->header.qdcount; i++) {
    strcpy(pkt+pos, msg->qdata[i].qname);
    pos += msg->qdata[i].length-4;
    byte_copy(pkt+pos, 2, msg->qdata[i].qtype);
    byte_copy(pkt+pos+2, 2, msg->qdata[i].qclass);
    pos += 4;
  }
  
  // copy answers 
  for (i=0; i<msg->maxrr; i++) {
    if (msg->rrset[i] != 0) {
      packResourceRecord(msg->rrset[i], pkt, &pos);
    }
  }

  *packet = pkt;
  return 1;
}

void freeDNSMessage(DNSMessage **msgPtr) {
  DNSMessage *msg = *msgPtr;  
  if (msg == 0) {
    return;
  }

  int i;
  if (msg->qdata != 0) {
    for (i=0; i<msg->header.qdcount; i++) {
      if (msg->qdata[i].qname != 0 && msg->expansive) {
	alloc_free_channel(msg->qdata[i].qname, 3);
      }
      msg->qdata[i].qname = 0;
    }
    msg->qdata = 0;
  }
  if (msg->rrset != 0) {
    for (i=0; i<msg->maxrr; i++) {
      if (msg->rrset[i] != 0 && msg->expansive) {
	freeResourceRecord(msg->rrset[i]);
      }
      msg->rrset[i] = 0;
    }
    msg->rrset = 0;
  }

  alloc_free_channel((char *)msg, 4);
  *msgPtr = 0;
}

int createErrorMessage(DNSMessage **msgPtr, uint8 rcode, DNSQueryMsg *qryMsg) {
  *msgPtr = 0;

  int qdcount = (qryMsg == 0) ? 0 : 1;

  DNSMessage *msg = (DNSMessage *)alloc_channel(sizeof(DNSMessage) + qdcount * sizeof(QueryData), 4);
  if (msg == 0) {
    errno = error_nomem;
    return 0;
  }

  byte_zero(msg, sizeof(DNSMessage) + qdcount * sizeof(QueryData));
  msg->freePtr = msg->data;

  ((Flags2 *)&msg->header.flags2)->response = 1;
  ((Flags3 *)&msg->header.flags3)->recurseavail = 1;
  ((Flags3 *)&msg->header.flags3)->rcode = rcode & 0x0f;
  msg->header.qdcount = qdcount;
  msg->length = 12;
  msg->expansive = 0;
  
  if (qdcount) {
    msg->qdata = (QueryData *)msg->freePtr;
    msg->freePtr += sizeof(QueryData);

    msg->qdata->qname = qryMsg->qdata;
    byte_copy(msg->qdata->qtype, 2, qryMsg->qdata+qryMsg->length-16);
    byte_copy(msg->qdata->qclass, 2, qryMsg->qdata+qryMsg->length-14);
    msg->qdata->length = qryMsg->length-12;
    msg->length += msg->qdata->length;
  }

  *msgPtr = msg;
  return 1;
}

int createVersionMessage(DNSMessage **msgPtr, DNSQueryMsg *qryMsg, char *versionStr) {
  *msgPtr = 0;

  int qdcount = (qryMsg == 0) ? 0 : 1;

  DNSMessage *msg = (DNSMessage *)alloc_channel(sizeof(DNSMessage) + qdcount * sizeof(QueryData) + sizeof(ResourceRecord) + sizeof(ResourceRecord *), 4);
  if (msg == 0) {
    errno = error_nomem;
    return 0;
  }

  byte_zero(msg, sizeof(DNSMessage) + qdcount * sizeof(QueryData) + sizeof(ResourceRecord) + sizeof(ResourceRecord *));
   msg->freePtr = msg->data;

  ((Flags2 *)&msg->header.flags2)->response = 1;
  ((Flags3 *)&msg->header.flags3)->recurseavail = 1;
  ((Flags3 *)&msg->header.flags3)->rcode = 0;
  msg->header.qdcount = qdcount;
  msg->header.ancount = 1;
  msg->maxrr = 1;
  msg->length = 12;
  msg->expansive = 0;
  
  if (qdcount) {
    msg->qdata = (QueryData *)msg->freePtr;
    msg->freePtr += sizeof(QueryData);

    msg->qdata->qname = qryMsg->qdata;
    byte_copy(msg->qdata->qtype, 2, qryMsg->qdata+qryMsg->length-16);
    byte_copy(msg->qdata->qclass, 2, qryMsg->qdata+qryMsg->length-14);
    msg->qdata->length = qryMsg->length-12;
    msg->length += msg->qdata->length;
  }

  msg->rrset = (ResourceRecord **)msg->freePtr;
  msg->freePtr += sizeof(ResourceRecord *);
  byte_zero((char *)msg->rrset, sizeof(ResourceRecord *));
  msg->rrset[0] = (ResourceRecord *)msg->freePtr;
  msg->freePtr += sizeof(ResourceRecord);
  byte_zero(msg->rrset[0], sizeof(ResourceRecord));

  ResourceRecord *rr = msg->rrset[0];
  rr->oname = versionname;
  rr->onamelen = dns_domain_length(rr->oname);
  byte_copy(rr->type, 2, DNS_T_TXT);
  byte_copy(rr->class, 2, DNS_C_CH);
  rr->ttl = 86400;
  rr->rdatalen = strlen(versionStr);
  rr->rdata = versionStr;
  rr->length = rr->onamelen + 10 + rr->rdatalen;

  msg->length += msg->rrset[0]->length;

  *msgPtr = msg;
  return 1;
}

int createStatsMessage(DNSMessage **msgPtr, DNSQueryMsg *qryMsg, char *statsStr) {
  *msgPtr = 0;

  int qdcount = (qryMsg == 0) ? 0 : 1;

  DNSMessage *msg = (DNSMessage *)alloc_channel(sizeof(DNSMessage) + qdcount * sizeof(QueryData) + sizeof(ResourceRecord) + sizeof(ResourceRecord *), 4);
  if (msg == 0) {
    errno = error_nomem;
    return 0;
  }

  byte_zero(msg, sizeof(DNSMessage) + qdcount * sizeof(QueryData) + sizeof(ResourceRecord) + sizeof(ResourceRecord *));
   msg->freePtr = msg->data;

  ((Flags2 *)&msg->header.flags2)->response = 1;
  ((Flags3 *)&msg->header.flags3)->recurseavail = 1;
  ((Flags3 *)&msg->header.flags3)->rcode = 0;
  msg->header.qdcount = qdcount;
  msg->header.ancount = 1;
  msg->maxrr = 1;
  msg->length = 12;
  msg->expansive = 0;
  
  if (qdcount) {
    msg->qdata = (QueryData *)msg->freePtr;
    msg->freePtr += sizeof(QueryData);

    msg->qdata->qname = qryMsg->qdata;
    byte_copy(msg->qdata->qtype, 2, qryMsg->qdata+qryMsg->length-16);
    byte_copy(msg->qdata->qclass, 2, qryMsg->qdata+qryMsg->length-14);
    msg->qdata->length = qryMsg->length-12;
    msg->length += msg->qdata->length;
  }

  msg->rrset = (ResourceRecord **)msg->freePtr;
  msg->freePtr += sizeof(ResourceRecord *);
  byte_zero((char *)msg->rrset, sizeof(ResourceRecord *));
  msg->rrset[0] = (ResourceRecord *)msg->freePtr;
  msg->freePtr += sizeof(ResourceRecord);
  byte_zero(msg->rrset[0], sizeof(ResourceRecord));

  ResourceRecord *rr = msg->rrset[0];
  rr->oname = statsname;
  rr->onamelen = dns_domain_length(rr->oname);
  byte_copy(rr->type, 2, DNS_T_TXT);
  byte_copy(rr->class, 2, DNS_C_CH);
  rr->ttl = 360;

  rr->rdatalen = strlen(statsStr);
  rr->rdata = statsStr;

  rr->length = rr->onamelen + 10 + rr->rdatalen;
  msg->length += msg->rrset[0]->length;

  printf("Debug: statsLen %d msgLen %d\n", rr->rdatalen, msg->length);

  *msgPtr = msg;
  return 1;
}

int createRedirectionMessage(DNSMessage **msgPtr, DNSQueryMsg *qryMsg, char redirectionip1[4], char redirectionip2[4]) {
  *msgPtr = 0;

  DNSMessage *msg = (DNSMessage *)alloc_channel(sizeof(DNSMessage) + sizeof(QueryData) + (sizeof(ResourceRecord) + sizeof(ResourceRecord *))*2, 4);
  if (msg == 0) {
    errno = error_nomem;
    return 0;
  }

  byte_zero(msg, sizeof(DNSMessage) + sizeof(QueryData) + (sizeof(ResourceRecord) + sizeof(ResourceRecord *))*2);
   msg->freePtr = msg->data;

  ((Flags2 *)&msg->header.flags2)->response = 1;
  ((Flags3 *)&msg->header.flags3)->recurseavail = 1;
  ((Flags3 *)&msg->header.flags3)->rcode = 0;
  msg->header.qdcount = 1;
  msg->header.ancount = 2;
  msg->maxrr = 2;
  msg->length = 12;
  msg->expansive = 0;
  
  msg->qdata = (QueryData *)msg->freePtr;
  msg->freePtr += sizeof(QueryData);
  
  msg->qdata->qname = qryMsg->qdata;
  byte_copy(msg->qdata->qtype, 2, qryMsg->qdata+qryMsg->length-16);
  byte_copy(msg->qdata->qclass, 2, qryMsg->qdata+qryMsg->length-14);
  msg->qdata->length = qryMsg->length-12;
  msg->length += msg->qdata->length;

  msg->rrset = (ResourceRecord **)msg->freePtr;
  msg->freePtr += 2*sizeof(ResourceRecord *);
  byte_zero((char *)msg->rrset, 2*sizeof(ResourceRecord *));
  msg->rrset[0] = (ResourceRecord *)msg->freePtr;
  msg->freePtr += sizeof(ResourceRecord);
  byte_zero(msg->rrset[0], sizeof(ResourceRecord));

  msg->rrset[1] = (ResourceRecord *)msg->freePtr;
  msg->freePtr += sizeof(ResourceRecord);
  byte_zero(msg->rrset[1], sizeof(ResourceRecord));

  ResourceRecord *rr = msg->rrset[0];
  rr->oname = qryMsg->qdata;
  rr->onamelen = dns_domain_length(rr->oname);
  byte_copy(rr->type, 2, DNS_T_A);
  byte_copy(rr->class, 2, DNS_C_IN);
  rr->ttl = 300;
  rr->rdatalen = 4;
  rr->rdata = redirectionip1;
  rr->length = rr->onamelen + 10 + rr->rdatalen;

  msg->length += msg->rrset[0]->length;

  rr = msg->rrset[1];
  rr->oname = qryMsg->qdata;
  rr->onamelen = dns_domain_length(rr->oname);
  byte_copy(rr->type, 2, DNS_T_A);
  byte_copy(rr->class, 2, DNS_C_IN);
  rr->ttl = 300;
  rr->rdatalen = 4;
  rr->rdata = redirectionip2;
  rr->length = rr->onamelen + 10 + rr->rdatalen;

  msg->length += msg->rrset[1]->length;

  *msgPtr = msg;
  return 1;
}

uint32 getttl(const DNSMessage *msg) {
  if (msg == 0 || msg->maxrr == 0) {
    return 0;
  }

  int minttl = 7*24*3600;
  int i;
  for (i=0; i<msg->maxrr; i++) {
    if (msg->rrset[i] == 0) {
      continue;
    }
    uint32 ttl = msg->rrset[i]->ttl;
    if (((Flags3 *)&msg->header.flags3)->rcode > 0 && byte_equal(msg->rrset[i]->type, 2 ,DNS_T_SOA)) {
      uint32 soattl = getint(msg->rrset[i]->rdata + msg->rrset[i]->rdatalen-4);
      ttl = (ttl < soattl) ? ttl : soattl;
    }
    minttl = (ttl < minttl) ? ttl : minttl;
  }
  
  return minttl;
}

uint8 matchresponses(const DNSMessage *newmsg, const DNSMessage *oldmsg) {
  if (newmsg == 0 || oldmsg == 0) {
    return 0; // sanity check
  }

  Flags2 *oldflags2 = (Flags2 *)&oldmsg->header.flags2;
  Flags2 *newflags2 = (Flags2 *)&newmsg->header.flags2;
  Flags3 *oldflags3 = (Flags3 *)&oldmsg->header.flags3;
  Flags3 *newflags3 = (Flags3 *)&newmsg->header.flags3;

  if (newflags3->rcode != oldflags3->rcode) {
     return 0; // rcodes don't match
  }

  //printf("DJBDNS: new rsvd %d auth %d old rsvd %d auth %d\n", newflags3->reserved, newflags2->authoritative, oldflags3->reserved, oldflags2->authoritative);

  if (newflags3->reserved && !oldflags3->reserved) {
    return 0; // new message is from secure server, but not old
  }

  if (newflags3->reserved == oldflags3->reserved) {
    if (newflags2->authoritative && !oldflags2->authoritative) {
      return 0; // new message is authoritative, but not old
    }

    if (newflags2->authoritative && oldflags2->authoritative && (newmsg->header.ancount != oldmsg->header.ancount || newmsg->header.nscount != oldmsg->header.nscount || newmsg->header.arcount != oldmsg->header.arcount)) {
      //printf("DJBDNS: new ancount %d nscount %d arcount %d old ancount %d nscount %d arcount %d", newmsg->header.ancount, newmsg->header.nscount, newmsg->header.arcount, oldmsg->header.ancount, oldmsg->header.nscount, oldmsg->header.arcount);
      return 0; // numbers of records don't match
    }
  }

  int i,j;

  for (i=0; i<newmsg->maxrr; i++) {
    if (newmsg->rrset[i] == 0 || (byte_equal(newmsg->rrset[i]->type, 2, DNS_T_SIG) && byte_equal(newmsg->rrset[i]->rdata+18, CODONS_NAMELEN, CODONS_NAME))) {
      continue;
    }

    for (j=0; j<oldmsg->maxrr; j++) {
      if (matchResourceRecord(newmsg->rrset[i], oldmsg->rrset[j])) {
	//printf("DJBDNS: Found RR name %s type %d\n", newmsg->rrset[i]->oname, getshort(newmsg->rrset[i]->type));
	break;
      }
    }
    
    if (j == oldmsg->maxrr) {
      //printf("DJBDNS: Missing RR name %s type %d\n", newmsg->rrset[i]->oname, getshort(newmsg->rrset[i]->type));
      return 0; //no match for record
    }      
  }

  return 1; // complete match
}

/* assumes that alternate rrs are empty */
/* allowing sig rrs to be inserted in their place */
int addSignatures(DNSMessage *msg) {
  orderResourceRecords(msg->rrset, msg->maxrr, 1);
  
  int i, j;
  int maxan = 2 * msg->header.ancount;
  int maxns = 2 * msg->header.nscount;

  for (i=0; i<msg->maxrr; i=j) {
    for (j=i+2; j<msg->maxrr; j+=2) {
      if (byte_diff(msg->rrset[i]->type, 2, msg->rrset[j]->type) || byte_diff(msg->rrset[i]->class, 2, msg->rrset[j]->class) || strcasecmp(msg->rrset[i]->oname, msg->rrset[j]->oname) != 0) {
	break;
      }
    }

    msg->rrset[j-1] = createSigRR(&msg->rrset[i], j-i, (ResourceRecord *)msg->freePtr);
    if (msg->rrset[j-1] == 0) {
      return 0;
    }
    msg->freePtr += sizeof(ResourceRecord);
    msg->length += msg->rrset[j-1]->length;
    
    if (i < maxan) {
      msg->header.ancount++;
    }
    else if (i < maxan+maxns) {
      msg->header.nscount++;
    }
    else {
      msg->header.arcount++;
    }
  }

  return 1;
}

void removeSignatures(DNSMessage *msg) {
  int expand = msg->expansive;
  int i, j;
  int maxan = msg->header.ancount;
  int maxns = msg->header.nscount;

  for (i=0,j=0; i<msg->maxrr; i++) {
    if (msg->rrset[i] != 0 && byte_equal(msg->rrset[i]->type, 2, DNS_T_SIG) && strcasecmp(msg->rrset[i]->rdata+18, CODONS_NAME) == 0) {
      ResourceRecord *sigrr = msg->rrset[i];

      msg->rrset[i] = 0;
      msg->length -= sigrr->length;
      if (j < maxan) {
	msg->header.ancount--;
      }
      else if (j < maxan+maxns) {
	msg->header.nscount--;
      }
      else {
	msg->header.arcount--;
      }
      
      if (expand) {
	freeResourceRecord(sigrr);
      }
    }
    j += (msg->rrset[i] != 0);
  }
}

int verifySignatures(DNSMessage *msg) {
  int i, j;

  for (i=0; i<msg->maxrr; i=j+1) {
    for(; i<msg->maxrr && msg->rrset[i] == 0; i++) {
    }
    if (i == msg->maxrr) break;

    for (j=i+1; j<msg->maxrr; j++) {
      for(; j<msg->maxrr && msg->rrset[j] == 0; j++) {
      }

      if (j == msg->maxrr || (byte_equal(msg->rrset[j]->type, 2, DNS_T_SIG) && strcasecmp(msg->rrset[j]->rdata+18, CODONS_NAME) == 0)) {
	break;
      }
    }

    if (j == msg->maxrr) {
      return 0; //sig not found
    }

    ResourceRecord *sigrr = msg->rrset[j];
    ResourceRecord **rrset = msg->rrset + i;

    if (byte_diff(rrset[0]->type, 2, sigrr->rdata) || byte_diff(rrset[0]->class, 2, sigrr->class) || strcasecmp(rrset[0]->oname, sigrr->oname) != 0) {
      return 0;
    }
    if (!verify(sigrr->rdata, sigrr->rdatalen, rrset, j-i, 0)) {
      return 0;
    }
  }

  return 1;
}

int add_dns_message( DNSMessageList** list, Status status, DNSMessage* message){
	log_default ( VVVERBOSE, "Entering add_dns_message\n");
	DNSMessageList* tmp1 = (DNSMessageList *)malloc(sizeof(DNSMessageList));
	tmp1->message = message;
	tmp1->status = status;
	DNSMessageList* tmp2 = *list;
	DNSMessageList* prev = NULL;
	int flag = 1;
	while(tmp2!=NULL && flag){
		int result = qdata_cmp (tmp2->message->qdata, message->qdata);
		if (result && tmp2->status == NONAUTH && tmp1->status==AUTH){
			tmp2->status=AUTH;
		}
		log_default ( VVERBOSE, "qdata_cmp=%d\n", result);
		flag = result?0:flag;
		prev=tmp2;
		tmp2=tmp2->next;
	}
	if (flag){
		log_default ( VVERBOSE, "Adding message to cache\n");
		if(prev==NULL){
			*list=tmp1;
			tmp1->next=tmp2;
		}else{
			prev->next=tmp1;
			tmp1->next=tmp2;
		}
	}
	log_dns_message_list ( VVVERBOSE, *list);
	log_default ( VVVERBOSE, "Leaving add_dns_message\n");
	return flag; 
}

void log_dns_message_list ( int level,  const DNSMessageList* list){
	DNSMessageList* tmp = list;
	log_default ( level, "The message cache\n");
	while ( tmp!=NULL){
		log_DNSMessage ( level,  tmp->message);
		log_default ( level, "********************\n");
		tmp=tmp->next;
	}
}

DNSMessage* get_dns_message ( const DNSMessageList* list, const DNSQueryMsg* qmsg){
	log_default ( VVVERBOSE, "Entering get_dns_message\n");
	DNSMessageList* tmp = list;
	log_default ( VERBOSE, "\nSearching cache\n");
	log_default ( VERBOSE, "Cache size=%d\n", cache_size (list));
	int count=0;
	while (tmp != NULL){
		log_default (VVERBOSE, "Record=%d\n", count);
		if ( dns_message_cmp (tmp->message->qdata,  qmsg)) {
			return tmp->message;
		}
		tmp = tmp->next;
	}
	log_default ( VVVERBOSE, "Leaving get_dns_message\n");
	return NULL;
}

int cache_size (DNSMessageList *list){
	DNSMessageList* tmp = list;
	int size = 0;
	while (tmp!=NULL){
		size++;
		tmp = tmp->next;
	}
	return size;
}

int dns_name_cmp ( const char* name1, const char* name2){
	log_default ( VVVERBOSE, "Entering dns_name_cmp\n");
	char buf1[100];
	char buf2[100];
	memset (buf1, 0, 100);
	memset (buf2, 0, 100);
	log_default ( VVERBOSE, "%s\n", name1);
	log_default ( VVERBOSE, "%s\n", name2);
	name_str(name1, buf1);
	name_str(name2, buf2);
	log_default ( VVERBOSE, "size(buf1)=%d, size(buf2)=%d\n", strlen(buf1), strlen(buf2));
	log_default (VERBOSE, "buf1=%s, buf2=%s\n", buf1, buf2);
	log_default ( VVVERBOSE, "Leaving dns_name_cmp\n");
	if( strcmp (buf1, buf2)==0)
		return 1;
	else 
		return 0;
}

void name_str(const char *name, char* buf) {
  log_default ( VVVERBOSE, "Entering name_str\n");
  int i;
  int pos = 0;
  int j=0;
  while(name[pos]) {
    for (i=0; i<name[pos]; j++,i++) {
      buf[j]=name[pos+1+i];
    }
    buf[j]='.';
	j++;
    pos += name[pos]+1;
  }
  log_default ( VVVERBOSE, "Leaving  name_str\n");
}

int dns_message_cmp ( const QueryData* qdata1, const DNSQueryMsg* qmsg){
	log_default ( VVVERBOSE, "Entering dns_message_cmp\n");
	unsigned short  type1, type2;
	unsigned short  class1, class2;
	type1 = getshort (qdata1->qtype);
	class1= getshort (qdata1->qclass);
	type2 = getshort(qmsg->qdata+qmsg->length-12-4);
	class2 = getshort(qmsg->qdata+qmsg->length-12-2);
	
//	if ( dns_name_cmp( qdata1->qname, qdata2->qname)==0 && (type1==type2) && (class1==class2))
	if ( dns_name_cmp( qdata1->qname, qmsg->qdata))
		return 1;
	else
		return 0;
}

int qdata_cmp ( const QueryData* qdata1, const QueryData* qdata2){
	unsigned short  type1, type2;
	unsigned short  class1, class2;
	type1 = getshort (qdata1->qtype);
	class1= getshort (qdata1->qclass);
	type2 = getshort(qdata2->qtype);
	class2 = getshort(qdata2->qclass);
	
//	if ( dns_name_cmp( qdata1->qname, qdata2->qname)==0 && (type1==type2) && (class1==class2))
	if ( dns_name_cmp( qdata1->qname, qdata2->qname) )
		return 1;
	else
		return 0;
}

int flush_message (int sockfd, void* msg, int length){
	int totalSent=0;
	char *buf=(char *)msg;
	while(totalSent<length){
		int sent = send( sockfd , buf+totalSent, length-totalSent,0);
		if(sent==-1)
			return -1;
		totalSent+=sent;
	}
	log_default( VERBOSE,"Send %d bytes on %d\n", totalSent, sockfd);
	return totalSent;
}


int send_message ( int sockfd, Message* message) {
	flush_message ( sockfd, message, sizeof(Message));
	flush_message ( sockfd, message->payload, message->payloadSize);
}

Message* receive_message (int sockfd){
	log_default ( VVVERBOSE, "Entering receive_message\n"); 
	Message* message = (Message *) malloc (sizeof(Message));
	assert (message!=NULL);
	
	int total = 0;
	while (total < sizeof (Message)){
		int numBytes = recv (sockfd, (char *)message, sizeof(Message)-total, 0);
		if (numBytes < 0){
			log_default ( SILENT, "Error in receive\n");
			return NULL;
		}
		total += numBytes;
	}
	total = 0;
	char* payload = (char *)malloc (message->payloadSize);
	assert (message->payload != NULL);
	while ( total < message->payloadSize ){
		int numBytes = recv (sockfd, payload, message->payloadSize-total, 0);
		if (numBytes < 0){
			log_default ( SILENT, "Error in receive\n");
			return NULL;
		}
		total += numBytes;
	}
	message->payload = payload;
	log_default ( VVVERBOSE, "Leaving receive_message\n"); 
	return message;
}

void free_message ( Message  **message){
	Message* msg = *message;
	free (msg->payload);
	free (msg);
	*message=NULL;
}


void log_header(int level, Header header) {
  Flags2 *flags2 = (Flags2 *)&header.flags2;
  Flags3 *flags3 = (Flags3 *)&header.flags3;
  log_default( level, "Id: %d, Flags: response %d, authoritative %d, truncation %d, recursion desired %d, recursion available %d, codons %d, authentic %d, checking disabled %d, rcode %d\n", getshort(header.id), flags2->response, flags2->authoritative, flags2->truncation, flags2->recurse, flags3->recurseavail, flags3->reserved, flags3->ad, flags3->cd, flags3->rcode);
  log_default( level, "RR Counts: query %d, answer %d, authoritative %d, additional %d\n", header.qdcount, header.ancount, header.nscount, header.arcount);
}

int log_name(int level, const char *name) {
  int i;
  int pos = 0;
  while(name[pos]) {
    for (i=0; i<name[pos]; i++) {
      log_default_notime ( level, "%c", name[pos+1+i]);
    }
    log_default_notime( level, ".");
    pos += name[pos]+1;
  }
  return pos+1;
}

void log_query_msg(int level, const DNSQueryMsg *msg) {
  log_header(level, msg->header);
  log_name(level, msg->qdata);
  log_default( level, " Type %d, Class %d Length %d\n", getshort(msg->qdata+msg->length-12-4), getshort(msg->qdata+msg->length-12-2), msg->length);
}


void log_query_data(int level, QueryData qdata) {
  log_name( level, qdata.qname);
  log_default( level, " Type %d, Class %d Length %d\n", getshort(qdata.qtype), getshort(qdata.qclass), qdata.length);
}

int log_char_strs(int level, const char *text, int length) {
  int i;
  int pos = 0;
  while(pos < length) {
    for (i=0; i<text[pos]; i++) {
      log_default ( level, "%c", text[pos+1+i]);
    }
    log_default(level, " ");
    pos += text[pos]+1;
  }
  return pos+1;
}

void log_RData(int level, const char type[2], const char *rdata, int rdatalen) {
  if (byte_equal(type, 2, DNS_T_A) && rdatalen == 4) {
     log_default (level,"A: %d.%d.%d.%d\n", (unsigned char)rdata[0], (unsigned char)rdata[1], (unsigned char)rdata[2], (unsigned char)rdata[3]);
  }
  else if (byte_equal(type, 2, DNS_T_CNAME) || byte_equal(type, 2, DNS_T_NS) || byte_equal(type, 2, DNS_T_PTR)) {
     log_default (level,"Name ");
     log_name(level, rdata);
     log_default (level,"\n");
  }
  else if (byte_equal(type, 2, DNS_T_MX)) {
     log_default (level,"MX: Pref %d, Exchange ", getshort(rdata));
     log_name(level, rdata+2);
     log_default (level,"\n");
  }
  else if (byte_equal(type, 2, DNS_T_SOA)) {
    log_default (level,"SOA: MName ");
    int pos = printName(rdata);
    log_default (level," RName ");
    pos += printName(rdata+pos);
    log_default (level," serial %d, refresh %d, retry %d, expire %d, minimum %d\n", getint(rdata+pos), getint(rdata+pos+4), getint(rdata+pos+8), getint(rdata+pos+12), getint(rdata+pos+16));
  }
  else if (byte_equal(type, 2, DNS_T_KEY)) {
    uint16 fdata = getshort(rdata);
    KEYFlags *flags = (KEYFlags *)&fdata;
    log_default (level,"KEY: ac %d, xt %d, nametype %d, sig %d, protocol %d, algorithm %d\n", flags->ac, flags->xt, flags->nametype, flags->sig, rdata[2], rdata[3]);
  }
  else if (byte_equal(type, 2, DNS_T_SIG)) {
    log_default (level,"SIG: type %d, algorithm %d, labels %d, ttl %d, expiration %d, inception %d SNAME ", getshort(rdata), rdata[2], rdata[3], getint(rdata+4), getint(rdata+8), getint(rdata+12));
    log_name(level, rdata+18);
    log_default (level,"\n");
  }
  else if (byte_equal(type, 2, DNS_T_NXT)) {
    log_default (level,"NXT: next domain name ");
    log_name(level, rdata);
    log_default (level,"\n");
  }
  else if (byte_equal(type, 2, DNS_T_SRV)) {
    log_default (level,"SRV: priority %d, weight %d, port %d, target  ", getshort(rdata), getshort(rdata+2), getshort(rdata+4));
    log_name(level, rdata+6);
    log_default (level,"\n");
  }
  else if (byte_equal(type, 2, DNS_T_TXT)) {
    log_default (level,"TXT: ");
    log_char_strs(level, rdata, rdatalen);
    log_default (level,"\n");
  }
  else {
  } 
}


void log_DNSMessage(int level, const DNSMessage *msg) {
  int i;

  log_header( level, msg->header);
  for (i=0; i<msg->header.qdcount; i++) {
    log_query_data(level, msg->qdata[i]);
  }
  for (i=0; i<msg->maxrr; i++) {
    if (msg->rrset[i] != 0) {
      log_resource_record( level, msg->rrset[i]);
    }
  }
}

void log_resource_record(int level, const ResourceRecord *rr) {
  log_name( level, rr->oname);
  log_default( level, " Type %d, Class %d, TTL %d Length %d\n", getshort(rr->type), getshort(rr->class), rr->ttl, rr->length);
  log_RData( level, rr->type, rr->rdata, rr->rdatalen);
}
