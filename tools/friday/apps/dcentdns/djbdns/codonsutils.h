#include "dns.h"
#include "uint16.h"
#include "uint32.h"

#ifndef CODONSUTILS_H
#define CODONSUTILS_H

typedef unsigned char uint8;

typedef struct Flags2 {
  unsigned int recurse:1;
  unsigned int truncation:1;
  unsigned int authoritative:1;
  unsigned int opcode:4;
  unsigned int response:1;
} Flags2;

typedef struct Flags3 {
  unsigned int rcode:4;
  unsigned int cd:1;
  unsigned int ad:1;
  unsigned int reserved:1;
  unsigned int recurseavail:1;
} Flags3;

typedef struct Header {
  char id[2];
  char flags2[1];
  char flags3[1];
  uint16 qdcount;
  uint16 ancount;
  uint16 nscount;
  uint16 arcount;
} Header;

typedef struct DNSQueryMsg {
  uint16 length;
  Header header; // assuming that header is exactly 12 bytes
  char qdata[];
} DNSQueryMsg;

typedef struct QueryData {
  char *qname;
  char qtype[2];
  char qclass[2];
  uint16 length;
} QueryData;

typedef struct ResourceRecord {
  char *oname;
  char type[2];
  char class[2];
  uint32 ttl;
  uint16 rdatalen;
  char *rdata;
  uint16 onamelen;
  uint16 length;
} ResourceRecord;

typedef struct DNSMessage {
  Header header;
  QueryData *qdata;
  ResourceRecord **rrset;
  uint16 maxrr;
  uint16 length;
  uint8 expansive;
  char *freePtr;
  char data[];
} DNSMessage;

/* big endian format */
typedef struct KEYFlags {
  unsigned int sig:4;
  unsigned int zero0:4;
  unsigned int nametype:2;
  unsigned int zero1:2;
  unsigned int xt:1;
  unsigned int zero2:1;
  unsigned int ac:2;
} KEYFlags;

typedef struct RData {
  uint16 length;
  char *data;
} RData;

/* used for CName, NS, and PTR rdata */
typedef struct NameData {
  uint16 length;
  char *name;
} NameData;

typedef struct MXData {
  uint16 length;
  char preference[2];
  char *exchange;
} MXData;

typedef struct SOAData {
  uint16 length;
  char *mname;
  char *rname;
  char serial[4];
  char refresh[4];
  char retry[4];
  char expire[4];
  char minimum[4];
  uint16 mnamelen;
} SOAData;

typedef struct KEYData {
  uint16 length;
  char flags[2];
  char protocol;
  char algorithm;
  char *publickey;
} KEYData;

typedef struct SIGData {
  uint16 length;
  char type[2];
  char algorithm;
  char labels;
  char ttl[4];
  char expiration[4];
  char inception[4];
  char keytag[2];
  char *sname;
  char *signature;
  uint16 snamelen;
} SIGData;

typedef struct NXTData {
  uint16 length;
  char *nname;
  char *typemap;
  uint16 nnamelen;
} NXTData;

typedef struct SRVData {
  uint16 length;
  char priority[2];
  char weight[2];
  char port[2];
  char *tname;
} SRVData;

unsigned short getshort(const char s[2]);
unsigned int getint(const char s[4]);

void getsha1hash(const char *name, unsigned char digest[20]);

int printName(const char *name);

int readDataFromQuery(char *pkt, int len, DNSQueryMsg **msgPtr);
void printQueryMsg(const DNSQueryMsg *msg);

void orderResourceRecords(ResourceRecord **rrset, int rrcount, int space);
int matchResourceRecord(ResourceRecord *rr1, ResourceRecord *rr2);

int readDataFromPacket(char *pkt, int len, DNSMessage **msgPtr, int space);
void printDNSMessage(const DNSMessage *msg);
int packDNSMessage(DNSMessage *msg, char **packet); 
void freeDNSMessage(DNSMessage **msgPtr);

int createErrorMessage(DNSMessage **msgPtr, uint8 rcode, DNSQueryMsg *qryMsg);
int createVersionMessage(DNSMessage **msgPtr, DNSQueryMsg *qryMsg, char *versionStr);
int createStatsMessage(DNSMessage **msgPtr, DNSQueryMsg *qryMsg, char *versionStr);
int createRedirectionMessage(DNSMessage **msgPtr, DNSQueryMsg *qryMsg, char redirectionip1[4], char redirectionip2[4]);

uint32 getttl(const DNSMessage *msg);
uint8 matchresponses(const DNSMessage *newmsg, const DNSMessage *oldmsg);

int addSignatures(DNSMessage *msg);
void removeSignatures(DNSMessage *msg);
int verifySignatures(DNSMessage *msg);

typedef enum {
	AUTH = 0,
	NONAUTH = 1
} Status;

typedef struct DNSMESSAGELIST{
	DNSMessage* message;
	Status status;
	struct DNSMESSAGELIST* next;
} DNSMessageList;

typedef struct MESSAGE{
	int type;
	int payloadSize;
	unsigned char* payload;
} Message;

//Message type
#define DNS_BROADCAST  1

int  add_dns_message( DNSMessageList** list, Status status, DNSMessage* message);
DNSMessage* get_dns_message ( const DNSMessageList* list, const DNSQueryMsg* qmsg);
int cache_size (DNSMessageList *list);
int dns_name_cmp ( const char* name1, const char* name2);
void log_dns_message_list ( int level,  const DNSMessageList* list);
void name_str(const char *name, char* buf);
int dns_message_cmp ( const QueryData* qdata1, const DNSQueryMsg* qmsg);
int qdata_cmp ( const QueryData* qdata1, const QueryData* qdata2);

int send_message ( int sockfd, Message* message);
Message* receive_message (int sockfd);


void log_RData(int level, const char type[2], const char *rdata, int rdatalen) ;
int log_char_strs(int level, const char *text, int length) ;
void log_query_data(int level, QueryData qdata) ;
void log_query_msg(int level, const DNSQueryMsg *msg) ;
int log_name(int level, const char *name) ;
void log_header(int level, Header header) ;
void log_resource_record(int level, const ResourceRecord *rr) ;
void log_DNSMessage(int level, const DNSMessage *msg) ;
#endif
