/***************************************************************************
                          dns_thread.h  -  description
                             -------------------
    begin                : Die Jan 14 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

 
#ifndef DNS_THREAD_H
#define DNS_THREAD_H

#include <pthread.h>

#include "i3.h"
#include "i3_proxy.h"



void 			*dns_answer_thread (void *arg);
void 			*tun_input_thread (void *arg);
void 			*proxy_input_thread (void *arg);
void 			*status_thread (void *arg);

void        remove_pub_dns(char *dns_str);
struct pub_i3_dns    *lookup_pub_i3_dns(char *dns_str);

void        push_dns_request_in_queue(char *buf);
int         get_dns_request_from_queue(char *buf, unsigned short udplen);
void        remove_dns_request_from_queue(struct real_dns_req *dns_req);
struct fake_dns_req   *lookup_fake_dns(char *dns_name);
void        answer_dns_query(char *dns_request, i3_addr *addr, unsigned int len);

void        printf_fake_dns_status(FILE *handle);
void        printf_pub_dns_status(FILE *handle);

void private_trigger_timeout(fake_addr* f);
void remove_fake_dns(struct fake_dns_req* fake);

void print_time();
void send_public_trigger(ID* senderid,ID* publicid,char*,char*);

int pack_variable_length(char *buf,char* str,int len);
int unpack_variable_length(char* buf,char** varstr,int len);

#endif



