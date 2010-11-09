/***************************************************************************
                          fake_mngm.h  -  description
                             -------------------
    begin                : Son Jun 22 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#ifndef FAKE_MNGM_H
#define FAKE_MNGM_H

#include "i3.h"
#include "i3_stack.h"
#include "i3_proxy.h"
#include "fake_mngm_common.h"
    
struct fake_addr* alloc_fake_addr(char addr_type, ID *id);

struct fake_addr *lookup_fake_addr(i3_addr *addr);
struct fake_addr *lookup_fake_id(ID *id);

void add_fake_addr(struct fake_addr  *fake);
void remove_fake_addr(fake_addr* fake);
void free_fake_addr(i3_addr *addr);

void init_fake_lists();

void handle_proxy_trigger_request(ID * sender_prv_id, ID *dns_pub_id);
void handle_proxy_trigger_confirmation(ID *sender_private_id, ID* arrival_id);

#endif

