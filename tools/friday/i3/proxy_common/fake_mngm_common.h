#ifndef FAKE_MNGM_COMMON_H
#define FAKE_MNGM_COMMON_H

#include "i3.h"
#include "i3_stack.h"
#include "i3_proxy.h"
#include "i3_client_api.h"
#include "i3_client.h"

void insert_pkt_to_queue(struct fake_addr *fake, char *buf, int len);
void flush_pkt_queue(struct fake_addr *fake);
void check_timeout();

#endif
