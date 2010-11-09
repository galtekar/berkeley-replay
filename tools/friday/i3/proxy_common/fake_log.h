#ifndef FAKE_LOG_H
#define FAKE_LOG_H

#include "i3.h"
#include "i3_stack.h"
#include "i3_proxy.h"

#define LOG_TYPE_ADD_CALLER 0x00
#define LOG_TYPE_ADD_CALLEE 0x01
#define LOG_TYPE_REMOVE 0x02
#define LOG_TYPE_CHANGE_ID 0x03

void log_fake_insertion_mutex(struct fake_addr *fake);
void log_fake_insertion(FILE *fdlog, struct fake_addr *fake);
void log_fake_removal_mutex(ID *prv_id);
void log_fake_removal(FILE *fdlog, ID *prv_id);
void log_fake_changeID_mutex(struct fake_addr *fake);
void log_fake_changeID(FILE *fdlog, struct fake_addr *fake);
int log_write_i3_id(FILE *handle, ID *id);
int log_read_i3_id(FILE *handle, ID *id);
void load_fake_log(FILE *fdlog);
void refresh_fake_log_mutex();
void refresh_fake_log(FILE *fdlog);
int load_log_entry(FILE *fdlog, int type);

#endif
