#include <stdio.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "fake_mngm.h"
#include "fake_log.h"
#include "dns_thread.h"
#include "i3_trigger.h"
#include "i3_client_api.h"

extern uint32_t fakes;
extern char fake_log_fname[MAX_DNS_NAME_LEN];
extern pthread_mutex_t mutexlog;
extern struct fake_addr  *fake_addr_list_start;
extern struct fake_addr  *fake_addr_list_end;
extern char tun_dev_address[MAX_DNS_NAME_LEN];
extern char fake_addr_range_start[MAX_DNS_NAME_LEN];
extern struct id_list *id_list_start;

void log_fake_insertion_mutex(struct fake_addr *fake)
{
  FILE *fdlog;

  pthread_mutex_lock (&mutexlog);

  fdlog = fopen(fake_log_fname, "a");
  if (!fdlog) {
    DEBUG(1, " Error opening fake_log_file !\n");
  } else {
    log_fake_insertion(fdlog, fake);
    fclose(fdlog);
  }
  pthread_mutex_unlock (&mutexlog);
}
  
void log_fake_insertion(FILE *fdlog, struct fake_addr *fake)
{
  if (fake->real_addr.type != I3_ADDR_TYPE_IPv4 ||
      fake->fake_addr.type != I3_ADDR_TYPE_IPv4)
    return; // currently, only IPv4 is supported

  if (fake->fake_dns_req != NULL) { // caller or callee ?
    fprintf(fdlog, "LOG TYPE %1d\n", LOG_TYPE_ADD_CALLER); // LOG_TYPE = ADD_CALLER
  } else {
    fprintf(fdlog, "LOG TYPE %1d\n", LOG_TYPE_ADD_CALLEE); // LOG_TYPE = ADD_CALLEE
  }

  fprintf(fdlog, "  real_addr %s\n", inet_ntoa(fake->real_addr.t.v4.addr)); // real_addr
  fprintf(fdlog, "  fake_addr %s\n", inet_ntoa(fake->fake_addr.t.v4.addr)); // fake_addr
  fprintf(fdlog, "  fake_num_req %lu\n", fake->num_req);
  log_write_i3_id(fdlog, &fake->prv_id); // prv_id
  log_write_i3_id(fdlog, &fake->dest_id); // dest_id

  if (fake->fake_dns_req != NULL) { // LOG_TYPE = ADD_CALLER
    fprintf(fdlog, "  dns_name %s\n", fake->fake_dns_req->dns_name); // dns_name
    fprintf(fdlog, "  dns_num_req %lu\n", fake->fake_dns_req->num_req);
    log_write_i3_id(fdlog, &fake->fake_dns_req->dns_id); // dns_id
  }
}

void log_fake_changeID_mutex(struct fake_addr *fake)
{
  // change partner's ID
  FILE *fdlog;

  pthread_mutex_lock (&mutexlog);

  fdlog = fopen(fake_log_fname, "a");
  if (!fdlog) {
    DEBUG(1, " Error opening fake_log_file !\n");
  } else {
    log_fake_changeID(fdlog, fake);
    fclose(fdlog);
  }
  pthread_mutex_unlock (&mutexlog);
}
  
void log_fake_changeID(FILE *fdlog, struct fake_addr *fake)
{
  // change partner's ID
  if (fake->real_addr.type != I3_ADDR_TYPE_IPv4 ||
      fake->fake_addr.type != I3_ADDR_TYPE_IPv4)
    return; // currently, only IPv4 is supported

  fprintf(fdlog, "LOG TYPE %1d\n", LOG_TYPE_CHANGE_ID); // LOG_TYPE = CHANGE_ID
  log_write_i3_id(fdlog, &fake->prv_id); // prv_id
  log_write_i3_id(fdlog, &fake->dest_id); // dest_id
}

void log_fake_removal_mutex(ID *prv_id)
{
  FILE *fdlog;

  pthread_mutex_lock (&mutexlog);
  fdlog = fopen(fake_log_fname, "a");
  if (!fdlog) {
    DEBUG(1, " Error opening fake_log_file !\n");
  } else {
    log_fake_removal(fdlog, prv_id);
    fclose(fdlog);
  }
  pthread_mutex_unlock (&mutexlog);
}

void log_fake_removal(FILE *fdlog, ID *prv_id)
{
  fprintf(fdlog, "LOG TYPE %1d\n", LOG_TYPE_REMOVE); // LOG_TYPE = REMOVE
  log_write_i3_id(fdlog, prv_id); // prv_id
}

int log_write_i3_id(FILE *handle, ID *id)
{
  uint i;

  fprintf(handle, "  ID ");

  for (i = 0; i < sizeof(ID); i++) {
    fprintf(handle, "%02x", id->x[i]);
  }

  fprintf(handle, "\n");
  return 1;
}

int log_read_i3_id(FILE *handle, ID *id)
{
  uint i;
  uint16_t c;

  fscanf(handle, "ID ");
  
  for (i = 0; i < sizeof(ID); i++) {
    fscanf(handle, "%2hx", &c);
    id->x[i] = (uint8_t) c;
  }

  fscanf(handle, "\n");
  return 1;
}

// load fake status from log file
void load_fake_log(FILE *fdlog)
{
  char fake_start[MAX_DNS_NAME_LEN];
  int ret, type;
  struct id_list *idl, *idlnext;
  struct fake_addr *fake;
  Key key;

  fscanf(fdlog, "FAKE_ADDR_RANGE_START %s\n", fake_start);

  if (strcmp(fake_start, fake_addr_range_start) != 0) {
    DEBUG(1, "fake IP address configuration was changed. Discard fake_log file.\n");
    return;
  }

  while (1) {
    ret = fscanf(fdlog, "LOG TYPE %1d\n", &type);
    if (ret == EOF || ret != 1)
      break;
    
    if (!load_log_entry(fdlog, type))
      break;
  }

  // insert triggers
  idl = id_list_start;
  while (idl)
    {
      if (idl->type == ID_LIST_ADDR) {
	fake = idl->s.addr;
	generate_r_constraint(&fake->prv_id, &key);
	fake->prv_trig = cl_insert_trigger_key(&fake->prv_id, ID_LEN_BITS, &key);
	if (fake->prv_trig == NULL) {
	  DEBUG(1, "\n Error inserting private trigger while loading fake_log_file\n");
	  if (fake->fake_dns_req != NULL)
	    remove_fake_dns(fake->fake_dns_req);
	  remove_fake_addr(fake);
	  idlnext = idl->next;
	  remove_id_from_id_list(&idl->id);
	  idl = idlnext;
	} else
	  idl = idl->next;
      } else
	idl = idl->next;
  }
}

// load each log entry and update id_list, fake_list, fake_dns_list
// trigger insertion and removal will be performed later
int load_log_entry(FILE *fdlog, int type)
{
  char real_addr[MAX_DNS_NAME_LEN];
  char fake_addr[MAX_DNS_NAME_LEN];
  char dns_name[MAX_DNS_NAME_LEN];
  ID prv_id, dest_id, dns_id;
  unsigned long fake_num_req, dns_num_req;
  struct fake_addr *fake;
  struct id_list *id;
  time_t last_use;

  time(&last_use);

  if (type == LOG_TYPE_REMOVE) {
    if (!log_read_i3_id(fdlog, &prv_id)) return 0;
    id = lookup_id(&prv_id);
    if (id != NULL && id->type == ID_LIST_ADDR) {
      if (id->s.addr->fake_dns_req != NULL)
	remove_fake_dns(id->s.addr->fake_dns_req);
      remove_fake_addr(id->s.addr);
      remove_id_from_id_list(&prv_id);
    }
    return 1;
  } else if (type == LOG_TYPE_CHANGE_ID) {
    if (!log_read_i3_id(fdlog, &prv_id)) return 0;
    if (!log_read_i3_id(fdlog, &dest_id)) return 0;
    id = lookup_id(&prv_id);
    if (id == NULL) {
      return 0;
  } else {
      memcpy(&id->s.addr->dest_id, &dest_id, ID_LEN);
      return 1;
    }
  } else { // CALLER & CALLEE
    if (fscanf(fdlog, "real_addr %s\n", real_addr) != 1) return 0;
    if (fscanf(fdlog, "fake_addr %s\n", fake_addr) != 1) return 0;
    if (fscanf(fdlog, "fake_num_req %lu\n", &fake_num_req) != 1) return 0;
    if (!log_read_i3_id(fdlog, &prv_id)) return 0;
    if (!log_read_i3_id(fdlog, &dest_id)) return 0;
    if (type == LOG_TYPE_ADD_CALLER) {
      if (fscanf(fdlog, "dns_name %s\n", dns_name) != 1) return 0;
      if (fscanf(fdlog, "dns_num_req %lu\n", &dns_num_req) != 1) return 0;
      if (!log_read_i3_id(fdlog, &dns_id)) return 0;
    }

    fake = (struct fake_addr *) malloc(sizeof(struct fake_addr));
    if ( !fake ) {
      DEBUG(1, "\nCould not allocate fake_addr struct in load_caller()\n");
      exit(-1);
    }
    memset(fake, 0, sizeof(struct fake_addr));
    fake->real_addr.type = I3_ADDR_TYPE_IPv4;
    fake->real_addr.t.v4.addr.s_addr = inet_addr(real_addr);
    fake->fake_addr.type = I3_ADDR_TYPE_IPv4;
    fake->fake_addr.t.v4.addr.s_addr = inet_addr(fake_addr);

    // fakes: used in alloc_fake_IP()
    // TODO: implement fake IP address management mechanism
    if (ntohl(fakes) <= ntohl(fake->fake_addr.t.v4.addr.s_addr))
      fakes = htonl(ntohl(fake->fake_addr.t.v4.addr.s_addr) + 1);

    fake->num_req = fake_num_req;
    fake->last_use = last_use;
    memcpy(&fake->prv_id, &prv_id, ID_LEN);
    memcpy(&fake->dest_id, &dest_id, ID_LEN);
    init_i3_stack(&fake->dest_stack, &fake->dest_id, 1);
    fake->state = FAKE_STATE_OK;
    add_fake_addr(fake);

    if (type == LOG_TYPE_ADD_CALLER) {
      fake->fake_dns_req = (struct fake_dns_req *) malloc(sizeof(struct fake_dns_req));
      if ( !fake->fake_dns_req ) {
	DEBUG(1, "\nCould not allocate fake_dns_req struct in load_caller()\n");
	exit(-1);
      }
      memset(fake->fake_dns_req, 0, sizeof(struct fake_dns_req));
      strcpy(fake->fake_dns_req->dns_name, dns_name);
      fake->fake_dns_req->num_req = dns_num_req;
      fake->fake_dns_req->fake_addr = fake;
      memcpy(&fake->fake_dns_req->dns_id, &dns_id, ID_LEN);
      init_i3_stack(&fake->fake_dns_req->dns_stack, &fake->fake_dns_req->dns_id, 1);
      add_fake_dns(fake->fake_dns_req);
    }

      insert_id_in_id_list(&fake->prv_id, ID_LIST_ADDR, fake);

    return 1;
  }
}

void refresh_fake_log_mutex()
{
  FILE *fdlog;

  pthread_mutex_lock (&mutexlog);
  fdlog = fopen(fake_log_fname, "w");
  if (!fdlog) {
    DEBUG(1, " Error opening fake_log_file !\n");
  } else {
    refresh_fake_log(fdlog);
    fclose(fdlog);
  }
  pthread_mutex_unlock (&mutexlog);
}

void refresh_fake_log(FILE *fdlog)
{
  struct fake_addr *fake;

  fprintf(fdlog, "FAKE_ADDR_RANGE_START %s\n", fake_addr_range_start);
  
  fake = fake_addr_list_start;
  while (fake) {
    log_fake_insertion(fdlog, fake);
    fake = fake->next;
  }
}
