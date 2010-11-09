#include "fake_mngm_common.h"

extern struct fake_addr  *fake_addr_list_start;

void insert_pkt_to_queue(struct fake_addr *fake, char *buf, int len)
{
  struct pkt_queue_entry *pkt, *qptr;

  pkt = malloc(sizeof(struct pkt_queue_entry));
  if (pkt) {
      pkt->next = NULL;
      pkt->packet_len = len;
      pkt->buf = malloc(len);
      if (!pkt->buf) {
	free(pkt);
	return;
      }
      memcpy(pkt->buf, buf, len);
      if (fake->output_queue == NULL)
	fake->output_queue = pkt;
      else {
	  qptr = fake->output_queue;
	  while (qptr->next != NULL)
	    qptr = qptr->next;
	  qptr->next = pkt;
      }
  }
  return;
}

void flush_pkt_queue(struct fake_addr *fake)
{
  static cl_buf	*clb = NULL;
  struct pkt_queue_entry *qptr, *qptr_next;
  int count = 0;

  if (NULL == clb)
    clb = cl_alloc_buf(BUF_LEN);

  qptr = fake->output_queue;

  if (qptr)
    time(&fake->last_use);

  while (qptr) {
    clb->data[0] = I3_PROXY_VERSION;
    clb->data[1] = I3_PROXY_DATA;
    clb->data_len = qptr->packet_len + 2;
    memcpy(clb->data + 2, qptr->buf, qptr->packet_len);
    cl_send_to_stack(&fake->dest_stack, clb);
    qptr_next = qptr->next;
    free(qptr);
    qptr = qptr_next;
    count++;
  }
  fake->output_queue = NULL;
}

void check_timeout()
{
  struct fake_addr *fake = fake_addr_list_start;
  struct fake_addr *fakenext;
  struct id_list *idl;
  time_t curtime;
  time(&curtime);

  static cl_buf* clb;
  if (clb == NULL)
    clb = cl_alloc_buf(I3_PROXY_HDR_LEN);

  while(fake)
    {
      if (curtime - fake->last_use >= FAKE_TIMEOUT)
	{
	  fakenext = fake->next;
	  DEBUG(11," fake for (%s) timeout \n", inet_ntoa(fake->fake_addr.t.v4.addr));
	  log_fake_removal_mutex(&fake->prv_id);
	  pack_fake_removal(clb,&(fake->prv_id));
	  cl_send_to_stack(&fake->dest_stack, clb);
          if (fake->prv_trig != NULL)
            cl_remove_trigger(fake->prv_trig);
	  private_trigger_timeout(fake);
	  remove_fake_addr(fake);
	  fake = fakenext;
	  continue;
	}

      if ((fake->state == FAKE_STATE_OK ||
	   fake->state == FAKE_STATE_PARTNER_DORMANT) &&
	  ((fake->fake_dns_req != NULL &&
	    curtime - fake->last_use >= CALLER_PRIVATE_TRIGGER_TIMEOUT) ||
	   (fake->fake_dns_req == NULL &&
	    curtime - fake->last_use >= CALLEE_PRIVATE_TRIGGER_TIMEOUT)))
	{
	  idl = lookup_id(&fake->prv_id);
	  if (idl != NULL && fake->prv_trig != NULL)
	    {
	      DEBUG(11," temporarily drop private trigger for (%s)\n",
		    inet_ntoa(fake->fake_addr.t.v4.addr));
	      if (fake->state == FAKE_STATE_OK) {
		//notify the partner that my private trigger is dropped
		pack_trigger_removal(clb,&(fake->prv_id));
		cl_send_to_stack(&fake->dest_stack, clb);
	      }
	      cl_remove_trigger(fake->prv_trig);
	      fake->prv_trig = NULL;
	    }
	}
      fake = fake->next;
   }
}
