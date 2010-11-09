#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "chord.h"

int process_data(Server *srv, chordID *id, ushort len, uchar *data)
{
    Node *np, *succ;

    CHORD_DEBUG(5, print_process(srv, "process_data", id, -1, -1)); 

    /* handle request locally? */
#ifdef SIM_CHORD
    if (sim_chord_is_local(srv, id)) {
	/* Upcall goes here... */
        sim_deliver_data(srv, id, len, data);
#else
    if (chord_is_local(id)) {
	/* Upcall goes here... */
        chord_deliver(len, data);
#endif
    } else if (SUCC(srv) != NULL) {
        succ = &(SUCC(srv)->node);
	if (is_between(id, &srv->node.id, &succ->id) || equals(id, &succ->id))
	    send_data(srv, succ, id, len, data);
	else {
	    /* send to the closest predecessor (that we know about) */
	    np = closest_preceding_node(srv, id);
	    send_data(srv, np, id, len, data);
	}
    }
    return 1;
}

/**********************************************************************/

int process_fs(Server *srv, chordID *id, ulong addr, ushort port)
{
  Node *succ, *np;

  if (srv->node.addr == addr && srv->node.port == port)
    return 1;

  CHORD_DEBUG(5, print_process(srv, "process_fs", id, addr, port));

  if (SUCC(srv) == NULL) {
    send_fs_repl(srv, addr, port, 
		 &srv->node.id, srv->node.addr, srv->node.port);
    return 0;
  }
  succ = &(SUCC(srv)->node);
  if (is_between(id, &srv->node.id, &succ->id) || equals(id, &succ->id))
    send_fs_repl(srv, addr, port, &succ->id, succ->addr, succ->port);
  else {
    np = closest_preceding_node(srv, id);
    send_fs(srv, np->addr, np->port, id, addr, port);
  }
  return 1;
}

/**********************************************************************/

int process_fs_repl(Server *srv, chordID *id, ulong addr, ushort port)
{
 
  if (srv->node.addr == addr && srv->node.port == port)
    return 1;

  CHORD_DEBUG(5, print_process(srv, "process_fs_repl", id, -1, -1));
  insert_finger(srv, id, addr, port);
  return 1;
}

/**********************************************************************/

int process_stab(Server *srv, chordID *id, ulong addr, ushort port)
{
  CHORD_DEBUG(5, print_process(srv, "process_stab", id, addr, port)); 

  insert_finger(srv, id, addr, port);
  send_stab_repl(srv, addr, port, 
		 &PRED(srv)->node.id, PRED(srv)->node.addr, 
		 PRED(srv)->node.port);
  
  return 1;
}

/**********************************************************************/

int process_stab_repl(Server *srv, chordID *id, ulong addr, ushort port)
{
  CHORD_DEBUG(5, print_process(srv, "process_stab_repl", id, -1, -1)); 

  if ((srv->node.addr == addr) && (srv->node.port == port))
    return 1;
  insert_finger(srv, id, addr, port);
  send_notify(srv, SUCC(srv)->node.addr, SUCC(srv)->node.port,
	      &srv->node.id, srv->node.addr, srv->node.port);
  return 1;
}

/**********************************************************************/

int process_notify(Server *srv, chordID *id, ulong addr, ushort port)
{
  CHORD_DEBUG(5, print_process(srv, "process_notify", id, addr, port)); 
  insert_finger(srv, id, addr, port);
  return 1;
}

/**********************************************************************/

int process_ping(Server *srv, ulong addr, ushort port, ulong time)
{
  CHORD_DEBUG(5, print_process(srv, "process_ping", NULL, addr, port)); 
  send_pong(srv, addr, port, time);
  return 1;
}

/**********************************************************************/

int process_pong(Server *srv, chordID *id, ulong addr, ushort port, ulong time)
{
  Finger *f;
  ulong   new_rtt;

  CHORD_DEBUG(5, print_process(srv, "process_pong", id, addr, port)); 
  f = insert_finger(srv, id, addr, port);
  f->npings = 0;
  new_rtt = get_current_time() - time; /* takes care of overlow */
  update_rtt(&f->rtt_avg, &f->rtt_dev, (long)new_rtt); 
  return 1;
}

/**********************************************************************/

int process_get_fingers(Server *srv, ulong addr, ushort port, ulong time)
{
  CHORD_DEBUG(5, print_process(srv, "process_get_fingers", NULL, addr, port));
  print_server(srv, "[just for test: process_get_fingers]", "");
  send_repl_fingers(srv, addr, port, time);
  return 1;
}

/**********************************************************************/

int process_repl_fingers(Server *srv, uchar ret_code, ulong time)
{
  CHORD_DEBUG(5, print_process(srv, "process_get_fingers", NULL, 0, 0)); 
  /* print something ... */
  print_server(srv, "[process_repl_fingers]", "");
  free_finger_list(srv->head_flist);
  return 1;
}
