#include <stdlib.h>
#include <sys/time.h>
#include <signal.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "chord.h"

/* Global variable that is a pointer to srv in chord main */
Server *srv_ref;

/* local functions */
static void fix_fingers(Server *srv);
static void fix_successors(Server *srv);
static void ping(Server *srv);
static void clean_finger_list(Server *srv);

/* stabilize: the following things are done periodically
 *  - stabilize successor by asking for its predecessor
 *  - fix one backup successor 
 *  - fix one proper finger 
 *  - ping one node in the finger list (the finger list includes 
 *    the backup successors, the proper fingers and the predecessor)
 *  - ping any node in the finger list that has not replied to the
 *    previous ping
 */

#define CHORD_CLEAN_PERIOD 60

void stabilize(Server *srv)
{
  static int idx = 0;
  int i;

  /* Hack to get around the fact that parameters
   * cannot be passed when setting signal timers */
#ifndef SIM_CHORD
  srv = srv_ref;
#endif

  /* While there is no successor, we fix that! */
  if (SUCC(srv) == NULL) {
#ifndef SIM_CHORD
    for (i = 0; i < nknown; i++)
      send_fs(srv, well_known[i].addr, well_known[i].port,
	      &srv->node.id, srv->node.addr, srv->node.port);
#else
    {
      Server *s;
#define SRV_PRESENT 2
      s = get_random_server(srv->node.addr, SRV_PRESENT);

      if (s != NULL)
	send_fs(srv, s->node.addr, s->node.port,
		&srv->node.id, srv->node.addr, srv->node.port);
    }
#endif
    return;
  }
  
  /* stabilize successor */
  assert(SUCC(srv));
  send_stab(srv, SUCC(srv)->node.addr, SUCC(srv)->node.port,
	    &srv->node.id, srv->node.addr, srv->node.port);

  /* fix one backup successor; backup successors are fixed
   * in a round-robin fashion 
   */
  fix_successors(srv);

  /* fix one proper finger that is not a backup successor; 
   * backup successors are fixed in a round-robin fashion 
   */
  fix_fingers(srv);

  /* ping one node in the finger list; these nodes are 
   * pinged in a round robin fashion. 
   * In addition, ping all nodes which have not replyed to previous pings
   */
  ping(srv);

  if ((idx++) % CHORD_CLEAN_PERIOD == 0)
    /* remove all nodes in the finger list that are neither (1)
     * backup successors, nor (2) proper fingers, and nor (3) predecessor
     */
    clean_finger_list(srv);
}


/**********************************************************************/

void fix_fingers(Server *srv)
{
  chordID id = successor(srv->node.id, srv->to_fix_finger);

  /** Only loop across most significant fingers */
  if( (srv->to_fix_finger == 0) ||
      is_between(&id, &srv->node.id, &SUCC(srv)->node.id) ) {
    srv->to_fix_finger = NFINGERS-1;
    id = successor(srv->node.id, srv->to_fix_finger);
  }

  if (SUCC(srv) != NULL) {
    CHORD_DEBUG(5, print_fun(srv, "fix_finger", &id));
    send_fs(srv, SUCC(srv)->node.addr, SUCC(srv)->node.port,
	    &id, srv->node.addr, srv->node.port);
  }

  srv->to_fix_finger--;
}


/**********************************************************************/
/* fix backup successors in a round-robin fashion                     */
/**********************************************************************/

void fix_successors(Server *srv)
{
  int k;
  Finger *f;
  chordID id;

  if (SUCC(srv) == NULL)
    return;

  /* find the next successor to be fixed; stop if 
   * there are no more successors
   */
  for (f = SUCC(srv), k = 0; 
       (k < srv->to_fix_succ) && f->next; 
       k++, f = f->next);

  id = successor(f->node.id, 0);

  CHORD_DEBUG(5, print_fun(srv, "fix_successors", &f->node.id));
  send_fs(srv, f->node.addr, f->node.port, 
	  &id, srv->node.addr, srv->node.port);


  srv->to_fix_succ++;
  if ((f->next == NULL) || (srv->to_fix_succ >= NSUCCESSORS))
    srv->to_fix_succ = 0;
}


/************************************************************************/

void ping(Server *srv)
{
  int i;
  struct in_addr ia;
  Finger *f, *f_next, *f_pinged = NULL;

  /* ping every finger who is still waiting for reply to a previous ping,
   * and the to_ping-th finger in the list 
   */
  for (f = srv->head_flist, i = 0; f; i++) {

    if (f->npings >= PING_THRESH) {
      ia.s_addr = htonl(srv->node.addr);
#ifdef SIM_CHORD
      // print_fun(srv, "dropping finger", &f->node.id); 
#else
      weprintf("dropping finger (at %s:%d) %d\n",
	  		inet_ntoa(ia), srv->node.port, i);
#endif
      f_next = f->next;
      remove_finger(srv, f);
    } else {
      if (f->npings || (srv->to_ping == i)) {
	f->npings++;
	send_ping(srv, f->node.addr, f->node.port, 
		  srv->node.addr, srv->node.port, get_current_time());
	if (srv->to_ping == i) 
	  f_pinged = f;
      }
      f_next = f->next;
    }
    f = f_next;
  }

  if (!f_pinged || !(f_pinged->next))
    srv->to_ping = 0;
  else
    srv->to_ping++;

}

/**********************************************************************
 * keep only (1) backup successors, (2) proper fingers, and (3) predecessor;
 * remove anything else from finger list
 ***********************************************************************/

void clean_finger_list(Server *srv)
{
  Finger *f, *f1, *f2, *f_tmp;
  int     k, no_finger;
  chordID id;

  /* skip successor list */
  for (f = srv->head_flist, k = 0; f && (k < NSUCCESSORS); f = f->next, k++);
  if (f == NULL || f->next == NULL)
    return;

  /* start from the tail and skip predecessor; f is the last backup succesor */
  f1 = PRED(srv)->prev;
  if (f1 == f)
    return; /* finger list contains only of backup successors and predecesor */

  /* keep only unique (proper) fingers */
  for (k = NFINGERS - 1; k >= 0; k--) {

    /* compute srv.id + 2^k */
    id = successor(srv->node.id, k);
    
    /* get the first node (f1) and the last node (f2) in the successor
     * list that belong to interval [srv.id + 2^k, srv.id + 2^{k+1})  
     */
    f2 = f1;
    no_finger = TRUE;
    while (is_between(&id, &srv->node.id, &f1->node.id) || 
	   (equals(&f1->node.id, &id))) {
      no_finger = FALSE;
      if (f1 == f) 
	break;
      f1 = f1->prev;
    }

    if (no_finger)
      continue;

    if (f1 != f) 
      f1 = f1->next; /* f1 is now the k-th proper finger */

    /* keep only f1; remove all nodes from f1->next to f2, if any */
    while (f2 != f1) {
      f_tmp = f2->prev;
      remove_finger(srv, f2);
      f2 = f_tmp;
    }

    if (f1 == f) 
      return;
    else
      f1 = f1->prev;
  }
}


/**********************************************************************/
/* set_stabilize_timer: Intialize timer that calls stabilize          */
/**********************************************************************/

void set_stabilize_timer(void)
{
    struct itimerval timer, otimer;
    
    timer.it_interval.tv_sec  = STABILIZE_PERIOD / 1000000;
    timer.it_interval.tv_usec = STABILIZE_PERIOD % 1000000;
    
    timer.it_value.tv_sec  = STABILIZE_PERIOD / 1000000;
    timer.it_value.tv_usec = STABILIZE_PERIOD % 1000000;
    
    /* set up signal catcher */
#ifndef CCURED    
    signal(SIGALRM, (void *)stabilize);
#else
    signal(SIGALRM, __trusted_cast(&stabilize));
#endif    
    
    /* set up timer */
    setitimer(ITIMER_REAL, &timer, &otimer);
}

