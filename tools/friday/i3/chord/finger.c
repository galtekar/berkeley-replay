#include <stdlib.h>
#include <assert.h>
#include "chord.h"

/* new_finger: allocate and initialize finger structure */
Finger *new_finger(Node *node)
{
    Finger *fp;

    /* allocate space for new finger */
    fp = emalloc(sizeof(Finger));
    fp->node = *node;
    fp->npings = 0;
    fp->next = fp->prev = NULL;
    fp->rtt_avg = fp->rtt_dev = 0;
    return fp;
}

/**********************************************************************/

/* closest_preceding_node: search table for highest predecessor of id */
/* closest_preceding_finger: search table for highest predecessor of id */
Finger *closest_preceding_finger(Server *srv, chordID *id)
{
  Finger *f;

  for (f = srv->tail_flist; f; f = f->prev)
    if (is_between(&f->node.id, &srv->node.id, id))
      return f;

  return NULL;
}

Node *closest_preceding_node(Server *srv, chordID *id)
{
  Finger *f = closest_preceding_finger(srv, id);

  if (f == NULL)
    return &(srv->node);
  else
    return &(f->node);
}

/**********************************************************************/

Finger *get_finger(Server *srv, chordID *id)
{
  Finger *f;

  for (f = srv->head_flist; f; f = f->next)
    if (equals(id, &f->node.id))
      return f;
  return NULL;
}

/**********************************************************************/

Finger *insert_finger(Server *srv, chordID *id, in_addr_t addr, in_port_t port)
{
  Finger *f, *new_f, *pred;
  Node   n;

  assert((srv->node.addr != addr) || (srv->node.port != port));
  pred = PRED(srv);
 
  f = get_finger(srv, id);

  if (f) {
    if (f->node.addr != addr) {
      f->node.addr = addr;
      f->node.port = port;
      f->rtt_avg = f->rtt_dev = 0;
      f->npings = 0;
    }
    /* f is already in the list. In this case, 
     * f is not refreshed, i.e., f->npings is not set to 0.
     * Refreshing f here might preclude the ping procedeure from removing
     * f when it dies.
     */
    CHORD_DEBUG(5, print_server(srv, "[insert_finger(1)]", "end"));
    return f;
  } 

  n.id = *id; n.addr = addr; n.port = port;
  new_f = new_finger(&n);

  f = srv->head_flist;
  if (f == NULL) {
    /* this is the first finger */
    srv->head_flist = srv->tail_flist = new_f;
  } else {

    f = closest_preceding_finger(srv, id);
    if (f == NULL) {
      new_f->next = srv->head_flist;
      new_f->prev = NULL;
      srv->head_flist->prev = new_f;
      srv->head_flist = new_f;
    } else {    
      new_f->next = f->next;
      if (f->next)
	f->next->prev = new_f;
      else
	srv->tail_flist = new_f;
      new_f->prev = f;
      f->next = new_f;
    }
  }

  CHORD_DEBUG(5, print_server(srv, "[insert_finger(2)]", ""));

  assert(PRED(srv));

  if (pred != PRED(srv))
    chord_update_range(&PRED(srv)->node.id, &srv->node.id);

  return new_f;
}
  

/**********************************************************************/

void remove_finger(Server *srv, Finger *f)
{
  Finger *pred;
  
  pred = PRED(srv);

  if ((srv->tail_flist != f) && (srv->head_flist != f)) {
    f->prev->next = f->next;
    f->next->prev = f->prev;
  } else {
    if (srv->head_flist == f) {
      srv->head_flist = f->next;
      if (f->next) f->next->prev = NULL;
    } 
    if (srv->tail_flist == f) {
      srv->tail_flist = f->prev;
      if (f->prev) f->prev->next = NULL;
    } 
  }

  if (pred != PRED(srv)) {
    if (PRED(srv) == NULL) 
      chord_update_range(&srv->node.id, &srv->node.id);
    else
      chord_update_range(&PRED(srv)->node.id, &srv->node.id);
  }


  CHORD_DEBUG(5, print_server(srv, "[remove_finger]", ""));
  free(f);
}

/**********************************************************************/

void free_finger_list(Finger *flist)
{
  Finger *f;

  while (flist) {
    f = flist;
    flist = flist->next;
    free(f);
  }
}



