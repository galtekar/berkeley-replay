/* Common API functions */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "chord.h"

#define RUNTIME_DIR "/var/run/chord"

#ifndef SIM_CHORD
static int sp[2];  /* Socket pair for communication between the two layers */
static chordID *shared_data;
pthread_mutex_t *mut = NULL;
#else
static chordID LeftId, RightId;
#endif

#ifndef SIM_CHORD 

/* route: forward message M towards the root of key K. */
void chord_route(chordID *k, char *data, int len)
{
  byte buf[BUFSIZE];

  if (send(sp[0], buf, pack_data(buf, k, len, data), 0) < 0)
    weprintf("send failed:");  /* ignore errors */
}

/**********************************************************************/

/* init: initialize chord server, return socket descriptor */
int chord_init(char *conf_file)
{
  FILE *fp;
  struct stat stat_buf;
    
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) < 0)
    eprintf("socket_pair failed:");

  shared_data = (chordID*) mmap(0x0, getpagesize(), PROT_READ | PROT_WRITE,
	MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  mut = (pthread_mutex_t*) shared_data;
  pthread_mutex_init(mut, NULL);

  shared_data = (chordID*)((char*)shared_data + sizeof(pthread_mutex_t));

  /* Catch all crashes/kills and cleanup */
  signal(SIGHUP, chord_cleanup);
  signal(SIGINT, chord_cleanup);
  signal(SIGILL, chord_cleanup);
  signal(SIGABRT, chord_cleanup);
  signal(SIGFPE, chord_cleanup);
  signal(SIGSEGV, chord_cleanup);
  signal(SIGPIPE, chord_cleanup);
  signal(SIGTERM, chord_cleanup);
  signal(SIGCHLD, chord_cleanup); /* If Chord process dies, exit */
  signal(SIGBUS, chord_cleanup);

  if (!fork()) {  /* child */
    chord_main(conf_file, sp[1]);
  }

  return sp[0];
}

/**********************************************************************/

void chord_cleanup(int signum)
{
  signal(SIGABRT, SIG_DFL);
  abort();
}

/**********************************************************************/

/* deliver: upcall */
void chord_deliver(int n, uchar *data)
{
  /* Convert to I3 format... by stripping off the Chord header */
  send(sp[1], data, n, 0);
}

#endif

/**********************************************************************/

/* get_range: returns the range [l,r) that this node is responsible for */
void chord_get_range(chordID *l, chordID *r)
{
#ifndef SIM_CHORD
pthread_mutex_lock(mut);
  *l = shared_data[0];
  *r = shared_data[1];
pthread_mutex_unlock(mut);
#else
  *l = LeftId;
  *r = RightId;
#endif
}



/**********************************************************************/

void chord_update_range(chordID *l, chordID *r)
{
  //printf("update_range(");
  //print_chordID(l);
  //printf(" - ");
  //print_chordID(r);
  //printf(")\n");
#ifndef SIM_CHORD
pthread_mutex_lock(mut);
  shared_data[0] = *l;
  shared_data[1] = *r;
pthread_mutex_unlock(mut);
#else
  LeftId = *l;
  RightId = *r;
#endif
}

/**********************************************************************/

int chord_is_local(chordID *x)
{
  chordID l, r;

  chord_get_range(&l, &r);
  return equals(x, &r) || is_between(x, &l, &r);
}
