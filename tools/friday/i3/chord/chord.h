#include <sys/types.h>
#include <netinet/in.h>
#ifdef __APPLE__
#include <inttypes.h>  // Need uint64_t
#endif
#include <stdio.h>
#include "debug.h"

#ifndef INCL_CHORD_H
#define INCL_CHORD_H

typedef struct Finger Finger;
typedef struct Node Node;
typedef struct Server Server;

#define NELEMS(a) (sizeof(a) / sizeof(a[0]))
#ifndef FALSE
#define FALSE 0
#define TRUE  1
#endif

//#define SIM_CHORD

#ifdef SIM_CHORD 
enum {
  NBITS          = 16,            
    ID_LEN       = NBITS/8,        /* bytes per ID */
    NFINGERS     = NBITS,          /* #fingers per node */
    NSUCCESSORS  = 3,              /* #successors kept */
    BUFSIZE      = 65536,          /* buffer for packets */
    STABILIZE_PERIOD = 1*1000000,  /* in usec  */
    MAX_WELLKNOWN = 4,             /* maximum number of "seed" servers */
    PING_THRESH = 3,               /* this many unanswered pings are allowed */
};
#else
enum {
  NBITS          = 160,            /* #bits per ID, same as SHA-1 output */
    ID_LEN       = NBITS/8,        /* bytes per ID */
    NFINGERS     = NBITS,          /* #fingers per node */
    NSUCCESSORS  = 8,              /* #successors kept */
    STABILIZE_PERIOD = 1*1000000,  /* in usec */
    BUFSIZE      = 65536,          /* buffer for packets */
    MAX_WELLKNOWN = 4,             /* maximum number of "seed" servers */
    PING_THRESH = 5,               /* this many unanswered pings are allowed */
};
#endif /* SIM_CHORD */

/* packet types */
enum {
    CHORD_ROUTE = 0,   /* data packet */
    CHORD_FS,          /* find_successor */
    CHORD_FS_REPL,     /* find_successor reply */
    CHORD_STAB,        /* get predecessor */
    CHORD_STAB_REPL,   /* ... response */
    CHORD_NOTIFY,      /* notify (predecessor) */
    CHORD_PING,        /* are you alive? */
    CHORD_PONG,        /* yes, I am */
    CHORD_GET_FINGERS, /* get your finger list */
    CHORD_REPL_FINGERS, /* .. here is my finger list */
};

/* XXX: warning: portability bugs */
typedef uint8_t byte;
typedef unsigned char  uchar;
#ifdef __APPLE__
typedef u_long ulong;
#endif

typedef struct {
    byte x[ID_LEN];
} chordID;

struct Node
{
    chordID id;
    in_addr_t addr;
    in_port_t port;
};

struct Finger
{
    Node node;          /* ID and address of finger */
    int npings;         /* # of unanswered pings */
    long rtt_avg;       /* average rtt to finger (ms in simulator, 
			 * usec in the implementation)
			 */
    long rtt_dev;       /* rtt's mean deviation (ms in simulator, 
			 * usec in the implementation)
			 */
                         /* rtt_avg, rtt_dev can be used to implement 
                          * proximity routing or set up RTO for ping 
                          */
    struct Finger *next;
    struct Finger *prev;
};

/* Finger table contains NFINGERS fingers, then predecessor, then
   the successor list */

struct Server
{
    Node node;          /* addr and ID */
    Finger *head_flist; /* head and tail of finger  */
    Finger *tail_flist; /* table + pred + successors 
			 */
    int to_fix_finger;  /* next finger to be fixed */
    int to_fix_succ;    /* next successor to be fixed */
    int to_ping;        /* next node in finger list to be refreshed */

    int in_sock;      /* incoming socket */
    int out_sock;     /* outgoing socket */
};

#define PRED(srv)  (srv->tail_flist)
#define SUCC(srv)  (srv->head_flist)

/* GLOBALS */
extern Node well_known[MAX_WELLKNOWN];
extern int nknown;

extern void chord_main(char *conf_file, int parent_sock);

/* finger.c */
extern Finger *new_finger(Node *node);
extern Finger *closest_preceding_finger(Server *srv, chordID *id);
extern Node *closest_preceding_node(Server *srv, chordID *id);
extern void remove_finger(Server *srv, Finger *f);
extern Finger *get_finger(Server *srv, chordID *id);
extern Finger *insert_finger(Server *srv, 
			     chordID *id, in_addr_t addr, in_port_t port);
void free_finger_list(Finger *flist);

/* hosts.c */
extern in_addr_t get_addr(void); /* get_addr: get IP address of server */

/* join.c */
extern void join(Server *srv, FILE *fp);

/* pack.c */
extern int dispatch(Server *srv, int n, uchar *buf);

extern int pack(uchar *buf, char *fmt, ...);
extern int unpack(uchar *buf, char *fmt, ...);

#ifdef CCURED
// These are the kinds of arguments that we pass to pack
struct pack_args {
  int f1;
  chordID * f2;
};
#pragma ccuredvararg("pack", sizeof(struct pack_args))
struct unpack_args {
  ushort * f1;
  uchar * f2;
  ulong * f3;
  chordID *id;
};
#pragma ccuredvararg("unpack", sizeof(struct unpack_args))
#endif

extern int pack_data(uchar *buf, chordID *id, ushort len, uchar *data);
extern int unpack_data(Server *srv, int n, uchar *buf);
extern int pack_fs(uchar *buf, chordID *id, ulong addr, ushort port);
extern int unpack_fs(Server *srv, int n, uchar *buf);
extern int pack_fs_repl(uchar *buf, chordID *id, ulong addr, ushort port);
extern int unpack_fs_repl(Server *srv, int n, uchar *buf);
extern int pack_stab(uchar *buf, chordID *id, ulong addr, ushort port);
extern int unpack_stab(Server *srv, int n, uchar *buf);
extern int pack_stab_repl(uchar *buf, chordID *id, ulong addr, ushort port);
extern int unpack_stab_repl(Server *srv, int n, uchar *buf);
extern int pack_notify(uchar *buf, chordID *id, ulong addr, ushort port);
extern int unpack_notify(Server *srv, int n, uchar *buf);
int pack_ping(uchar *buf, ulong addr, ushort port, ulong time);
extern int unpack_ping(Server *srv, int n, uchar *buf);
extern int pack_pong(uchar *buf, chordID *id, 
		     ulong addr, ushort port, ulong time);
extern int unpack_pong(Server *srv, int n, uchar *buf);
extern int pack_get_fingers(uchar *buf, ulong addr, ushort port, ulong time);
extern int unpack_get_fingers(Server *srv, int n, uchar *buf);
extern int pack_repl_fingers(uchar *buf, Server *srv, ulong time);
extern int unpack_repl_fingers(Server *null, int n, uchar *buf);

/* process.c */
extern int process_data(Server *srv, chordID *id, ushort len, uchar *data);
extern int process_fs(Server *srv, chordID *id, ulong addr, ushort port);
extern int process_fs_repl(Server *srv, chordID *id, ulong addr, ushort port);
extern int process_stab(Server *srv, chordID *id, ulong addr, ushort port);
extern int process_stab_repl(Server *srv, chordID *id, 
			     ulong addr, ushort port);
extern int process_notify(Server *srv, chordID *id, ulong addr, ushort port);
extern int process_ping(Server *srv, ulong addr, ushort port, ulong time);
extern int process_pong(Server *srv, chordID *id, 
			ulong addr, ushort port, ulong time);
int process_get_fingers(Server *srv, ulong addr, ushort port, ulong time);
int process_repl_fingers(Server *srv, uchar ret_code, ulong time);

/* sendpkt.c */
extern void send_raw(Server *srv, in_addr_t addr, in_port_t port, 
		     int n, uchar *buf);
extern void send_data(Server *srv, Node *np, 
		      chordID *id, ushort n, uchar *data);
extern void send_fs(Server *srv, ulong to_addr, ushort to_port,
		    chordID *id, ulong addr, ushort port);
extern void send_fs_repl(Server *srv, ulong to_addr, ushort to_port,
			 chordID *id, ulong addr, ushort port);
extern void send_stab(Server *srv, ulong to_addr, ushort to_port,
		      chordID *id, ulong addr, ushort port);
extern void send_stab_repl(Server *srv, ulong to_addr, ushort to_port,
			   chordID *id, ulong addr, ushort port);
extern void send_notify(Server *srv, ulong to_addr, ushort to_port,
			chordID *id, ulong addr, ushort port);
extern void send_ping(Server *srv, ulong to_addr, ulong to_port,
		      ulong addr, ushort port, ulong time);
extern void send_pong(Server *srv, ulong to_addr, ulong to_port, ulong time);
extern void send_get_fingers(Server *srv, ulong to_addr, ulong to_port,
			     ulong addr, ushort port, ulong time);
extern void send_repl_fingers(Server *srv, 
			      ulong to_addr, ulong to_port, ulong time);

/* stabilize.c */
extern void stabilize(Server *srv);
extern void set_stabilize_timer(void);

/* api.c */
extern int chord_init(char *conf_file);
extern void chord_cleanup(int signum);
extern void chord_route(chordID *k, char *data, int len);
extern void chord_deliver(int n, uchar *data);
extern void chord_get_range(chordID *l, chordID *r);
void chord_update_range(chordID *l, chordID *r);
int chord_is_local(chordID *x);

/* util.c */
extern double f_rand(void);
extern double funif_rand(double a, double b);
extern int n_rand(int n);
extern int unif_rand(int a, int b);
extern uint64_t wall_time(void);
extern ulong get_current_time();
extern void update_rtt(long *rtt_avg, long *rtt_std, long new_rtt);
extern chordID rand_ID(void);
extern chordID successor(chordID id, int n);
extern chordID predecessor(chordID id, int n);
extern chordID add(chordID a, chordID b);
extern chordID subtract(chordID a, chordID b);
extern int msb(chordID *x);
extern int equals(chordID *a, chordID *b);
extern int is_zero(chordID *x);
extern int is_between(chordID *x, chordID *a, chordID *b);
extern void print_id(FILE *f, chordID *id);
extern chordID atoid(const char *str);
extern unsigned hash(chordID *id, unsigned n);
extern void print_chordID(chordID *id);
extern void print_node(Node *node, char *prefix, char *suffix);
extern void print_finger(Finger *f, char *prefix, char *suffix);
extern void print_finger_list(Finger *fhead, char *prefix, char *suffix);
extern void print_server(Server *s, char *prefix, char *suffix);
extern void print_process(Server *srv, char *process_type, chordID *id,
			  ulong addr, ushort port);
extern void print_send(Server *srv, char *send_type, chordID *id,
		       ulong addr, ushort port);
extern void print_fun(Server *srv, char *fun_name, chordID *id);
void print_current_time(char *prefix, char *suffix);

#ifdef SIM_CHORD
void sim_send_raw(Server *srv, 
		  in_addr_t addr, in_port_t port, int n, uchar *buf);
void sim_deliver_data(Server *srv, chordID *id, int n, uchar *data);
Server *get_random_server(int no_idx, int status);
int sim_chord_is_local(Server *srv, chordID *x);
double sim_get_time(void);
#endif

#include "eprintf.h"

#endif /* INCL_CHORD_H */
