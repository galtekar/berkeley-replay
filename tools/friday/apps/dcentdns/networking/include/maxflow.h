#ifndef _MAXFLOW_H

#define _MAXFLOW_H

#include "types.h"          /* type definitions */
using namespace std;
#include <iostream>

class MaxFlow {
/* global variables */

long   n;                    /* number of nodes */
long   m;                    /* number of arcs */
long   nm;                   /* n + ALPHA * m */
long   nMin;                 /* smallest node id */
node   *nodes;               /* array of nodes */
arc    *arcs;                /* array of arcs */
bucket *buckets;             /* array of buckets */
cType  *cap;                 /* array of capacities */
node   *source;              /* source node pointer */
node   *sink;                /* sink node pointer */
//node   **queue;              /* queue for BFS */
//node   **qHead, **qTail, **qLast;     /* queue pointers */
long   dMax;                 /* maximum label */
long   aMax;                 /* maximum actie node label */
long   aMin;                 /* minimum active node label */
double flow;                 /* flow value */
long pushCnt  ;           /* number of pushes */
long relabelCnt   ;       /* number of relabels */
long updateCnt    ;       /* number of updates */
long gapCnt   ;           /* number of gaps */
long gNodeCnt ;           /* number of nodes after gap */  
float t, t2;                 /* for saving times */
node   *sentinelNode;        /* end of the node list marker */
arc *stopA;                  /* used in forAllArcs */
long workSinceUpdate;      /* the number of arc scans since last update */
float globUpdtFreq;          /* global update frequency */


	int allocDS( );
	void checkMax();
	void globalUpdate ();
	void stageTwo ( );
	int gap ( bucket* emptyB);
	long relabel (node *i);
	void discharge (node* i);
	void wave() ;
	void stageOne ( );
	void init () ;
	int parse( long *n_ad, long *m_ad, node ** nodes_ad, arc **arcs_ad, long **cap_ad,
           node** source_ad, node **sink_ad, long* node_min_ad , std::istream& is);

public:
	MaxFlow( istream& is);
	double run ( int sinkIndex );
};

#endif
