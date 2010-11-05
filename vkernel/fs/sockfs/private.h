#pragma once

struct SockStruct;

struct SockOps {
   int      (*socket)(struct SockStruct *);
   int      (*bind)(struct SockStruct *, const struct sockaddr *, int);
   int      (*connect)(struct SockStruct *, struct sockaddr *, int);
   int      (*listen)(struct SockStruct *, int);
   int      (*accept)(struct SockStruct *, struct SockStruct *, struct sockaddr *, int *);
   int      (*socketpair)(struct SockStruct *, struct SockStruct *);
   int      (*getname)(struct SockStruct *, struct sockaddr *, int *, int);
   int      (*sockopt)(struct SockStruct *, int, int, char *, int *, int);
   int      (*shutdown)(struct SockStruct *, int);
};


extern struct SockStruct* Sock_Alloc(int family, int type, int protocol);
extern void               Sock_Free(struct SockStruct *sockp);

extern const struct SockOps RdSock_Sops;

extern struct SuperBlockStruct *sbSock;
