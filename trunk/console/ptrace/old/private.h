#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ipc.h>

#include <vk.h>

#include "../libcommon/public.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ----- BDR client ----- */
typedef struct {
   struct MapField pidMap;
   int fd;
   char sessionDir[PATH_MAX];
   Resolver *resolverP;
} BDR;

extern void    BDR_Init();
extern int     BDR_Open(pid_t pid);
extern BDR *   BDR_Lookup(pid_t pid);
extern void    BDR_Close(BDR *bdrP);
extern void    BDR_Resume(const BDR *bdrP, enum __ptrace_request req, long sig);
extern int     BDR_GetRegs(const BDR *bdrP, char *dstP, off_t off, size_t len);
extern int     BDR_ReadMem(const BDR *bdrP, char *dstP, ulong addr, size_t len);
extern pid_t   BDR_WaitForEvent(BDR *bdrP, VKDbgEvent *evP, int shouldBlock);
extern int     BDR_SetBrkpt(const BDR *bdrP, ulong addr);
extern int     BDR_RmBrkpt(const BDR *bdrP, ulong addr);
extern void    BDR_MakeAllAsync();
extern void    BDR_MakeAllSync();

#ifdef __cplusplus
}
#endif
