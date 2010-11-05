#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/un.h>
#include <unistd.h>

#include "private.h"

static struct MapStruct *bdrMapP = NULL;
static fd_set childFdSet;
static int maxChildFd = 0;


static void
BDRMakeAsync(int fd)
{
   ASSERT(fd >= 0);
   fcntl(fd, F_SETFL, O_ASYNC);
   fcntl(fd, F_SETOWN, syscall(SYS_gettid));
   /* Default is SIGIO. */
   //fcntl(fd, F_SETSIG, SIGIO);
}



int
BDR_Open(pid_t pid)
{
   int rval = 1;
   char *tmpPath = (char*)malloc(PATH_MAX);
   BDR *bdrP = NULL;


   bdrP = (BDR*)malloc(sizeof(*bdrP));
   memset(bdrP, 0, sizeof(*bdrP));
   Map_NodeInit(&bdrP->pidMap, pid);


   snprintf(tmpPath, PATH_MAX, "%s/%d/session", VK_PROC_DIR, pid);
   if (readlink(tmpPath, bdrP->sessionDir, sizeof(bdrP->sessionDir)) < 0) {
      rval = 0;
      goto out;
   }

   snprintf(tmpPath, PATH_MAX, "%s/%d/sock", VK_PROC_DIR, pid);

   if ((bdrP->fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
      DEBUG_MSG(2, "can't create BDR socket");
      rval = 0;
      goto out;
   }

   struct  sockaddr_un servAddr;
   memset(&servAddr, 0, sizeof(servAddr));
   servAddr.sun_family = AF_UNIX;
   strncpy(servAddr.sun_path, tmpPath, sizeof(servAddr.sun_path));
   if (connect(bdrP->fd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
      DEBUG_MSG(2, "can't connect to BDR socket\n");
      rval = 0;
      goto out;
   }

   DEBUG_MSG(2, "Sending attach request.\n");
   struct VkMsg msg;
   msg.tag = VkMsg_Attach;
   msg.Msg.Dbg.pid = pid;
   msg.Msg.Dbg.addr = 0;
   msg.Msg.Dbg.Un.data = 0;
   if (safe_write(bdrP->fd, &msg, sizeof(msg)) != sizeof(msg)) {
      rval = 0;
      goto out;
   }

   char dbPath[PATH_MAX];
   snprintf(dbPath, sizeof(dbPath), "%s/formDb.gdbm", bdrP->sessionDir);
   if (!access(dbPath, R_OK)) {
      bdrP->resolverP = new DiskResolver(bdrP->sessionDir);
   }

   Map_Insert(bdrMapP, pidMap, (uint)pid, bdrP);
   FD_SET(bdrP->fd, &childFdSet);
   maxChildFd = MAX(maxChildFd, bdrP->fd);

   /* We need async notification for us to emulate SIGCHLD delivery
    * to GDB when it is in sigsuspend. */
   BDRMakeAsync(bdrP->fd);

out:
   free(tmpPath);

   return rval;
}

void
BDR_Resume(const BDR *bdrP, enum __ptrace_request req, long sig)
{
   struct VkMsg msg;
   msg.Msg.Dbg.pid = bdrP->pidMap.keyLong;
   msg.Msg.Dbg.Un.data = sig;

   switch (req) {
   case PTRACE_CONT:
      msg.tag = VkMsg_Cont;
      break;
   case PTRACE_SINGLESTEP:
      msg.tag = VkMsg_SingleStep;
      break;
   case PTRACE_DETACH:
      msg.tag = VkMsg_Detach;
      break;
   default:
      ASSERT_UNIMPLEMENTED(0);
      break;
   }

   safe_write(bdrP->fd, &msg, sizeof(msg));
   long ip;
   safe_read(bdrP->fd, &ip, sizeof(ip));
}

static int
BDRResolveSymbolic(const BDR *bdrP, char *dstP, const struct ReplyReadState *stP)
{
   int err = 0;
   uint i;

   if (stP->err) {
      err = stP->err;
      goto out;
   }

   for (i = 0; i < stP->len; i++) {
      if (stP->bytes[i].isSymbolic) {
         ASSERT_UNIMPLEMENTED(bdrP->resolverP);
         dstP[i] = Resolve_Solve(bdrP->resolverP, &stP->bytes[i].Un.symVar);
      } else {
         dstP[i] = stP->bytes[i].Un.concVal;
      }
   }

out:
   return err;
}

int
BDR_GetRegs(const BDR *bdrP, char *dstP, off_t off, size_t len)
{
   ASSERT((size_t)off < sizeof(struct user_regs_struct));
   ASSERT(len <= sizeof(struct user_regs_struct));

   struct VkMsg msg;
   msg.tag = VkMsg_GetRegs;
   msg.Msg.Dbg.pid = bdrP->pidMap.keyLong;
   msg.Msg.Dbg.addr = off;
   msg.Msg.Dbg.Un.len = len;

   safe_write(bdrP->fd, &msg, sizeof(msg));

   struct VkMsgReply reply;
   const struct ReplyReadState *stP = &reply.Un.State;

   safe_read(bdrP->fd, &reply, sizeof(reply));

   ASSERT(reply.tag == VkReply_RegState);
   ASSERT(stP->addr == (size_t)off);
   ASSERT(stP->len == len);

   return BDRResolveSymbolic(bdrP, dstP, stP);
}

int
BDR_ReadMem(const BDR *bdrP, char *dstP, ulong addr, size_t len)
{
   struct VkMsg msg;
   msg.tag = VkMsg_ReadMem;
   msg.Msg.Dbg.pid = bdrP->pidMap.keyLong;
   msg.Msg.Dbg.addr = addr;
   msg.Msg.Dbg.Un.len = len;

   safe_write(bdrP->fd, &msg, sizeof(msg));

   struct VkMsgReply reply;
   const struct ReplyReadState *stP = &reply.Un.State;
   safe_read(bdrP->fd, &reply, sizeof(reply));

   ASSERT(reply.tag == VkReply_MemState);
   ASSERT(stP->addr == addr);
   ASSERT(stP->len == len);

   return BDRResolveSymbolic(bdrP, dstP, stP);
}

void
BDR_Close(BDR *bdrP)
{
   int i, newMax = 0;

   ASSERT(bdrP->fd >= 0);

   BDR_Resume(bdrP, PTRACE_DETACH, 0);

   FD_CLR(bdrP->fd, &childFdSet);
   close(bdrP->fd);
   bdrP->fd = -1;

   delete bdrP->resolverP;

   for (i = 0; i < maxChildFd; i++) {
      if (FD_ISSET(i, &childFdSet)) {
         newMax = i;
      }
   }
   maxChildFd = newMax;

   Map_Remove(bdrMapP, pidMap, bdrP);
   free(bdrP);
   bdrP = NULL;
}

BDR *
BDR_Lookup(pid_t pid)
{
   BDR *bdrP;

   bdrP = Map_Find(bdrMapP, pidMap, (uint)pid, bdrP);

   return bdrP;
}

void
BDR_Init()
{
   bdrMapP = Map_Create(0);
   FD_ZERO(&childFdSet);
}


pid_t
BDR_WaitForEvent(BDR *bdrP, VKDbgEvent *evP, int shouldBlock)
{
   int i;
   struct timeval tv;
   tv.tv_sec = 0;
   tv.tv_usec = 0;

   int maxFd;
   fd_set readfds, exceptfds;

   if (bdrP) {
      FD_ZERO(&readfds);
      FD_ZERO(&exceptfds);
      FD_SET(bdrP->fd, &readfds);
      exceptfds = readfds;
      maxFd = bdrP->fd;
   } else {
      readfds = exceptfds = childFdSet;
      maxFd = maxChildFd;
   }

   if (select(maxFd+1, &readfds, NULL, &exceptfds, shouldBlock ? NULL : &tv) 
         > 0) {
      for (i = 0; i <= maxFd; i++) {
         int eof = 0;

         if (FD_ISSET(i, &readfds)) {
            if (safe_read(i, evP, sizeof(*evP)) == 0) {
               eof = 1;
            } else {
               BDR *bP;
               list_for_each_entry(bP, &bdrMapP->list, pidMap.list) {
                  if (i == bP->fd) {
                     pid_t pid = bP->pidMap.keyLong;
                     ASSERT(pid > 0);
                     return pid;
                  }
               }
               ASSERT(0);
            }
         } 

         if (eof || FD_ISSET(i, &exceptfds)) {
            ASSERT_UNIMPLEMENTED(0);
         }
      }
   }
   return 0;
}

int
BDR_IsMsgPending()
{
   int maxFd;
   fd_set readfds, exceptfds;
   struct timeval tv;
   tv.tv_sec = 0;
   tv.tv_usec = 0;

   readfds = exceptfds = childFdSet;
   maxFd = maxChildFd;

   if (select(maxFd+1, &readfds, NULL, &exceptfds, &tv) > 0) {
      return 1;
   }

   return 0;
}

int
BDR_SetBrkpt(const BDR *bdrP, ulong addr)
{
   struct VkMsg msg;
   msg.tag = VkMsg_SetBrkpt;
   msg.Msg.Dbg.pid = bdrP->pidMap.keyLong;
   msg.Msg.Dbg.addr = addr;

   ulong res;

   safe_write(bdrP->fd, &msg, sizeof(msg));
   safe_read(bdrP->fd, &res, sizeof(res));
   return res == addr;
}

int
BDR_RmBrkpt(const BDR *bdrP, ulong addr)
{
   struct VkMsg msg;
   msg.tag = VkMsg_RmBrkpt;
   msg.Msg.Dbg.pid = bdrP->pidMap.keyLong;
   msg.Msg.Dbg.addr = addr;

   int res;

   safe_write(bdrP->fd, &msg, sizeof(msg));
   safe_read(bdrP->fd, &res, sizeof(res));

   return res == 1;
}


#if 0
void
BDR_MakeAllAsync()
{
   BDR *bdrP;
   list_for_each_entry(bdrP, &bdrMapP->list, list) {
      BDRMakeAsync(bdrP->fd);
   }
}

void
BDR_MakeAllSync()
{
   BDR *bdrP;
   list_for_each_entry(bdrP, &bdrMapP->list, list) {
      int err;

      err = fcntl(bdrP->fd, F_SETFL, 0);
      ASSERT(!err);
   }
}
#endif
