/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"

#include <stdio.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static int _is_controlled = False;
static int ctrl_fd = -1;

static SHAREDAREA int _break_on_syscall = False;
static SHAREDAREA int _break_on_file_io = False;
static SHAREDAREA int _break_on_file_action = False;

typedef int (*HandleReqFn)(const int fd, const VkReqTag tag, void *arg);


/*
 
   Summary:
 
   Design notes:

 */

#undef U
#define U(r) offsetof(struct user_regs_struct, r)

#define V(r) offsetof(VexGuestX86State, r)

#define REG16(r) \
   [U(r)] = V(R(r)), \
[U(r)+1] = V(R(r))+1, \
[U(r)+2] = -1, \
[U(r)+3] = -1

#define REG32(r) \
   [U(r)] = V(R(e##r)), \
[U(r)+1] = V(R(e##r))+1, \
[U(r)+2] = V(R(e##r))+2, \
[U(r)+3] = V(R(e##r))+3

static const int usrRegsToVexRegsOffMap[] = {
   REG32(bx),
   REG32(cx),
   REG32(dx),
   REG32(si),
   REG32(di),
   REG32(bp),
   REG32(ax),
   REG32(ip),
   REG32(sp),
   REG32(flags),
   REG16(ds),
   REG16(es),
   REG16(fs),
   REG16(gs),
   REG16(cs),
   REG16(ss),
};
#undef U
#undef V

#if 0
static char
BDRGetRegByteWithUsrOff(off_t off)
{

   int vo = usrRegsToVexRegsOffMap[off];

   if (vo >= 0) {
      return Task_GetRegByte(curr_regs, vo);
   }

   /* XXX: accesse to eflags offset need to return
    * LibVEX_Eflags() rather than the raw value. */

   /* There is no valid mapping. */
   ASSERT(vo == -1);
   return 0;
}
#endif

static void
ServerSendString(const int fd, const char *str)
{
   char buf[32];
   const size_t len = strlen(str);
   size_t buf_len;

   buf_len = NetOps_Pack( buf, sizeof(buf), "L", len );
   ASSERT(buf_len > 0);
   NetOps_SendAll(fd, buf, buf_len, 0 );
   NetOps_SendAll(fd, str, len, 0);
}



static void
ServerSendByte( int fd, struct StateByte *sb_p )
{
   size_t out_len;
   char buf[256];

   out_len = NetOps_Pack( buf, sizeof(buf), "BBBBQQ", 
         sb_p->is_symbolic, sb_p->un.val, sb_p->un.var.byte, 
         sb_p->un.var.is_origin, 
         sb_p->un.var.name, sb_p->un.var.bb_exec_count );

   NetOps_SendAll( fd, buf, out_len, 0 );
}

static void
ServerHandleReadRegReq( int fd, int task_tid, ulong off, size_t len )
{
   int i;
   long res_len = len;
   size_t out_len;
   char buf[32];
   struct Task *tsk_ptr = NULL;

   DEBUG_MSG( 5, "task_tid=%d off=%d len=%d\n", task_tid, off, len );

   /* Check args. */
   tsk_ptr = Task_GetByPid( task_tid );
   if (!(0 <= off && off+len < sizeof(struct user_regs_struct)) ||
         !tsk_ptr) {
      res_len = 0;
   }

   /* Tell client how many bytes to expect. */
   out_len = NetOps_Pack( buf, sizeof(buf), "L", res_len );
   ASSERT( out_len > 0 );
   NetOps_SendAll( fd, buf, out_len, 0 );

   for ( i = off; i < off+res_len; i++ ) {
      off_t vo = usrRegsToVexRegsOffMap[i];
      struct StateByte sb;
      ASSERT_KPTR(tsk_ptr);
      TaskRegs *regs_ptr = Task_GetRegs( tsk_ptr );
      ASSERT_KPTR( regs_ptr );

      memset( &sb, 0, sizeof(sb) );
#if 1
      /* XXX: eflags needs special handling. */
      if (vo >= 0) {
         /* XXX: shouldn't be invoked each loop iteration. */
         if (Module_IsLoaded(MODULE_PTR(DCGen))) {
            D__;
            Cgen_GetRegByte(tsk_ptr, vo, &sb);
         } else {
            D__;
            sb.is_symbolic = 0;
            sb.un.val = Task_GetRegByte(regs_ptr, vo);
         }
      } else {
#if DEBUG
         /* Segment segs are stored as ulong in the user struct */
         struct user_regs_struct rs;
         ASSERT(sizeof(rs.ds) == sizeof(ulong));
         ASSERT(vo == -1);
#endif
         sb.un.val = 0;
      }
#endif

      ServerSendByte( fd, &sb );
   }
}

#if 1
static void
ServerReadMemReqWork(int fd, const struct Task *tsk_ptr, ulong addr, 
                     size_t len)
{
   ASSERT_KPTR(tsk_ptr);

   int i, is_foreign_aspace = (tsk_ptr->mm->id != current->mm->id);
   if (is_foreign_aspace) {
      int status, pid;
      SysOps_ptrace(PTRACE_ATTACH, tsk_ptr->realPid, NULL, NULL);
      pid = waitpid(tsk_ptr->realPid, &status, __WALL);
      ASSERT(pid == tsk_ptr->realPid);
      ASSERT(WIFSTOPPED(status));
   }

   for (i = 0; i < len; i++) {
      struct StateByte sb;
      int err;

      memset( &sb, 0, sizeof(sb) );

      if (Module_IsLoaded(MODULE_PTR(DCGen))) {
         if ((err = Cgen_GetMemByte( tsk_ptr, (void*)(addr+i), &sb ))) {
            ASSERT( err < 0 );
            sb.is_symbolic = err;
         }
      } else {
         if ((err = Task_GetMemByte(tsk_ptr, addr+i, &sb.un.val))) {
            ASSERT(!err || err < 0);
            sb.is_symbolic = err;
         } else {
            sb.is_symbolic = 0;
         }
      }

      ServerSendByte( fd, &sb );
   }

   if (is_foreign_aspace) {
      SysOps_ptrace(PTRACE_DETACH, tsk_ptr->realPid, NULL, NULL);
   }
}

static void
ServerHandleReadMemReq( int fd, ulong task_tid, ulong addr, size_t len )
{
   long res_len = len;
   size_t out_len;
   char buf[32];
   struct Task *tsk_ptr = NULL;

   DEBUG_MSG(5, "task_tid=%d addr=0x%x len=%d\n", task_tid, addr, len);

   /* Check args. */
   tsk_ptr = Task_GetByPid( task_tid );
   if (!(PAGE_SIZE <= addr) || !tsk_ptr) {
      res_len = 0;
   }

   /* XXX: should really translate to gaddrs here and return errors
    * before responding; but this works for now */

   /* Tell client how many bytes to expect. */
   out_len = NetOps_Pack( buf, sizeof(buf), "L", res_len );
   ASSERT( out_len > 0 );
   NetOps_SendAll( fd, buf, out_len, 0 );

   if (res_len) {
      ServerReadMemReqWork(fd, tsk_ptr, addr, res_len);
   }

   return;
}
#endif

#if 0
static void
ServerHandleWriteMemReq(int fd, struct MsgDbg *msgP)
{
   const long *dstP = (long*)msgP->addr;
   const long data = msgP->Un.data;
   size_t resLen = sizeof(data);

   DEBUG_MSG(5, "addr=0x%x data=0x%lx\n", msgP->addr, data);
   ASSERT_UNIMPLEMENTED(Task_IsUPtr(dstP));

   origProt = GetProtVma(dstP);
   mprotect(dstP, sizeof(data), PROT_READ | PROT_WRITE);
   if (copy_to_user(dstP, &data, sizeof(data))) {
      resLen = 0;
   }
   mprotect(dstP, sizeof(data), origProt);
   TrnsTab_Invalidate(dstP, sizeof(data));

   safe_write(fd, &resLen, sizeof(resLen));
}
#endif

static void
ServerHandleTaskListReq( int fd )
{
   struct Task *tsk_ptr;
   ssize_t out_len;
   char buf[128];
   ulong nr_tasks = 0;

   /* XXX: avoid iterating through the list twice; have vkernel
    * maintain the task count; modify fork.c and exit.c accordingly */
   tsk_ptr = &initTask;
   do {
      DEBUG_MSG(5, "tid=%d vcpu_id=%d\n", tsk_ptr->pid, tsk_ptr->vcpu->id);
      if (tsk_ptr->vcpu == curr_vcpu) {
         nr_tasks++;
      }
   } while ( (tsk_ptr = next_task(tsk_ptr)) != &initTask );

   DEBUG_MSG(5, "nr_tasks=%d\n", nr_tasks);
   out_len = NetOps_Pack(buf, sizeof(buf), "L", nr_tasks);
   ASSERT(out_len > 0);
   NetOps_SendAll(fd, buf, out_len, 0);

   tsk_ptr = &initTask;
   do {
      if (tsk_ptr->vcpu == curr_vcpu) {
         out_len = NetOps_Pack(buf, sizeof(buf), "L", tsk_ptr->pid);
         ASSERT(out_len > 0);
         NetOps_SendAll(fd, buf, out_len, 0);
      }
   } while ( (tsk_ptr = next_task(tsk_ptr)) != &initTask );
}

static void
ServerHandleTaskInfoReq( int fd, int task_tid )
{
   ASSERT_UNIMPLEMENTED(0);
}


static void
ServerOnBrkptHit(void *argP UNUSED)
{
   D__;

   /* We want to exit the dispatch loop and re-enter the debug loop
    * so that we can process more debug commands. */
   Task_SetCurrentFlag(TIF_ENTER_DEBUG_LOOP);

   /* When we re-enter the debug loop, notify the tracer that it was due
    * to a breakpoint hit. */
   ASSERT(current->dbgRespEv == 0);

   current->dbgRespEv = VK_EVENT_BRKPT_HIT;
}

static void
ServerHandleSetBrkptReq(const int fd, const ulong tid, const ulong brkpt_type,
                        const ulong brkpt_loc)
{
   char buf[32];
   ssize_t out_len;

   DEBUG_MSG(5, "brkpt_loc=0x%x\n", brkpt_loc);
   ASSERT_UNIMPLEMENTED_MSG(Task_IsAddrInUser(brkpt_loc), 
         "Handle this error gracefully.\n");
   ASSERT(tid > 0);

   switch (brkpt_type) {
   case VK_BRKPT_SYSCALL:
      _break_on_syscall = True;
      break;
   case VK_BRKPT_FILE_PEEK:
   case VK_BRKPT_FILE_DEQUEUE:
   case VK_BRKPT_FILE_WRITE:
      _break_on_file_io = True;
      break;
   case VK_BRKPT_FILE_OPEN:
   case VK_BRKPT_FILE_CLOSE:
   case VK_BRKPT_FILE_PUT:
      _break_on_file_action = True;
      break;
   case VK_BRKPT_INSN_ENTRY: {
      struct ExecPoint ep = { .eip = brkpt_loc, .ecx = 0, .brCnt = 0 };
      Brkpt_SetAbsolute(Bpk_Static, &ep, &ServerOnBrkptHit, NULL);
      break;
   }
   default:
      ASSERT_MSG(0, "tid=%d brkpt_type=0x%x brkpt_loc=0x%x\n",
            tid, brkpt_type, brkpt_loc);
      break;
   }

   out_len = NetOps_Pack(buf, sizeof(buf), "L", 0);
   ASSERT(out_len > 0);
   NetOps_SendAll(fd, buf, out_len, 0);
}

static void
ServerHandleDelBrkptReq(const int fd, const ulong tid, const ulong brkpt_type, const ulong brkpt_loc)
{
   int res = 1;
   char buf[32];
   ssize_t out_len;

   DEBUG_MSG(5, "brkpt_loc=0x%x\n", brkpt_loc);
   ASSERT_UNIMPLEMENTED_MSG(Task_IsAddrInUser(brkpt_loc), 
         "Handle this error gracefully.\n");
   ASSERT(tid > 0);

   switch (brkpt_type) {
   case VK_BRKPT_SYSCALL:
         _break_on_syscall = False;
      break;
   case VK_BRKPT_FILE_PEEK:
   case VK_BRKPT_FILE_DEQUEUE:
   case VK_BRKPT_FILE_WRITE:
      _break_on_file_io = False;
      break;
   case VK_BRKPT_FILE_OPEN:
   case VK_BRKPT_FILE_CLOSE:
   case VK_BRKPT_FILE_PUT:
      _break_on_file_action = False;
      break;
   case VK_BRKPT_INSN_ENTRY: {
      struct ExecPoint ep = { .eip = brkpt_loc, .ecx = 0, .brCnt = 0 };
      res = Brkpt_RmAbsolute(Bpk_Static, &ep);
      break;
   }
   default:
      ASSERT_MSG(0, "tid=%d brkpt_type=0x%x brkpt_loc=0x%x\n",
            tid, brkpt_type, brkpt_loc);
      break;
   }

   out_len = NetOps_Pack(buf, sizeof(buf), "L", res ? 0 : -1);
   ASSERT(out_len > 0);
   NetOps_SendAll(fd, buf, out_len, 0);
}

static int
ServerHandleSystemReq(const int fd, const VkReqTag tag)
{
   int was_handled = 1, err = 0;
   size_t len;
   uchar buf[128];

   switch (tag) {
   case VK_REQ_STATUS:
      {
         ASSERT( env.end_vclock );
         len = NetOps_Pack(buf, sizeof(buf), "QQQB", curr_vcpu->vclock,
               env.end_vclock, curr_vcpu->wall_clock, env.is_value_det);
         DEBUG_MSG(5, "vclock=%llu end_vclock=%llu\n", 
               curr_vcpu->vclock, env.end_vclock);

         ASSERT(len > 0);
         NetOps_SendAll( fd, buf, len, 0 );
      }
      break;
   case VK_REQ_CONT:
      {
         err = NetOps_ReadAll(fd, buf, sizeof(uint64_t), 0);
         ASSERT_UNIMPLEMENTED(err == sizeof(uint64_t));
         NetOps_Unpack(buf, sizeof(buf), "Q", &curr_vcpu->target_vclock);
         if (curr_vcpu->target_vclock == 0) {
            curr_vcpu->target_vclock = ULLONG_MAX;
         }
#if 0
         len = NetOps_Pack(buf, sizeof(buf), "L", 0);

         ASSERT(len > 0);
         NetOps_SendAll( fd, buf, len, 0 );
#endif
      }
      break;
   case VK_REQ_READMEM:
   case VK_REQ_READREG:
      {
         int task_tid = -1;
         ulong range_start, range_len;
         const size_t msg_len = sizeof(ulong)*3;
         err = NetOps_ReadAll(fd, buf, msg_len, 0);
         ASSERT_UNIMPLEMENTED(err == msg_len);
         len = NetOps_Unpack( buf, sizeof(buf), "LLL", &task_tid, 
               &range_start, &range_len );
         ASSERT( len > 0 );
         if (tag == VK_REQ_READMEM) {
            ServerHandleReadMemReq( fd, task_tid, range_start, range_len );
         } else {
            ServerHandleReadRegReq( fd, task_tid, range_start, range_len );
         }
      }
      break;
   case VK_REQ_TASKLIST:
      ServerHandleTaskListReq( fd );
      break;
   case VK_REQ_TASKINFO:
      {
         int task_tid;
         err = NetOps_ReadAll(fd, buf, sizeof(ulong), 0);
         ASSERT_UNIMPLEMENTED(err == sizeof(ulong));
         len = NetOps_Unpack( buf, sizeof(buf), "L", &task_tid );
         ASSERT( len > 0 );
         ServerHandleTaskInfoReq( fd, task_tid );
      }
      break;
   case VK_REQ_SET_BRKPT:
   case VK_REQ_DEL_BRKPT:
      {
         const size_t msg_len = sizeof(ulong)*3;
         err = NetOps_ReadAll(fd, buf, msg_len, 0);
         ASSERT_UNIMPLEMENTED(err == msg_len);
         ulong tid, brkpt_loc, brkpt_type;
         len = NetOps_Unpack( buf, sizeof(buf), "LLL", &tid, &brkpt_type, 
                              &brkpt_loc);
         ASSERT( len > 0 );

         if (tag == VK_REQ_SET_BRKPT) {
            ServerHandleSetBrkptReq(fd, tid, brkpt_type, brkpt_loc);
         } else {
            ASSERT(tag == VK_REQ_DEL_BRKPT);
            ServerHandleDelBrkptReq(fd, tid, brkpt_type, brkpt_loc);
         }
      }
      break;
   case VK_REQ_GET_FILENAME_BY_FD:
   case VK_REQ_SET_PLANE_BY_FD:
      {
         const size_t msg_len = sizeof(ulong)*2;
         err = NetOps_ReadAll(fd, buf, msg_len, 0);
         ASSERT_UNIMPLEMENTED(err == msg_len);
         ulong req_fd, req_tid;
         len = NetOps_Unpack(buf, sizeof(buf), "LL", &req_tid, &req_fd);
         ASSERT(len > 0);
         ASSERT(req_fd >= 0);
         ASSERT(req_tid >= 1);

         const struct Task *tsk_ptr = Task_GetByPid(req_tid);
         ASSERT_UNIMPLEMENTED(tsk_ptr);
         struct FileStruct *file_ptr = 
            Files_LookupUnlocked(tsk_ptr->files, req_fd);
         ASSERT_UNIMPLEMENTED(file_ptr);

         if (tag == VK_REQ_GET_FILENAME_BY_FD) {
            ServerSendString(fd, File_Name(file_ptr));
         } else {
            ASSERT(tag == VK_REQ_SET_PLANE_BY_FD);
            file_ptr->channel_kind = Chk_Data;
         }
      }
      break;
   default:
      was_handled = 0;
      break;
   };

   return was_handled;
}

static int
ServerHandleControlMsg(const int fd, HandleReqFn *callbacks, void **args,
      int nr_callbacks)
{
   int err, was_handled = 0;
   VkReqTag tag = 0xdeadbeef;
   char buf[sizeof(tag)];

   ASSERT(fd == ctrl_fd);

   err = NetOps_ReadAll(fd, buf, sizeof(tag), 0);
   ASSERT_UNIMPLEMENTED_MSG(err == sizeof(tag), "err=%d", err);
   err = NetOps_Unpack(buf, sizeof(buf), "L", &tag);
   ASSERT(err > 0);

   ASSERT_MSG(tag >= VK_REQ_STATUS && tag < VK_REQ_LAST_DUMMY,
         "tag=0x%x", tag);

   was_handled |= ServerHandleSystemReq(fd, tag);
   int i = 0;
   while (!was_handled && i < nr_callbacks) {
      /* It should be a context-specific request. */
      was_handled |= (callbacks[i])(fd, tag, args[i]);
      i++;
   }
   ASSERT_UNIMPLEMENTED_MSG(was_handled, "tag=0x%x", tag);

   return (tag == VK_REQ_CONT);
}

static void
ServerNotifyController(struct Task *tsk, VkEventTag tag)
{
   char buf[256];
   size_t len;
   ssize_t res;

   ASSERT_MSG(tag >= VK_EVENT_STOP, "tag=%d", tag);
   ASSERT(tsk->pid > 0);

   len = NetOps_Pack( buf, sizeof(buf), "LL", tag, tsk->pid );
   ASSERT( len > 0 )
   res = NetOps_SendAll( ctrl_fd, buf, len, 0 );
   ASSERT( res == len );
}

void
ServerEnterControlLoop(HandleReqFn* callbacks, void **args, int num_callbacks)
{
   ASSERT(ctrl_fd >= 0);
   D__;

   Task_ClearCurrentFlag(TIF_ENTER_DEBUG_LOOP);
   while (!ServerHandleControlMsg(ctrl_fd, callbacks, args, num_callbacks));
}

void
Server_NotifyAndEnterControlLoop(const VkEventTag ev)
{
   ASSERT(ctrl_fd >= 0);
   D__;

   ServerNotifyController(current, ev);
   ServerEnterControlLoop(NULL, NULL, 0);
}

/* ---------- Event handlers ---------- */

static void
ServerOnSyscallWork(const int is_pre)
{
   char buf[256];
   size_t len;
   ssize_t res;

   ServerNotifyController(current, VK_EVENT_SYSCALL);
   len = NetOps_Pack(buf, sizeof(buf), "L", current->orig_eax);
   res = NetOps_SendAll(ctrl_fd, buf, len, 0);
   ASSERT( res == len );
   ServerEnterControlLoop(NULL, NULL, 0);
}

void
Server_OnPreSyscall()
{
#if 0
   DEBUG_MSG(5, "_is_controlled=%d _break_on_sys_entry=%d\n",
         _is_controlled, _break_on_sys_entry);
   if (_is_controlled && _break_on_syscall) {
      ServerOnSyscallWork(1);
   }
#endif
}

void
Server_OnPostSyscall()
{
   if (_is_controlled && _break_on_syscall) {
      ServerOnSyscallWork(0);
   }
}

struct IoReqArg {
   struct FileStruct *file_ptr;
   const struct IoVec *iov_ptr;
   const tsock_chunk_t *chunk_ptr;
   const size_t total_len;
};

static int
ServerHandleIoMsgReqs(const int fd, const VkReqTag tag, void *arg)
{
   int was_handled = 1;
   const struct IoReqArg *arg_ptr = (struct IoReqArg *) arg;
   const struct IoVec *iov_ptr = arg_ptr->iov_ptr;
   //struct FileStruct *file_ptr = arg_ptr->file_ptr;
   const tsock_chunk_t *chunk_ptr = arg_ptr->chunk_ptr;
   const struct MsgTag *tag_ptr = (struct MsgTag *)&chunk_ptr->tag_buf;
   const size_t total_len = arg_ptr->total_len;

   ASSERT_KPTR(iov_ptr);
   //ASSERT_KPTR(file_ptr);

   DEBUG_MSG(5, "tag=0x%x\n", tag);

   int err;
   char buf[128];

   switch (tag) {
   case VK_REQ_GET_MSG_TAINT:
   case VK_REQ_SET_MSG_TAINT:
      if (!Module_IsLoaded(MODULE_PTR(DCGen))) {
         was_handled = 0;
         break;
      }

      if (tag == VK_REQ_GET_MSG_TAINT) {
         struct IoBuffer *buf_ptr = NULL;
         const size_t len = IovOps_GetCapacity(iov_ptr);
         ssize_t bytes_sent;

         char *taint_vec = malloc(len), *tvec_ptr = taint_vec;
         list_for_each_entry(buf_ptr, &iov_ptr->iov_list, list) {
            ASSERT_UPTR(buf_ptr->base);
            ASSERT(buf_ptr->len > 0);

            Cgen_GetTaintMap(current, buf_ptr->base, buf_ptr->len, 
                  tvec_ptr);
            tvec_ptr += buf_ptr->len;
         }
         bytes_sent = NetOps_SendAll(fd, taint_vec, len, 0);
         ASSERT(bytes_sent == len);

         free(taint_vec);
         taint_vec = NULL;
      } else {
         ASSERT(tag == VK_REQ_SET_MSG_TAINT);
         struct IoBuffer *buf_ptr = NULL;
         const size_t len = IovOps_GetCapacity(iov_ptr);
         char *taint_vec = malloc(len), *ptr = taint_vec;

         err = NetOps_ReadAll(fd, taint_vec, len, 0);
         ASSERT_UNIMPLEMENTED(err == len);

         list_for_each_entry(buf_ptr, &iov_ptr->iov_list, list) {
            size_t i;
            for (i = 0; i < buf_ptr->len; i++) {
               ASSERT(*ptr == 0 || *ptr == 1);
               if ((int)*ptr) {
                  Cgen_TaintMemRegion(buf_ptr->base+i, 1);
               }
               ptr++;
            }
         }
         free(taint_vec);
         taint_vec = NULL;
      }
      break;
   case VK_REQ_GET_MSG_INFO:
      {
         uuid_t uuid;
         uint64_t msg_idx = 0;
         struct IoBuffer *bufp;
         ssize_t len;

         memset(&uuid, 0, sizeof(uuid));
         if (chunk_ptr->tag_len) {
            memcpy(&uuid, tag_ptr->uuid, sizeof(uuid));
            msg_idx = tag_ptr->msg_idx;
         }

         len = NetOps_Pack(buf, sizeof(buf), "LLLLQLL",
               uuid[0], uuid[1], uuid[2], uuid[3], msg_idx, total_len,
               iov_ptr->len);
         NetOps_SendAll(ctrl_fd, buf, len, 0);

         list_for_each_entry(bufp, &iov_ptr->iov_list, list) {
            len = NetOps_Pack(buf, sizeof(buf), "LL",
               bufp->base, bufp->len);
            NetOps_SendAll(ctrl_fd, buf, len, 0);
         }
         break;
      }
   default:
      was_handled = 0;
      break;
   }

   return was_handled;
}

static int
ServerHandleIoReqs(const int fd, const VkReqTag tag, void *arg)
{
   int was_handled = 1;
   struct FileStruct *file_ptr = (struct FileStruct*)arg;
   ASSERT_KPTR(file_ptr);

   DEBUG_MSG(5, "tag=0x%x\n", tag);

   int err;
   char buf[128];

   switch (tag) {
   case VK_REQ_GET_FILE_NAME:
      ServerSendString(fd, File_Name(file_ptr));
      break;
   case VK_REQ_SET_FILE_PLANE:
      {
         const size_t len = sizeof(ulong);
         int req_plane;

         err = NetOps_ReadAll(fd, buf, len, 0);
         ASSERT(err == len);
         err = NetOps_Unpack(buf, sizeof(buf), "L", &req_plane);
         ASSERT(err > 0);
         ASSERT(req_plane == 0 || req_plane == 1);
         file_ptr->channel_kind = req_plane ? Chk_Data : Chk_Control;
      }
      break;
   case VK_REQ_GET_FILE_INFO:
      {
         int family = 0, type = 0, protocol = 0;
         size_t len;
         ssize_t res;

         struct InodeStruct *inoP = File_Inode(file_ptr);
         const InodeMajor inoMaj = Inode_GetMajor(inoP);
         if (inoMaj == InodeMajor_Sock) {
            const struct SockStruct *sockP = Sock_GetStruct(inoP);
            family = sockP->family;
            type = sockP->type;
            protocol = sockP->protocol;
         }

         len = NetOps_Pack(buf, sizeof(buf), "LLLLL",
               inoMaj, family, type, protocol, (ulong)file_ptr);
         ASSERT(len > 0);
         res = NetOps_SendAll(ctrl_fd, buf, len, 0);
      }
      break;
   default:
      was_handled = 0;
      break;
   }

   return was_handled;
}

#if 0
static void
ServerOnIoWork(const VkEventTag tag,
      const struct CopySource *cs_ptr,
      const struct IoVec *iov_ptr, 
      const size_t total_len) 
{
   const tsock_chunk_t *chunk_ptr = cs_ptr->Un.SysIO.chunk_ptr;
   struct InodeStruct *inoP = File_Inode(cs_ptr->Un.SysIO.filP);
   const InodeMajor inoMaj = Inode_GetMajor(inoP);
   const struct MsgTag *tag_ptr = (struct MsgTag *)&chunk_ptr->tag_buf;

   DEBUG_MSG(5, "tag_len=%d\n", chunk_ptr->tag_len);

   int family = 0, type = 0, protocol = 0;
   char buf[128];
   size_t len;
   ssize_t res;

   if (inoMaj == InodeMajor_Sock) {
      const struct SockStruct *sockP = Sock_GetStruct(inoP);
      family = sockP->family;
      type = sockP->type;
      protocol = sockP->protocol;
   }

   uuid_t uuid;
   uint64_t msg_idx = 0;
   memset(&uuid, 0, sizeof(uuid));
   if (chunk_ptr->tag_len) {
      memcpy(&uuid, tag_ptr->uuid, sizeof(uuid));
      msg_idx = tag_ptr->msg_idx;
   }

   ServerNotifyController(current, tag);
   len = NetOps_Pack(buf, sizeof(buf), "LLLLQLLLLLL",
         uuid[0], uuid[1], uuid[2], uuid[3], msg_idx,
         inoMaj, family, type, protocol,
         !is_write ? (cs_ptr->Un.SysIO.msg_flags & MSG_PEEK ? 0 : 1) : 2,
         total_len);
   ASSERT(len > 0);
   res = NetOps_SendAll(ctrl_fd, buf, len, 0);
   ASSERT(res == len);
   struct IoReqArg arg = { .file_ptr = (struct FileStruct *)cs_ptr->Un.SysIO.filP,
      .iov_ptr = iov_ptr };
   ServerEnterControlLoop(&ServerHandleIoReqs, (void*)&arg);
}
#endif

void
Server_OnUserCopy(const int is_write,
      const struct CopySource *cs_ptr,
      const struct IoVec *iov_ptr, 
      const size_t total_len) 
{
   if (_is_controlled && cs_ptr->tag == Sk_SysIO && _break_on_file_io) {
      ASSERT(IovOps_GetCapacity(iov_ptr) == total_len);

      DEBUG_MSG(5, "IO event: is_write=%d total_len=%d\n", is_write,
            total_len);

      ServerNotifyController(current, is_write ? VK_EVENT_FILE_WRITE : 
            ((cs_ptr->Un.SysIO.msg_flags & MSG_PEEK) ? VK_EVENT_FILE_PEEK : 
             VK_EVENT_FILE_DEQUEUE));
      struct FileStruct *filp = 
         (struct FileStruct *)cs_ptr->Un.SysIO.filP;

      struct IoReqArg arg2 = { .file_ptr = filp, .iov_ptr = iov_ptr, 
         .chunk_ptr = cs_ptr->Un.SysIO.chunk_ptr, .total_len = total_len };
      void* args[] = { (void*) filp, (void*) &arg2 };
      HandleReqFn callbacks[] = { ServerHandleIoReqs, 
         ServerHandleIoMsgReqs };
      ServerEnterControlLoop(callbacks, args, 2);
   }
}

void
Server_OnFileEvent(VkEventTag event, const struct FileStruct *filp)
{
   if (_is_controlled && (_break_on_file_action)) {
      DEBUG_MSG(5, "File event: 0x%x\n", event);
      ServerNotifyController(current, event);
      void* args[] = { (void*) filp };
      HandleReqFn callbacks[] = { ServerHandleIoReqs };
      ServerEnterControlLoop(callbacks, args, 1);
   }
}

void
Server_OnResumeUser()
{
   /* Nothing to do here, yet */
}

void
Server_OnTagRecv(const char *tagBuf, size_t tagLen)
{
   /* To guarantee that we replay in increasing lamport clock order,
    * we must stop execution and notify the controller at this point. 
    * We can't do this at OnResumeUser, because the message receive
    * callbacks would've fired already, hence resulting in message
    * reception actions being invoked before the corresponding sending
    * process has had a chance to execute. */

   /* XXX: currently we notify only on tag reception. Shouldn't we
    * notify on tag send as well? It seems that we needn't. 
    *
    * galtekar: So long as receives happen on causal order, no need to 
    * stop on sends. An advantage is fewer context switches. 
    * Any disadvantages? */
   if (_is_controlled) {
      if (curr_vcpu->target_vclock <= curr_vcpu->vclock) {
         ServerNotifyController(current, VK_EVENT_STOP);
         ServerEnterControlLoop(NULL, NULL, 0);
      }
   }
}

void
Server_Shutdown()
{
   if (_is_controlled) {
      ASSERT( ctrl_fd >= 0 );
      ServerNotifyController(current, VK_EVENT_SHUTDOWN);
      UNUSED int err = shutdown( ctrl_fd, SHUT_RDWR );
      ASSERT( !err );
   }
}

void
Server_OnTaskStart()
{
   if (_is_controlled) {
      ServerNotifyController(current, VK_EVENT_TASK_START);
      ServerEnterControlLoop(NULL, NULL, 0);
   }
}

void
Server_OnTaskExit()
{
   if (_is_controlled) {
      ServerNotifyController(current, VK_EVENT_TASK_EXIT);
      ServerEnterControlLoop(NULL, NULL, 0);
   }
}

static int
ServerConnectUsingTCP()
{
   struct addrinfo hints, *resultP, *rP;
   int fd;

   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = 0;
   hints.ai_protocol = 0;

   if (getaddrinfo(session.ctrl_host, session.ctrl_port, &hints, 
            &resultP) != 0) {
      FATAL("cannot resolve %s\n", session.ctrl_host);
   }

   for (rP = resultP; rP != NULL; rP = rP->ai_next) {
      DEBUG_MSG(5, "rp->family=%d rp->socktype=%d rp->protocol=%d\n",
            rP->ai_family, rP->ai_socktype, rP->ai_protocol);
      if ((fd = socket(rP->ai_family, rP->ai_socktype, 
                  rP->ai_protocol)) == -1) {
         continue;
      }

      ASSERT(fd >= 0);
      if (connect(fd, rP->ai_addr, rP->ai_addrlen) != -1) {
         break;
      }

      close(fd);
      fd = -1;
   }

   if (rP == NULL) {
      FATAL("could not connect to controller\n");
   }

   freeaddrinfo(resultP);
   return fd;
}

static int
ServerConnectUsingUNIX()
{
   int fd;
   fd = socket(AF_UNIX, SOCK_STREAM, 0);

   struct sockaddr_un saddr;
   saddr.sun_family = AF_UNIX;
   ASSERT_UNIMPLEMENTED(strlen(session.ctrl_port) < UNIX_PATH_MAX);
   strncpy(saddr.sun_path, session.ctrl_port, UNIX_PATH_MAX);
   int socklen = sizeof(sa_family_t) + strlen(saddr.sun_path) + 1;
   if (connect(fd, (struct sockaddr*)&saddr, socklen) == -1) {
      FATAL("could not connect to controller\n");
   }

   return fd;
}

int
Server_Init()
{
   if (!VCPU_IsReplaying()) {
      return 0;
   }

   /* XXX: Make this optional. */
   if ( strlen(session.ctrl_host) ) {
      ASSERT( strlen(session.ctrl_port) );

      if (session.ctrl_port[0] == '/') {
         ctrl_fd = ServerConnectUsingUNIX();
      } else {
         ctrl_fd = ServerConnectUsingTCP();
      }

      _is_controlled = 1;
   }

   return 0;
}
