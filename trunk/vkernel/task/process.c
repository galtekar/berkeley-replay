#include "vkernel/public.h"
#include "private.h"

#include <errno.h>

SYSCALLDEF(sys_clone, struct SyscallArgs args)
{
   int err;
   struct CloneArgs cloneArgs;

   cloneArgs.flags = args.ebx;
   cloneArgs.stack = (void __user *)args.ecx;
   cloneArgs.ptid = (pid_t __user *)args.edx;
   cloneArgs.tlsDescp = (struct LinuxSegmentDesc __user*)args.esi;

   /* We must copy in the TLS desc from user-level in case there
    * are races on the descriptor. */
   if (cloneArgs.flags & CLONE_SETTLS) {
      if (!cloneArgs.tlsDescp || 
          Task_CopyFromUser(&cloneArgs.tlsDesc, cloneArgs.tlsDescp, 
               sizeof(cloneArgs.tlsDesc))) {
         err = -EFAULT;
         goto out;
      }
   }

   cloneArgs.ctid = (pid_t __user *)args.edi;
   if (!cloneArgs.stack) {
      /* Looks like a stack wasn't specified for the clone. So use
       * the current user-mode stack position. */
      cloneArgs.stack = (void __user *)Task_GetCurrentRegs()->R(esp);
   }

   err = Task_Clone(&cloneArgs, &args);

out:
   return err;
}

SYSCALLDEF(sys_fork, struct SyscallArgs args)
{
   struct CloneArgs cloneArgs;

   cloneArgs.flags = SIGCHLD;
   cloneArgs.stack = (void __user *)Task_GetCurrentRegs()->R(esp);
   cloneArgs.ptid = NULL;
   cloneArgs.tlsDescp = NULL;
   cloneArgs.ctid = NULL;

   return Task_Clone(&cloneArgs, &args);
}

SYSCALLDEF(sys_vfork, struct SyscallArgs args)
{

   /* 4.3BSD, POSIX.1-2001.  The requirements put on vfork() by the standards
      are  weaker  than  those put on fork(2), so an implementation where the
      two are synonymous is compliant.  In particular, the programmer  cannot
      rely  on  the  parent  remaining  blocked  until a call of execve(2) or
      _exit(2) and cannot rely on any specific behavior wth respect to shared
      memory. */

   /* XXX: some apps may break POSIX compliance and assume Linux vfork 
    * behavior... */

   return sys_fork(args);
}

SYSCALLDEF(sys_execve, struct SyscallArgs args)
{
   int error;
   char * filename;

   filename = Task_GetName((char __user *) args.ebx);
   error = PTR_ERR(filename);

   if (IS_ERR(filename)) {
      goto out;
   }

   error = Exec_DoExecve(filename,
         (char __user * __user *) args.ecx,
         (char __user * __user *) args.edx);

   Task_PutName(filename);

   //sleep(1000);

out:
   return error;
}

static void 
TaskShadowGDT2HardwareGDT ( /* IN  */ struct LinuxSegmentDesc *inn,
      /* OUT */ VexGuestX86SegDescr* out,
      Int oldmode )
{
   UInt entry_1, entry_2;
   ASSERT(8 == sizeof(VexGuestX86SegDescr));

   DEBUG_MSG(6, "translate_to_hw_format: base %p, limit %d\n",
         inn->base_addr, inn->limit );

   /* Allow LDTs to be cleared by the user. */ 
   if (inn->base_addr == 0 && inn->limit == 0) {
      if (oldmode ||
            (inn->contents == 0      && 
             inn->read_exec_only == 1   &&
             inn->seg_32bit == 0      &&
             inn->limit_in_pages == 0   &&
             inn->seg_not_present == 1   &&
             inn->useable == 0 )) {
         entry_1 = 0;
         entry_2 = 0;
         goto install;
      }
   }

   entry_1 = ((inn->base_addr & 0x0000ffff) << 16) |
      (inn->limit & 0x0ffff);
   entry_2 = (inn->base_addr & 0xff000000) |
      ((inn->base_addr & 0x00ff0000) >> 16) |
      (inn->limit & 0xf0000) |
      ((inn->read_exec_only ^ 1) << 9) |
      (inn->contents << 10) |
      ((inn->seg_not_present ^ 1) << 15) |
      (inn->seg_32bit << 22) |
      (inn->limit_in_pages << 23) |
      0x7000;
   if (!oldmode) 
      entry_2 |= (inn->useable << 20);

   /* Install the new entry ...  */
install:
   out->LdtEnt.Words.word1 = entry_1;
   out->LdtEnt.Words.word2 = entry_2;
}

void
Task_InstallDescInGDT(struct Task *tsk, struct LinuxSegmentDesc *descp)
{
   TaskRegs *regs = Task_GetRegs(tsk);
   VexGuestX86SegDescr* gdt;
   int nidx;

   gdt = (VexGuestX86SegDescr*)regs->guest_GDT;

   if (!gdt) {
      /* Allocate a shadow GDT on demand -- shadow GDTs, like the hardware
       * GDT, are 64KB a pop, and each thread gets one (though there is only 
       * 1 hardware GDT). The reason why each thread gets one has to do
       * with the way TLS is implemented in the kernel -- the hardware
       * GDT entry corresponding to the TLS is made thread-local.
       * So we must allocate on demand. */
      gdt = BT_AllocZeroedX86GDT();
      regs->guest_GDT = (HWord)gdt;
   }

   /* We need to keep the VEX guest state updated in case we
    * try to emulate an instruction that loads from a 
    * segment register. */
   nidx = descp->entry_number;
   ASSERT(nidx >= 0 && nidx < VEX_GUEST_X86_GDT_NENT);
   TaskShadowGDT2HardwareGDT(descp, &gdt[nidx], 0);
}

SYSCALLDEF(sys_set_thread_area, struct LinuxSegmentDesc __user *u_info)
{
   struct LinuxSegmentDesc info;
   int err = 0, oidx, nidx;

   if (Task_CopyFromUser(&info, u_info, sizeof(info))) {
      err = -EFAULT;
      goto out;
   }
   oidx = info.entry_number;

	/*
	 * index -1 means the kernel should try to find and
	 * allocate an empty descriptor:
	 */
   ASSERT(oidx >= -1);
   err = syscall(SYS_set_thread_area, &info);
   if (SYSERR(err)) {
      goto out;
   }

   nidx = info.entry_number;
   /* XXX: We reserve a TLS slot for quick access to each task's vkernel
    * task struct. But that assumes that app-code won't use that slot.
    * If they do, we need to return an appropriate error code... */
   ASSERT_UNIMPLEMENTED(nidx != VK_TLS_ENTRY_NR);

   DEBUG_MSG(5, "oidx=%d nidx=%d \n", oidx, nidx);
   if (oidx == -1) {
      if (__put_user(nidx, &u_info->entry_number)) {
         err = -EFAULT;
         goto out;
      }
   }

   Task_InstallDescInGDT(current, &info);

out:
   /* Indicates that no more TLS descriptor slots available. If this
    * happens, then we may not be cleaning up the descriptors properly
    * on an exec. */
   WARN_UNIMPLEMENTED(err != -ESRCH);
   return err;
}

SYSCALLDEF(sys_get_thread_area, struct LinuxSegmentDesc __user *u_info)
{
   /* The shadow gdt and the kernel gdt are always in sync, since 
    * user-level can't touch it without going through the kernel 
    * (i.e., without invoking set_thread_area). */

   int err, idx;
   struct LinuxSegmentDesc kinfo;

   if (Task_CopyFromUser(&kinfo, u_info, sizeof(*u_info))) {
      err = -EFAULT;
      goto out;
   }

   idx = kinfo.entry_number;

   if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX) {
      err = -EINVAL;
      goto out;
   }

   /* Should return 0 every time, if we've vetting the args properly. */
   err = syscall(SYS_get_thread_area, &kinfo);
   ASSERT(!err);

   if (Task_CopyToUser(u_info, &kinfo, sizeof(kinfo))) {
      err = -EFAULT;
      goto out;
   }

   err = 0;

out:
   return err;
}

SYSCALLDEF(sys_modify_ldt, int func, void __user *ptr, ulong bytecount)
{
   func = func;
   ptr = ptr;
   bytecount = bytecount;
   /* Similar to set_thread_area, but we need to allocate an LDT. */
   ASSERT_UNIMPLEMENTED(0);

   return -EINVAL;
}
