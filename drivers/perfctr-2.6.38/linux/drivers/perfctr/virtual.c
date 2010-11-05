/* $Id: virtual.c,v 1.88.2.25 2009/01/23 17:21:20 mikpe Exp $
 * Virtual per-process performance counters.
 *
 * Copyright (C) 1999-2009  Mikael Pettersson
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#include <linux/config.h>
#endif
#define __NO_VERSION__
#include <linux/module.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/perfctr.h>

#include <asm/io.h>
#include <asm/uaccess.h>

#include "compat.h"
#include "virtual.h"
#include "marshal.h"

/****************************************************************
 *								*
 * Data types and macros.					*
 *								*
 ****************************************************************/

#define IS_RUNNING(perfctr)	perfctr_cstatus_enabled((perfctr)->cpu_state.cstatus)

#if 0
#define DEBUG_MSG(s, ...) printk(KERN_INFO s, ##__VA_ARGS__)
#else
#define DEBUG_MSG(s, ...) 
#endif

/* XXX: disabled: called from switch_to() where printk() is disallowed */
#if 0 && defined(CONFIG_PERFCTR_DEBUG)
#define debug_free(perfctr) \
do { \
	int i; \
	for(i = 0; i < PAGE_SIZE/sizeof(int); ++i) \
		((int*)(perfctr))[i] = 0xfedac0ed; \
} while(0)
#define debug_init(perfctr)	do { (perfctr)->suspended = 1; } while(0)
#define debug_suspend(perfctr) \
do { \
	if ((perfctr)->suspended) \
		printk(KERN_ERR "%s: BUG! suspending non-running perfctr (pid %d, comm %s)\n", \
		       __FUNCTION__, current->pid, current->comm); \
	(perfctr)->suspended = 1; \
} while(0)
#define debug_resume(perfctr) \
do { \
	if (!(perfctr)->suspended) \
		printk(KERN_ERR "%s: BUG! resuming non-suspended perfctr (pid %d, comm %s)\n", \
		       __FUNCTION__, current->pid, current->comm); \
	(perfctr)->suspended = 0; \
} while(0)
#define debug_check_smp_id(perfctr) \
do { \
	if ((perfctr)->start_smp_id != smp_processor_id()) { \
		printk(KERN_ERR "%s: BUG! current cpu %u differs from start cpu %u (pid %d, comm %s)\n", \
		       __FUNCTION__, smp_processor_id(), (perfctr)->start_smp_id, \
		       current->pid, current->comm); \
		return; \
	} \
} while(0)
#define debug_set_smp_id(perfctr) \
	do { (perfctr)->start_smp_id = smp_processor_id(); } while(0)
#else	/* CONFIG_PERFCTR_DEBUG */
#define debug_free(perfctr)		do{}while(0)
#define debug_init(perfctr)		do{}while(0)
#define debug_suspend(perfctr)		do{}while(0)
#define debug_resume(perfctr)		do{}while(0)
#define debug_check_smp_id(perfctr)	do{}while(0)
#define debug_set_smp_id(perfctr)	do{}while(0)
#endif	/* CONFIG_PERFCTR_DEBUG */

#ifdef CONFIG_PERFCTR_INTERRUPT_SUPPORT

static void vperfctr_ihandler(unsigned long pc);
static void vperfctr_handle_overflow(struct task_struct*, struct vperfctr*);

static inline void vperfctr_set_ihandler(void)
{
	perfctr_cpu_set_ihandler(vperfctr_ihandler);
}

static inline void vperfctr_clear_iresume_cstatus(struct vperfctr *perfctr)
{
	perfctr->iresume_cstatus = 0;
}

#else
static inline void vperfctr_set_ihandler(void) { }
static inline void vperfctr_clear_iresume_cstatus(struct vperfctr *perfctr) { }
#endif

#ifdef CONFIG_PERFCTR_CPUS_FORBIDDEN_MASK

static inline void vperfctr_init_bad_cpus_allowed(struct vperfctr *perfctr)
{
	atomic_set(&perfctr->bad_cpus_allowed, 0);
}

/* Concurrent set_cpus_allowed() is possible. The only lock it
   can take is the task lock, so we have to take it as well.
   task_lock/unlock also disables/enables preemption. */

static inline void vperfctr_task_lock(struct task_struct *p)
{
	task_lock(p);
}

static inline void vperfctr_task_unlock(struct task_struct *p)
{
	task_unlock(p);
}

#else	/* !CONFIG_PERFCTR_CPUS_FORBIDDEN_MASK */

static inline void vperfctr_init_bad_cpus_allowed(struct vperfctr *perfctr) { }

/* Concurrent set_cpus_allowed() is impossible or irrelevant.
   Disabling and enabling preemption suffices for an atomic region. */

static inline void vperfctr_task_lock(struct task_struct *p)
{
	preempt_disable();
}

static inline void vperfctr_task_unlock(struct task_struct *p)
{
	preempt_enable();
}

#endif	/* !CONFIG_PERFCTR_CPUS_FORBIDDEN_MASK */

/* How to lock around find_task_by_vpid(). The tasklist_lock always
   works, but it's no longer exported starting with kernel 2.6.18.
   For kernels 2.6.18 and newer use rcu_read_{lock,unlock}(). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
static inline void vperfctr_lock_find_task_by_vpid(void)
{
	rcu_read_lock();
}

static inline void vperfctr_unlock_find_task_by_vpid(void)
{
	rcu_read_unlock();
}
#else	/* < 2.6.18 */
static inline void vperfctr_lock_find_task_by_vpid(void)
{
	read_lock(&tasklist_lock);
}

static inline void vperfctr_unlock_find_task_by_vpid(void)
{
	read_unlock(&tasklist_lock);
}
#endif	/* < 2.6.18 */

/****************************************************************
 *								*
 * Resource management.						*
 *								*
 ****************************************************************/

/* XXX: perhaps relax this to number of _live_ perfctrs */
static DEFINE_MUTEX(nrctrs_mutex);
static int nrctrs;
static const char this_service[] = __FILE__;

static int inc_nrctrs(void)
{
	const char *other;

	other = NULL;
	mutex_lock(&nrctrs_mutex);
	if (++nrctrs == 1) {
		other = perfctr_cpu_reserve(this_service);
		if (other)
			nrctrs = 0;
	}
	mutex_unlock(&nrctrs_mutex);
	if (other) {
		printk(KERN_ERR __FILE__
		       ": cannot operate, perfctr hardware taken by '%s'\n",
		       other);
		return -EBUSY;
	}
	vperfctr_set_ihandler();
	return 0;
}

static void dec_nrctrs(void)
{
	mutex_lock(&nrctrs_mutex);
	if (--nrctrs == 0)
		perfctr_cpu_release(this_service);
	mutex_unlock(&nrctrs_mutex);
}

static struct vperfctr *vperfctr_alloc(void)
{
	unsigned long page;

	if (inc_nrctrs() != 0)
		return ERR_PTR(-EBUSY);
	page = get_zeroed_page(GFP_KERNEL);
	if (!page) {
		dec_nrctrs();
		return ERR_PTR(-ENOMEM);
	}
	SetPageReserved(virt_to_page(page));
	return (struct vperfctr*) page;
}

static void
ctx_signal_free(struct vperfctr *perfctr)
{
   struct ctx_sigmask *m, *n;

   list_for_each_entry_safe(m, n, &perfctr->ctx_sigmask_list, list) {
      list_del_init(&m->list);
      kfree(m);
      m = NULL;
   }
}

static void vperfctr_free(struct vperfctr *perfctr)
{
	debug_free(perfctr);
	ClearPageReserved(virt_to_page(perfctr));
	free_page((unsigned long)perfctr);
	dec_nrctrs();
   ctx_signal_free(perfctr);
}

static struct vperfctr *get_empty_vperfctr(void)
{
	struct vperfctr *perfctr = vperfctr_alloc();
	if (!IS_ERR(perfctr)) {
		atomic_set(&perfctr->count, 1);
		vperfctr_init_bad_cpus_allowed(perfctr);
		spin_lock_init(&perfctr->owner_lock);
		debug_init(perfctr);
      perfctr->vkernel_start = perfctr->vkernel_end = 0;
      perfctr->emu_opt_flags = 0;
      perfctr->emu_status_flags = 0;
      /* We want it to start off at 0 when we resume user space,
       * hence we start it at -1, expecting that resume_to_userspace
       * will increment it by 1. */
      perfctr->cpu_state.intr_count = -1;

#if 0
      siginitset(&perfctr->notifier_mask, ~(sigmask(SIGKILL) | sigmask(SIGSTOP)));
#endif
      INIT_LIST_HEAD(&perfctr->ctx_sigmask_list);
      perfctr->sigmask_count = 0;
   }
	return perfctr;
}

static void put_vperfctr(struct vperfctr *perfctr)
{
	if (atomic_dec_and_test(&perfctr->count))
		vperfctr_free(perfctr);
}

/****************************************************************
 *								*
 * Basic counter operations.					*
 * These must all be called by the owner process only.		*
 * These must all be called with preemption disabled.		*
 *								*
 ****************************************************************/

/* PRE: IS_RUNNING(perfctr)
 * Suspend the counters.
 */
static inline void vperfctr_suspend(struct vperfctr *perfctr)
{
	debug_suspend(perfctr);
	debug_check_smp_id(perfctr);
	perfctr_cpu_suspend(&perfctr->cpu_state);
}

static inline void vperfctr_reset_sampling_timer(struct vperfctr *perfctr)
{
	/* XXX: base the value on perfctr_info.cpu_khz instead! */
	perfctr->sampling_timer = HZ/2;
}

/* PRE: perfctr == current->thread.perfctr && IS_RUNNING(perfctr)
 * Restart the counters.
 */
static inline void vperfctr_resume(struct vperfctr *perfctr)
{
	debug_resume(perfctr);
	perfctr_cpu_resume(&perfctr->cpu_state);
	vperfctr_reset_sampling_timer(perfctr);
	debug_set_smp_id(perfctr);
}

static inline void vperfctr_resume_with_overflow_check(struct vperfctr *perfctr)
{
#ifdef CONFIG_PERFCTR_INTERRUPT_SUPPORT
	if (perfctr_cpu_has_pending_interrupt(&perfctr->cpu_state)) {
		vperfctr_handle_overflow(current, perfctr);
		return;
	}
#endif
	vperfctr_resume(perfctr);
}

/* Sample the counters but do not suspend them. */
static void vperfctr_sample(struct vperfctr *perfctr)
{
	if (IS_RUNNING(perfctr)) {
		debug_check_smp_id(perfctr);
		perfctr_cpu_sample(&perfctr->cpu_state);
		vperfctr_reset_sampling_timer(perfctr);
	}
}

#ifdef CONFIG_PERFCTR_INTERRUPT_SUPPORT
/* vperfctr interrupt handler (XXX: add buffering support) */
/* PREEMPT note: called in IRQ context with preemption disabled. */
static void vperfctr_ihandler(unsigned long pc)
{
	struct task_struct *tsk = current;
	struct vperfctr *perfctr;

	perfctr = tsk->thread.perfctr;
	if (!perfctr) {
		printk(KERN_ERR "%s: BUG! pid %d has no vperfctr\n",
		       __FUNCTION__, tsk->pid);
		return;
	}
	if (!perfctr_cstatus_has_ictrs(perfctr->cpu_state.cstatus)) {
		printk(KERN_ERR "%s: BUG! vperfctr has cstatus %#x (pid %d, comm %s)\n",
		       __FUNCTION__, perfctr->cpu_state.cstatus, tsk->pid, tsk->comm);
		return;
	}
	vperfctr_suspend(perfctr);
	vperfctr_handle_overflow(tsk, perfctr);
}

static void vperfctr_handle_overflow(struct task_struct *tsk,
				     struct vperfctr *perfctr)
{
   unsigned int pmc_mask;
   siginfo_t si;

   pmc_mask = perfctr_cpu_identify_overflow(&perfctr->cpu_state);
   if (!pmc_mask) {
      printk(KERN_ERR "%s: BUG! pid %d has unidentifiable overflow source\n",
            __FUNCTION__, tsk->pid);
      return;
   }
   /* suspend a-mode and i-mode PMCs, leaving only TSC on */
   /* XXX: some people also want to suspend the TSC */
   perfctr->iresume_cstatus = perfctr->cpu_state.cstatus;
   if (perfctr_cstatus_has_tsc(perfctr->iresume_cstatus)) {
      if (perfctr->flags & VPERFCTR_CONTROL_NOSUSPEND_AMODE) {
         /* Disable i-mode counters, but not a-mode counters. */
#if 0
         printk(KERN_WARNING "%s: not suspending a-mode for pid %d\n", __FUNCTION__, 
               tsk->pid);
#endif
         perfctr->cpu_state.cstatus = perfctr_mk_cstatus(1, 
               perfctr_cstatus_nractrs(perfctr->cpu_state.cstatus), 0);
      } else {
         perfctr->cpu_state.cstatus = perfctr_mk_cstatus(1, 0, 0);
      }
      vperfctr_resume(perfctr);
   } else
      perfctr->cpu_state.cstatus = 0;
   si.si_signo = perfctr->si_signo;
   si.si_errno = 0;
   si.si_code = SI_PMC_OVF;
   si.si_pmc_ovf_mask = pmc_mask;

   /* Wake up the receiver right away, since we don't want
    * PMIs to be late. */
   send_sig_info(si.si_signo, &si, tsk);
}
#endif

/****************************************************************
 *								*
 * Process management operations.				*
 * These must all, with the exception of vperfctr_unlink()	*
 * and __vperfctr_set_cpus_allowed(), be called by the owner	*
 * process only.						*
 *								*
 ****************************************************************/

static inline void
__vperfctr_enable_emulation(struct vperfctr *perfctr)
{
   preempt_disable();

   /* XXX: check this flag on every call is inefficient.
    * If the vkernel wants FPU emu, then we should invoke
    * a different function for that case. */
   int wants_fpu_emu = perfctr->emu_opt_flags & VPERFCTR_EMUOPT_FPU;

   /* Disable TSC/FPU. */
   write_cr4(read_cr4() | X86_CR4_TSD);
   if (wants_fpu_emu) write_cr0(read_cr0() | X86_CR0_EM);
   perfctr->emu_status_flags |= VPERFCTR_EMUSTAT_ENABLED;

   preempt_enable();
}

static inline void
__vperfctr_disable_emulation(struct vperfctr *perfctr)
{
   preempt_disable();

   int wants_fpu_emu = perfctr->emu_opt_flags & VPERFCTR_EMUOPT_FPU;

   /* Securecomp may want TSC disabled at user-level, so
    * we must respect its wishes. */
   if (!test_tsk_thread_flag(current, TIF_NOTSC)) {
      write_cr4(read_cr4() & ~X86_CR4_TSD);
   }

   if (wants_fpu_emu) {
      //printk(KERN_EMERG "About to clear EM bit.\n");
      write_cr0(read_cr0() & ~X86_CR0_EM);
      //printk(KERN_EMERG "Cleared EM bit.\n");
   }

   perfctr->emu_status_flags &= ~VPERFCTR_EMUSTAT_ENABLED;

   preempt_enable();
}

/* Called from exit_thread() or sys_vperfctr_unlink().
 * If the counters are running, stop them and sample their final values.
 * Detach the vperfctr object from its owner task.
 * PREEMPT note: exit_thread() does not run with preemption disabled.
 */
static void vperfctr_unlink(struct task_struct *owner, struct vperfctr *perfctr)
{
   /* this synchronises with vperfctr_ioctl() */
   spin_lock(&perfctr->owner_lock);
   perfctr->owner = NULL;
   spin_unlock(&perfctr->owner_lock);

   /* perfctr suspend+detach must be atomic wrt process suspend */
   /* this also synchronises with perfctr_set_cpus_allowed() */
   vperfctr_task_lock(owner);
   if (IS_RUNNING(perfctr) && owner == current)
      vperfctr_suspend(perfctr);
   owner->thread.perfctr = NULL;
   vperfctr_task_unlock(owner);

   perfctr->cpu_state.cstatus = 0;
   vperfctr_clear_iresume_cstatus(perfctr);
   put_vperfctr(perfctr);
}

void __vperfctr_exit(struct vperfctr *perfctr)
{
   /* Disabling emulation is essential. Otherwise, the TSC and EM bits may
    * leak to non-vkernel tasks (by way of perfctr_switch_to), 
    * hence triggering BUG_ON(!perfctr) in math_emulate(). */

   /* XXX: why not do this in unlink above? */
   __vperfctr_disable_emulation(perfctr);

   vperfctr_unlink(current, perfctr);
}

/* sys_execve() -> .. -> flush_old_exec() -> .. -> __vperfctr_flush().
 * Unlink the thread's perfctr state, if the CLOEXEC control flag is set.
 * PREEMPT note: flush_old_exec() does not run with preemption disabled.
 */
void __vperfctr_flush(struct vperfctr *perfctr)
{
   if (perfctr->flags & VPERFCTR_CONTROL_CLOEXEC)
      __vperfctr_exit(perfctr);
}

static int 
vperfctr_sigprocmask(int how, sigset_t *set, sigset_t *oldset)
{
	int error;
   ulong flags;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	if (oldset)
		*oldset = current->blocked;

	error = 0;
	switch (how) {
	case SIG_BLOCK:
		sigorsets(&current->blocked, &current->blocked, set);
		break;
	case SIG_UNBLOCK:
		signandsets(&current->blocked, &current->blocked, set);
		break;
	case SIG_SETMASK:
		current->blocked = *set;
		break;
	default:
		error = -EINVAL;
	}
	recalc_sigpending();
	spin_unlock_irqrestore(&current->sighand->siglock, flags);

	return error;
}


/*
 * Calling context:
 *
 * Anytime task returns to userspace.
 *
 * Used to:
 *
 * Enable timestamp emulation on sigreturn out of the vkernel 
 * back to app-space. vkernel sets  to 1.
 *
 * Disable timestamp emulation on vkernel entrance via signal. 
 * __vperfctr_handle_signal sets emu to 0.
 *
 * Performance:
 *
 * Write CRs only on a emu status change.
 *
 */
void __vperfctr_resume_userspace(struct vperfctr *perfctr)
{
   /* vkernel uses the intr_count to check for a particular
    * race that occurs when trying to read the virtual timestamp
    * counter (see pmcops.h). 
    *
    * XXX: do we really need this? can we accomplish same task
    * using the tsc_start field, as done by the perfctr user-space lib? 
    *
    * no, but the user-space assembly is simpler as a result */
   if (IS_RUNNING(perfctr)) {
      perfctr->cpu_state.intr_count++;
   }

   if (perfctr->emu_status_flags & VPERFCTR_EMUSTAT_RESTORE_SIGMASK) {
      vperfctr_sigprocmask(SIG_SETMASK, &perfctr->saved_sigmask, NULL);
      perfctr->emu_status_flags &= ~VPERFCTR_EMUSTAT_RESTORE_SIGMASK;
   }
}

/* XXX: we'll try out best to avoid using this, so we can limit our
 * modifications to the kernel */
void __vperfctr_handle_signal(struct vperfctr *perfctr)
{
   /* Not needed now since we disable emulation only on a
    * FP/SSE/TSC trap, and leave it on otherwise, even
    * when executing in the vkernel. */
}

int next_signal(struct sigpending *pending, sigset_t *mask)
{
	unsigned long i, *s, *m, x;
	int sig = 0;
	
	s = pending->signal.sig;
	m = mask->sig;
	switch (_NSIG_WORDS) {
	default:
		for (i = 0; i < _NSIG_WORDS; ++i, ++s, ++m)
			if ((x = *s &~ *m) != 0) {
				sig = ffz(~x) + i*_NSIG_BPW + 1;
				break;
			}
		break;

	case 2: if ((x = s[0] &~ m[0]) != 0)
			sig = 1;
		else if ((x = s[1] &~ m[1]) != 0)
			sig = _NSIG_BPW + 1;
		else
			break;
		sig += ffz(~x);
		break;

	case 1: if ((x = *s &~ *m) != 0)
			sig = ffz(~x) + 1;
		break;
	}
	
	return sig;
}

static int
vperfctr_ctxmaskinfo_find(struct ctx_maskinfo *info, const struct vperfctr *perfctr, 
                          const ulong ip)
{
   struct ctx_sigmask *m = NULL;

	list_for_each_entry(m, &perfctr->ctx_sigmask_list, list) {
		if (m->info.start_ip <= ip && ip < m->info.end_ip) {
         *info = m->info;
         return 1;
      }
   }

   return 0;
}

#if 0
static int
vperfctr_signal_notifier(void *priv)
{
   struct vperfctr *perfctr = (struct vperfctr *) priv;
   struct pt_regs *regs = task_pt_regs(current);
   ulong ip = instruction_pointer(regs);
   struct ctx_sigmask *m = NULL;
	int sig;

   BUG_ON(!perfctr);

   sig = next_signal(&current->pending, &current->blocked);
   if (!sig) {
      sig = next_signal(&current->signal->shared_pending, &current->blocked);
   }

   BUG_ON(!sig);

   DEBUG_MSG("vperfctr: got sig %d, ip 0x%lx\n", sig, ip);

	list_for_each_entry(m, &perfctr->ctx_sigmask_list, list) {
		if (m->info.start_ip <= ip && ip < m->info.end_ip) {
         if (sigismember((sigset_t*)&m->info.mask, sig)) {
            /* Block the signal. */
#if 1
            DEBUG_MSG("vperfctr:  blocked in [0x%lx:0x%lx]\n", 
                  m->info.start_ip, m->info.end_ip);
#endif
            return 0;
         }

         return 1;
		}
	}

   return 1;
}
#endif

static inline void 
vperfctr_notify_userspace(struct vperfctr *perfctr, int code)
{
   siginfo_t info;

   info.si_signo = perfctr->si_signo;
   info.si_errno = 0;
   info.si_code = code;
   info.si_addr = 0;

   send_sig_info(info.si_signo, &info, current);
}

/*
 * Return 0 to let kernel execute the syscall, 1 to indicate
 * that kernel shouldn't execute syscall (i.e., vkernel will emulate
 * it).
 */
int __vperfctr_handle_sysemu(struct vperfctr *perfctr)
{
   struct pt_regs *regs = task_pt_regs(current);
   ulong pc = instruction_pointer(regs);

   if (!perfctr->vkernel_start) {
      return 0;
   } else if (__perfctr_is_in_vkernel(perfctr, pc)) {
      struct ctx_maskinfo ctxinfo;
      sigset_t *ctxmask = (sigset_t *) ctxinfo.mask;


      /* Execute the syscall as though the ctx-sensitive mask
       * is in effect. */
      if (vperfctr_ctxmaskinfo_find(&ctxinfo, perfctr, pc)) {
         DEBUG_MSG("call from vkernel ip 0x%x\n", pc);
         DEBUG_MSG("found ctxmask start_ip 0x%x end_ip 0x%x\n",
               ctxinfo.start_ip, ctxinfo.end_ip);

         vperfctr_sigprocmask(SIG_SETMASK, ctxmask, &perfctr->saved_sigmask);
         perfctr->emu_status_flags |= VPERFCTR_EMUSTAT_RESTORE_SIGMASK;
      }

      return 0;
   } else {
      DEBUG_MSG("perfctr syscall emulation ax %d ip 0x%x\n", regs->ax, pc);

      vperfctr_notify_userspace(perfctr, SI_PERF_SYSEMU);
      return 1;
   }
}

/*
 * When CR4's TSD bit is enabled, then timestamp counter instructions
 * will generate a general protection (#GP) exception. We catch that
 * here and send the vkernel a signal so it can emulate the TSC
 * call.
 */
int __vperfctr_handle_tscemu(struct vperfctr *perfctr)
{
   /* To be consistent with the fpu trap behavior. */
   __vperfctr_disable_emulation(perfctr);

   vperfctr_notify_userspace(perfctr, SI_PERF_TSCEMU);

   return 1;
}

/*
 * When CR0's EM bit is enabled, any FP instructions will generate
 * a #NM exception. We catch it and notify the vkernel via a
 * signal. 
 */
int __vperfctr_handle_fpuemu(struct vperfctr *perfctr)
{
   /* Disable EM bit, or we'll recurse when kernel invokes
    * an FPU/MMX insn on signal delivery path. See BUG #20. */
   __vperfctr_disable_emulation(perfctr);

   //printk(KERN_EMERG "Disabled FPU emulation.\n");

   vperfctr_notify_userspace(perfctr, SI_PERF_FPUEMU);

   return 1;
}

/* schedule() --> switch_to() --> .. --> __vperfctr_suspend().
 * If the counters are running, suspend them.
 * PREEMPT note: switch_to() runs with preemption disabled.
 */
void __vperfctr_suspend(struct vperfctr *perfctr)
{
   if (IS_RUNNING(perfctr))
      vperfctr_suspend(perfctr);
}

/* schedule() --> switch_to() --> .. --> __vperfctr_resume().
 * PRE: perfctr == current->thread.perfctr
 * If the counters are runnable, resume them.
 * PREEMPT note: switch_to() runs with preemption disabled.
 */
void __vperfctr_resume(struct vperfctr *perfctr)
{
	if (IS_RUNNING(perfctr)) {
#ifdef CONFIG_PERFCTR_CPUS_FORBIDDEN_MASK
		if (unlikely(atomic_read(&perfctr->bad_cpus_allowed)) &&
		    perfctr_cstatus_nrctrs(perfctr->cpu_state.cstatus)) {
			perfctr->cpu_state.cstatus = 0;
			vperfctr_clear_iresume_cstatus(perfctr);
			BUG_ON(current->state != TASK_RUNNING);
			send_sig(SIGILL, current, 1);
			return;
		}
#endif
		vperfctr_resume_with_overflow_check(perfctr);
	}
}

/* Called from update_one_process() [triggered by timer interrupt].
 * PRE: perfctr == current->thread.perfctr.
 * Sample the counters but do not suspend them.
 * Needed to avoid precision loss due to multiple counter
 * wraparounds between resume/suspend for CPU-bound processes.
 * PREEMPT note: called in IRQ context with preemption disabled.
 */
void __vperfctr_sample(struct vperfctr *perfctr)
{
	if (--perfctr->sampling_timer == 0)
		vperfctr_sample(perfctr);
}

#ifdef CONFIG_PERFCTR_CPUS_FORBIDDEN_MASK
/* Called from set_cpus_allowed().
 * PRE: current holds task_lock(owner)
 * PRE: owner->thread.perfctr == perfctr
 */
void __vperfctr_set_cpus_allowed(struct task_struct *owner,
				 struct vperfctr *perfctr,
				 cpumask_t new_mask)
{
	cpumask_t tmp;

	cpus_and(tmp, new_mask, perfctr_cpus_forbidden_mask);
	if (!cpus_empty(tmp)) {
		atomic_set(&perfctr->bad_cpus_allowed, 1);
		printk(KERN_WARNING "perfctr: process %d (comm %s) issued unsafe"
		       " set_cpus_allowed() on process %d (comm %s)\n",
		       current->pid, current->comm, owner->pid, owner->comm);
	} else
		atomic_set(&perfctr->bad_cpus_allowed, 0);
}
#endif

/****************************************************************
 *								*
 * Virtual perfctr "system calls".				*
 * These can be called by the owner process (tsk == current),	*
 * a monitor process which has the owner under ptrace ATTACH	*
 * control (tsk && tsk != current), or anyone with a handle to	*
 * an unlinked perfctr (!tsk).					*
 *								*
 ****************************************************************/

static int sys_vperfctr_control(struct vperfctr *perfctr,
				struct perfctr_struct_buf *argp,
				struct task_struct *tsk)
{
	struct vperfctr_control control;
	int err;
	unsigned int next_cstatus;
	unsigned int nrctrs, i;

	if (!tsk)
		return -ESRCH;	/* attempt to update unlinked perfctr */

	err = perfctr_copy_from_user(&control, argp, &vperfctr_control_sdesc);
	if (err)
		return err;

	if (control.cpu_control.nractrs || control.cpu_control.nrictrs) {
		cpumask_t old_mask, new_mask;

		old_mask = tsk->cpus_allowed;
		cpus_andnot(new_mask, old_mask, perfctr_cpus_forbidden_mask);

		if (cpus_empty(new_mask))
			return -EINVAL;
		if (!cpus_equal(new_mask, old_mask))
			set_cpus_allowed(tsk, new_mask);
	}

	/* PREEMPT note: preemption is disabled over the entire
	   region since we're updating an active perfctr. */
	preempt_disable();
	if (IS_RUNNING(perfctr)) {
		if (tsk == current)
			vperfctr_suspend(perfctr);
		perfctr->cpu_state.cstatus = 0;
		vperfctr_clear_iresume_cstatus(perfctr);
	}
	perfctr->cpu_state.control = control.cpu_control;
	/* remote access note: perfctr_cpu_update_control() is ok */
	err = perfctr_cpu_update_control(&perfctr->cpu_state, 0);
	if (err < 0)
		goto out;
	next_cstatus = perfctr->cpu_state.cstatus;
	if (!perfctr_cstatus_enabled(next_cstatus))
		goto out;

	/* XXX: validate si_signo? */
	perfctr->si_signo = control.si_signo;

	if (!perfctr_cstatus_has_tsc(next_cstatus))
		perfctr->cpu_state.tsc_sum = 0;

	nrctrs = perfctr_cstatus_nrctrs(next_cstatus);
	for(i = 0; i < nrctrs; ++i)
		if (!(control.preserve & (1<<i)))
			perfctr->cpu_state.pmc[i].sum = 0;

	perfctr->flags = control.flags;

	if (tsk == current)
		vperfctr_resume(perfctr);

 out:
	preempt_enable();
	return err;
}

/* Starts I-mode counter 1. Called from assembly by vkernel
 * to enable PMI notification at next event. */
static int sys_vperfctr_start_ictr_1(struct vperfctr *perfctr,
      uint pmiTarget, struct task_struct *tsk)
{
   int err;
   unsigned int next_cstatus;
   if (!tsk) {
      err = -ESRCH;
      goto out;	/* attempt to update unlinked perfctr */
   }

   /* perfctr_cpu_update_control will disable all counters
    * if pmiTarget is invalid, so validate pmiTarget before
    * we call it. */
   if (!pmiTarget) {
      err = -EINVAL;
      goto out;
   }

   /* PREEMPT note: preemption is disabled over the entire
      region since we're updating an active perfctr. */
   preempt_disable();
   if (IS_RUNNING(perfctr)) {
      if (tsk == current)
         vperfctr_suspend(perfctr);
      //perfctr->cpu_state.cstatus = 0;
      vperfctr_clear_iresume_cstatus(perfctr);
   }

   perfctr->cpu_state.control.nrictrs = 1;
   /* 
    * The PMI is generated when the counter overflows. Hence
    * assign the counter the negated branch count eta.
    */
   perfctr->cpu_state.control.ireset[1] = -((int) pmiTarget);

   /* remote access note: perfctr_cpu_update_control() is ok */
   err = perfctr_cpu_update_control(&perfctr->cpu_state, 0);
   if (err < 0)
      goto out_preempt;

   next_cstatus = perfctr->cpu_state.cstatus;
   if (!perfctr_cstatus_enabled(next_cstatus)) {
      /* If this happens, then all the counters are disabled.
       * Check that counters are setup with correct parameters. */
      /*printk(KERN_ERR "%s: should be enabled: next_cstatus=%d\n",
            __FUNCTION__, next_cstatus);*/
      goto out_preempt;
   }

   if (tsk == current)
      vperfctr_resume(perfctr);

out_preempt:
   preempt_enable();
out:
   if (err) {
      printk(KERN_ERR "%s: err=%d pmiTarget=%d\n",
            __FUNCTION__, err, pmiTarget);
   }
   return err;
}

static int sys_vperfctr_iresume(struct vperfctr *perfctr, 
      const struct task_struct *tsk)
{
#ifdef CONFIG_PERFCTR_INTERRUPT_SUPPORT
	unsigned int iresume_cstatus;

	if (!tsk)
		return -ESRCH;	/* attempt to update unlinked perfctr */

	iresume_cstatus = perfctr->iresume_cstatus;
	if (!perfctr_cstatus_has_ictrs(iresume_cstatus))
		return -EPERM;

	/* PREEMPT note: preemption is disabled over the entire
	   region because we're updating an active perfctr. */
	preempt_disable();

	if (IS_RUNNING(perfctr) && tsk == current)
		vperfctr_suspend(perfctr);

	perfctr->cpu_state.cstatus = iresume_cstatus;
	perfctr->iresume_cstatus = 0;

	/* remote access note: perfctr_cpu_ireload() is ok */
	perfctr_cpu_ireload(&perfctr->cpu_state);

	if (tsk == current)
		vperfctr_resume(perfctr);

	preempt_enable();

	return 0;
#else
	return -ENOSYS;
#endif
}

static int sys_vperfctr_unlink(struct vperfctr *perfctr, struct task_struct *tsk)
{
	if (tsk)
		vperfctr_unlink(tsk, perfctr);
	return 0;
}

static int sys_vperfctr_read_sum(struct vperfctr *perfctr,
				 struct perfctr_struct_buf *argp,
				 const struct task_struct *tsk)
{
	struct perfctr_sum_ctrs sum;

	if (tsk == current) {
		preempt_disable();
		vperfctr_sample(perfctr);
	}
	//sum = perfctr->cpu_state.sum;
	{
		int j;
		sum.tsc = perfctr->cpu_state.tsc_sum;
		for(j = 0; j < ARRAY_SIZE(sum.pmc); ++j)
			sum.pmc[j] = perfctr->cpu_state.pmc[j].sum;
	}
	if (tsk == current)
		preempt_enable();
	return perfctr_copy_to_user(argp, &sum, &perfctr_sum_ctrs_sdesc);
}

static int sys_vperfctr_read_control(struct vperfctr *perfctr,
				     struct perfctr_struct_buf *argp,
				     const struct task_struct *tsk)
{
	struct vperfctr_control control;

	/* PREEMPT note: While we're reading our own control, another
	   process may ptrace ATTACH to us and update our control.
	   Disable preemption to ensure we get a consistent copy.
	   Not needed for other cases since the perfctr is either
	   unlinked or its owner is ptrace ATTACH suspended by us. */
	if (tsk == current)
		preempt_disable();
	control.si_signo = perfctr->si_signo;
	control.cpu_control = perfctr->cpu_state.control;
	control.flags = perfctr->flags;
	if (tsk == current)
		preempt_enable();
	control.preserve = 0;
	return perfctr_copy_to_user(argp, &control, &vperfctr_control_sdesc);
}

static int
sys_vperfctr_emu(struct vperfctr *perfctr, int enable,
                 const struct task_struct *tsk)
{
   if (enable) {
      __vperfctr_enable_emulation(perfctr);
   } else {
      __vperfctr_disable_emulation(perfctr);
   }

   return 0;
}

static int 
sys_vperfctr_emu_setup(struct vperfctr *perfctr, 
                   struct perfctr_emu_setup_struct __user *argp,
                   const struct task_struct *tsk)
{
   int err = 0;
   struct perfctr_emu_setup_struct ks;

   if (copy_from_user(&ks, argp, sizeof(ks))) {
      err = -EFAULT;
      goto out;
   }

   if (ks.vkernel_start && ks.vkernel_end) {
      if (ks.vkernel_end <= ks.vkernel_start) {
         err = -EINVAL;
         goto out;
      }
   }


   perfctr->vkernel_start = ks.vkernel_start;
   perfctr->vkernel_end = ks.vkernel_end;
   perfctr->emu_opt_flags = ks.flags;

   err = sys_vperfctr_emu(perfctr, 1, tsk);

out:
   return err;
}


/* 
 * Summary:
 *
 *    Permits blocking of signals based on task's user-mode ip value
 *    at time of signal delivery. 
 */
static int
sys_ctx_sigprocmask(struct vperfctr *perfctr, 
                   struct ctx_maskinfo __user *argp)
{
   int err = 0;
   struct ctx_maskinfo ks;
   struct ctx_sigmask *m;

   if (perfctr->sigmask_count >= 4) {
      err = -EINVAL;
      goto out;
   }

   if (copy_from_user(&ks, argp, sizeof(ks))) {
      err = -EFAULT;
      goto out;
   }

   m = kmalloc(sizeof(*m), GFP_KERNEL);
   if (unlikely(!m)) {
      err = -ENOMEM;
      goto out;
   } else {
      if (!(ks.start_ip && ks.end_ip && ks.start_ip < ks.end_ip)) {
         err = -EINVAL;
         goto out;
      } 

      INIT_LIST_HEAD(&m->list);
      m->info = ks;
   }

   list_add_tail(&m->list, &perfctr->ctx_sigmask_list);

#if 0
   if (!perfctr->sigmask_count) {
      block_all_signals(&vperfctr_signal_notifier, perfctr, &perfctr->notifier_mask);
   }
#endif

   perfctr->sigmask_count++;

out:
   return err;
}

/****************************************************************
 *								*
 * Virtual perfctr file operations.				*
 *								*
 ****************************************************************/

static int vperfctr_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct vperfctr *perfctr;

#ifdef CONFIG_ARM
#define _PAGE_RW	L_PTE_WRITE
#endif
	/* Only allow read-only mapping of first page. */
	if ((vma->vm_end - vma->vm_start) != PAGE_SIZE ||
	    vma->vm_pgoff != 0)
		return -EPERM;
	perfctr = filp->private_data;
	if (!perfctr)
		return -EPERM;
	/* 2.6.29-rc1 changed arch/x86/mm/pat.c to WARN_ON when
	   remap_pfn_range() is applied to plain RAM pages.
	   Comments there indicate that one should set_memory_wc()
	   before the remap, but that doesn't silence the WARN_ON.
	   Luckily vm_insert_page() works without complaints. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
	return vm_insert_page(vma, vma->vm_start, virt_to_page((unsigned long)perfctr));
#else
	return remap_pfn_range(vma, vma->vm_start,
			       virt_to_phys(perfctr) >> PAGE_SHIFT,
			       PAGE_SIZE, vma->vm_page_prot);
#endif
}

static int vperfctr_release(struct inode *inode, struct file *filp)
{
	struct vperfctr *perfctr = filp->private_data;
	filp->private_data = NULL;
	if (perfctr)
		put_vperfctr(perfctr);
	return 0;
}

static long vperfctr_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct vperfctr *perfctr;
	struct task_struct *tsk;
	int ret;

	switch (cmd) {
	case PERFCTR_ABI:
		return sys_perfctr_abi((unsigned int*)arg);
	case PERFCTR_INFO:
		return sys_perfctr_info((struct perfctr_struct_buf*)arg);
	case PERFCTR_CPUS:
		return sys_perfctr_cpus((struct perfctr_cpu_mask*)arg);
	case PERFCTR_CPUS_FORBIDDEN:
		return sys_perfctr_cpus_forbidden((struct perfctr_cpu_mask*)arg);
	}
	perfctr = filp->private_data;
	if (!perfctr)
		return -EINVAL;
	tsk = current;
	if (perfctr != current->thread.perfctr) {
		/* this synchronises with vperfctr_unlink() and itself */
		spin_lock(&perfctr->owner_lock);
		tsk = perfctr->owner;
		if (tsk)
			get_task_struct(tsk);
		spin_unlock(&perfctr->owner_lock);
		if (tsk) {
			ret = ptrace_check_attach(tsk, 0);
			if (ret < 0)
				goto out;
		}
	}
	switch (cmd) {
   case VPERFCTR_CTX_SIGPROCMASK:
      ret = sys_ctx_sigprocmask(perfctr, (struct ctx_maskinfo __user *) arg);
      break;
   case VPERFCTR_EMU_SETUP:
      ret = sys_vperfctr_emu_setup(perfctr, 
            (struct perfctr_emu_setup_struct __user *)arg, tsk);
      break;
   case VPERFCTR_EMU_ENABLE:
      ret = sys_vperfctr_emu(perfctr, 1, tsk);
      break;
   case VPERFCTR_EMU_DISABLE:
      ret = sys_vperfctr_emu(perfctr, 0, tsk);
      break;
	case VPERFCTR_CONTROL:
		ret = sys_vperfctr_control(perfctr, (struct perfctr_struct_buf*)arg, tsk);
      break;
   case VPERFCTR_START_ICTR_1:
      ret = sys_vperfctr_start_ictr_1(perfctr, (uint) arg, tsk);
      break;
   case VPERFCTR_UNLINK:
      /* XXX: we shouldn't allow others to unlink the page -- for example,
       * we need to disable emulation when that happens and it could get
       * tricky. */
		ret = sys_vperfctr_unlink(perfctr, tsk);
		break;
	case VPERFCTR_READ_SUM:
		ret = sys_vperfctr_read_sum(perfctr, (struct perfctr_struct_buf*)arg, tsk);
		break;
	case VPERFCTR_IRESUME:
		ret = sys_vperfctr_iresume(perfctr, tsk);
		break;
	case VPERFCTR_READ_CONTROL:
		ret = sys_vperfctr_read_control(perfctr, (struct perfctr_struct_buf*)arg, tsk);
		break;
	default:
		ret = -EINVAL;
	}
 out:
	if (tsk && tsk != current)
		put_task_struct(tsk);
	return ret;
}

#if !HAVE_UNLOCKED_IOCTL
static int vperfctr_ioctl_oldstyle(struct inode *inode, struct file *filp,
				   unsigned int cmd, unsigned long arg)
{
	return vperfctr_ioctl(filp, cmd, arg);
}
#endif

static
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
const
#endif
struct file_operations vperfctr_file_ops = {
	.owner = THIS_MODULE,
	.mmap = vperfctr_mmap,
	.release = vperfctr_release,
	/* 2.6.11-rc2 introduced HAVE_UNLOCKED_IOCTL and HAVE_COMPAT_IOCTL */
#if HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl = vperfctr_ioctl,
#else
	.ioctl = vperfctr_ioctl_oldstyle,
#endif
#if defined(CONFIG_IA32_EMULATION) && HAVE_COMPAT_IOCTL
	.compat_ioctl = vperfctr_ioctl,
#endif
};

/****************************************************************
 *								*
 * File system for virtual perfctrs. Based on pipefs.		*
 *								*
 ****************************************************************/

#define VPERFCTRFS_MAGIC (('V'<<24)|('P'<<16)|('M'<<8)|('C'))

#include <linux/mount.h>

/* 2.6 kernels prior to 2.6.11-rc1 don't EXPORT_SYMBOL() get_sb_pseudo().
   This is a verbatim copy, only renamed. */
#if defined(MODULE) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
static
struct super_block *
perfctr_get_sb_pseudo(struct file_system_type *fs_type, char *name,
	struct super_operations *ops, unsigned long magic)
{
	struct super_block *s = sget(fs_type, NULL, set_anon_super, NULL);
	static struct super_operations default_ops = {.statfs = simple_statfs};
	struct dentry *dentry;
	struct inode *root;
	struct qstr d_name = {.name = name, .len = strlen(name)};

	if (IS_ERR(s))
		return s;

	s->s_flags = MS_NOUSER;
	s->s_maxbytes = ~0ULL;
	s->s_blocksize = 1024;
	s->s_blocksize_bits = 10;
	s->s_magic = magic;
	s->s_op = ops ? ops : &default_ops;
	root = new_inode(s);
	if (!root)
		goto Enomem;
	root->i_mode = S_IFDIR | S_IRUSR | S_IWUSR;
	root->i_uid = root->i_gid = 0;
	root->i_atime = root->i_mtime = root->i_ctime = CURRENT_TIME;
	dentry = d_alloc(NULL, &d_name);
	if (!dentry) {
		iput(root);
		goto Enomem;
	}
	dentry->d_sb = s;
	dentry->d_parent = dentry;
	d_instantiate(dentry, root);
	s->s_root = dentry;
	s->s_flags |= MS_ACTIVE;
	return s;

Enomem:
	up_write(&s->s_umount);
	deactivate_super(s);
	return ERR_PTR(-ENOMEM);
}
#undef get_sb_pseudo
#define get_sb_pseudo perfctr_get_sb_pseudo
#endif	/* MODULE && VERSION < 2.6.11 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
static int
vperfctrfs_get_sb(struct file_system_type *fs_type,
		  int flags, const char *dev_name, void *data,
		  struct vfsmount *mnt)
{
	return get_sb_pseudo(fs_type, "vperfctr:", NULL, VPERFCTRFS_MAGIC, mnt);
}
#else
static struct super_block *
vperfctrfs_get_sb(struct file_system_type *fs_type,
		  int flags, const char *dev_name, void *data)
{
	return get_sb_pseudo(fs_type, "vperfctr:", NULL, VPERFCTRFS_MAGIC);
}
#endif

static struct file_system_type vperfctrfs_type = {
	.name		= "vperfctrfs",
	.get_sb		= vperfctrfs_get_sb,
	.kill_sb	= kill_anon_super,
};

/* XXX: check if s/vperfctr_mnt/vperfctrfs_type.kern_mnt/ would work */
static struct vfsmount *vperfctr_mnt;

static int __init vperfctrfs_init(void)
{
	int err = register_filesystem(&vperfctrfs_type);
	if (!err) {
		vperfctr_mnt = kern_mount(&vperfctrfs_type);
		if (!IS_ERR(vperfctr_mnt))
			return 0;
		err = PTR_ERR(vperfctr_mnt);
		unregister_filesystem(&vperfctrfs_type);
	}
	return err;
}

static void __exit vperfctrfs_exit(void)
{
	unregister_filesystem(&vperfctrfs_type);
	mntput(vperfctr_mnt);
}

static struct inode *vperfctr_get_inode(void)
{
	struct inode *inode;

	inode = new_inode(vperfctr_mnt->mnt_sb);
	if (!inode)
		return NULL;
	inode->i_fop = &vperfctr_file_ops;
	inode->i_state = I_DIRTY;
	inode->i_mode = S_IFCHR | S_IRUSR | S_IWUSR;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19) && !defined(DONT_HAVE_i_blksize)
	inode->i_blksize = 0;
#endif
	return inode;
}

static int vperfctrfs_delete_dentry(struct dentry *dentry)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
	/*
	 * At creation time, we pretended this dentry was hashed
	 * (by clearing DCACHE_UNHASHED bit in d_flags)
	 * At delete time, we restore the truth : not hashed.
	 * (so that dput() can proceed correctly)
	 */
	dentry->d_flags |= DCACHE_UNHASHED;
	return 0;
#else
	return 1;
#endif
}

static struct dentry_operations vperfctrfs_dentry_operations = {
	.d_delete	= vperfctrfs_delete_dentry,
};

static struct dentry *vperfctr_d_alloc_root(struct inode *inode)
{
	struct qstr this;
	char name[32];
	struct dentry *dentry;

	sprintf(name, "[%lu]", inode->i_ino);
	this.name = name;
	this.len = strlen(name);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
	this.hash = 0;
#else
	this.hash = inode->i_ino; /* will go */
#endif
	dentry = d_alloc(vperfctr_mnt->mnt_sb->s_root, &this);
	if (dentry) {
		dentry->d_op = &vperfctrfs_dentry_operations;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
		/*
		 * We dont want to publish this dentry into global dentry hash table.
		 * We pretend dentry is already hashed, by unsetting DCACHE_UNHASHED
		 * This permits a working /proc/$pid/fd/XXX on vperfctrs
		 */
		dentry->d_flags &= ~DCACHE_UNHASHED;
		d_instantiate(dentry, inode);
#else
		d_add(dentry, inode);
#endif
	}
	return dentry;
}

static struct file *vperfctr_get_filp(void)
{
	struct file *filp;
	struct inode *inode;
	struct dentry *dentry;

	inode = vperfctr_get_inode();
	if (!inode)
		goto out;
	dentry = vperfctr_d_alloc_root(inode);
	if (!dentry)
		goto out_inode;
	/*
	 * Create the filp _after_ the inode and dentry, to avoid
	 * needing access to put_filp(), which is no longer exported
	 * starting with kernel 2.6.10-rc1. fput() is available but
	 * doesn't work on incomplete files. We now need access to
	 * dput() instead, but that's Ok.
	 */
	filp = get_empty_filp();
	if (!filp)
		goto out_dentry;

	filp_vfsmnt(filp) = mntget(vperfctr_mnt);
	filp_dentry(filp) = dentry;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,2)
	filp->f_mapping = dentry->d_inode->i_mapping;
#endif

	filp->f_pos = 0;
	filp->f_flags = 0;
	filp->f_op = fops_get(&vperfctr_file_ops); /* fops_get() for MODULE */
	filp->f_mode = FMODE_READ | FMODE_WRITE;
	filp->f_version = 0;

	return filp;

 out_dentry:
	dput(dentry);
	goto out; /* dput() also does iput() */
 out_inode:
	iput(inode);
 out:
	return NULL;
}

/* tid is the actual task/thread id (née pid, stored as ->pid),
   pid/tgid is that 2.6 thread group id crap (stored as ->tgid) */
int vperfctr_attach(int tid, int creat)
{
	struct file *filp;
	struct task_struct *tsk;
	struct vperfctr *perfctr;
	int err;
	int fd;

	filp = vperfctr_get_filp();
	if (!filp)
		return -ENOMEM;
	err = fd = get_unused_fd();
	if (err < 0)
		goto err_filp;
	perfctr = NULL;
	if (creat) {
		perfctr = get_empty_vperfctr(); /* may sleep */
		if (IS_ERR(perfctr)) {
			err = PTR_ERR(perfctr);
			goto err_fd;
		}
	}
	tsk = current;
	if (tid != 0 && tid != task_pid_vnr(tsk)) { /* remote? */
		vperfctr_lock_find_task_by_vpid();
		tsk = find_task_by_vpid(tid);
		if (tsk)
			get_task_struct(tsk);
		vperfctr_unlock_find_task_by_vpid();
		err = -ESRCH;
		if (!tsk)
			goto err_perfctr;
		err = ptrace_check_attach(tsk, 0);
		if (err < 0)
			goto err_tsk;
	}
	if (creat) {
		/* check+install must be atomic to prevent remote-control races */
		vperfctr_task_lock(tsk);
		if (!tsk->thread.perfctr) {
			perfctr->owner = tsk;
			tsk->thread.perfctr = perfctr;
			err = 0;
		} else
			err = -EEXIST;
		vperfctr_task_unlock(tsk);
		if (err)
			goto err_tsk;
	} else {
		perfctr = tsk->thread.perfctr;
		/* PERFCTR_ABI and PERFCTR_INFO don't need the perfctr.
		   Hence no non-NULL check here. */
	}
	filp->private_data = perfctr;
	if (perfctr)
		atomic_inc(&perfctr->count);
	if (tsk != current)
		put_task_struct(tsk);
	fd_install(fd, filp);
	return fd;
 err_tsk:
	if (tsk != current)
		put_task_struct(tsk);
 err_perfctr:
	if (perfctr)	/* can only occur if creat != 0 */
		put_vperfctr(perfctr);
 err_fd:
	put_unused_fd(fd);
 err_filp:
	fput(filp);
	return err;
}

/****************************************************************
 *								*
 * module_init/exit						*
 *								*
 ****************************************************************/

#ifdef MODULE
static struct vperfctr_stub off;

static void vperfctr_stub_init(void)
{
	off = vperfctr_stub;
	vperfctr_stub.owner = THIS_MODULE;
	vperfctr_stub.exit = __vperfctr_exit;
	vperfctr_stub.flush = __vperfctr_flush;
	vperfctr_stub.suspend = __vperfctr_suspend;
	vperfctr_stub.resume = __vperfctr_resume;
	vperfctr_stub.sample = __vperfctr_sample;
#ifdef CONFIG_PERFCTR_CPUS_FORBIDDEN_MASK
	vperfctr_stub.set_cpus_allowed = __vperfctr_set_cpus_allowed;
#endif
   vperfctr_stub.resume_userspace = __vperfctr_resume_userspace;
   vperfctr_stub.handle_signal = __vperfctr_handle_signal;
   vperfctr_stub.handle_sysemu = __vperfctr_handle_sysemu;
   vperfctr_stub.handle_tscemu = __vperfctr_handle_tscemu;
   vperfctr_stub.handle_fpuemu = __vperfctr_handle_fpuemu;
}

static void vperfctr_stub_exit(void)
{
	vperfctr_stub = off;
}
#else
static inline void vperfctr_stub_init(void) { }
static inline void vperfctr_stub_exit(void) { }
#endif	/* MODULE */

#include <asm/ucontext.h>
struct sigframe
{
	char __user *pretcode;
	int sig;
	struct sigcontext sc;
	struct _fpstate fpstate;
	unsigned long extramask[_NSIG_WORDS-1];
	char retcode[8];
};

struct rt_sigframe
{
	char __user *pretcode;
	int sig;
	struct siginfo __user *pinfo;
	void __user *puc;
	struct siginfo info;
	struct ucontext uc;
	struct _fpstate fpstate;
	char retcode[8];
};

int __init vperfctr_init(void)
{
	int err = vperfctrfs_init();
	if (err)
		return err;
	vperfctr_stub_init();

   printk("Size of various kernel structs:\n");
   printk("struct rt_sigframe: %d\n"
         "struct sigframe   : %d\n"
         "struct siginfo    : %d\n"
         "struct ucontext   : %d\n"
         "struct sigcontext : %d\n"
         "struct _fpstate   : %d\n"
         "stack_t           : %d\n"
         "sigset_t          : %d\n",
         sizeof(struct rt_sigframe),
         sizeof(struct sigframe),
         sizeof(struct siginfo),
         sizeof(struct ucontext),
         sizeof(struct sigcontext),
         sizeof(struct _fpstate),
         sizeof(stack_t),
         sizeof(sigset_t)
         );
   return 0;
}

void __exit vperfctr_exit(void)
{
	vperfctrfs_exit();
	vperfctr_stub_exit();
}
