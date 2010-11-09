/* $Id: perfctr.h,v 1.69.2.6 2009/01/23 17:31:57 mikpe Exp $
 * Performance-Monitoring Counters driver
 *
 * Copyright (C) 1999-2009  Mikael Pettersson
 */
#ifndef _LINUX_PERFCTR_H
#define _LINUX_PERFCTR_H

#ifdef CONFIG_KPERFCTR	/* don't break archs without <asm/perfctr.h> */

#include <asm/perfctr.h>

struct perfctr_info {
	unsigned int abi_version;
	char driver_version[32];
	unsigned int cpu_type;
	unsigned int cpu_features;
	unsigned int cpu_khz;
	unsigned int tsc_to_cpu_mult;
	unsigned int _reserved2;
	unsigned int _reserved3;
	unsigned int _reserved4;
};

struct perfctr_cpu_mask {
	unsigned int nrwords;
	unsigned int mask[1];	/* actually 'nrwords' */
};

/* abi_version values: Lower 16 bits contain the CPU data version, upper
   16 bits contain the API version. Each half has a major version in its
   upper 8 bits, and a minor version in its lower 8 bits. */
#define PERFCTR_API_VERSION	0x0502	/* 5.2 */
#define PERFCTR_ABI_VERSION	((PERFCTR_API_VERSION<<16)|PERFCTR_CPU_VERSION)

/* cpu_features flag bits */
#define PERFCTR_FEATURE_RDPMC	0x01
#define PERFCTR_FEATURE_RDTSC	0x02
#define PERFCTR_FEATURE_PCINT	0x04

/* user's view of mmap:ed virtual perfctr */
struct vperfctr_state {
   /* Any vkernel-visible vars must come first -- 
    * sizeof(struct perfctr_cpu_state) differs in kernel/user mode, so you
    * shouldn't place these vars after it. */

	struct perfctr_cpu_state cpu_state;
};

/* parameter in VPERFCTR_CONTROL command */
struct vperfctr_control {
	int si_signo;
	struct perfctr_cpu_control cpu_control;
	unsigned int preserve;
	unsigned int flags;
	unsigned int _reserved2;
	unsigned int _reserved3;
	unsigned int _reserved4;
};

/* vperfctr_control flags bits */
#define VPERFCTR_CONTROL_CLOEXEC	0x01	/* close (unlink) state before exec */
/* If set, don't suspend amode counters on PMI. */
#define VPERFCTR_CONTROL_NOSUSPEND_AMODE	0x2

/* Emulation options. */
#define VPERFCTR_EMUOPT_FPU           0x1
/* Emulation status. */
#define VPERFCTR_EMUSTAT_ENABLED          0x1
#define VPERFCTR_EMUSTAT_RESTORE_SIGMASK   0x2

/* parameter in GPERFCTR_CONTROL command */
struct gperfctr_cpu_control {
	unsigned int cpu;
	struct perfctr_cpu_control cpu_control;
	unsigned int _reserved1;
	unsigned int _reserved2;
	unsigned int _reserved3;
	unsigned int _reserved4;
};

/* returned by GPERFCTR_READ command */
struct gperfctr_cpu_state {
	unsigned int cpu;
	struct perfctr_cpu_control cpu_control;
	struct perfctr_sum_ctrs sum;
	unsigned int _reserved1;
	unsigned int _reserved2;
	unsigned int _reserved3;
	unsigned int _reserved4;
};

/* buffer for encodings of most of the above structs */
struct perfctr_struct_buf {
	unsigned int rdsize;
	unsigned int wrsize;
	unsigned int buffer[1]; /* actually 'max(rdsize,wrsize)' */
};

struct perfctr_emu_setup_struct {
   unsigned long vkernel_start, vkernel_end;
   unsigned int flags;
};

struct ctx_maskinfo {
   unsigned long start_ip, end_ip;
#ifdef __KERNEL
#if __NSIG_WORDS > 2
#error "You need to incrase the mask size below."
#endif
#endif
   unsigned long mask[2];
};

//#include <linux/ioctl.h>
#define _PERFCTR_IOCTL	0xD0	/* 'P'+128, currently unassigned */

#define PERFCTR_ABI		 _IOR(_PERFCTR_IOCTL,0,unsigned int)
#define PERFCTR_INFO		 _IOR(_PERFCTR_IOCTL,1,struct perfctr_struct_buf)
#define PERFCTR_CPUS		_IOWR(_PERFCTR_IOCTL,2,struct perfctr_cpu_mask)
#define PERFCTR_CPUS_FORBIDDEN	_IOWR(_PERFCTR_IOCTL,3,struct perfctr_cpu_mask)
#define VPERFCTR_CREAT		  _IO(_PERFCTR_IOCTL,6)/*int tid*/
#define VPERFCTR_OPEN		  _IO(_PERFCTR_IOCTL,7)/*int tid*/

#define VPERFCTR_READ_SUM	 _IOR(_PERFCTR_IOCTL,8,struct perfctr_struct_buf)
#define VPERFCTR_UNLINK		  _IO(_PERFCTR_IOCTL,9)
#define VPERFCTR_CONTROL	 _IOW(_PERFCTR_IOCTL,10,struct perfctr_struct_buf)
#define VPERFCTR_IRESUME	  _IO(_PERFCTR_IOCTL,11)
#define VPERFCTR_READ_CONTROL	 _IOR(_PERFCTR_IOCTL,12,struct perfctr_struct_buf)
#define VPERFCTR_START_ICTR_1	  _IO(_PERFCTR_IOCTL,13)

#define GPERFCTR_CONTROL	_IOWR(_PERFCTR_IOCTL,16,struct perfctr_struct_buf)
#define GPERFCTR_READ		_IOWR(_PERFCTR_IOCTL,17,struct perfctr_struct_buf)
#define GPERFCTR_STOP		  _IO(_PERFCTR_IOCTL,18)
#define GPERFCTR_START		  _IO(_PERFCTR_IOCTL,19)/*unsigned int*/

#define VPERFCTR_EMU_SETUP	  _IOR(_PERFCTR_IOCTL,20,struct perfctr_emu_setup_struct)
#define VPERFCTR_EMU_ENABLE	  _IO(_PERFCTR_IOCTL,21)
#define VPERFCTR_EMU_DISABLE	  _IO(_PERFCTR_IOCTL,22)
#define VPERFCTR_CTX_SIGPROCMASK _IOR(_PERFCTR_IOCTL,23,struct ctx_maskinfo)

#ifdef __KERNEL__
extern struct perfctr_info perfctr_info;
extern int sys_perfctr_abi(unsigned int*);
extern int sys_perfctr_info(struct perfctr_struct_buf*);
extern int sys_perfctr_cpus(struct perfctr_cpu_mask*);
extern int sys_perfctr_cpus_forbidden(struct perfctr_cpu_mask*);
#endif	/* __KERNEL__ */

#endif	/* CONFIG_KPERFCTR */

#ifdef __KERNEL__

#ifdef CONFIG_PERFCTR_VIRTUAL

struct ctx_sigmask {
   struct ctx_maskinfo info;

   struct list_head list;
};

/*
 * Virtual per-process performance-monitoring counters.
 */

/* The first page of this struct is mmapped into the user-visible
 * perfctr page. */
struct vperfctr {
   /* User-visible fields: (must be first for mmap()) */
   struct perfctr_cpu_state cpu_state;


   /* Kernel-private fields: */
   int si_signo;
   atomic_t count;
   spinlock_t owner_lock;
	struct task_struct *owner;
	/* sampling_timer and bad_cpus_allowed are frequently
	   accessed, so they get to share a cache line */
	unsigned int sampling_timer ____cacheline_aligned;
#ifdef CONFIG_PERFCTR_CPUS_FORBIDDEN_MASK
	atomic_t bad_cpus_allowed;
#endif
#if 0 && defined(CONFIG_PERFCTR_DEBUG)
	unsigned start_smp_id;
	unsigned suspended;
#endif
#ifdef CONFIG_PERFCTR_INTERRUPT_SUPPORT
	unsigned int iresume_cstatus;
#endif
	unsigned int flags;
   /* We want to be able to change emulation options while remembering
    * the emulation status (enabled or disabled). Hence two variables. */
   unsigned int emu_opt_flags, emu_status_flags;
   ulong vkernel_start, vkernel_end;

   /* Context-sensitive signal support. */
#if 0
   sigset_t notifier_mask;
#endif
   sigset_t saved_sigmask;
   struct list_head ctx_sigmask_list;
   int sigmask_count;
};

/* process management operations */
extern void __vperfctr_exit(struct vperfctr*);
extern void __vperfctr_flush(struct vperfctr*);
extern void __vperfctr_suspend(struct vperfctr*);
extern void __vperfctr_resume(struct vperfctr*);
extern void __vperfctr_sample(struct vperfctr*);
extern void __vperfctr_set_cpus_allowed(struct task_struct*, struct vperfctr*, cpumask_t);
extern void __vperfctr_resume_userspace(struct vperfctr*);
extern void __vperfctr_handle_signal(struct vperfctr*);
extern int  __vperfctr_handle_sysemu(struct vperfctr*);
extern int  __vperfctr_handle_tscemu(struct vperfctr*);
extern int  __vperfctr_handle_fpuemu(struct vperfctr*);

#ifdef CONFIG_PERFCTR_MODULE
extern struct vperfctr_stub {
	struct module *owner;
	void (*exit)(struct vperfctr*);
	void (*flush)(struct vperfctr*);
	void (*suspend)(struct vperfctr*);
	void (*resume)(struct vperfctr*);
	void (*sample)(struct vperfctr*);
#ifdef CONFIG_PERFCTR_CPUS_FORBIDDEN_MASK
	void (*set_cpus_allowed)(struct task_struct*, struct vperfctr*, cpumask_t);
#endif
   void (*resume_userspace)(struct vperfctr*);
	void (*handle_signal)(struct vperfctr*);
   int (*handle_sysemu)(struct vperfctr*);
   int (*handle_tscemu)(struct vperfctr*);
   int (*handle_fpuemu)(struct vperfctr*);
} vperfctr_stub;
extern void _vperfctr_exit(struct vperfctr*);
extern void _vperfctr_flush(struct vperfctr*);
#define _vperfctr_suspend(x)	vperfctr_stub.suspend((x))
#define _vperfctr_resume(x)	vperfctr_stub.resume((x))
#define _vperfctr_sample(x)	vperfctr_stub.sample((x))
#define _vperfctr_set_cpus_allowed(x,y,z) (*vperfctr_stub.set_cpus_allowed)((x),(y),(z))
#define _vperfctr_resume_userspace(x) vperfctr_stub.resume_userspace((x))
#define _vperfctr_handle_signal(x) vperfctr_stub.handle_signal((x))
#define _vperfctr_handle_sysemu(x) vperfctr_stub.handle_sysemu((x))
#define _vperfctr_handle_tscemu(x) vperfctr_stub.handle_tscemu((x))
#define _vperfctr_handle_fpuemu(x) vperfctr_stub.handle_fpuemu((x))
#else	/* !CONFIG_PERFCTR_MODULE */
#define _vperfctr_exit(x)	__vperfctr_exit((x))
#define _vperfctr_flush(x)	__vperfctr_flush((x))
#define _vperfctr_suspend(x)	__vperfctr_suspend((x))
#define _vperfctr_resume(x)	__vperfctr_resume((x))
#define _vperfctr_sample(x)	__vperfctr_sample((x))
#define _vperfctr_set_cpus_allowed(x,y,z) __vperfctr_set_cpus_allowed((x),(y),(z))
#define _vperfctr_resume_userspace(x) __vperfctr_resume_userspace((x))
#define _vperfctr_handle_signal(x) __vperfctr_handle_signal((x))
#define _vperfctr_handle_sysemu(x) __vperfctr_handle_sysemu((x))
#define _vperfctr_handle_tscemu(x) __vperfctr_handle_tscemu((x))
#define _vperfctr_handle_fpuemu(x) __vperfctr_handle_fpuemu((x))
#endif	/* CONFIG_PERFCTR_MODULE */

static inline void perfctr_copy_task(struct task_struct *tsk, struct pt_regs *regs)
{
	tsk->thread.perfctr = NULL; /* inheritance is not yet implemented */
}

static inline void perfctr_release_task(struct task_struct *tsk)
{
	/* nothing to do until inheritance is implemented */
}

static inline void perfctr_exit_thread(struct thread_struct *thread)
{
	struct vperfctr *perfctr;
	perfctr = thread->perfctr;
	if (perfctr)
		_vperfctr_exit(perfctr);
}

static inline void perfctr_flush_thread(struct thread_struct *thread)
{
	struct vperfctr *perfctr;
	perfctr = thread->perfctr;
	if (perfctr)
		_vperfctr_flush(perfctr);
}

static inline void perfctr_suspend_thread(struct thread_struct *prev)
{
	struct vperfctr *perfctr;
	perfctr = prev->perfctr;
	if (perfctr)
		_vperfctr_suspend(perfctr);
}

static inline int
has_tsc_disabled(struct task_struct *tsk)
{
   struct vperfctr *perfctr = tsk->thread.perfctr;

   return (perfctr && (perfctr->emu_status_flags & VPERFCTR_EMUSTAT_ENABLED)) ||
      /* Careful: securecomp may want the TSC disabled at user-level
       * as well. We need to respect its wishes to be broadly
       * compatible. */
      test_tsk_thread_flag(tsk, TIF_NOTSC);
}

static inline int
has_fp_disabled(struct task_struct *tsk)
{
   struct vperfctr *perfctr = tsk->thread.perfctr;

   /* CAREFUL: 1 doesn't mean that fp is disabled, just
    * that vkernel has requested that it be disabled.
    * Won't be disabled until kernel acks is by incrementing
    * it to 2. */
   return (perfctr && (perfctr->emu_status_flags & VPERFCTR_EMUSTAT_ENABLED) &&
         (perfctr->emu_opt_flags & VPERFCTR_EMUOPT_FPU));
}

/*
 * This function selects if the context switch from prev to next
 * has to tweak the TSC disable bit in the cr4.
 *
 * XXX: does this conflict with use of TIF_NOTSC flag for
 * securecomp?
 */
static inline void disable_tsc(struct task_struct *prev_p,
			       struct task_struct *next_p)
{
	if (has_tsc_disabled(prev_p) ^ has_tsc_disabled(next_p)) {
      if (has_tsc_disabled(next_p)) {
			write_cr4(read_cr4() | X86_CR4_TSD);
      } else {
			write_cr4(read_cr4() & ~X86_CR4_TSD);
      }
   }
}

/*
 * This function selects if the context switch from prev to next
 * has to tweak the EMU (Floating Point disable) bit in cr0. 
 * vkernel needs it to emulate FP ops.
 */
static inline void disable_fp(struct task_struct *prev_p,
			       struct task_struct *next_p)
{
	if (has_fp_disabled(prev_p) ^ has_fp_disabled(next_p)) {
		/* slow path here */
      if (has_fp_disabled(next_p)) {
			write_cr0(read_cr0() | X86_CR0_EM);
      } else {
			write_cr0(read_cr0() & ~X86_CR0_EM);
      }
	}
}

static inline void perfctr_switch_to(struct task_struct *prev_p, 
      struct task_struct *next_p)
{
	struct thread_struct *next = &next_p->thread;
	struct vperfctr *perfctr = next->perfctr;

   disable_tsc(prev_p, next_p);
   disable_fp(prev_p, next_p);

	if (perfctr)
		_vperfctr_resume(perfctr);
}

static inline void perfctr_sample_thread(struct thread_struct *thread)
{
	struct vperfctr *perfctr;
	perfctr = thread->perfctr;
	if (perfctr)
		_vperfctr_sample(perfctr);
}

static inline void perfctr_set_cpus_allowed(struct task_struct *p, cpumask_t new_mask)
{
#ifdef CONFIG_PERFCTR_CPUS_FORBIDDEN_MASK
	struct vperfctr *perfctr;

	task_lock(p);
	perfctr = p->thread.perfctr;
	if (perfctr)
		_vperfctr_set_cpus_allowed(p, perfctr, new_mask);
	task_unlock(p);
#endif
}

static inline void perfctr_handle_signal()
{
   struct vperfctr *perfctr = current->thread.perfctr;

   if (perfctr) {
      _vperfctr_handle_signal(perfctr);
   }
}

static inline void perfctr_sigprocmask(int how, sigset_t *set)
{
   int error;

   sigdelsetmask(set, sigmask(SIGKILL)|sigmask(SIGSTOP));

   error = sigprocmask(how, set, NULL);

   BUG_ON(error);
}

static inline int __perfctr_is_in_vkernel(struct vperfctr *perfctr, ulong pc)
                                       
{
   unsigned long start = perfctr->vkernel_start, end = perfctr->vkernel_end;
   return (start <= pc && pc < end);
}

static inline void perfctr_do_signal_hook(struct pt_regs *regs)
{
   struct vperfctr *perfctr = current->thread.perfctr;

   if (perfctr && __perfctr_is_in_vkernel(perfctr, instruction_pointer(regs))) {
      printk(KERN_INFO "do_signal() while in vkernel.\n");
#if 0
      if (in_drainage) {
         perfctr_sigprocmask(perfctr->drainage_blockset);
      } else {
         perfctr_sigprocmask(perfctr->blockset);
      }
#endif
   }
}

static inline int perfctr_tsc_emu()
{
	struct vperfctr *perfctr = current->thread.perfctr;

   return (perfctr && _vperfctr_handle_tscemu(perfctr));
}



#else	/* !CONFIG_PERFCTR_VIRTUAL */

static inline void perfctr_copy_task(struct task_struct *p, struct pt_regs *r) { }
static inline void perfctr_release_task(struct task_struct *p) { }
static inline void perfctr_exit_thread(struct thread_struct *t) { }
static inline void perfctr_flush_thread(struct thread_struct *t) { }
static inline void perfctr_suspend_thread(struct thread_struct *t) { }
static inline void perfctr_resume_thread(struct thread_struct *t) { }
static inline void perfctr_sample_thread(struct thread_struct *t) { }
static inline void perfctr_set_cpus_allowed(struct task_struct *p, cpumask_t m) { }

#endif	/* CONFIG_PERFCTR_VIRTUAL */

#endif	/* __KERNEL__ */

#endif	/* _LINUX_PERFCTR_H */
