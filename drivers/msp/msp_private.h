#ifndef _MSP_H
#define _MSP_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/init.h>
#include <linux/stringify.h>
#include <linux/wait.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/msp.h>


/* Helper macros to deal with page tables and addresses. pte_pfn is already 
 * defined in the kernel. */
#define pgd_flags(x)	(pgd_val(x) & ~PAGE_MASK)
#define pgd_pfn(x)	(pgd_val(x) >> PAGE_SHIFT)
#define pmd_pfn(x)  ((pmd_val((x)) & __PHYSICAL_MASK) >> PAGE_SHIFT)
#define fn_to_addr(x) ((x) << PAGE_SHIFT)
#define addr_to_fn(x) ((x) >> PAGE_SHIFT)
#define is_page_aligned(x) (!((x) & ~PAGE_MASK))
#define pte_user(x) (pte_flags(x) & _PAGE_USER)

/*H:035 Using memory-copy operations like that is usually inconvient, so we
 * have the following helper macros which read and write a specific type (often
 * an unsigned long).
 *
 * This reads into a variable of the given type then returns that. */
#define lgread(addr, type)						\
	({ type _v; memcpy(&_v, (void*)(addr), sizeof(_v)); _v; })

/* This checks that the variable is of the given type, then writes it out. */
#define lgwrite(addr, type, val)				\
	do {							\
		typecheck(type, val);				\
		memcpy((void*)(addr), &(val), sizeof(val));	\
	} while(0)
/* (end of memory access helper routines) :*/

struct pgdir
{
	unsigned long gpgdir;
   pgd_t *pgdir;

   bool is_kernel_mapped;
};

#define NR_SHADOW_PGD 4

#define NR_MAX_EVENTS 256
struct msp_cpu
{
   unsigned int id;
   struct shadow *sh;

	int cpu_pgd; /* which pgd this cpu is currently using */
   unsigned long guest_cr3; 

   struct pgdir pgdirs[NR_SHADOW_PGD];

   int event_head, event_tail, event_count;
   msp_event_t events[NR_MAX_EVENTS];
   spinlock_t event_lock;
   wait_queue_head_t read_waitqueue;
   struct fasync_struct *fasync;
};

#define NR_BUCKET_BITS  12
#define NR_BUCKETS (1 << NR_BUCKET_BITS)

#define ENABLE_IPT_CODE 1
#define IPT_ENABLE_ALL 1 /* Maintain IPT for whole system? */

struct ipt_entry {
   unsigned long pfn;      /* Physical frame #. */

   unsigned long gpgdir;   /* Physical address of guest pgdir. */
   unsigned long vfn;      /* Virtual frame #. */

   struct hlist_node by_pfn;
   struct hlist_node by_gpgdir_and_vfn;
   struct hlist_node by_gpgdir;
};

/* The inverted page table (IPT): a mapping from physical pages to
 * virtual pages. We need this to perform CREW invalidations efficiently.
 * Without it, we would have to scan all shadow pagetable on each
 * invalidation. */
struct ipt_struct
{
#if IPT_ENABLE_ALL
   struct hlist_head pfn_map[NR_BUCKETS];
   struct hlist_head gpv_map[NR_BUCKETS];
   struct hlist_head gp_map[NR_BUCKETS];
#else
   struct hlist_head *pfn_map;
   struct hlist_head *gpv_map;
   struct hlist_head *gp_map;
#endif
   unsigned long nr_iptes;
};

void
ipt_set_pte(unsigned long gpgdir, unsigned long vaddr, pte_t gpte);

void
ipt_set_pmd(unsigned long gpgdir, unsigned long start_vaddr, pmd_t new_gpmd);

void
ipt_pgd_free(unsigned long gpgdir);

int
ipt_init(void);

extern struct ipt_struct ipt;

struct shadow
{
   int is_initialized;
   struct msp_cpu cpus[NR_CPUS];
   unsigned int nr_cpus;
   unsigned int nr_guests;


   /* CREW clock: provides a total ordering of CREW
    * upgrade/downgrade events. */
   uint64_t clock;

   /* The so called shadow lock. This protects many things:
    *    - all shadow pagetables (i.e., spts)
    *    - CREW event counts
    *    - inverted page table (ipt)
    *    - XXX: potentially other stuff
    *
    * It also ensures atomicity of:
    *    - CREW upgrade/downgrade events (i.e., events of a previous CREW
    *    transaction are queued before events that come after).
    */
   spinlock_t lock;
};


extern struct msp_config_struct msp_config;

void guest_set_pmd(struct msp_cpu *cpu, unsigned long gpgdir, u32 i);
void guest_pagetable_clear_all(struct msp_cpu *cpu, bool repin);
void guest_pagetable_flush_user(struct msp_cpu *cpu);
void guest_free_pagetable(struct msp_cpu *cpu, unsigned long gpgdir);
void guest_set_pte(struct msp_cpu *cpu, unsigned long gpgdir,
		   unsigned long vaddr, pte_t val);
int guest_page_fault(struct msp_cpu *cpu, unsigned long cr2, int errcode);


void  msp_switch_to(unsigned long pgdir);
int   MSP_find_guest(unsigned long gpgdir);

void  msp_queue_event(msp_event_t event, struct msp_cpu *cpu);


int   msp_fasync_helper(int fd, struct file * filp, int on, 
         struct fasync_struct **fapp);
int   msp_kill_fasync(struct fasync_struct **fp, int sig, int band);
void  msp_fasync_init(void);

extern struct shadow msp_state;

static inline struct msp_cpu *
my_msp_state(void)
{
   return (&(msp_state.cpus[smp_processor_id()]));
}
#define curr_sh (my_msp_state())



void
paravirt_init(void);

#define shadow_lock()                 spin_lock(&msp_state.lock)
#define shadow_unlock()               spin_unlock(&msp_state.lock)
#define shadow_lock_irqsave(flags)    spin_lock_irqsave(&msp_state.lock, flags)
#define shadow_unlock_irqrestore(flags) spin_unlock_irqrestore(&msp_state.lock, flags)
#define shadow_is_locked()            spin_is_locked(&msp_state.lock)


#define kill_guest(cpu, fmt...)					\
do {								\
	   kasprintf(GFP_ATOMIC, fmt);	\
      BUG(); \
} while(0)

#define ASSERT(x)							\
	if (!(x)) {							\
		printk(KERN_EMERG "assertion failed %s:%d: %s\n",	\
		       __FILE__, __LINE__, #x);				\
      BUG(); \
	}

#define ASSERT_UNIMPLEMENTED(x)							\
	if (!(x)) {							\
		printk(KERN_EMERG "assert unimplemented failed %s:%d: %s\n",	\
		       __FILE__, __LINE__, #x);				\
      BUG(); \
	}

#define DEBUG_MSG(fmt, ...) \
do { \
   printk(KERN_DEBUG "msp [%d:%s]: " fmt, current->pid, current->comm, ##__VA_ARGS__); \
} while (0)

#define DEBUG_MSG_LIMIT(fmt, ...) \
   if (printk_ratelimit()) { \
      DEBUG_MSG(fmt, ##__VA_ARGS__); \
   }

#define STATIC static noinline
#define STATIC_INLINE static inline

#endif	/* __ASSEMBLY__ */
#endif	/* _MSP_H */
