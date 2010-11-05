#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <linux/signal.h>
#include <asm/pgtable.h>

#include "msp.h"
#include "msp_private.h"

struct msp_file {
   unsigned long gpgdir;
   struct msp_cpu *cpu;
};

#if 0
struct guest {
   unsigned long gpgdir;
};

#define MAX_NR_GUESTS 10
struct guest guest_array[MAX_NR_GUESTS];
DEFINE_SPINLOCK(guest_lock);

struct msp_config_struct msp_config = {
   .signo = MSP_DEFAULT_SIG,
   .vkernel_start = 0, .vkernel_len = 0,
};


STATIC int
msp_find_guest(unsigned long gpgdir)
{
   int i, res = -1;

   ASSERT(is_page_aligned(gpgdir));

   for (i = 0; i < ARRAY_SIZE(guest_array); i++) {
      if (guest_array[i].gpgdir == gpgdir) {
         res = i;
         goto out;
      }
   }

out:
   return res;
}

int
MSP_find_guest(unsigned long gpgdir) 
{
   int res;
   unsigned long flags;

   ASSERT(is_page_aligned(gpgdir));

   /* XXX: why disable IRQs here? */
   spin_lock_irqsave(&guest_lock, flags);
   res = msp_find_guest(gpgdir);
   spin_unlock_irqrestore(&guest_lock, flags);

   return res;
}


STATIC void
register_guest(unsigned long gpgdir)
{
   int i;
   unsigned long flags;
   spin_lock_irqsave(&guest_lock, flags);

   DEBUG_MSG("Registering guest pgdir 0x%lx\n", gpgdir);
   ASSERT(gpgdir);
   ASSERT(is_page_aligned(gpgdir));

   i = msp_find_guest(gpgdir);
   if (i != -1) {
      /* Already registered. */
      goto out;
   }

   i = msp_find_guest(0);
   if (i != -1) {
      guest_array[i].gpgdir = gpgdir;
      if (msp_state.nr_guests == 0) {
         int j;
         for (j = 0; j < NR_CPUS; j++) {
            struct msp_cpu *cpu = &msp_state.cpus[j];
            init_waitqueue_head(&cpu->read_waitqueue);
            spin_lock_init(&cpu->event_lock);
            cpu->event_head = cpu->event_tail = cpu->event_count = 0;
            memset(cpu->events, 0, sizeof(cpu->events));
         }
      }
      msp_state.nr_guests++;
   } else {
      ASSERT_UNIMPLEMENTED(0);
   }

out:
   spin_unlock_irqrestore(&guest_lock, flags);
}

STATIC void
deregister_guest(unsigned long gpgdir)
{
   int i;
   unsigned long flags;
   spin_lock_irqsave(&guest_lock, flags);

   ASSERT(gpgdir);
   ASSERT(is_page_aligned(gpgdir));

   i = msp_find_guest(gpgdir);
   if (i != -1) {
      guest_array[i].gpgdir = 0;
      msp_state.nr_guests--;
   }
   spin_unlock_irqrestore(&guest_lock, flags);
}
#endif

STATIC int
msp_open(struct inode *inode, struct file *file)
{
   struct msp_file *data = kmalloc(sizeof(*data), GFP_KERNEL);
   if (!data) {
      return -ENOMEM;
   }

   ASSERT(current->mm->pgd);
   data->gpgdir = __pa(current->mm->pgd);
   data->cpu = curr_sh;

   DEBUG_MSG("task [%d:%s:%d] enabling gpgdir (0x%lx)\n", 
         smp_processor_id(), current->comm, current->pid, data->gpgdir);

   /* We'll need to restore the guest pgdir on close, so save it. */
   file->private_data = (void*) data;

   return 0;
}


STATIC int
msp_fasync(int fd, struct file *filp, int on)
{
   int err;
   struct msp_file *data = (struct msp_file*) filp->private_data;
   ASSERT(data);
   ASSERT(data->cpu);

	err = msp_fasync_helper(fd, filp, on, &data->cpu->fasync);

   return err;
}

STATIC void
cpu_on_release(void *arg)
{
   unsigned long gpgdir = (unsigned long) arg;

   ASSERT(in_irq() && irqs_disabled() && !preemptible());

   DEBUG_MSG("cleanup for gpgdir 0x%lx, current pgdir 0x%lx\n", gpgdir,
         native_read_cr3());
   /* If the CPU isn't shadowing gpgdir, then we have nothing to do. */
   if (curr_sh->guest_cr3 == gpgdir) {
      /* Switch back to the guest pgdir. */
      msp_switch_to(gpgdir);
      ASSERT(native_read_cr3() == gpgdir);
   }
   /* Now we are no longer shadowing the guest, so free up the slot. */
   guest_free_pagetable(curr_sh, gpgdir);
}

STATIC int
msp_release(struct inode *inode, struct file *file)
{
   struct msp_file *data = (struct msp_file*) file->private_data;

   ASSERT(data);
   ASSERT(data->gpgdir);

   /* Remove file from fasync list: this appears to be done by __fput,
    * but it doesn't hurt to do it in case that isn't the only path to
    * the VFS release call. */
   msp_fasync(-1, file, 0);

   DEBUG_MSG("disabling for task [%s:%d], gpgdir (0x%lx)\n", 
         current->comm, current->pid, data->gpgdir);
#if 0
   /* Deregister the current pgdir. */
   deregister_guest(data->gpgdir);
#else
   /* Deactivate (but do not deallocate) spts. */
   shadow_lock_irq();
   remove_gpgdir_from_cpus(data->gpgdir);
   shadow_unlock_irq();
#endif

   /* Make all CPUs switch to the real pagetable, hence ensuring that no
    * one is using the spts. */
   on_each_cpu(cpu_on_release, (void*)data->gpgdir,  1 /* wait */);

   /* Now it's safe to deallocate the spts. */
   deallocate_inactive_list();

   kfree(data);
   file->private_data = NULL;

   return 0;
}

STATIC void
cpu_on_start(void *arg)
{
   unsigned long gpgdir = (unsigned long) arg;
   /* Other CPUs may or may not be using gpgdir, but if they are we want
    * them to switch to the shadow right away. If they aren't, then they
    * will use the shadow when they finally switch to it. */
   if (native_read_cr3() == gpgdir) {
      /* Now switch to the shadow pgdir. */
      msp_switch_to(gpgdir);
   }
}

STATIC long
register_guest(unsigned long gpgdir)
{
   shadow_lock_irq();
   for_each_cpu() {
      spt_add_entry(cpu, gpgdir);
   }
   shadow_unlock_irq();
}


STATIC long
msp_ioctl_start(const struct file *filp)
{
   int err = 0;
   struct msp_file *data = (struct msp_file*) filp->private_data;

   /* Add gpgdir on all CPUs. */
   register_guest(data->gpgdir);

   /* Make all CPUs switch to the shadow pagetable, if they are currently
    * running a task that uses gpgdir. */
   on_each_cpu(cpu_on_start, (void*)data->gpgdir,  1 /* wait */);

   return err;
}

STATIC long
msp_ioctl_setup(struct msp_config_struct __user * uptr)
{
   int err = 0;
   struct msp_config_struct kc;

   if (copy_from_user(&kc, uptr, sizeof(kc))) {
      err = -EFAULT;
      goto out;
   }

   if (kc.signo) {
      if (!valid_signal(kc.signo)) {
         err = -EINVAL;
         goto out;
      }
   }

   if (kc.vkernel_len) {
      if (kc.vkernel_len & ~PAGE_MASK) {
         err = -EINVAL;
         goto out;
      }
      if (kc.vkernel_start + kc.vkernel_len > PAGE_OFFSET) {
         err = -EINVAL;
         goto out;
      }
   }
   msp_config = kc;
out:
   return err;
}

STATIC long
msp_ioctl_smp_id(void)
{
   return smp_processor_id();
}

STATIC long
msp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
   int err = 0;


   switch (cmd) {
   case MSP_IOCTL_SETUP:
      return msp_ioctl_setup((struct msp_config_struct __user *) arg);
   case MSP_IOCTL_START:
      return msp_ioctl_start(filp);
   case MSP_IOCTL_SMP_ID:
      return msp_ioctl_smp_id();
   default:
      err = -EINVAL;
      break;
   }

   return err;
}

#if !HAVE_UNLOCKED_IOCTL
STATIC int
msp_ioctl_oldstyle(struct inode *inode, struct file *filp, unsigned int cmd,
      unsigned long arg)
{
   return msp_ioctl(filp, cmd, arg);
}
#endif

STATIC int 
msp_queue_empty(struct msp_cpu *cpu)
{
	return cpu->event_count == 0;
}

STATIC int
msp_get_queued_event(struct msp_cpu *cpu, msp_event_t *event)
{
   int nr_dequeued = 0;
   unsigned long flags;

   shadow_lock_irqsave(flags);

   if (cpu->event_count > 0) {
	   *event = cpu->events[cpu->event_head];
      cpu->event_head = (cpu->event_head+1) % NR_MAX_EVENTS;
      cpu->event_count--;
      nr_dequeued = 1;
   } 

   shadow_unlock_irqrestore(flags);

   return nr_dequeued;
}

void
msp_queue_event(msp_event_t event, struct msp_cpu *cpu)
{
   ASSERT(shadow_is_locked());

   if (cpu->event_count < NR_MAX_EVENTS) {
      cpu->events[cpu->event_tail] = event;
      cpu->event_tail = (cpu->event_tail+1) % NR_MAX_EVENTS;
      cpu->event_count++;
   } else {
      if (printk_ratelimit()) {
         pr_crit("shpt: dropped event [0x%x:0x%lx:%lu:%d:%llu], event_count=%d\n",
               event.kind, event.vaddr, event.pfn, smp_processor_id(), 
               event.timestamp, cpu->event_count);
      }
   }
   /* These functions try to acquire the waiting task's task-locks, which
    * can lead to deadlock with the shadow lock. So do this outside of
    * the shadow lock. */
   //wake_up_interruptible(&cpu->read_waitqueue);
	//kill_fasync(&cpu->fasync, SIGIO, POLL_IN);
}

STATIC ssize_t
msp_read(struct file *fp, char __user *buf, size_t count, loff_t *ppos)
{
   size_t n;
   msp_event_t event;
   struct msp_cpu *cpu = curr_sh;

   if (count < sizeof(event) || (count % sizeof(event)) != 0) {
      return -EINVAL;
   }
   if ((msp_queue_empty(cpu)) && (fp->f_flags & O_NONBLOCK)) {
      return -EAGAIN;
   }

   /* We wait only if condition is false. */
   wait_event_interruptible(cpu->read_waitqueue, !msp_queue_empty(cpu));

   /* XXX: Could someone else dequeue the events before we get the
    * chance? */
   n = count;
   while (n >= sizeof(event) && msp_get_queued_event(cpu, &event)) {
      if (copy_to_user(buf, &event, sizeof(event))) {
         if (n < count) {
            break;
         }
         return -EFAULT;
      }
      buf += sizeof(event);
      n -= sizeof(event);
   }
   if (n < count) {
      return count - n;
   }
   if (signal_pending(current)) {
      return -ERESTARTSYS;
   }
   return 0;
}

/*
 * Setup VFS callbacks. */

static struct file_operations msp_fops = {
	.owner	 = THIS_MODULE,
	.release =  msp_release,
   .open =     msp_open,
	/* 2.6.11-rc2 introduced HAVE_UNLOCKED_IOCTL and HAVE_COMPAT_IOCTL */
#if HAVE_UNLOCKED_IOCTL
   .unlocked_ioctl = msp_ioctl,
#else
   .ioctl = msp_ioctl_oldstyle,
#endif
#if defined(CONFIG_IA32_EMULATION) && HAVE_COMPAT_IOCTL
   .compat_ioctl = msp_ioctl,
#endif
   .read = msp_read,
   .fasync = msp_fasync,
};

/* This is a textbook example of a "misc" character device.  Populate a "struct
 * miscdevice" and register it with misc_register(). */
static struct miscdevice msp_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= MSP_DEVICE_NAME,
	.fops	= &msp_fops,
};

int __init 
msp_device_init(void)
{
#if !IPT_ENABLE_ALL
   int err;
   if ((err = ipt_init())) {
      pr_err("failed to initialize IPT tables\n");
      return err;
   }
#endif

   msp_fasync_init();

	return misc_register(&msp_dev);
}

void __exit 
msp_device_remove(void)
{
   /* XXX: what cleanup must we do? */

	misc_deregister(&msp_dev);
}

device_initcall(msp_device_init);
