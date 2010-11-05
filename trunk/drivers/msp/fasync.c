#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/signal.h>
#include <linux/security.h>
#include <asm/pgtable.h>

#include "msp.h"
#include "msp_private.h"


static DEFINE_RWLOCK(fasync_lock);
static struct kmem_cache *fasync_cache __read_mostly;

/*
 * fasync_helper() is used by some character device drivers (mainly mice)
 * to set up the fasync queue. It returns negative on error, 0 if it did
 * no changes and positive if it added/deleted the entry.
 */
int 
msp_fasync_helper(int fd, struct file * filp, int on, 
      struct fasync_struct **fapp)
{
	struct fasync_struct *fa, **fp;
	struct fasync_struct *new = NULL;
	int result = 0;

	if (on) {
		new = kmem_cache_alloc(fasync_cache, GFP_KERNEL);
		if (!new)
			return -ENOMEM;
	}
	write_lock_irq(&fasync_lock);
	for (fp = fapp; (fa = *fp) != NULL; fp = &fa->fa_next) {
		if (fa->fa_file == filp) {
			if(on) {
				fa->fa_fd = fd;
				kmem_cache_free(fasync_cache, new);
			} else {
				*fp = fa->fa_next;
				kmem_cache_free(fasync_cache, fa);
				result = 1;
			}
			goto out;
		}
	}

	if (on) {
		new->magic = FASYNC_MAGIC;
		new->fa_file = filp;
		new->fa_fd = fd;
		new->fa_next = *fapp;
		*fapp = new;
		result = 1;
	}
out:
	write_unlock_irq(&fasync_lock);
	return result;
}

/* Table to convert sigio signal codes into poll band bitmaps */

static const long band_table[NSIGPOLL] = {
	POLLIN | POLLRDNORM,			/* POLL_IN */
	POLLOUT | POLLWRNORM | POLLWRBAND,	/* POLL_OUT */
	POLLIN | POLLRDNORM | POLLMSG,		/* POLL_MSG */
	POLLERR,				/* POLL_ERR */
	POLLPRI | POLLRDBAND,			/* POLL_PRI */
	POLLHUP | POLLERR			/* POLL_HUP */
};

STATIC_INLINE int 
sigio_perm(struct task_struct *p,
                             struct fown_struct *fown, int sig)
{
	const struct cred *cred;
	int ret;

	rcu_read_lock();
	cred = __task_cred(p);
	ret = ((fown->euid == 0 ||
		fown->euid == cred->suid || fown->euid == cred->uid ||
		fown->uid  == cred->suid || fown->uid  == cred->uid) &&
	       !security_file_send_sigiotask(p, fown, sig));
	rcu_read_unlock();
	return ret;
}

/* Sends to a specific task, rather than to some thread in the task's 
 * thread group. */
STATIC void 
msp_send_sigio_to_task(struct task_struct *p,
			       struct fown_struct *fown, 
			       int fd,
			       int reason)
{
	if (!sigio_perm(p, fown, fown->signum))
		return;

	switch (fown->signum) {
		siginfo_t si;
		default:
			/* Queue a rt signal with the appropriate fd as its
			   value.  We use SI_SIGIO as the source, not 
			   SI_KERNEL, since kernel signals always get 
			   delivered even if we can't queue.  Failure to
			   queue in this case _should_ be reported; we fall
			   back to SIGIO in that case. --sct */
			si.si_signo = fown->signum;
			si.si_errno = 0;
		        si.si_code  = reason;
			/* Make sure we are called with one of the POLL_*
			   reasons, otherwise we could leak kernel stack into
			   userspace.  */
			BUG_ON((reason & __SI_MASK) != __SI_POLL);
			if (reason - POLL_IN >= NSIGPOLL)
				si.si_band  = ~0L;
			else
				si.si_band = band_table[reason - POLL_IN];
			si.si_fd    = fd;
			if (!send_sig_info(fown->signum, &si, p))
				break;
		/* fall-through: fall back on the old plain SIGIO signal */
		case 0:
			send_sig_info(SIGIO, SEND_SIG_PRIV, p);
	}
}

STATIC void 
msp_send_sigio(struct fown_struct *fown, int fd, int band)
{
	struct task_struct *p;
	enum pid_type type;
	struct pid *pid;
	
	type = fown->pid_type;
	pid = fown->pid;
	if (!pid) {
      return;
   }
	
	read_lock(&tasklist_lock);
	do_each_pid_task(pid, type, p) {
		msp_send_sigio_to_task(p, fown, fd, band);
	} while_each_pid_task(pid, type, p);
	read_unlock(&tasklist_lock);
}

STATIC int
msp_kill_fasync_one(struct fasync_struct *fa, int sig, int band)
{
   int sent_to_current = 0;
   struct fasync_struct *start_fa = fa;

   ASSERT(fa);
   ASSERT(start_fa);

	while (fa && !sent_to_current) {
		struct fown_struct * fown;
		if (fa->magic != FASYNC_MAGIC) {
			printk(KERN_ERR "kill_fasync: bad magic number in "
			       "fasync_struct!\n");
         goto out;
		}
		fown = &fa->fa_file->f_owner;

      read_lock(&fown->lock);

      ASSERT(fown->pid);

      if (pid_nr(fown->pid) == current->pid) {
         /* Don't send SIGURG to processes which have not set a
            queued signum: SIGURG has its own default signalling
            mechanism. */
         if (!(sig == SIGURG && fown->signum == 0)) {
            msp_send_sigio(fown, fa->fa_fd, band);
            sent_to_current = 1;
         }
      } else {
         //volatile struct task_struct *tsk = current;
         //DEBUG_MSG("pid_nr=%d current_pid=%d[%s]\n", pid_nr(fown->pid), tsk->pid, tsk->comm);
      }

      read_unlock(&fown->lock);

		fa = fa->fa_next;
	}

   if (!sent_to_current) {
      /* XXX: Just send to the first one in the list for now. */
      struct fown_struct * fown;
      fa = start_fa;
      if (fa->magic != FASYNC_MAGIC) {
         printk(KERN_ERR "kill_fasync: bad magic number in "
               "fasync_struct!\n");
         goto out;
      }
      fown = &fa->fa_file->f_owner;

      read_lock(&fown->lock);

      /* Don't send SIGURG to processes which have not set a
         queued signum: SIGURG has its own default signalling
         mechanism. */
      if (!(sig == SIGURG && fown->signum == 0)) {
         msp_send_sigio(fown, fa->fa_fd, band);
      }

      read_unlock(&fown->lock);
   }

out:
   return sent_to_current;
}

int
msp_kill_fasync(struct fasync_struct **fp, int sig, int band)
{
   int sent_to_current = 0;
   /* First a quick test without locking: usually
    * the list is empty.
    */
   if (*fp) {
      read_lock(&fasync_lock);
		/* reread *fp after obtaining the lock */
		sent_to_current = msp_kill_fasync_one(*fp, sig, band);
		read_unlock(&fasync_lock);
	}

   return sent_to_current;
}

void
msp_fasync_init(void)
{
	fasync_cache = kmem_cache_create("msp_fasync_cache",
		sizeof(struct fasync_struct), 0, SLAB_PANIC, NULL);

   ASSERT(fasync_cache);
}
