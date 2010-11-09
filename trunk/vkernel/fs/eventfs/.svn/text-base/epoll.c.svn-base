#include "vkernel/public.h"
#include "private.h"


static void
EpollLockInit(struct EpollStruct *ep)
{
   ORDERED_LOCK_INIT(&ep->lock, "epoll");
}

static void
EpollLock(struct EpollStruct *ep)
{
   ORDERED_LOCK(&ep->lock);
}

static void
EpollUnlock(struct EpollStruct *ep)
{
   ORDERED_UNLOCK(&ep->lock);
}

#if DEBUG
static int
EpollIsLocked(struct EpollStruct *epoll)
{
   return ORDERED_IS_LOCKED(&epoll->lock);
}
#endif

struct EpollStruct *
Epoll_Alloc()
{
   struct EpollStruct *ep;

   ep = SharedArea_Malloc(sizeof(*ep));

   ep->map = Map_Create(0);

   EpollLockInit(ep);

   return ep;
}

static int
EpollRemove(struct EpollItemStruct *epi);

void
Epoll_Free(struct EpollStruct *ep)
{
   struct EpollItemStruct *epi, *tmp;

   /* Can't just call Map_Destory(ep->map) --
    * we must remove each epi from any filp->epoll_item_list
    * chains it may be attached to as well. */

   /* No need to acquire ep->lock, since we don't expect
    * any one to hold references to the ep object. But we
    * do it for consistency and so that the assertion
    * in EpollRemove does not fire. */

   DEBUG_MSG(5, "Freeing epoll.\n");

   EpollLock(ep);

   list_for_each_entry_safe(epi, tmp, &ep->map->list, rfdMap.list) {
      EpollRemove(epi);
   }

   EpollUnlock(ep);

   epi = NULL;
   Map_Destroy(ep->map, rfdMap, epi);

   memset(ep, 0, sizeof(*ep));
   SharedArea_Free(ep, sizeof(*ep));
}

struct EpollStruct *
Epoll_GetStruct(struct InodeStruct *inodp)
{
   struct EpollStruct *ep = (struct EpollStruct *) inodp->data;

   /* User-space may pass in a non-epoll fd, so we can't just return NULL. */
   if (Inode_GetMajor(inodp) != InodeMajor_Epoll) {
      ep = ERR_PTR(-EINVAL);
      goto out;
   }

out:
   return ep;
}




static struct EpollItemStruct*
EpollFind(struct EpollStruct *ep, struct FileStruct *filp, int vfd)
{
   struct EpollItemStruct *epi;

   MAP_FOR_EACH_KEY_ENTRY_DO(ep->map, rfdMap, filp->orig_rfd, epi) {
      if (epi->vfd == vfd) {
         return epi;
      }
   } END_MAP_FOR_EACH_KEY_ENTRY;

   return NULL;
}

static int
EpollInsert(struct EpollStruct *ep, struct epoll_event *kevent, 
            struct FileStruct *filp, int vfd)
{
   int err = 0;
   struct EpollItemStruct *epi;

   epi = SharedArea_Malloc(sizeof(*epi));

   Map_NodeInit(&epi->rfdMap, filp->orig_rfd);
   epi->file = filp;
   epi->vfd = vfd;
   epi->event = *kevent;
   epi->ep = ep;


   ASSERT(EpollIsLocked(ep));
   Map_Insert(ep->map, rfdMap, filp->orig_rfd, epi);

   /* Keep track of what epoll sets filp belongs to so that
    * we may remove filp from each of those sets (as dictated
    * by Linux epoll semantics) when filp is closed. 
    *
    * We need the lock guard against concurrent add/remove of
    * filp to th ep. */
   File_Lock(filp);

   List_Add(&epi->file_link, &filp->epoll_item_list);

   File_Unlock(filp);

   return err;
}

static int
EpollRemove(struct EpollItemStruct *epi)
{
   int err = 0;
   struct FileStruct *filp = epi->file;

   ASSERT(filp);

   /* Why lock? Tasks may concurrently add and/or remove
    * filp to an ep. */
   File_Lock(filp);
   List_Del(&epi->file_link);
   File_Unlock(filp);


   DEBUG_MSG(5, "Removing %s.\n", File_Name(filp));

   ASSERT(EpollIsLocked(epi->ep));
   Map_Remove(epi->ep->map, rfdMap, epi);

   memset(epi, 0, sizeof(*epi));
   SharedArea_Free(epi, sizeof(*epi));

   return err;
}

static int
EpollModify(struct EpollItemStruct *epi, struct epoll_event *kevent)
{
   int err = 0;

   ASSERT(EpollIsLocked(epi->ep));
   epi->event = *kevent;

   return err;
}

/* Used to cleanup filp from all epoll lists when closed. */
void
Epoll_Release(struct FileStruct *filp)
{
   struct EpollItemStruct *epi, *tmp;

   /* No need to acquire the filp->lock, since this function
    * is called on the file cleanup path and hence we expect no one
    * (other than this task) to use it. 
    *
    * Also, we shouldn't acquire it or we'll deadlock
    * in EpollRemove. */

   DEBUG_MSG(5, "Removing from all epoll lists.\n");
   list_for_each_entry_safe(epi, tmp, &filp->epoll_item_list, file_link) {
      struct EpollStruct *eP = epi->ep;

      ASSERT(eP);

      EpollLock(eP);

      EpollRemove(epi);
      epi = NULL;

      EpollUnlock(eP);
   }

   /* NOTE: no need to invoke ops->ctl -- Linux will remove
    * filp->rfd from the ep->fd epoll set upon
    * sys_close(filp->rfd). */
}


static int
EpollCalcEvents(struct EpollStruct *ep, int rfd, int *op)
{
   int events = 0, cnt = 0;
   struct EpollItemStruct *epi;

   /* Many vfds can map to the same rfd. For any given rfd, the set of
    * events we are interested in is the union of events that each vfd
    * is interested in. */

   MAP_FOR_EACH_KEY_ENTRY_DO(ep->map, rfdMap, rfd, epi) {
      cnt++;
      events |= epi->event.events;
   } END_MAP_FOR_EACH_KEY_ENTRY;

   switch (*op) {
   case EPOLL_CTL_ADD:
      /* We shouldn't add an rfd, if it was previously added. */
      if (cnt == 1) {
         /* rfd was recently added to the set */
         break;
      }
      /* fallthrough */
   case EPOLL_CTL_DEL:
      /* We're still interested in the rfd if some vfd backed by it 
       * is in the epoll set. */
      if (cnt) {
         *op = EPOLL_CTL_MOD;
      }
      break;
   default:
      break;
   }

   return events;
}


/* This is called from multiple places where the lock is already held,
 * for example, to disable an fd that had EPOLLONESHOT set. 
 * Hence the Unlocked designation. */
static int
EpollCtlUnlocked(struct EpollStruct *ep, struct FileStruct *filp, 
      int vfd, int op, struct epoll_event *kevent)
{
   int err = 0;
   struct EpollItemStruct *epi;
   struct epoll_event revent;

   if (DEBUG) {
      if (!kevent) {
         ASSERT(op == EPOLL_CTL_DEL);
      }
   }


   /* Linux epoll_wait will always wait for these events whether they
    * are requested or not. But we need to make it explicit to ensure
    * that we select the corresponding vfds when these are set. */
   kevent->events |= POLLERR | POLLHUP;

   /* XXX: Is this used by Apache? */
   //ASSERT_UNIMPLEMENTED(!(kevent->events & EPOLLET));

   epi = EpollFind(ep, filp, vfd);

   switch (op) {
   case EPOLL_CTL_ADD: 
      {
         if (!epi) {
            err = EpollInsert(ep, kevent, filp, vfd);
         } else {
            err = -EEXIST;
            goto out;
         }
      } 
      break;

   case EPOLL_CTL_DEL: 
      {
         if (epi) {
            err = EpollRemove(epi);
         } else {
            err = -ENOENT;
            goto out;
         }
      } 
      break;

   case EPOLL_CTL_MOD: 
      {
         if (epi) {
            err = EpollModify(epi, kevent);
         } else {
            err = -ENOENT;
            goto out;
         }
      } 
      break;

   default:
      err = -EINVAL;
      goto out;
      break;
   }

   /* epoll_wait needs to know what rfd an event maps to in order to
    * dtermine the corresponding vfd.
    *
    * XXX: why not just put the vfd here? Linux doesn't care what this
    * data is... */
   revent.data.fd = filp->rfd;

   /* NOTE: filp->rfd is not deterministically replayed, but that's
    * okay -- we don't call through to Linux, during replay, in the 
    * epoll_ctl below. */

   /* We want the set of events that
    * all vfds corresponding to associated rfd are interested in. */
   revent.events = EpollCalcEvents(ep, filp->orig_rfd, &op);

   /* We'll emulate one-shot behavior and edgetriggering, so
    * we don't want the kernel to do it for us. */
   revent.events &= ~(EPOLLONESHOT | EPOLLET);

   /* Now tell Linux about the events all the vfds (backed by rfd)
    * are interested in. */
   ASSERT(ep->ops->ctl);
   err = ep->ops->ctl(ep, filp, op, &revent);
   ASSERT(!SYSERR(err));

out:
   return err;
}

SYSCALLDEF(sys_epoll_ctl, int epfd, int op, int vfd, struct epoll_event __user *event)
{
   int err;
   struct FileStruct *efilp, *vfilp;
   struct epoll_event kevent;
   struct EpollStruct *ep;

   err = -EFAULT;
   if (Task_CopyFromUser(&kevent, event, sizeof(struct epoll_event))) {
      goto out;
   }

   err = -EINVAL;
   if (epfd == vfd) {
      goto out;
   }

   err = -EBADF;
   efilp = File_Get(epfd);
   if (!efilp) {
      goto out;
   }


   err = -EBADF;
   vfilp = File_Get(vfd);
   if (!vfilp) {
      goto out_pute;
   }

   ep = Epoll_GetStruct(efilp->dentry->inode);
   if (IS_ERR(ep)) {
      err = PTR_ERR(ep);
      goto out_putv;
   }

   EpollLock(ep);
   err = EpollCtlUnlocked(ep, vfilp, vfd, op, &kevent);
   EpollUnlock(ep);

   if (SYSERR(err)) {
      goto out_putv;
   }

out_putv:
   File_Put(vfilp);
out_pute:
   File_Put(efilp);
out:
   return err;
}

int
Epoll_RealToVirt(struct EpollStruct *ep, struct epoll_event *vevents, 
                int maxevents, struct epoll_event *revents, 
                int revCount)
{
   int err = 0, i, evCnt = 0;
   struct EpollItemStruct *epi;

   ASSERT(ep->map);

   DEBUG_MSG(5, "maxevents=%d revCount=%d\n", maxevents, revCount);

   EpollLock(ep);

   /* Okay, we have some events to process. But who's interested in them? 
    * Here we produce an event array that can be used by user space (i.e.,
    * it will refer to vfds rather than rfds). */
   for (i = 0; i < revCount; i++) {
      struct epoll_event *evp = &revents[i];
      int rfd = evp->data.fd;

      DEBUG_MSG(5, "i=%d rfd=%d\n", i, rfd);

      MAP_FOR_EACH_KEY_ENTRY_DO(ep->map, rfdMap, rfd, epi) {

         DEBUG_MSG(5, "epi: rfd=%d,events=0x%x rfd=%d,events=0x%x\n", 
               epi->rfdMap.keyLong, epi->event.events, rfd, evp->events);
         ASSERT(epi->rfdMap.keyLong == rfd);

         if (evCnt >= maxevents) {
            goto out;
         }

         if (epi->event.events & evp->events) {
            /* This vfd is interested in at least some of the events. */
            struct epoll_event tmp;

            tmp = epi->event;
            /* Data field should contain user-provided data, not
             * necesarily the fd. */
            //tmp.data.fd = epi->vfd;
            tmp.events &= evp->events;
            vevents[evCnt] = tmp;

            /* Emulate one-shot behavior for this vfd. */
            if (epi->event.events & EPOLLONESHOT) {
               tmp.events = 0;
               EpollCtlUnlocked(ep, epi->file, epi->vfd, EPOLL_CTL_MOD, &tmp);
            }

            evCnt++;
         }
      } END_MAP_FOR_EACH_KEY_ENTRY;
   }

out:
   err = evCnt;
   EpollUnlock(ep);
   return err;
}


static int
EpollWait(struct EpollStruct *ep, struct epoll_event *kevents, int maxevents,
          int timeout)
{
   int err;

   ASSERT(ep);
   ASSERT(ep->ops->wait);

   err = ep->ops->wait(ep, kevents, maxevents, timeout);
   if (err == -ERESTARTNOHAND) {
      /* Unlike select, epoll_wait does not automatically restart. */
      err = -EINTR;
   }

   return err;
}


SYSCALLDEF(sys_epoll_wait, int epfd, struct epoll_event __user *events,
			  int maxevents, int timeout)
{
   struct FileStruct *filp;
   struct EpollStruct *ep;
   int err;
	struct epoll_event *kevents = NULL;
   size_t evSz = sizeof(struct epoll_event) * maxevents;

#define MAX_EVENTS (INT_MAX / sizeof(struct epoll_event))
	/* The maximum number of events must be greater than zero */
   err = -EINVAL;
   if (maxevents <= 0 || maxevents > MAX_EVENTS) {
      goto out;
   }

   err = -EBADF;
   filp = File_Get(epfd);
   if (!filp) {
      goto out;
   }

   ep = Epoll_GetStruct(filp->dentry->inode);
   if (IS_ERR(ep)) {
      err = PTR_ERR(ep);
      goto out_putf;
   }

   kevents = SharedArea_Malloc(evSz);

   err = EpollWait(ep, kevents, maxevents, timeout);
   if (SYSERR(err)) {
      goto out_kevfree;
   }

   ASSERT(err >= 0);
   ASSERT(err <= maxevents);

   if (err > 0 && Task_CopyToUser(events, kevents, err*sizeof(*events))) {
      err = -EFAULT;
      goto out_kevfree;
   }

out_kevfree:
   SharedArea_Free(kevents, evSz);
   kevents = NULL;
out_putf:
   File_Put(filp);
out:
   return err;
}



/* 0 is invalid, and 1 is reserved for the root inode. */
static SHAREDAREA uint epGen = 2;

SYSCALLDEF(sys_epoll_create, int size)
{
   int err;
   struct DentryStruct *root = sbEpoll->root, *dentryp;
   struct EpollStruct *ep;
   struct FileStruct *filp;
   char name[32];
   ino_t ino;

   Inode_Lock(root->inode);

   ino = epGen++;
   snprintf(name, sizeof(name), "epoll:%lu", ino);

   dentryp = Dentry_Open(root, name, O_CREAT | O_EXCL);
   if (IS_ERR(dentryp)) {
      err = PTR_ERR(dentryp);
      goto out;
   }

   D__;

   ep = Epoll_Alloc(size);
   ep->size = size;
   ep->ino = ino;

   err = VFS_create(root->inode, dentryp, 0, (void*) ep);
   if (err) {
      goto out_free_epoll;
   }

   D__;

   filp = File_DentryOpen(dentryp, O_RDWR, 0);
   if (IS_ERR(filp)) {
      err = PTR_ERR(filp);
      goto out_free_epoll;
   }

   D__;

   err = File_GetUnusedFd();
   if (err < 0) {
      goto out_putd;
   }

   DEBUG_MSG(5, "fd=%d\n", err);

   File_FdInstall(err, filp);

   goto out_putd;

out_free_epoll:
   Epoll_Free(ep);
out_putd:
   Dentry_Put(dentryp);
out:
   Inode_Unlock(root->inode);
   return err;
}
