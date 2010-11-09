#include "vkernel/public.h"
#include "private.h"

/* 
 * ----------------------------------------
 *
 * Epoll ops.
 *
 * ----------------------------------------
 */

int
RdEpoll_ctl(struct EpollStruct *ep, struct FileStruct *filp, int op,
            struct epoll_event *revent)
{
   int err;

   err = ReadDet_epoll_ctl(ep->fd, op, filp->rfd, revent);

   return err;
}

/*
 * OUT:
 *
 *    @vevents: buffer to place rfd->vfd translated events 
 */
int
RdEpoll_wait(struct EpollStruct *ep, struct epoll_event *vevents, 
             int maxevents, int timeout)
{
   int err;

   err = ReadDet_epoll_wait(ep, vevents, maxevents, timeout);

   return err;
}


const struct EpollOps RdEpoll_Eops = {
   .ctl =   &RdEpoll_ctl,
   .wait =  &RdEpoll_wait,
};


/* 
 * ----------------------------------------
 *
 * Inode ops.
 *
 * ----------------------------------------
 */

static long
RdEpoll_create(struct InodeStruct *dir, struct DentryStruct *dentryp, 
               int mode, void *data)
{
   int err;
   struct InodeStruct *inodp;
   struct EpollStruct *ep = (struct EpollStruct *) data;

   ASSERT(!dentryp->inode);

   err = ReadDet_epoll_create(ep->size);
   if (err < 0) {
      goto out;
   }
   ep->orig_fd = err;
   if (VCPU_IsReplaying()) {
      ep->fd = -1;
   } else {
      ep->fd = ep->orig_fd;
   }

   ep->ops = &RdEpoll_Eops;

   inodp = Inode_Get(dir->sb, dentryp->name, ep->ino);

   /* Make sure we aren't grabbing some existing inode. 
    * This inode should be brand new (and the INode_Get
    * should've missed in the inode cache). */
   ASSERT(inodp->count == 1);

   inodp->data = data;

   Dentry_Instantiate(dentryp, inodp);

   err = 0;

out:
   return err;
}


static long
RdEpoll_lstat(struct DentryStruct *dentry, struct kstat64 *statp)
{
   int err;
   struct EpollStruct *ep = Epoll_GetStruct(Dentry_Inode(dentry));

   err = ReadDet_fstat(ep->fd, statp);

   return err;
}

static const struct InodeOps RdEpoll_Iops = {
   .create =      &RdEpoll_create,
   .lstat =       &RdEpoll_lstat,
};

/* 
 * ----------------------------------------
 *
 * File ops.
 *
 * ----------------------------------------
 */
static int
RdEpoll_open(struct FileStruct *filp, int mode)
{
   const struct EpollStruct *ep = Epoll_GetStruct(File_Inode(filp));
   ASSERT(!IS_ERR(ep));

   filp->orig_rfd = ep->orig_fd;
   filp->rfd = ep->fd;

   return 0;
}

static void
RdEpoll_release(struct FileStruct *filp)
{
#if DEBUG
   ASSERT(filp->orig_rfd >= 0);
   if (VCPU_IsReplaying()) {
      ASSERT(filp->rfd == -1);
   }
#endif
}

static long
RdEpoll_fstat(struct FileStruct *filp, struct kstat64 *statp)
{
   int err;
   struct EpollStruct *ep = Epoll_GetStruct(File_Inode(filp));

   err = ReadDet_fstat(ep->fd, statp);

   return err;
}



static const struct FileOps RdEpoll_Fops = {
   .llseek =      &no_llseek,
   .open =        &RdEpoll_open,
   .release =     &RdEpoll_release,
   .fstat =       &RdEpoll_fstat,
};


/* 
 * ----------------------------------------
 *
 * Superblock ops.
 *
 * ----------------------------------------
 */

struct InodeStruct *
EpollFs_alloc_inode(struct SuperBlockStruct *sb)
{
   struct InodeStruct *inodp;

   inodp = Inode_GenericAlloc(sb);
   inodp->i_op = &RdEpoll_Iops;
   inodp->f_op = &RdEpoll_Fops;
   inodp->major = InodeMajor_Epoll;

   return inodp;
}

void
EpollFs_free_inode(struct InodeStruct *inodp)
{
   struct EpollStruct *ep = Epoll_GetStruct(inodp);

   ASSERT(ep);

   Epoll_Free(ep);

   Inode_GenericFree(inodp);
}

void
EpollFs_drop_inode(struct InodeStruct *inodp)
{
   struct EpollStruct *ep = Epoll_GetStruct(inodp);

   /* XXX: this assert should be inside SysOps_Close() */
   ASSERT(ep->orig_fd >= 0);
   if (VCPU_IsReplaying()) {
      ASSERT(ep->fd == -1);
   } else {
      ASSERT(ep->fd == ep->orig_fd);
      SysOps_Close(ep->fd);
   }
}

static struct SuperBlockOps EpollFs_SbOps = {
   .alloc_inode =       &EpollFs_alloc_inode,
   .free_inode =        &EpollFs_free_inode,
   .drop_inode =        &EpollFs_drop_inode,
};

struct SuperBlockStruct *
EpollFs_GetSb()
{
   return SuperBlock_AllocPseudo("epollfs", &EpollFs_SbOps);
}

SHAREDAREA struct SuperBlockStruct *sbEpoll;

static int
EpollFs_Init()
{
   DEBUG_MSG(5, "EpollFs\n");

   sbEpoll = EpollFs_GetSb();

   return 0;
}

FS_INITCALL(EpollFs_Init);
