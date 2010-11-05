#include "vkernel/public.h"
#include "private.h"

/* 
 * ----------------------------------------
 *
 * Inode ops.
 *
 * ----------------------------------------
 */

static long
EventFs_create(struct InodeStruct *dir, struct DentryStruct *dentryp, 
               int mode, void *data)
{
   int err;
   struct InodeStruct *inodp = NULL;
   struct event_data *ev_ptr = (struct event_data *) data;
   ASSERT_KPTR(ev_ptr);
   ASSERT(!dentryp->inode);

   err = ReadDet_eventfd2(ev_ptr->count_initval, ev_ptr->flags);
   if (err < 0) {
      goto out;
   }
   ev_ptr->orig_fd = err;

   if (VCPU_IsReplaying()) {
      ev_ptr->fd = -1;
   } else {
      ev_ptr->fd = ev_ptr->orig_fd;
   }

   inodp = Inode_Get(dir->sb, dentryp->name, ev_ptr->ino);

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

static const struct InodeOps EventFs_Iops = {
   .create =      &EventFs_create,
};

/* 
 * ----------------------------------------
 *
 * File ops.
 *
 * ----------------------------------------
 */
static int
EventFs_open(struct FileStruct *filp, int mode)
{
   const struct event_data *ev_ptr = (struct event_data *)
      File_Inode(filp)->data;
   ASSERT_KPTR(ev_ptr);

   filp->orig_rfd = ev_ptr->orig_fd;
   filp->rfd = ev_ptr->fd;

   return 0;
}

static void
EventFs_release(struct FileStruct *filp)
{
#if DEBUG
   ASSERT(filp->orig_rfd >= 0);
   if (VCPU_IsReplaying()) {
      ASSERT(filp->rfd == -1);
   }
#endif
}

static ssize_t
EventFs_io(const int io_req_flags, const struct FileStruct *file_ptr,
          struct msghdr *kmsg_ptr, UNUSED const int flags, loff_t pos)
{
  
   return ReadDet_io(io_req_flags, file_ptr, file_ptr->rfd, kmsg_ptr, 0, 
         0, pos);
}

#if 0
static int
EventFs_select(const struct FileStruct *file_ptr, const int is_read, 
      const int should_block)
{
   return FileSys_default_select(file_ptr, is_read, should_block);
}
#endif

static const struct FileOps EventFs_Fops = {
   .llseek =      &no_llseek,
   .open =        &EventFs_open,
   .release =     &EventFs_release,
   .io =          &EventFs_io,
   .select =      &Select_DefaultUntaggedFop,
};


/* 
 * ----------------------------------------
 *
 * Superblock ops.
 *
 * ----------------------------------------
 */

struct InodeStruct *
EventFs_alloc_inode(struct SuperBlockStruct *sb)
{
   struct InodeStruct *inodp;

   inodp = Inode_GenericAlloc(sb);
   inodp->i_op = &EventFs_Iops;
   inodp->f_op = &EventFs_Fops;
   inodp->major = InodeMajor_Event;

   return inodp;
}

void
EventFs_free_inode(struct InodeStruct *inodp)
{
   struct event_data *ev_ptr = (struct event_data *) inodp->data;
   ASSERT_KPTR(ev_ptr);

   free(ev_ptr);
   inodp->data = NULL;
   Inode_GenericFree(inodp);
}

void
EventFs_drop_inode(struct InodeStruct *inodp)
{
   struct event_data *ev_ptr = (struct event_data *) inodp->data;

   /* XXX: this assert should be inside SysOps_Close() */
   ASSERT(ev_ptr->orig_fd >= 0);
   if (VCPU_IsReplaying()) {
      ASSERT(ev_ptr->fd == -1);
   } else {
      ASSERT(ev_ptr->fd == ev_ptr->orig_fd);
      SysOps_Close(ev_ptr->fd);
   }
}

static struct SuperBlockOps EventFs_SbOps = {
   .alloc_inode =       &EventFs_alloc_inode,
   .free_inode =        &EventFs_free_inode,
   .drop_inode =        &EventFs_drop_inode,
};

struct SuperBlockStruct *
EventFs_GetSb()
{
   return SuperBlock_AllocPseudo("eventfs", &EventFs_SbOps);
}

SHAREDAREA struct SuperBlockStruct *sb_event = NULL;

static int
EventFs_Init()
{
   sb_event = EventFs_GetSb();

   return 0;
}

FS_INITCALL(EventFs_Init);
