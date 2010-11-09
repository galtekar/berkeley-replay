#include "vkernel/public.h"
#include "vkernel/fs/private.h"
#include "private.h"

#define START_INODE_GEN 2

static SHAREDAREA unsigned int eventfd_gen = START_INODE_GEN;

static int
EventFdDo(unsigned int count_initval, int flags)
{
   int err;
   struct DentryStruct *root = sb_event->root, *dentryp = NULL;
   struct FileStruct *file = NULL;
   char name[32];

   Inode_Lock(root->inode);
   snprintf(name, sizeof(name), "eventfd:%d", eventfd_gen);
   dentryp = Dentry_Open(root, name, O_CREAT | O_EXCL);
   if (IS_ERR(dentryp)) {
      err = PTR_ERR(dentryp);
      goto out;
   }

   struct event_data *ev_ptr = malloc(sizeof(*ev_ptr));
   ev_ptr->count_initval = count_initval;
   ev_ptr->flags = flags;
   ev_ptr->ino = eventfd_gen++;

   err = VFS_create(root->inode, dentryp, 0, (void*) ev_ptr);
   if (err) {
      goto out_putd;
   }

   ASSERT(!(flags & ~(O_CLOEXEC | O_NONBLOCK)));
   file = File_DentryOpen(dentryp, O_RDWR | flags, 0);
   if (IS_ERR(file)) {
      err = PTR_ERR(file);
      goto out_putd;
   }

   err = File_GetUnusedFd();
   if (err < 0) {
      goto out_close_file;
   }

   File_FdInstall(err, file);
   goto out_putd;

out_close_file:
   File_Close(file);
out_putd:
   Dentry_Put(dentryp);
out:
   Inode_Unlock(root->inode);
   return err;
}

SYSCALLDEF(sys_eventfd2, unsigned int count, int flags)
{
   if (flags & ~(O_CLOEXEC | O_NONBLOCK)) {
      return -EINVAL;
   }
   return EventFdDo(count, flags);
}

SYSCALLDEF(sys_eventfd, unsigned int count)
{
   return sys_eventfd2(count, 0);
}
