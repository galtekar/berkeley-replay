#include "vkernel/public.h"
#include "vkernel/fs/private.h"
#include "private.h"


/* 0 is invalid, and 1 is reserved for the pipefs root inode. */
static SHAREDAREA unsigned int pipeGen = 2;

/*
 * Create a new file in the pipe filesystem. 
 * This is similar to creating a file in the disk filesystem
 * in that it involves creating an inode dentry in the filesystem for
 * the new file.
 */
static int
PipeDo(int *fd)
{
   int err, i, j;

   DEBUG_MSG(5, "sbPipe=0x%x root=0x%x\n", sbPipe, sbPipe->root);
   struct DentryStruct *root = sbPipe->root, *dentryp;
   struct FileStruct *f1, *f2;
   char name[32];

   ASSERT(sbPipe);

   Inode_Lock(root->inode);

   snprintf(name, sizeof(name), "pipe:%d", pipeGen++);

   dentryp = Dentry_Open(root, name, O_CREAT | O_EXCL);
   if (IS_ERR(dentryp)) {
      err = PTR_ERR(dentryp);
      goto out;
   }

   err = VFS_create(root->inode, dentryp, 0, (void*) pipeGen);
   if (err) {
      goto out_putd;
   }

   f1 = File_DentryOpen(dentryp, O_RDONLY, 0);
   if (IS_ERR(f1)) {
      err = PTR_ERR(f1);
      goto out_putd;
   }

   f2 = File_DentryOpen(dentryp, O_WRONLY, 0);
   if (IS_ERR(f2)) {
      err = PTR_ERR(f2);
      goto out_close_f1;
   }

   err = File_GetUnusedFd();
   if (err < 0) {
      goto out_close_f12;
   }
   i = err;

   err = File_GetUnusedFd();
   if (err < 0) {
      goto out_close_f12_i;
   }
   j = err;


   File_FdInstall(i, f1);
   File_FdInstall(j, f2);

   fd[0] = i;
   fd[1] = j;

   err = 0;
   goto out_putd;


out_close_f12_i:
   File_PutUnusedFd(i);
out_close_f12:
   File_Close(f2);
out_close_f1:
   File_Close(f1);
out_putd:
   Dentry_Put(dentryp);
out:
   Inode_Unlock(root->inode);
   return err;
}

SYSCALLDEF(sys_pipe, ulong __user *fildes)
{
   int fd[2];
   int error;

   error = PipeDo(fd);

   if (!error) {
      if (Task_CopyToUser(fildes, fd, 2*sizeof(int))) {
         error = -EFAULT;
      }
   }

   return error;
}
