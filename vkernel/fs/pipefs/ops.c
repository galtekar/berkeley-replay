#include "vkernel/public.h"
/*
 * Why store the fds in the inode?
 *
 *    o Precludes the need for an fstat file op, since we can access
 *    the fd from the inode and hence implement stat (sys_fstat can then
 *    be implemented with stat op).
 *
 */

static struct PipeStruct *
PipeAlloc()
{
   struct PipeStruct *pipep;

   pipep = SharedArea_Malloc(sizeof(*pipep));
   memset(pipep, 0, sizeof(*pipep));

   return pipep;
}

static void
PipeFree(struct PipeStruct *pipep)
{
   memset(pipep, 0, sizeof(*pipep));
   SharedArea_Free(pipep, sizeof(*pipep));
}

struct PipeStruct *
Pipe_GetStruct(struct InodeStruct *inodp)
{
   struct PipeStruct *pipep = (struct PipeStruct *) inodp->data;

   ASSERT(pipep);

   ASSERT(Inode_GetMajor(inodp) == InodeMajor_Pipe);

   return pipep;
}

/* 
 * ----------------------------------------
 *
 * Inode ops.
 *
 * ----------------------------------------
 */

static long
RdPipe_lookup(UNUSED struct InodeStruct *dir, 
              UNUSED struct DentryStruct *dentryp)
{
   /* We don't expect lookups of pipes, so this is a no-op. */
   return -ENOENT;
}

static long
RdPipe_create(struct InodeStruct *dir, struct DentryStruct *dentryp, 
              UNUSED int mode, void *data)
{
   int err;
   int rfds[2] = { 0, 0 };
   uint pipeGen = (uint)data;
   struct InodeStruct *inodp;
   struct PipeStruct *pipep;

   err = ReadDet_pipe(rfds);
   if (err) {
      goto out;
   }

   inodp = Inode_Get(dir->sb, dentryp->name, pipeGen);
   pipep = Pipe_GetStruct(inodp);

   pipep->orig_fds[0] = rfds[0];
   pipep->orig_fds[1] = rfds[1];

   if (VCPU_IsReplaying()) {
      pipep->fds[0] = -1;
      pipep->fds[1] = -1;
   } else {
      pipep->fds[0] = pipep->orig_fds[0];
      pipep->fds[1] = pipep->orig_fds[1];
   }

   /* Make sure we aren't grabbing some existing inode. 
    * This inode should be brand new (and the INode_Get
    * should've missed in the inode cache). */
   ASSERT(inodp->count == 1);

   Dentry_Instantiate(dentryp, inodp);

out:
   return err;
}


static long
RdPipe_lstat(struct DentryStruct *dentryp, struct kstat64 *statp)
{
   int err;
   struct InodeStruct *inodp = Dentry_Inode(dentryp);
   struct PipeStruct *pipep;

   pipep = Pipe_GetStruct(inodp);

   /* Doesn't matter what fd we pick -- both point to the same
    * Linux inode. */
   err = ReadDet_fstat(pipep->fds[0], statp);

   return err;
}

static const struct InodeOps RdPipe_Iops = {
   .lookup =   &RdPipe_lookup,
   .create =   &RdPipe_create,
   .lstat =    &RdPipe_lstat,
};

/* 
 * ----------------------------------------
 *
 * File ops.
 *
 * ----------------------------------------
 */

static int
RdPipe_open(struct FileStruct *filp, UNUSED int mode)
{
   int idx;
   struct PipeStruct *pipep = Pipe_GetStruct(File_Inode(filp));

   idx = filp->accMode & FMODE_WRITE ? 1 : 0;

   filp->orig_rfd = pipep->orig_fds[idx];
   filp->rfd = pipep->fds[idx];
   if (!VCPU_IsReplaying()) {
      /* Pipe endpoints are accessible only within the vkernel domain
       * so we can be sure that both endpoints are vkernel tasks, and
       * hence tagged. */
      TSock_Open(&pipep->tsock[idx], filp->rfd, TSOCK_FAMILY_PIPE,
            TSOCK_PROTOCOL_TCP, TSOCK_PEER_TAGS);
   }

   return 0;
}

static void
RdPipe_release(struct FileStruct *filp)
{
   const int idx = filp->accMode & FMODE_WRITE ? 1 : 0;

   struct PipeStruct *pipep = Pipe_GetStruct(File_Inode(filp));

   if (VCPU_IsReplaying()) {
      ASSERT(filp->rfd == -1);
   } else {
      ASSERT(filp->rfd >= 0);

      /* Must perform close on Linux fd to ensure that
       * other side gets an EOF. */
      SysOps_Close(filp->rfd);
      filp->rfd = -1;

      TSock_Close(&pipep->tsock[idx]);
   }

   pipep->orig_fds[idx] = -1;
   pipep->fds[idx] = -1;
}

static ssize_t
RdPipe_io(const int ioReqFlags, const struct FileStruct *filp, 
      struct msghdr *kmsgp, const int flags, loff_t pos)
{
   int err;

   err = ReadDet_io(ioReqFlags, filp, filp->rfd, kmsgp, flags, 
               0, pos);

   /* See BUG #5 for info on why we do this */
   return err == -EINTR ? -ERESTARTSYS : err;
}

static int
RdPipe_fsync(struct FileStruct *filp, int datasync)
{
   int err;

   err = ReadDet_fsync(filp->rfd, datasync);

   return err;
}

static int
RdPipe_setfl(struct FileStruct *filp, int flags)
{
   int err;

   err = ReadDet_setfl(filp->rfd, flags);

   return err;
}

static int
RdPipeIoctl_FIONREAD(int fd, uint cmd, int __user * arg)
{
   int err, count;

   if (!VCPU_IsReplaying()) {
      err = syscall(SYS_ioctl, fd, cmd, &count);

      if (VCPU_IsLogging()) {
         DO_WITH_LOG_ENTRY(RdPipeIoctl_FIONREAD) {
            entryp->ret = err;
            entryp->count = count;
         } END_WITH_LOG_ENTRY(0);
      }
   } else {
      DO_WITH_LOG_ENTRY(RdPipeIoctl_FIONREAD) {
         err = entryp->ret;
         count = entryp->count;
      } END_WITH_LOG_ENTRY(0);
   }

   if (!err && __put_user(count, arg)) {
      err = -EFAULT;
   }

   return err;
}

static int
RdPipeIoctl(struct FileStruct *filp, uint cmd, ulong arg)
{
   int err, fd = filp->rfd;

   switch (cmd) {
   case FIONREAD:
      err = RdPipeIoctl_FIONREAD(fd, cmd, (int __user *)arg);
      break;
   default:
      DEBUG_MSG(5, "cmd=0x%x unsupported on pipe.\n", cmd);
      err = -EINVAL;
      break;
   }

   return err;
}

static int
RdPipe_ioctl(struct FileStruct *filp, uint cmd, ulong arg)
{
   int err;

   err = RdPipeIoctl(filp, cmd, arg);

   return err;
}

static long
RdPipe_fstat(struct FileStruct *filp, struct kstat64 *statp)
{
   int err;
   struct InodeStruct *inodp = File_Inode(filp);
   struct PipeStruct *pipep;

   pipep = Pipe_GetStruct(inodp);

   /* Doesn't matter what fd we pick -- both point to the same
    * Linux inode. */
   err = ReadDet_fstat(pipep->fds[0], statp);

   return err;
}

static int
RdPipe_select(const struct FileStruct *filP, const int is_read, 
              const int should_block)
{
   const struct PipeStruct *pipep = Pipe_GetStruct(File_Inode(filP));
   ASSERT(!IS_ERR(pipep));
   const int idx = filP->accMode & FMODE_WRITE ? 1 : 0;
   const tsock_socket_info_t *s_info = &pipep->tsock[idx];
   return Select_DefaultTaggedFop(s_info, is_read, should_block);
}

static const struct FileOps RdPipe_Fops = {
   .llseek =   &no_llseek,
   .open    =  &RdPipe_open,
   .release =  &RdPipe_release,
   .io =       &RdPipe_io,
   .fsync =    &RdPipe_fsync,
   .setfl =    &RdPipe_setfl,
   .ioctl =    &RdPipe_ioctl,
   .fstat =    &RdPipe_fstat,
   .select =   &RdPipe_select,
};

/* 
 * ----------------------------------------
 *
 * Superblock ops.
 *
 * ----------------------------------------
 */

struct InodeStruct *
PipeFs_alloc_inode(struct SuperBlockStruct *sb)
{
   struct InodeStruct *inodp;

   inodp = Inode_GenericAlloc(sb);

   inodp->data = (void*) PipeAlloc();
   inodp->i_op = &RdPipe_Iops;
   inodp->f_op = &RdPipe_Fops;
   inodp->major = InodeMajor_Pipe;

   return inodp;
}

void
PipeFs_free_inode(struct InodeStruct *inodp)
{
   ASSERT(inodp);

   D__;

   DEBUG_MSG(5, "inodp->data=0x%x\n", inodp->data);

   PipeFree(inodp->data);
   inodp->data = NULL;

   D__;

   Inode_GenericFree(inodp);
}

void
PipeFs_drop_inode(struct InodeStruct *inodp)
{
   struct PipeStruct *pipep = Pipe_GetStruct(inodp);

   /* For a pipe inode to be destroyed, all
    * file objects that refer to it must be closed,
    * which means that reader and writer must've
    * already called release(). */
   ASSERT(pipep->fds[0] == -1 && pipep->fds[1] == -1);

   SysOps_Close(pipep->fds[0]);
   SysOps_Close(pipep->fds[1]);
}

static struct SuperBlockOps PipeFs_SbOps = {
   .alloc_inode =       &PipeFs_alloc_inode,
   .free_inode =        &PipeFs_free_inode,
   .drop_inode =        &PipeFs_drop_inode,
};


struct SuperBlockStruct *
PipeFs_GetSb()
{
   return SuperBlock_AllocPseudo("pipefs", &PipeFs_SbOps);
}

SHAREDAREA struct SuperBlockStruct *sbPipe = NULL;

static int
PipeFs_Init()
{
   DEBUG_MSG(5, "PipeFs\n");

   sbPipe = PipeFs_GetSb();

   D__;

   ASSERT_PTR(sbPipe);
   ASSERT_PTR(sbPipe->root);

   return 0;
}

FS_INITCALL(PipeFs_Init);
