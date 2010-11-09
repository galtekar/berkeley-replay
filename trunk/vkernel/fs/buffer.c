#include "vkernel/public.h"
#include "private.h"


static int
VFS_fsync(struct FileStruct *filp, int datasync)
{
	int err;

	if (!filp->f_op || !filp->f_op->fsync) {
		/* Why?  We can still call filemap_fdatawrite */
		err = -EINVAL;
		goto out;
	}

   err = filp->f_op->fsync(filp, datasync);

out:
	return err;
}

static int
FsyncDo(uint fd, int datasync)
{
	struct FileStruct *filp;
	int err = -EBADF;

	filp = File_Get(fd);

	if (filp) {
		err = VFS_fsync(filp, datasync);
		File_Put(filp);
	}

	return err;
}


SYSCALLDEF(sys_fsync, unsigned int fd)
{
	return FsyncDo(fd, 0);
}

SYSCALLDEF(sys_fdatasync, unsigned int fd)
{
	return FsyncDo(fd, 1);
}
