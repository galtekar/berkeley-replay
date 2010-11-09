#include "vkernel/public.h"
#include "private.h"

/*
 * Each file object carries a reference to an inode object. When all references to
 * the file are released (via File_Put), then the file object will will free
 * its memory and drop the inode reference.
 */


/* XXX: actually finds the last open fd -- rename
 * appropriately. */
static int 
FilesCountOpenFiles(struct FdTableStruct *fdt)
{
	int size = fdt->maxFds;
	int i;

	/* Find the last open fd */
	for (i = size/(8*sizeof(long)); i > 0; ) {
		if (fdt->openFds->fds_bits[--i])
			break;
	}
	i = (i+1) * 8 * sizeof(long);
	return i;
}

static void
FilesClose(struct FilesStruct *files)
{
   uint i, j;
   struct FdTableStruct *fdt;

   j = 0;

   fdt = files->fdt;

   for (;;) {
      ulong set;
      i = j * NFDBITS;
      if (i >= fdt->maxFds) {
         break;
      }

      set = fdt->openFds->fds_bits[j++];
      while (set) {
         if (set & 1) {
            struct FileStruct *file = xchg(&fdt->vfdTable[i], NULL);
            ASSERT(file);
            if (file) {
               File_Close(file);
            }
         }
         i++;
         set >>= 1;
      }
   }
}


static struct FilesStruct*
FilesAlloc()
{
   struct FilesStruct *newf;
   struct FdTableStruct *fdt;

   newf = SharedArea_Malloc(sizeof(struct FilesStruct));
   if (!newf) {
      goto out;
   }

   memset(newf, 0, sizeof(*newf));

   newf->count = 1;
   ORDERED_LOCK_INIT(&newf->lock, "files");
   newf->nextFd = 0;
   fdt = &newf->fdtab;
   fdt->maxFds = NR_OPEN_DEFAULT;
   /* closeOnExecInit and openFdsInit should be zeroed out
    * and thus intialized already. */
   fdt->closeOnExec = (fd_set*)&newf->closeOnExecInit;
   fdt->openFds = (fd_set*)&newf->openFdsInit;
   fdt->vfdTable = &newf->vfdArray[0];
   newf->fdt = fdt;

out:
   return newf;
}

static void
FilesPutWork(struct FilesStruct *files, int isUnused)
{
   DEBUG_MSG(5, "isUnused=%d\n", isUnused);
   /* Must rely on files->count rather than mm->users since FILES
    * sharing is independent of address-space sharing. */
   if (isUnused) {
      ASSERT(files);

      FilesClose(files);
      /* XXX: free the fd and fdset arrays if we expanded them. 
       * We don't support expansion yet, but when we do, make sure
       * you do this. */
      SharedArea_Free(files, sizeof(*files));
   }
}

static void
FilesPut(struct FilesStruct *files)
{
   int isUnused;

   D__;

   Files_Lock(files);
   files->count--;
   isUnused = (files->count == 0);
   Files_Unlock(files);

   FilesPutWork(files, isUnused);
   D__;
}

/*
 * Allocate a new files structure and copy contents from the
 * passed in files structure. Note that the new files table
 * will contain references to the same file objects pointed
 * to by the old files table.
 *
 * errp will be valid only when the returned files_struct is NULL.
 */
static struct FilesStruct*
FilesDupFd(struct FilesStruct *oldf, int *errp)
{
   struct FilesStruct *newf;
   struct FdTableStruct *old_fdt, *new_fdt;
   struct FileStruct **old_fds, **new_fds;
   uint open_files, size, i, expand;

   *errp = -ENOMEM;
   newf = FilesAlloc();
   if (!newf) {
      goto out;
   }


   old_fdt = oldf->fdt;
   new_fdt = newf->fdt;
   open_files = FilesCountOpenFiles(old_fdt);

   expand = 0;

#if 0
   /* XXX: how is maxFdset different than maxFds? 
    * Do we need it? */
   if (open_files > new_fdt->maxFdset) {
      ASSERT_UNIMPLEMENTED(0);
      new_fdt->maxFdset = 0;
      expand = 1;
   }
#endif

   if (open_files > new_fdt->maxFds) {
      ASSERT_UNIMPLEMENTED(0);
      new_fdt->maxFds = 0;
      expand = 1;
   }

   if (expand) {
      /* XXX: expand the fd table and associated fdsets */
      ASSERT_UNIMPLEMENTED(0);
   }

   old_fds = old_fdt->vfdTable;
   new_fds = new_fdt->vfdTable;

   memcpy(new_fdt->openFds->fds_bits, old_fdt->openFds->fds_bits, open_files/8);
   memcpy(new_fdt->closeOnExec->fds_bits, old_fdt->closeOnExec->fds_bits, open_files/8);

   DEBUG_MSG(5, "open_files=%d\n", open_files);
   for (i = open_files; i != 0; i--) {
      struct FileStruct *f = *old_fds++;

      DEBUG_MSG(7, "i=%d f=0x%x\n", i, f);
      if (f) {
         ASSERT(Files_IsLocked(oldf));
         File_GetFile(f);
      } else {
         FD_CLR(open_files-i, new_fdt->openFds);
      }

      *new_fds = f;
      new_fds++;
   }


   /* Clear the remaining, unused entries. */
   size = (new_fdt->maxFds - open_files) * sizeof(struct FileStruct*);

   memset(new_fds, 0, size);

   if (new_fdt->maxFds > open_files) {
      int left = (new_fdt->maxFds-open_files)/8;
      int start = open_files / (8 * sizeof(ulong));

      memset(&new_fdt->openFds->fds_bits[start], 0, left);
      memset(&new_fdt->closeOnExec->fds_bits[start], 0, left);
   }
   
out:
   return newf;
}

static int 
CopyFilesUnlocked(ulong cloneFlags, struct Task *tsk)
{
   struct FilesStruct *oldf, *newf;
   int err = 0;

   oldf = current->files;

   ASSERT(oldf);

   ASSERT(Files_IsLocked(oldf));

   if (cloneFlags & CLONE_FILES) {
      oldf->count++;
      goto out;
   }

   newf = FilesDupFd(oldf, &err);
   if (!newf) {
      goto out;
   }

   tsk->files = newf;
   err = 0;

out:
   D__;
   return err;
}


int 
Files_Fork(ulong cloneFlags, struct Task *tsk)
{
   struct FilesStruct *oldf;
   int err = 0;

	/*
	 * A background process may not have any files.
    * In that case, there is nothing to copy. So it's a success.
	 */
   oldf = current->files;
   if (!oldf) {
      goto out;
   }

   Files_Lock(oldf);

   err = CopyFilesUnlocked(cloneFlags, tsk);

   Files_Unlock(oldf);

out:
   return err;
}

static void
FilesFlushOld(struct FilesStruct *files)
{
   long j = -1;
   struct FdTableStruct *fdt;

   Files_Lock(files);

   for (;;) {
      ulong set, i;

      j++;
      i = j * NFDBITS;
      fdt = files->fdt;
      if (i >= fdt->maxFds) {
         break;
      }
      set = fdt->closeOnExec->fds_bits[j];
      if (!set) {
         continue;
      }
      fdt->closeOnExec->fds_bits[j] = 0;

      /* sys_close will acquire the files lock, so
       * unlock it before invoking it. */
      Files_Unlock(files);

      for ( ; set ; i++, set >>= 1) {
         if (set & 1) {
            sys_close(i);
         }
      }

      Files_Lock(files);
   }

   Files_Unlock(files);
}

static int
FilesUnshare(struct FilesStruct *oldf)
{
   int err;

   DEBUG_MSG(5, "oldf->count=%d\n", oldf->count);

   /* No need to unshare if we're not sharing with anyone. */
   if (oldf->count > 1) {
      err = CopyFilesUnlocked(0, current);

      if (!err) {
         ASSERT(current->files != oldf);
      } else {
         /* XXX: is this possible? can it ever happen? */
         ASSERT_UNIMPLEMENTED(0);
         current->files = oldf;
      }
   } else {
      ASSERT(oldf->count == 1);
      ASSERT(current->files == oldf);
      oldf->count++;
   }

   return err;
}

void
Files_Exec()
{
   struct FilesStruct *oldf;
   int isUnused;

   oldf = current->files;
   ASSERT(oldf);

   Files_Lock(oldf);

   /* Starting a new prog, so we need a private files table. */
   FilesUnshare(oldf);

   oldf->count--;
   isUnused = (oldf->count == 0);

   Files_Unlock(oldf);

   FilesPutWork(oldf, isUnused);
   oldf = NULL;

   /* Close close-on-exec files marked by old program. */
   ASSERT(current->files);
   FilesFlushOld(current->files);
}


void
Files_Exit(struct Task *tsk)
{
   struct FilesStruct *files = tsk->files;

   ASSERT_TASKLIST_LOCKED();

   /* XXX: why wouldn't it have an fd table?! */
   ASSERT_UNIMPLEMENTED(files);

   D__;

   if (files) {
      tsk->files = NULL;
      FilesPut(files);
   }
   D__;
}
