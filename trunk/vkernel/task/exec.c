#include <errno.h>
#include <sys/mman.h>

#include "vkernel/public.h"
#include "private.h"

/* 
 * We need to intercept user-vkernel communication, but these exec
 * routines don't always access user memory; some of it is to/from the
 * vkernel. Hence these macros.
 */
#define MACRO_may_get_user(x, ptr) \
({ \
   int ures = 0; \
   if (!Task_IsAddrInUser((ulong)ptr)) { \
      memcpy(&(x), ptr, sizeof(x)); \
   } else { \
      ures = __get_user(x, ptr); \
   } \
   ures; \
})

#define STRNLEN_USER(sP, n) \
({ \
   int sres; \
   if (!Task_IsAddrInUser((ulong)sP)) { \
      sres = strnlen_user(sP, n); \
   } else { \
      sres = Task_CountUserStringLen(sP, n); \
   } \
   sres; \
})

#define MACRO_may_copy_from_user(toP, fromP, len) \
({ \
   int ures = 0; \
   if (!Task_IsAddrInUser((ulong)fromP)) { \
      memcpy(toP, fromP, len); \
   } else { \
      Task_CopyFromUser(toP, fromP, len); \
   } \
   ures; \
})


/*
 * Counts the number of strings in array ARGV.
 */
static int 
ExecCountStrings(char __user * __user * argv, int max)
{
	int i = 0;

	if (argv != NULL) {
		for (;;) {
			char __user * p;

			if (MACRO_may_get_user(p, argv))
				return -EFAULT;

			if (!p)
				break;
			argv++;
			if(++i > max)
				return -E2BIG;
		}
	}
	return i;
}

int
ExecCopyStrings(int argc, char __user * __user * argv, 
                 struct LinuxBinPrm *bprm)
{
   int ret;
   ulong *p = &bprm->p;
   char *page = bprm->tmpArgs;

   while (argc-- > 0) {
      char __user *str; /* argv[argc] */
      int len, err;
      int res;

      DEBUG_MSG(8, "p=0x%x\n", argv+argc);
      res = MACRO_may_get_user(str, argv+argc);
      DEBUG_MSG(8, "str=0x%x\n", str);

      len = STRNLEN_USER(str, *p);

      /* Get argv[argc] pointer. */
      if (res ||
            /* len should count NULL terminator as well */
            !len) {
         D__;
         ret = -EFAULT;
         goto out;
      }

      /* Arg length shouldn't exceed space available for all args. */
      if (*p < (uint)len) {
         ret = -E2BIG;
         goto out;
      }

      /* Adjust available arg space by length of string we just
       * accepted. */
      *p -= len;

      /* Start filling from the top of page (recall that the stack grows
       * down). */
      err = MACRO_may_copy_from_user(page + *p, str, len);
      if (err) {
         D__;
         ret = -EFAULT;
         goto out;
      }
   }

   ret = 0;
out:
   return ret;
}

int
Exec_CopyStringsKernel(int argc, char **argv, struct LinuxBinPrm *bprm)
{
   return ExecCopyStrings(argc, (char __user * __user *) argv, bprm);
}

static
int ExecFlushOld(struct LinuxBinPrm *bprm)
{
   int retval = 0;

   /* XXX: nuke all other threads in the group */
   WARN_XXX(0);


   /* Reset the signal stack. */
   current->sas_ss_sp = current->sas_ss_size = 0;


   /* Make sure we have private file handles. */
   Files_Exec();

   /* XXX: make sure we have private signal handling table. */
   WARN_XXX(0);
   ASSERT_UNIMPLEMENTED(current->mm->users == 1);

   Signal_FlushSignalHandlers(current, 0 /* = force default */); 


#define PR_SET_NAME    15		/* Set process name */ 
/* Task command name length */
#define TASK_COMM_LEN 16
   {
      const char *fname = File_Name(bprm->file);
      char *basename = strrchr(fname, '/');
      char ncomm[TASK_COMM_LEN] = "";

      ASSERT(basename);
      basename++;

      /* XXX: what if neither logging or replaying? */
      snprintf(ncomm, sizeof(ncomm), "%s:%s",
            VCPU_IsLogging() ? "log" : "rep",
            basename);

      retval = syscall(SYS_prctl, PR_SET_NAME, ncomm);
      ASSERT(!retval);
   }

   return retval;
}

struct FileStruct *
Exec_Open(const char *filename)
{
   struct FileStruct *filp;
   mode_t mode;

   filp = File_Open(AT_FDCWD, filename, O_RDONLY, 0, 1);
   if (IS_ERR(filp)) {
      goto out;
   }

   mode = File_Inode(filp)->mode;

   /* Should be a file and should be executable. */
   if (!S_ISREG(mode) || !(mode & S_IXUGO)) {
      File_Put(filp);
      filp = ERR_PTR(-EACCES);
      goto out;
   }

out:
   return filp;
}

static void
ExecDone(const char *filename)
{
   filename = filename;
   /* GDB breakpoint hook. */
}

int
Exec_PrepareBprm(struct LinuxBinPrm *bprm)
{
   int err;

   /* Read a little bit of the exec into the bprm buffer so
    * that handlers can determine if the file applies to them or not. */

   ASSERT(bprm->file);

   err = File_KernRead(bprm->file, bprm->buf, BINPRM_BUF_SIZE, 0);
   if (err > 0) {
      err = 0;
   } else if (err == 0) {
      err = -EIO;
   }

   return err;
}

struct BinaryFormat {
   char name[64];
	int (*load_binary)(struct LinuxBinPrm *, TaskRegs * regs);
};

struct BinaryFormat formats[] = {
   { .name = "ELF", .load_binary = &ELF_LoadBinary },
   { .name = "Script", .load_binary = &Script_Load },
};
const int NUM_BINFMTS = sizeof(formats) / sizeof(formats[0]);

int
Exec_SearchBinaryHandler(struct LinuxBinPrm *bprm, TaskRegs *regs)
{
   int err, i;

   for (i = 0; i < NUM_BINFMTS; i++) {
      struct BinaryFormat * fmt = &formats[i];
      int (*fn)(struct LinuxBinPrm *, TaskRegs *) = fmt->load_binary;

      ASSERT(fn);

      err = fn(bprm, regs);

      if (err >= 0) {
         /* Success. */
         DEBUG_MSG(5, "%s binary loaded.\n", formats[i].name);
         return err;
      }
   }

   return err;
}

/*
 * Chop off the first arg (argv[0]) from the bprm->tmpArgs buffer. 
 */
void
Exec_RemoveArgZero(struct LinuxBinPrm *bprm)
{
   if (bprm->argc) {
      char * kaddr;

      kaddr = bprm->tmpArgs + bprm->p;
      while (bprm->p++, *(kaddr++));
      bprm->argc--;
   }
}

int
Exec_DoExecve(const char *filename, char __user * __user *argv,
      char __user * __user *envp)
{
   struct LinuxBinPrm *bprm = NULL;
   int retval;
   extern void UserMem_Exec();

   DEBUG_MSG(5, "filename=%s argv=0x%x envp=0x%x\n", filename, argv, envp);

   bprm = SharedArea_Malloc(sizeof(*bprm));
   bprm->tmpArgs = SharedArea_Malloc(MAX_ARG_BYTES);

   if (!bprm) {
      retval = -ENOMEM;
      goto out_ret;
   }

   bprm->file = Exec_Open(filename);
   if (IS_ERR(bprm->file)) {
      retval = PTR_ERR(bprm->file);
      bprm->file = NULL;
      goto out_kfree;
   }

   bprm->p = MAX_ARG_BYTES; 
   bprm->filename = (char*)filename;
   bprm->interp = (char*) filename;
   bprm->sh_bang = 0;

   bprm->argc = ExecCountStrings(argv, bprm->p / sizeof(void *));
   if ((retval = bprm->argc) < 0) {
      goto out_putf;
   }

   bprm->envc = ExecCountStrings(envp, bprm->p / sizeof(void*));
   if ((retval = bprm->envc) < 0) {
      goto out_putf;
   }

   DEBUG_MSG(5, "bprm count: argc=%d envc=%d\n", bprm->argc, bprm->envc);

   /* Copy args into vkernel before clearing the address space. */
   retval = ExecCopyStrings(bprm->envc, envp, bprm);
   if (retval < 0) {
      D__;
      goto out_putf;
   }

   retval = ExecCopyStrings(bprm->argc, argv, bprm);
   if (retval < 0) {
      D__;
      goto out_putf;
   }


      /* It is now safe to clear the address-space -- we've copied the arguments
       * from the old address space. */
   UserMem_Exec();

   retval = Exec_PrepareBprm(bprm);
   ASSERT_UNIMPLEMENTED(!retval);

   /* XXX: point of no return -- you've just nuked the old address space
    * and there's no way to get it back. */

   /* XXX: why not put this at the very end? */
   Task_Exec();
   BT_Exec();

   retval = Exec_SearchBinaryHandler(bprm, curr_regs);
   if (retval) {
      /* XXX: old address space is gone -- can't return */
      ASSERT_UNIMPLEMENTED(0);
      goto out_putf;
   }

   retval = ExecFlushOld(bprm);
   ASSERT_UNIMPLEMENTED(!retval);

   FileSys_Exec();

   Module_OnExec();


out_putf:
   ASSERT(bprm->file);
   File_Close(bprm->file);
   bprm->file = NULL;
out_kfree:
   SharedArea_Free(bprm->tmpArgs, MAX_ARG_BYTES);
   bprm->tmpArgs = NULL;
   ASSERT(!bprm->file);
   SharedArea_Free(bprm, sizeof(*bprm));
   bprm = NULL;
out_ret:
   ExecDone(filename);
   ASSERT(!bprm);
   return retval;
}
