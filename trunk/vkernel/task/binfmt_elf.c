/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <elf.h>
#include <limits.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/types.h>

#include "vkernel/public.h"
#include "private.h"


#define STACK_ADD(sp, items) ((ulong __user *)(sp) - (items))
#define STACK_ROUND(sp, items) \
	(((unsigned long) (sp - items)) &~ 15UL)
#define STACK_ALLOC(sp, len) ({ sp -= len ; sp; })

void
Entry_Vsyscall()
{
   ASSERT_UNIMPLEMENTED(0);
}

/* 
 * We need to explicitly zero any fractional pages
 * after the data section (i.e. bss).  This would
 * contain the junk from the file that should not
 * be in memory
 */
static int
ElfPadZero(ulong elf_bss)
{
   int err = 0;
   ulong rembytes;

   rembytes = PAGE_OFFSET(elf_bss);
   if (rembytes) {
      rembytes = PAGE_SIZE - rembytes;
      if (Task_ClearUser((void __user *) elf_bss, rembytes)) {
         err = -EFAULT;
      }
   }

   return err;
}

static ulong
arch_align_stack(unsigned long sp)
{
#if 0
	if (randomize_va_space)
		sp -= get_random_int() % 8192;
#endif
	return sp & ~0xf;
}

/* Setup the user-mode stack for execution: this mainly involves
 * placing argc, argv, and envp vectors, as well as the auxv
 * table. At the end, bprm->p should point to the final esp
 * value before we start the app. */
static int
ELFCreateTables(Elf32_Ehdr* ehdrp, ulong load_addr, ulong interp_load_addr,
      struct LinuxBinPrm *bprm)
{
   ulong p = bprm->p;
   int argc = bprm->argc;
   int envc = bprm->envc;
   ulong __user * sp, *argv, *envp;
   ulong *elf_info;
   int ei_index = 0;
   int items;
   const char *k_platform = env.platform;
   ulong __user *u_platform;

   D__;
   DEBUG_MSG(5, "argc=%d envc=%d\n", argc, envc);

   /*
	 * If this architecture has a platform capability string, copy it
	 * to userspace.  In some cases (Sparc), this info is impossible
	 * for userspace to get any other way, in others (i386) it is
	 * merely difficult.
	 */
	u_platform = NULL;
	if (k_platform) {
		size_t len = strlen(k_platform) + 1;

		p = arch_align_stack(p);

		u_platform = (ulong __user *)STACK_ALLOC(p, len);
		if (Task_CopyToUser(u_platform, (void*)k_platform, len))
			return -EFAULT;
	}

   D__;

   /* Create the ELF interpreter info */
   elf_info = current->saved_auxv;
#define NEW_AUX_ENT(id, val) \
   do { \
      ASSERT(ei_index < AT_VECTOR_SIZE); \
      elf_info[ei_index++] = id; \
      elf_info[ei_index++] = val; \
      DEBUG_MSG(5, "id=%d val=0x%x (%d)\n", id, val, val); \
   } while (0) 

 
   /* XXX: make sure these values are deterministic across
    * multi-platform executions. */
   WARN_XXX(0);
   NEW_AUX_ENT(AT_SYSINFO, (ulong)&Gate_vsyscall);
   NEW_AUX_ENT(AT_SYSINFO_EHDR, env.auxv[AT_SYSINFO_EHDR]);
   NEW_AUX_ENT(AT_HWCAP, env.auxv[AT_HWCAP]);
   NEW_AUX_ENT(AT_PAGESZ, env.auxv[AT_PAGESZ]);
   NEW_AUX_ENT(AT_CLKTCK, env.auxv[AT_CLKTCK]);
	NEW_AUX_ENT(AT_PHDR, load_addr + ehdrp->e_phoff);
	NEW_AUX_ENT(AT_PHENT, ehdrp->e_phentsize);
	NEW_AUX_ENT(AT_PHNUM, ehdrp->e_phnum);
	NEW_AUX_ENT(AT_BASE, interp_load_addr);
	NEW_AUX_ENT(AT_FLAGS, 0);
	NEW_AUX_ENT(AT_ENTRY, ehdrp->e_entry);
   NEW_AUX_ENT(AT_UID, env.auxv[AT_UID]);
   NEW_AUX_ENT(AT_EUID, env.auxv[AT_EUID]);
   NEW_AUX_ENT(AT_GID, env.auxv[AT_GID]);
   NEW_AUX_ENT(AT_EGID, env.auxv[AT_EGID]);
   NEW_AUX_ENT(AT_SECURE, env.auxv[AT_SECURE]);
   if (k_platform) {
      NEW_AUX_ENT(AT_PLATFORM, (ulong)u_platform);
   }
   /* XXX: AT_EXECFD */

#undef NEW_AUX_ENT 

   /* AT_NULL is zero; clear the rest too */
   memset(&elf_info[ei_index], 0,
         sizeof current->saved_auxv - ei_index * sizeof elf_info[0]);

   /* And advance past the AT_NULL entry.  */
	ei_index += 2;

   /* Make space for the auxv table and argp/envp pointers. */
   sp = STACK_ADD(p, ei_index);
   items = (argc + 1) + (envc + 1);
   items++; /* for argc */
   bprm->p = STACK_ROUND(sp, items);

   sp = (ulong __user *)bprm->p;

   D__;
   /* Now, let's put argc and argv, envp on the stack */
   if (__put_user(argc, sp++)) {
      return -EFAULT;
   }

   D__;
   argv = sp;
   envp = argv + argc + 1;

   /* Populate argv and envp pointers -- they should point to
    * the arg strings at the base of the stack (highest points) once 
    * we are done. */
   p = (ulong)current->arg_start;
   ASSERT(p);
   while (argc-- > 0) {
      size_t len;
      __put_user(p, argv++);
      len = Task_CountUserStringLen((void __user *)p, PAGE_SIZE*MAX_ARG_PAGES);
      if (!len || len > PAGE_SIZE*MAX_ARG_PAGES) {
         return 0;
      }
      p += len;
   }
   D__;
   if (__put_user(0, argv)) {
      return -EFAULT;
   }
#if 0
   /* XXX: do we need these pointers? */
   current->arg_end = current->env_start = p;
#endif
   D__;
   while (envc-- > 0) {
      size_t len;
      __put_user(p, envp++);
      len = Task_CountUserStringLen((void __user *)p, PAGE_SIZE*MAX_ARG_PAGES);
      if (!len || len > PAGE_SIZE*MAX_ARG_PAGES) {
         return 0;
      }
      p += len;
   }
   if (__put_user(0, envp)) {
      return -EFAULT;
   }
#if 0
   /* XXX: do we need these pointers? */
   current->env_end = p;
#endif

   D__;
   /* Now put in the elf_info (auxv) table. */
   sp = envp + 1;
   DEBUG_MSG(5, "auxv=0x%x ei_index=%d\n", sp, ei_index);
   if (Task_CopyToUser(sp, elf_info, ei_index * sizeof(ulong))) {
      return -EFAULT;
   }

   return 0;
}

static
void PrintPhdr(Elf32_Phdr *phdr)
{
   DEBUG_MSG(3, "Type: %2d\n"
         "Offset: 0x%x\n"
         "Vaddr: 0x%x\n"
         "Paddr: 0x%x\n"
         "Filesz: 0x%x\n"
         "Memsz: 0x%8x\n"
         "Flags: 0x%x\n"
         "Align: 0x%x\n",
         phdr->p_type,
         phdr->p_offset,
         phdr->p_vaddr,
         phdr->p_paddr,
         phdr->p_filesz,
         phdr->p_memsz,
         phdr->p_flags, 
         phdr->p_align);
}

static ulong 
ELFLoadInterp(struct FileStruct *filp, ulong *interp_load_addr) 
{
   Elf32_Ehdr ehdr;
   Elf32_Phdr* phdrs = NULL;
   size_t phdrs_size;
   ulong load_addr = 0, k, elf_bss = 0, last_bss = 0;
   ulong error = ~0UL;
   int load_addr_set = 0;
   int i, res;

   /* Read the entry point header. */
   if (File_KernRead(filp, &ehdr, sizeof(ehdr), -1) != sizeof(ehdr)) {
      ASSERT_UNIMPLEMENTED(0);
   }

   /* First, some simple consistency checks. */
   if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
      goto out;
   }

   /* BUG: make sure the architecture is right. */


   if (ehdr.e_phentsize != sizeof(Elf32_Phdr)) {
      goto out;
   }

   if (ehdr.e_phnum < 1 || ehdr.e_phnum > 65536U / sizeof(Elf32_Phdr)) {
      goto out;
   }

   /* Read the section headers into an array of program headers. */
   phdrs_size = ehdr.e_phentsize * ehdr.e_phnum;

   phdrs = (Elf32_Phdr*) SharedArea_Malloc(phdrs_size);
   if (!phdrs) { goto out; }

   /* Seek to the program headers. */
   if (File_Seek(filp, ehdr.e_phoff, SEEK_SET) < 0) {
      ASSERT_UNIMPLEMENTED(0);
   }

   res = File_KernRead(filp, phdrs, phdrs_size, -1);
   ASSERT_UNIMPLEMENTED(res == (int)phdrs_size);

   DEBUG_MSG(3, "Loading INTERPRETER sections:\n");
   for (i = 0; i < ehdr.e_phnum; i++) {
      ulong map_addr, vaddr;
      ulong offset, filesz, align_diff;
      int elf_prot, elf_type;
      Elf32_Phdr *php = &phdrs[i];

      elf_prot = 0;

      if (php->p_type == PT_LOAD) {
         PrintPhdr(php);

         /* Align the starting address by rounding down. */
         vaddr = php->p_vaddr & ~(php->p_align - 1);
         DEBUG_MSG(5, "vaddr=0x%x\n", vaddr);

         /* We need to adjust the file offest and size, by how much
          * we round the starting address down. This is because we
          * want data to be mapped into the same location even
          * after rounding down. */
         align_diff = php->p_vaddr - vaddr;

         DEBUG_MSG(4, "Allocating segment at 0x%x, aligndiff=0x%x.\n", vaddr,
               align_diff);


         offset = php->p_offset - (align_diff);
         filesz = php->p_filesz + align_diff;

         ASSERT(PAGE_ALIGNED(offset));

         if (php->p_flags & PF_R) elf_prot |= PROT_READ;
         if (php->p_flags & PF_W) elf_prot |= PROT_WRITE;
         if (php->p_flags & PF_X) elf_prot |= PROT_EXEC;

         elf_type = MAP_PRIVATE | MAP_DENYWRITE;
         if (ehdr.e_type == ET_EXEC || load_addr_set) {
            elf_type |= MAP_FIXED;
         }

         if (filesz) {
            /* NOTE: Offset argument of mmap2 is in pages, not bytes! */
            map_addr = (ulong) UserMem_Map(
                  filp,
                  /* Add load_addr to ensure that section is contiguous with
                   * first loaded section. */
                  load_addr + vaddr,
                  filesz,
                  elf_prot,
                  elf_type,
                  offset / PAGE_SIZE);
         } else {
            map_addr = load_addr + vaddr;
         }

         ASSERT(!SYSERR(map_addr));
         ASSERT(map_addr > 0);

         /* We may not be able to map sections at the address suggested in the
          * binary (i.e., vaddr). In that case, we still need to ensure that
          * all sections are continguous with the first loaded section--where
          * ever that may be mapped. Here, we compute load_addr--the amount
          * we need to shift all loaded sections such that they are contiguous
          * with the first loaded section. Note that it may be a negative
          * number. */
         if (!load_addr_set && ehdr.e_type == ET_DYN) {
            load_addr = map_addr - PAGE_START(vaddr);
            DEBUG_MSG(5, 
                  "map_addr=0x%x PAGE_START(vaddr)=0x%x load_addr=0x%x\n", 
                  map_addr, PAGE_START(vaddr), load_addr);
            load_addr_set = 1;
         }

         k = load_addr + php->p_vaddr + php->p_filesz;
         /* XXX: handle BAD_ADDR(k) */
         if (k > elf_bss) {
            elf_bss = k;
         }

         k = load_addr + php->p_memsz + php->p_vaddr;
         if (k > last_bss) {
            last_bss = k;
         }
      }
   }

   if (ElfPadZero(elf_bss)) {
      error = -EFAULT;
      goto out_free_headers;
   }

   /* Round up to nearest page boundary -- this is what we've mapped
    * so far. */
   elf_bss = PAGE_START(elf_bss + PAGE_SIZE - 1);

   /* Map the remaining portion of the bss. */
   if (last_bss > elf_bss) {
      error = UserMem_Brk(elf_bss, last_bss - elf_bss);
      if (BAD_ADDR(error)) {
         goto out_free_headers;
      }
   }

   *interp_load_addr = load_addr;
   error = ehdr.e_entry + load_addr;

out_free_headers:
   SharedArea_Free(phdrs, phdrs_size);
   phdrs = NULL;
out:
   ASSERT(!phdrs);
   return error;
}

static int
ELFSetupStack(struct LinuxBinPrm *bprm)
{
   int err;
   ulong stackaddr, stack_base, stack_top;

#define USER_STACK_SIZE (1 << 23)
   stackaddr = UserMem_Map(NULL, 0, USER_STACK_SIZE, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS, 0);
   if (SYSERR(stackaddr)) {
      err = (int) stackaddr;
      goto out;
   }

   ASSERT(Task_IsAddrInUser(stackaddr));
   current->stack_addr = stackaddr;
   current->stack_size = USER_STACK_SIZE;

   stack_top = stackaddr + USER_STACK_SIZE;
   stack_base = stack_top - MAX_ARG_PAGES*PAGE_SIZE;
   stack_base = PAGE_ALIGN(stack_base);
   bprm->stack_base = (char*)stack_base;

   DEBUG_MSG(5, "stackaddr=0x%x stack_base=0x%x\n", stackaddr, stack_base);

   /* Copy the args into the new image's stack. */
   err = Task_CopyToUser(bprm->stack_base+bprm->p, bprm->tmpArgs+bprm->p, 
               MAX_ARG_BYTES - bprm->p);
   ASSERT(!err);

   /* setup arg pages: bprm->p now contains the number of
    * bytes unused by argv and envp strings */
   bprm->p += stack_base; /* points to argv strings */
   current->arg_start = (void*)bprm->p;

   /* bprm->p should now point to the start of the argv strings
    * on the user-mode stack. */

out:
   return err;
}


#define INTERPRETER_NONE 0
#define INTERPRETER_AOUT 1
#define INTERPRETER_ELF 2

int 
ELF_LoadBinary(struct LinuxBinPrm *bprm, TaskRegs *regs) 
{
   struct FileStruct *filp = NULL, *interpreter = NULL;
   uint interpreter_type = INTERPRETER_NONE;
   Elf32_Ehdr *ehdrp;
   Elf32_Phdr *phdrs = NULL;
   size_t phdrs_size;
   ulong map_addr, offset, filesz, align_diff;
   char *elf_interpreter = NULL;
   ulong interp_load_addr = 0;
   ulong load_addr = 0, load_bias = 0;
   int load_addr_set = 0;
   int i, retval = 0;
   ulong entry_eip, elf_bss = 0, elf_brk = 0;


   filp = bprm->file;
   ASSERT(!IS_ERR(filp));

   ehdrp = (Elf32_Ehdr*) bprm->buf;

   retval = -ENOEXEC;
   /* First, some simple consistency checks. */
   if (memcmp(ehdrp->e_ident, ELFMAG, SELFMAG) != 0) {
      goto out;
   }

   if (ehdrp->e_type != ET_EXEC && ehdrp->e_type != ET_DYN) {
      goto out;
   }

   /* BUG: check executable is right architecture. */


   if (ehdrp->e_phentsize != sizeof(Elf32_Phdr)) {
      goto out;
   }

   if (ehdrp->e_phnum < 1 || ehdrp->e_phnum > 65536U / sizeof(Elf32_Phdr)) {
      goto out;
   }


   /* Read the section headers into an array of program headers. */
   phdrs_size = ehdrp->e_phentsize * ehdrp->e_phnum;

   retval = -ENOMEM;
   phdrs = (Elf32_Phdr*) SharedArea_Malloc(phdrs_size);
   if (!phdrs) { goto out; }

   /* Seek to and read in the program headers. */
   retval = File_Seek(filp, ehdrp->e_phoff, SEEK_SET);
   if (retval < 0) {
      goto out_free_headers;
   }

   retval = File_KernRead(filp, phdrs, phdrs_size, -1);
   if ((uint)retval != phdrs_size) {
      goto out_free_headers;
   }

   /* Read the interpreter (i.e., dynamic linker) filename. */
   for (i = 0; i < ehdrp->e_phnum; i++) {
      if (phdrs[i].p_type == PT_INTERP) {
         elf_interpreter = SharedArea_Malloc(PATH_MAX);

         retval = File_Seek(filp, phdrs[i].p_offset, SEEK_SET);
         if (retval < 0) {
            goto out_free_headers;
         }

         retval = File_KernRead(filp, elf_interpreter, phdrs[i].p_filesz, -1);
         if ((uint)retval != phdrs[i].p_filesz) {
            goto out_free_headers;
         }

         if (elf_interpreter[phdrs[i].p_filesz - 1] != '\0') {
            /* Cleanup if path is not null-terminated. */
            ASSERT_UNIMPLEMENTED(0);
         }

         interpreter = Exec_Open(elf_interpreter);
         if (IS_ERR(interpreter)) {
            retval = PTR_ERR(interpreter);
            goto out_free_interp;
         }
      }
   }

   /* Consistency checks for the interepreter. */
   if (elf_interpreter) {
#if 0 /* XXX */
		interpreter_type = INTERPRETER_ELF | INTERPRETER_AOUT;

		/* Now figure out which format our binary is */
		if ((N_MAGIC(loc->interp_ex) != OMAGIC) &&
		    (N_MAGIC(loc->interp_ex) != ZMAGIC) &&
		    (N_MAGIC(loc->interp_ex) != QMAGIC))
			interpreter_type = INTERPRETER_ELF;

		if (memcmp(ehdrp->e_ident, ELFMAG, SELFMAG) != 0)
			interpreter_type &= ~INTERPRETER_ELF;

		retval = -ELIBBAD;
		if (!interpreter_type)
			goto out_close_interp;

		/* Make sure only one type was selected */
		if ((interpreter_type & INTERPRETER_ELF) &&
		     interpreter_type != INTERPRETER_ELF) {
	     		// FIXME - ratelimit this before re-enabling
			// printk(KERN_WARNING "ELF: Ambiguous type, using ELF\n");
			interpreter_type = INTERPRETER_ELF;
		}
#else
      interpreter_type = INTERPRETER_ELF;
#endif

#if 0 /* XXX */
		/* Verify the interpreter has a valid arch */
		if ((interpreter_type == INTERPRETER_ELF) &&
		    !elf_check_arch(&loc->interp_elf_ex))
			goto out_free_dentry;
#endif
   } else {
      /* XXX: set personality */
   }

   DEBUG_MSG(3, "Loading ELF sections:\n");
   for (i = 0; i < ehdrp->e_phnum; i++) {
      int elf_prot = 0, elf_flags;
      ulong k, vaddr;
      Elf32_Phdr* php = &phdrs[i];

      PrintPhdr(php);
      if (php->p_type != PT_LOAD) {
         DEBUG_MSG(5, "Not PT_LOAD, skipping.\n");
         continue;
      }


      if (elf_brk > elf_bss) {
         /* XXX: There was a PT_LOAD segment with p_memsz > p_filesz
            before this one. Map anonymous pages, if needed,
            and clear the area.  */
         ASSERT_UNIMPLEMENTED(0);
      }

      /* Align the starting address by rounding down. */
      vaddr = php->p_vaddr & ~(php->p_align - 1);

      align_diff = phdrs[i].p_vaddr - vaddr;

      DEBUG_MSG(4, "Allocating segment at 0x%x, aligndiff=0x%x.\n", 
            vaddr, align_diff);


      /* We need to adjust the file offest and size, by how much
       * we round the starting address down. This is because we
       * want file data to be mapped into the same location 
       * (phdrs[i].p_vaddr) even after rounding down. */
      offset = php->p_offset - (align_diff);
      ASSERT(PAGE_ALIGNED(offset));
      filesz = php->p_filesz + align_diff;


      if (php->p_flags & PF_R) elf_prot |= PROT_READ;
      if (php->p_flags & PF_W) elf_prot |= PROT_WRITE;
      if (php->p_flags & PF_X) elf_prot |= PROT_EXEC;

      elf_flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE;

      if (ehdrp->e_type == ET_EXEC || load_addr_set) {
         elf_flags |= MAP_FIXED;
      } else if (ehdrp->e_type == ET_DYN) {
#define ELF_ET_DYN_BASE         (__LINUX_KERNEL_START / 3 * 2)
         load_bias = PAGE_START(ELF_ET_DYN_BASE - vaddr);
      }

      if (filesz) {
         /* NOTE: Offset argument of mmap2 is in pages, not bytes! */
         map_addr = (ulong)UserMem_Map(
               filp,
               load_bias + vaddr, 
               filesz,
               elf_prot,
               elf_flags,
               /* We expect that offset is page aligned, so
                * there is no possibility of rounding truncation. */
               offset / PAGE_SIZE);

         ASSERT(PAGE_ALIGNED(offset));
         ASSERT(!SYSERR(map_addr));
      } else {
         /* A segment with zero filesize is perfectly valid. */
         map_addr = vaddr;
      }

      if (!load_addr_set) {
         load_addr_set = 1;
         load_addr = php->p_vaddr - php->p_offset;
         DEBUG_MSG(5, "load_addr=0x%x\n", load_addr);

         if (ehdrp->e_type == ET_DYN) {
            /* Telnet, ssh, and ld.so are this type of executable. */

            /* XXX: why do this? shouldn't it always be 0? */
            load_bias += map_addr - PAGE_START(load_bias + vaddr);

            load_addr += load_bias;
            DEBUG_MSG(5, "load_addr=0x%x load_bias=0x%x\n", 
                  load_addr, load_bias);
         }
      }

      /* Identify the bss section...we need to zero it out. 
       * The end of teh bss is the start of the brk (i.e., heap). */
      k = php->p_vaddr + php->p_filesz;
      if (k > elf_bss) {
         elf_bss = k;
      }

      k = php->p_vaddr + php->p_memsz;
      if (k > elf_brk) {
         elf_brk = k;
      }
   }

   ehdrp->e_entry += load_bias;
   elf_bss += load_bias;
   elf_brk += load_bias;

   /* Do this before loading the interpreter to ensure
    * that the interpreted doesn't occupy the mapping
    * where the brk must go. */
   retval = UserMem_SetBrk(elf_bss, elf_brk);
   if (retval) {
      /* Send task SIGKILL */
      ASSERT_UNIMPLEMENTED(0);
      goto out_close_interp;
   }

   if ((elf_bss != elf_brk) && ElfPadZero(elf_bss)) {
      ASSERT_UNIMPLEMENTED(0);
   }

   if (elf_interpreter) {
      /* XXX: Check for a.out --> assert-unimp */
      WARN_XXX(0);

      /* Dynamically linked executable. */
      ASSERT(interpreter);
      entry_eip = ELFLoadInterp(interpreter, &interp_load_addr);
   } else {
      /* Statically linked executable. */
      entry_eip = ehdrp->e_entry;
      if (BAD_ADDR(entry_eip)) {
         retval = IS_ERR((void*) entry_eip) ? (int) entry_eip : -EINVAL;
         goto out_close_interp;
      }
   }

   retval = ELFSetupStack(bprm);
   if (retval) {
      goto out_close_interp;
   }

   DEBUG_MSG(5, "load_addr=0x%x\n", load_addr);
   retval = ELFCreateTables(ehdrp, load_addr, interp_load_addr, bprm);
   if (retval) {
      /* XXX: Destroy stack. */
      ASSERT_UNIMPLEMENTED(0);
      goto out_close_interp;
   }

   /* Now bprm->p should point to argc's location on the user-mode
    * stack. */

   retval = 0;

   Task_StartThread(regs, entry_eip, bprm->p);
   DEBUG_MSG(5, "Resuming to EIP=0x%x ESP=0x%x\n", regs->R(eip), regs->R(esp));

out_close_interp:
   if (interpreter) {
      File_Close(interpreter);
      interpreter = NULL;
   }
out_free_interp:
   if (elf_interpreter) {
      SharedArea_Free(elf_interpreter, PATH_MAX);
      elf_interpreter = NULL;
   }
out_free_headers:
   SharedArea_Free(phdrs, phdrs_size);
   phdrs = NULL;
out:
   ASSERT(!interpreter);
   ASSERT(!elf_interpreter);
   ASSERT(!phdrs);
   return retval;
}
