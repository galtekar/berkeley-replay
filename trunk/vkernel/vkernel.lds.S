/* This file is preprocessed into vkernel.lds. */

#define PAGE_SIZE 4096

#include "vkernel.lds.h"
#include "asm-offsets.h"

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH("i386")

ENTRY(_start)

SECTIONS
{
	. = __IMAGE_START;

   /* vkernel-provided code that runs at user-mode
    * (similar to that of the Linux kernel's vsyscall page).
    *
    * This has to come first, since it's technically app-level
    * code and not part of the vkernel, even though it is in
    * the image. That is, we want any syscalls made from this page
    * to be emulated and not actually be executed by the kernel. */
   .vsyscall : {
   __vdso_text_start = .;
      *(.vsyscall)
   }
   __vdso_text_end = .;

   __kernel_text_start = .;
	.text : {
      *(.text)
	}
	__kernel_text_end = .;


   /* We use exception tables for detecting faulting
    * accesses made by apps and recovering from them
    * gracefully (e.g., by returning -EACCESS). We store
    * this table in a special section in the executable
    * so that new entries can easily be added from
    * assembly source file. */
	. = ALIGN(16);
   __StartExceptionTable = .;
   .__ex_table : {
      *(.__ex_table)
   }
   __StopExceptionTable = .;

   . = ALIGN(16);
   __initcall_start = .;
   .initcall0.init : { *(.initcall0.init) }
   .initcall1.init : { *(.initcall1.init) }
   .initcall2.init : { *(.initcall2.init) }
   .initcall3.init : { *(.initcall3.init) }
   .initcall4.init : { *(.initcall4.init) }
   .initcall5.init : { *(.initcall5.init) }
   .initcall6.init : { *(.initcall5.init) }
   __initcall_end = .;
   __finicall_start = .;
   .finicall0.init : { *(.finicall0.fini) }
   __finicall_end = .;
   __mod_desc_start = .;
   .moddesc : { 
      __modbasic_desc_start = .;
      *(.mod_desc_basic) 
      __modbasic_desc_end = .;
      __modadv_desc_start = .;
      *(.mod_desc_advanced) 
      __modadv_desc_end = .;
      __modanalysis_desc_start = .;
      *(.mod_desc_analysis) 
      __modanalysis_desc_end = .;
   }
   __mod_desc_end = .;

	. = ALIGN(PAGE_SIZE);
	.data : {
      *(.data)
	}

	. = ALIGN(PAGE_SIZE);
	.bss : {
      *(.bss)
	}

   . = ALIGN(PAGE_SIZE);
   .tls : {
   __tdata_start = .;
      *(.tdata)
   __tdata_end = .;
      *(.tbss)
   }
   __tls_size = SIZEOF(.tls);


	. = ALIGN(PAGE_SIZE);
	.sharedarea : {
      /* Careful: SHAREDAREA may have high > PAGE_SIZE default
      alignment. Thus this label should be placed inside the
      SHAREDAREA output descriptor as it is now. */
      __sharedarea_start = .;
		*(.sharedarea)
	}
   . = ALIGN(PAGE_SIZE);
   __sharedarea_end = .;
	. = ALIGN(TASK_SIZE);
   __sharedarea_heap_start = .;
}
