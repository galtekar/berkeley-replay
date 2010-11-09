#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <assert.h>
#include <string.h>

#include "child.h"
#include "debug.h"

/* Save the child's general registers, since our code will be
   clobbering some of them. */
#define SAVE_CHILD_CONTEXT() struct user_regs_struct old_gregs; \
						save_gregs(pid, &old_gregs);

/* Restore the original code's general registers (which
   includes the PC). */
#define RESTORE_CHILD_CONTEXT() restore_gregs(pid, &old_gregs);

long Ptrace(enum __ptrace_request request, pid_t pid, void *addr,
    void *data) {

    long ret;

    errno = 0;
    ret = ptrace(request, pid, addr, data);

    if (errno != 0) {
        perror("ptrace");
    }

    return ret;
}

void save_gregs(pid_t pid, struct user_regs_struct* gregs) {
   int res;

	res = Ptrace(PTRACE_GETREGS, pid, NULL, gregs);

   ASSERT(res == 0);
}

void restore_gregs(pid_t pid, struct user_regs_struct* gregs) {
   int res;

	res = Ptrace(PTRACE_SETREGS, pid, NULL, gregs);

   ASSERT(res == 0);
}

int resume_child(pid_t pid, int* status, int should_wait) {
	int ret_pid = 0;

	/* Let the child continue execution. */
	if ((Ptrace(PTRACE_CONT, pid, NULL, 0)) != 0) {
      FATAL("cannot continue child\n");
	}

	if (should_wait) {
		assert(status != NULL);
		*status = 0;
		ret_pid = waitpid(pid, status, __WALL);	
		assert(ret_pid == pid);
	}

	return ret_pid;
}

int attach_child(pid_t pid, int* status, int should_wait) {
	int ret_pid = 0;

	*status = 0;
	/* Attach to the specified child process. */
	if ((Ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0)) {
		FATAL("unable to attach to pid %d\n", pid);
	}

	if (should_wait) {
		ret_pid = waitpid(pid, status, __WALL);	
		assert(ret_pid == pid);
	}

	return ret_pid;
}

int single_step_child(pid_t pid, int* status) {
	int ret_pid = 0;

	*status = 0;
	if ((Ptrace(PTRACE_SINGLESTEP, pid, NULL, 0)) != 0) {
		FATAL("cannot single step %d\n", pid);
	}

	ret_pid = waitpid(pid, status, __WALL);	
	assert(ret_pid == pid);

	return ret_pid;
}

void print_child_regs(pid_t pid) {
	struct user_regs_struct g;

	Ptrace(PTRACE_GETREGS, pid, NULL, &g);

	printf("Register dump for pid %d:\n", pid);
	printf("ebx=0x%.8lx\n"
			"ecx=0x%.8lx\n"
			"edx=0x%.8lx\n"
			"esi=0x%.8lx\n"
			"edi=0x%.8lx\n"
			"ebp=0x%.8lx\n"
			"eax=0x%.8lx\n"
			"xds=0x%.8lx\n"
			"xes=0x%.8lx\n"
			"xfs=0x%.8lx\n"
			"xgs=0x%.8lx\n"
			"orig_eax=0x%.8lx\n"
			"eip=0x%.8lx\n"
			"xcs=0x%.8lx\n"
			"eflags=0x%.8lx\n"
			"esp=0x%.8lx\n"
			"xss=0x%.8lx\n",
			g.ebx, g.ecx, g.edx, g.esi, g.edi, g.ebp, g.eax, g.xds, g.xes,
			g.xfs, g.xgs, g.orig_eax, g.eip, g.xcs, g.eflags, g.esp, g.xss);
}

/* Print's child's memory starting from addr for len bytes. */
void print_child_mem(pid_t pid, void* addr, int len) {
	int i;
	assert(addr != NULL);

	printf("Mem dump @ 0x%p for %d bytes\n", addr, len);

	char* caddr = (char*)addr;
	for (i = 0; i < len; i += sizeof(long)) {
		long word = Ptrace(PTRACE_PEEKTEXT, pid, (void*)(caddr + i), NULL);
		printf("%8p: %.8lx\n", caddr + i, word);
	}
}

/* Writes data in buf (of specified size) into location addr in
 * child's address space. 
 * BUG: write word size chunks only. What happens if only size
 * is not multiple of the word size?
 */
void copy_to_child(pid_t pid, void* dest, void* src, long size) {
	int i;
	assert(dest != NULL);
	assert(src != NULL);

	if (size >= 4) {
		char* csrc = (char*)src;
		long* iaddr = (long*)dest;
		for (i = 0; i < size; i += sizeof(long)) {
			long* lsrc = (long*)(csrc + i);

			if (Ptrace(PTRACE_POKEDATA, pid, (void*)iaddr, (void*)*lsrc) != 0) {
				FATAL("can't write to new segment\n");
			}
			iaddr++;
		}
	} else {
		/* Subword writes need to be handled so that they don't overwrite
		 * the entire word. */
		long src_word = *(long*)src;

		long word = Ptrace(PTRACE_PEEKTEXT, pid, dest, NULL);

		//printf("word=0x%x src_word=0x%x\n", word, src_word);

		src_word &= ~((signed)0xFF000000L >> (8 * (3 - size)));
		word &= ((signed)0xFF000000L >> (8 * (3 - size)));

		long new_word = word | src_word;

		//printf("word=0x%x src_word=0x%x new_word=0x%x\n", word, src_word, new_word);

		if (Ptrace(PTRACE_POKEDATA, pid, (void*)dest, (void*)new_word) != 0) {
			FATAL("can't write to new segment\n");
			exit(-1);
		}
	}
}


/* Copy len bytes from location src in the child's address space to
 * location dest in current address space. */
void copy_from_child(pid_t pid, void* dest, const void *src, long size) {
	int i;
	assert(dest != NULL);
	assert(src != NULL);

	char* saddr = (char*)src;
	char* daddr = (char*)dest;
	for (i = 0; i < size; i += sizeof(long)) {
		long* laddr = (long*)(daddr + i);

		long word = Ptrace(PTRACE_PEEKTEXT, pid, (void*)(saddr + i), NULL);
		*laddr = word;
	}
}

#define NR_WORD_BYTES sizeof(void*)
char *
strncpy_from_child(pid_t pid, char *dstP, const char __child *srcP, size_t n)
{
   const char __child *sP = srcP;
   char __child *dP = dstP;

   while (1) {
      char word[NR_WORD_BYTES+1];
      int len;

      copy_from_child(pid, word, sP, NR_WORD_BYTES);

      word[NR_WORD_BYTES] = 0;
      len = strlen(word);
      if (dP+len < dstP+n) {
         memcpy(dP, word, len);
      } else {
         /* Don't null terminate per strncpy semantics. */
         break;
      }

      if (len != NR_WORD_BYTES) {
         assert(len < NR_WORD_BYTES);
         /* String has terminated. */
         dP[len] = 0;
         break;
      }

      sP += NR_WORD_BYTES;
      dP += NR_WORD_BYTES;
   }

   return dstP;
}

long insert_child_func_breakpoint(pid_t pid, void* func_addr) {
	/* Place the TRAP after the frame has been set up. */
	void* real_break_addr = (void*)((long)func_addr + HEADER_SIZE);

	return insert_child_breakpoint(pid, real_break_addr);
}

void remove_child_func_breakpoint(pid_t pid, void* func_addr, long orig_word) {
	/* Place the TRAP after the frame has been set up. */
	void* real_break_addr = (void*)((long)func_addr + HEADER_SIZE);

	remove_child_breakpoint(pid, real_break_addr, orig_word);
}

long insert_child_breakpoint(pid_t pid, void* addr) {
	assert(addr != NULL);

	long orig_word;

	/* Save the word before overwriting it, thereby allowing us to
	 * restore it in the future. */
	copy_from_child(pid, &orig_word, addr, sizeof(long));

	/* Here we are careful to damage only the 1st byte, the rest of
	 * the word must be preserved. I can't think of a great reason why
	 * we need to be so careful, but it's useful to know that only the
	 * 1st byte will have changed. */
	long new_instr = (orig_word & ~(0xFF)) | 0xCC;

	/* Insert the breakpoint. */
	copy_to_child(pid, addr, &new_instr, sizeof(long));

	return orig_word;
}

/* Look for the substring ``5589e5'' under the current PC. If the PC
 * is pointing to once of these instructions then, we haven't
 * finished executing the preamble yet. Return the number of
 * single steps we have to perform to finish executing the preamble. */
static int is_child_in_preamble(pid_t pid) {
	long word_after, word_before, byte0, byte1, byte2;

	long pc = GET_REG(pid, eip);

	copy_from_child(pid, &word_after, (void*)pc, sizeof(long));

	copy_from_child(pid, &word_before, (void*) (pc - 2), sizeof(long));

	long curr_byte = (word_after & 0xFF);

	switch (curr_byte) {
		case 0x55:
			/* The next two bytes should be 0x89 and 0xe5. */
			byte1 = (word_after >> 8) & 0xFF;
			byte2 = (word_after >> 16) & 0xFF;

			if (byte1 == 0x89 && byte2 == 0xe5) {
				/* Need to perform 2 single steps to execute the push
				 * and the move. */
				return 2;
			} 
			break;
		case 0x89:
			/* The previous byte should 0x55 and the next should be 0xe5. */
			byte0 = (word_before >> 8) & 0xFF;
			byte2 = (word_after >> 8) & 0xFF;

			if (byte0 == 0x55 && byte2 == 0xe5) {
				/* Need to perform 1 single step to execute the move. */
				return 1;
			}
			break;
		case 0xe5:
			/* The previous two bytes should be 0x55 and 0x89. */
			byte0 = (word_before) & 0xFF;
			byte1 = (word_before >> 8) & 0xFF;

			if (byte0 == 0x55 && byte1 == 0x89) {
				/* This should never be the case since 0xe589 is one
				 * instruction and the PC should never be ``in between''
				 * the two. */
				assert(0);
			}
			break;

		default:
			return 0;
	}

	return 0;
}

/* Look for the substring ``c9c3'' under the current PC. If the PC
 * is pointing to once of these instructions then, we haven't
 * finished executing the epilogue yet. Return the number of
 * single steps we have to perform to finish executing it. */
static int is_child_in_conclusion(pid_t pid) {
	/* TODO: handle the case that the epilogue uses a ``move'' followed
	 * by a ``pop'' rather than a ``leave''. */

	long word_after, word_before, byte0, byte1, pc, curr_byte;

	pc = GET_REG(pid, eip);

	copy_from_child(pid, &word_after, (void*)pc, sizeof(long));

	copy_from_child(pid, &word_before, (void*) (pc - 1), sizeof(long));

	curr_byte = (word_after & 0xFF);

	switch (curr_byte) {
		case 0xC9:
			/* The next byte should be 0xc3. */
			byte1 = (word_after >> 8) & 0xFF;
	
			/* This function should be called before breakpoints are set. */
			assert(byte1 != 0xCC);

			if (byte1 == 0xC3) {
				/* Need to perform 2 single steps to execute the ``leave''
				 * and the ``ret''. */
				return 2;
			} 
			break;
		case 0xC3:
			/* The previous byte should 0xc9. */
			byte0 = word_before & 0xFF;

			/* This function should be called before breakpoints are set. */
			assert(byte0 != 0xCC);

			if (byte0 == 0xC9) {
				/* Need to perform 1 single step to execute the ``ret''. */
				return 1;
			}
			break;
		default:
			return 0;
	}

	return 0;
}

/* Inserts an indirect JMP instruction in child's memory at location ADDR.
 * The JMP is indirect through the location INDIR_ADDR. */
void insert_child_func_jump(pid_t pid, void* addr, long indir_addr) {
	long jump_instr = 0x25FF;
	long jump_instr_addr = (long)addr;

	assert(addr != NULL);
	/* Write the opcode header. */
	copy_to_child(pid, (void*)jump_instr_addr, &jump_instr, sizeof(jump_instr));

	/* Now write the indirect address. */
	copy_to_child(pid, (void*)(jump_instr_addr+2), &indir_addr, 
		sizeof(indir_addr)); 
}

/* If the child is in the preamble or conclusion of the function,
 * then single step the child out of that part. The reason for this
 * is as follows. If the child is in the preamble, then it hasn't made the
 * transition to the function yet since it hasn't setup its frame.
 * If the child is in the conclusion, then it hasn't made the transition
 * out of the function since it may not have returned to the previous
 * function (thereby changing its PC to indicate it presence there).
 */
void make_child_stack_consistent(pid_t pid) {
	long num_steps;
	int i, status;

	num_steps = is_child_in_preamble(pid);
	/*printf("preamble step=%d\n", num_steps);*/
	for (i = 0; i < num_steps; i++) {
		single_step_child(pid, &status);
	}

	num_steps = is_child_in_conclusion(pid);
	/*printf("conclusion step=%d\n", num_steps);*/
	for (i = 0; i < num_steps; i++) {
		single_step_child(pid, &status);
	}
}

void remove_child_breakpoint(pid_t pid, void* addr, long orig_word) {
	/* Restore the original word at addr, thereby removing the breakpoint
	 * we previously inserted. */

	copy_to_child(pid, addr, &orig_word, sizeof(long));
}

/* Resumes child process pid at location code_inject_ptr in its
 * address space. Returns the value of eax once a breakpoint trap is
 * encountered. */
 /* WARNING: This function is for debugging purposes only! Observe
  * that it does not return the value of the executed system call 
  * (assuming one was executed). */
long make_child_execute_code_ss(pid_t pid, void* code_inject_ptr) {

	/* Save the child's general registers, since our code will be
	   clobbering some of them. */
	SAVE_CHILD_CONTEXT();

	/* Set the PC to the beginning of our injected code, which is
	   now in the child playground. */
   SET_REG(pid, eip, (long)code_inject_ptr);

	printf("Executing code at 0x%p\n", code_inject_ptr);
	print_child_mem(pid, code_inject_ptr, 48);

	while (getchar()) {
		print_child_mem(pid, (void*)GET_REG(pid, eip), 8);
		/* Let the child resume; it should resume at the new PC, thereby 
		   executing our injected code. */
		if ((Ptrace(PTRACE_SINGLESTEP, pid, 0, 0)) != 0) {
			FATAL("unable to continue child process\n");
		}

		/* Wait until the child is finished executing our code. */
		int status;
		wait(&status);
	}

	return 0;
}

/* Resumes child process pid at location code_inject_ptr in its
 * address space. Returns the value of eax once a breakpoint trap is
 * encountered. */
long make_child_execute_code(pid_t pid, void* code_inject_ptr) {

	long ret_val = 0;
	int status, ret_pid;

	/* Save the child's general registers, since our code will be
	   clobbering some of them. */
	SAVE_CHILD_CONTEXT();

#if defined(PREDICT_EIP_SUBTRACTION)
	/* We need to handle the case that the child was interrupted during
	 * a system call. If that is the case, then the Linux kernel will
	 * in some cases restart the system call by subtracting 2 from the PC.
	 * In order to avoid associated problems, we make sure that there are
	 * no pending system calls. We do so by placing a trap at the current
	 * PC and then letting the kernel SIGTRAP on that instruction. 
	 * The assumption is that since the SIGTRAP was generated by the
	 * instruction and not some external interrupt, the kernel will
	 * not subtract 2 from the PC in the subsequent execution of the child. */
	pc = get_eip(pid);
	assert(pc != 0);
	long orig_word = insert_child_breakpoint(pid, (void*)pc);
	print_child_mem(pid, (void*)pc, 16);

	printf("pc=0x%x\n", pc);

	/* Let the child execute the breakpoint instruction, letting the kernel
	 * restart any interrupted system call in the process. */
	if ((Ptrace(PTRACE_CONT, pid, 0, 0)) != 0) {
		FATAL("unable to continue child process\n");
	}
	ret_pid = waitpid(pid, &status, __WALL);
	assert(ret_pid == pid);
	assert(WSTOPSIG(status) == SIGTRAP);
#endif

#if defined(CIRCUMVENT_EIP_SUBTRACTION)
	/* The first two instructions of the child playground should
	 * be no ops. Start after the no ops in case the kernel
	 * decides to subtract 2. */
	SET_REG(pid, eip, ((long)code_inject_ptr) + 2);
#else
	/* Set the PC to the beginning of our injected code, which is
	   now in the child playground. */
	SET_REG(pid, eip, (long)code_inject_ptr);
#endif
	//print_child_mem(pid, code_inject_ptr, 48);

	/* Let the child resume; it should resume at the new PC, thereby 
	   executing our injected code. */
	if ((Ptrace(PTRACE_CONT, pid, 0, 0)) != 0)
		FATAL("unable to continue child process\n");

	/* Wait until the child is finished executing our code. */
	ret_pid = waitpid(pid, &status, __WALL);
	assert(ret_pid == pid);

	if (WIFSTOPPED(status)) {
		switch(WSTOPSIG(status)) {
			case SIGTRAP:
				/* Obtain syscall's return value, which should be in %eax. */
				ret_val = GET_REG(pid, eax);

				/* Restore the original code's general registers (which
				   includes the PC). */
				RESTORE_CHILD_CONTEXT();

#if defined(PREDICT_EIP_SUBTRACTION)
				/* Remove the breakpoint we inserted earlier. */
				remove_child_breakpoint(pid, (void*)get_eip(pid), orig_word);
#endif
				break;
			default:
				FATAL("something went wrong when executing the "
						"injected code: got signal %d (pc=0x%x)\n",
						WSTOPSIG(status), GET_REG(pid, eip));
				print_child_mem(pid, (void*)GET_REG(pid, eip), 48);
				print_child_mem(pid, code_inject_ptr, 48);
				print_child_regs(pid);
				exit(-1);
				break;
		}
	} else if (WIFEXITED(status)) {
		FATAL("program exited and returned %d\n",
				WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		DEBUG_MSG(2, "child terminated b/c of unhandled signal\n");
	} else if (WTERMSIG(status)) {
		DEBUG_MSG(2, "got term\n");
	} else {
		FATAL("child returned unknown status\n");
	}

	return ret_val;
}
