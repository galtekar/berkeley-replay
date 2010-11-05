#pragma once


#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ptrace.h>
#include <sys/user.h>

/* ----- Child manipulation ops. ----- */

/* Size of the function header that saves ebp. */
#define HEADER_SIZE 3
#define ILLEGAL_ADDRESS 0x0

#define GET_REG(pid, reg) ({ \
	struct user_regs_struct gregs; \
   int res; \
   \
	res = Ptrace(PTRACE_GETREGS, pid, NULL, &gregs); \
   ASSERT(res == 0); \
	gregs.reg; \
})

#define SET_REG(pid, reg, val) { \
	struct user_regs_struct gregs; \
   \
	save_gregs(pid, &gregs); \
	gregs.reg = val; \
	restore_gregs(pid, &gregs); \
}

#define __child

extern long Ptrace(enum __ptrace_request request, pid_t pid, void *addr,
    void *data);

extern void save_gregs(pid_t pid, struct user_regs_struct* gregs);
extern void restore_gregs(pid_t pid, struct user_regs_struct* gregs);

extern int attach_child(pid_t pid, int* status, int should_wait);
extern int resume_child(pid_t pid, int* status, int should_wait);
extern int single_step_child(pid_t pid, int* status);

extern void print_child_regs(pid_t pid);
extern void print_child_mem(pid_t pid, void* addr, int len);
extern void copy_to_child(pid_t pid, void* dest, void* src, long size);
extern void copy_from_child(pid_t pid, void* dest, const void* src, long size);
extern char *
strncpy_from_child(pid_t pid, char *dstP, const char __child *srcP, size_t n);

extern long insert_child_breakpoint(pid_t pid, void* addr);
extern void remove_child_breakpoint(pid_t pid, void* addr, long orig_word);
extern long insert_child_func_breakpoint(pid_t pid, void* func_addr);
extern void remove_child_func_breakpoint(pid_t pid, void* func_addr, 
	long orig_word);

extern void make_child_stack_consistent(pid_t pid);
extern void insert_child_func_jump(pid_t pid, void* addr, long indir_addr);

extern long make_child_execute_code(pid_t pid, void* code_inject_ptr);
extern long make_child_execute_code_ss(pid_t pid, void* code_inject_ptr);

#ifdef __cplusplus
}
#endif
