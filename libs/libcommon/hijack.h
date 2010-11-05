#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* ----- Child hijacking operations ----- */

/* Make child call these functions. */
extern void* make_child_do_mmap(pid_t pid, void* addr, int size, int perm);
extern void* make_child_do_dlopen(pid_t pid, char* filename);
extern void* make_child_do_dlsym(pid_t pid, void* handle, char *symbol_str);
extern char* make_child_do_dlerror(pid_t pid);

/* Child address space setup functions. */
extern void* make_child_playground(pid_t pid, void*);
extern void make_child_load_libdl(pid_t pid);

extern void init_libdl(pid_t pid);

extern void* child_playground_addr;

#ifdef __cplusplus
}
#endif
