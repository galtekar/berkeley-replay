#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include <assert.h>

#include "child.h"
#include "debug.h"
#include "hijack.h"

/* Use the _dlopen function in libdl as the initial location
 * we inject code into. */
#define _DLOPEN _dlopen
#define _DLSYM _dlsym
#define _DLERROR _dlerror

void* child_playground_addr = NULL;
void* libdl_addr = NULL;
void* _dlopen = NULL;
void* _dlsym = NULL;
void* _dlerror = NULL;
char str_buf[256];

/***********************************************************************
 * Machine instructions to be injected.                                *
 ***********************************************************************/
unsigned char do_mmap_o[] = {
	0x55,								/* pushl %ebp		*/
	0x89, 0xe5,							/* movl %esp, %ebp	*/
	0x83, 0xec, 0x08,					/* subl $0x8, %esp	*/
	0x83, 0xec, 0x08,					/* subl $0x8, %esp	*/
	0x6a, 0x00,							/* pushl $0			*/ 
	0x6a, 0xff,							/* pushl $-1		*/
	0x6a, 0x22,							/* pushl $34		*/
	0x6a,								/* pushl $7			*/
		/* begin permissions flag */ 
		0x07,						
		/* end permissions flag */
	0x68, 0x00, 0x04, 0x00, 0x00,		/* pushl $1024		*/
	0x68, 0x00,	0x00, 0x00, 0x00,		/* pushl $0			*/

	0xb8, 0x5a, 0x00, 0x00, 0x00,		/* movl $90, %eax	*/
	0x89, 0xe3,							/* movl %esp, %ebx	*/
	0xcd, 0x80,							/* int $0x80		*/
	0xcc								/* int $0x3			*/ 
};

/* NOTE: mode is currently set to (RTLD_NOW | RTLD_GLOBAL) = 0x102 */
unsigned char do_dlopen_o[] = {
	0x55,								/* pushl %ebp		*/
	0x89, 0xe5,							/* movl %esp, %ebp	*/
	0x83, 0xec, 0x08,					/* subl $0x8, %esp	*/
	0x83, 0xec, 0x08,					/* subl $0x8, %esp	*/
	0x68, 
		/* begin mode flag */ 
		0x02, 0x01, 
		/* end mode flag */ 0x00, 0x00,	/* pushl $0x102		*/
	0x68, 0xef, 0xbe, 0xad, 0xde,		/* pushl $0xdeadbeef */
	0xff, 0x15, 0xef, 0xbe, 0xad, 0xde, /* call *0xdeadbeef	*/
	0xcc								/* int $0x3			*/
};

unsigned char do_dlsym_o[] = {
	0x55,								/* pushl %ebp		*/
	0x89, 0xe5,							/* movl %esp, %ebp	*/
	0x83, 0xec, 0x08,					/* subl $0x8, %esp	*/
	0x83, 0xec, 0x08,					/* subl $0x8, %esp	*/
	0x68, 0xef, 0xbe, 0xad, 0xde,		/* pushl $0xdeadbeef (addr of symstr) */
    0xff, 0x35, 0xef, 0xbe, 0xad, 0xde, /* pushl $0xdeadbeef (addr of handle) */
	0xff, 0x15, 0xef, 0xbe, 0xad, 0xde, /* call *0xdeadbeef */
	0xcc								/* int $0x3			*/
};

unsigned char do_dlerror_o[] = {
	0x55,								/* pushl %ebp		*/
	0x89, 0xe5,							/* movl %esp, %ebp	*/
	0x83, 0xec, 0x08,					/* subl $0x8, %esp	*/
	0xff, 0x15, 0xef, 0xbe, 0xad, 0xde,	/* call *0xdeadbeef	*/
	0xcc								/* int $0x3			*/
};
/***********************************************************************
 ***********************************************************************/


/* Modify the mmap() instruction sequence to reflect the specified 
 * parameters. */
static void create_do_mmap_o(unsigned char* buf, void* addr, int size, 
	int perm) {
	assert(buf != NULL);
	memcpy(buf, do_mmap_o, sizeof(do_mmap_o));

	/* TODO: It's too dangerous to hardcode offsets! */
	unsigned char* perm_ptr = &buf[16];
	short* size_ptr = (short*)&buf[19];
	long* addr_ptr = (long*)&buf[23];

	*perm_ptr = (unsigned char)perm;
	*size_ptr = (short)size;
	*addr_ptr = (long)addr;
}

/* Modify the dlopen() instruction sequence to reflect the specified
 * parameters. */
static void create_do_dlopen_o(unsigned char* buf, void* filename_ptr, 
		void* __dlopen) {
	assert(buf != NULL);
	assert(__dlopen != NULL);

	memcpy(buf, do_dlopen_o, sizeof(do_dlopen_o));

	/* TODO: It's too dangerous to hardcore offsets! */
	long* n_ptr = (long*)&buf[15];
	long* f_ptr = (long*)&buf[21];

	*n_ptr = (long)filename_ptr;
	*f_ptr = (long)dlopen;
}

/* Modify the dlsym() instruction sequence to reflect the specified
 * parameters. */
static void create_do_dlsym_o(unsigned char* buf, void* handle, void* symstr,
	void* __dlsym) {
	assert(buf != NULL);
	assert(__dlsym != NULL);

	memcpy(buf, do_dlsym_o, sizeof(do_dlsym_o));

	/* TODO: It's too dangerous to hardcore offsets! */
	long* symstr_ptr = (long*)&buf[10];
	long* handle_ptr = (long*)&buf[16];
	long* dlsym_ptr = (long*)&buf[22];

	*symstr_ptr = (long)symstr;
	*handle_ptr = (long)handle;

	*dlsym_ptr = (long)__dlsym;
}

/* Modify the dlsym() instruction sequence to reflect the specified
 * parameters. */
static void create_do_dlerror_o(unsigned char* buf, void* __dlerror) {
	assert(buf != NULL);
	assert(__dlerror != NULL);

	memcpy(buf, do_dlerror_o, sizeof(do_dlerror_o));

	/* TODO: It's too dangerous to hardcore offsets! */
	long* dlerror_ptr = (long*)&buf[8];

	*dlerror_ptr = (long)__dlerror;
}

/* Injects machine code into child's destination memory address. */
static void inject_code(pid_t pid, void* dest, unsigned char* code, 
		int code_size) {
	assert(dest != NULL);
	assert(code != NULL);

#if defined(CIRCUMVENT_EIP_SUBTRACTION)
	unsigned char no_ops[] = {0x90, 0x90};

	/* Insert 2 no ops to circumvent the kernel subtraction 2
	 * in order to restart system calls. */
	copy_to_child(pid, dest, no_ops, code_size);

	dest = (void*)(((long)dest) + 2);
#endif

	/* Inject code into child's address space. */
	copy_to_child(pid, dest, code, code_size);
}

/* Saves code in child's address space to a buffer in this address space. */
static void save_code(pid_t pid, void* dest, void* src, int code_size) {
	assert(dest != NULL);
	assert(src != NULL);

	copy_from_child(pid, dest, src, code_size);
}

/* Mmap page(s) in the child process's address space. You
 * can size of the mmap (which will determine the number of
 * pages) and their permissions. */
void* make_child_do_mmap(pid_t pid, void* addr, int size, int perm) {
	size_t do_mmap_o_len = sizeof(do_mmap_o);
	unsigned char buf[do_mmap_o_len];
	assert(do_mmap_o_len <= (size_t)getpagesize());
	assert(child_playground_addr != NULL);

	/* Fill in the parameters of the mmap call. */
	create_do_mmap_o(buf, addr, size, perm);

	/* Inject the mmap code into the playground segment. */
	inject_code(pid, child_playground_addr, buf, do_mmap_o_len);

	void* ret_addr = (void*)make_child_execute_code(pid, child_playground_addr);

	if (ret_addr == (void*)-1) {
		FATAL("child's mmap call failed\n");
	}

	assert(ret_addr != NULL);

	return ret_addr;
}

/* Find the function addresses of dlopen and dlsym in the libdl
 * library. */
void init_libdl(pid_t child_pid) {
	void *libc_handle = NULL, *libdl_handle = NULL;
	const char* libc_name = "/lib/tls/libc-2.3.3.so";
	//void* saved_playground_addr;

	/* Open up libc. */
	libc_handle = dlopen(libc_name, RTLD_NOW);
	if (!libc_handle) {
		FATAL("can't open %s: %s\n", libc_name, dlerror());
	}

	dlerror();

	/* Get pointers into the dlopen routine in libc. */
	_dlopen = dlsym(libc_handle, "__libc_dlopen_mode");
	if (dlerror() != NULL) {
		FATAL("can't find dlopen: %s\n", dlerror());
	}
	
	dlerror();

	/* Get pointers into the dlsym routine in libc. */
	_dlsym = dlsym(libc_handle, "__libc_dlsym");
	if (dlerror() != NULL) {
		FATAL("can't find dlsym: %s\n", dlerror());
	}

	dlerror();

#if 0
	/* CAUTION: The code below is not necessary since it is _dl_open
	 * that does the caller check, not it's parent function
	 * __libc_dlopen_mode. __libc_dlopen_mode is exists in libc's text. */

	/* We want the __libc_dlopen_mode to execute in libc's text
	 * region so that we can fool libc into thinking that it's executing
	 * it. This is necessary since __libc_dlopen_mode performs checks
	 * on the return address to make sure the caller is either libc or
	 * libdl. */
	printf("here 1\n");
	saved_playground_addr = child_playground_addr;
	child_playground_addr = dlsym(libc_handle, "strcpy");
	assert(child_playground_addr != NULL);
#endif
	/* Now load in libdl using the libc dlopen and dlsym routines. */
	libdl_handle = make_child_do_dlopen(child_pid, "/usr/lib/libdl.so");
	if (!libdl_handle) {
		FATAL("can't open libdl\n");
	}
#if 0
	child_playground_addr = saved_playground_addr;
	printf("here 2\n");
#endif

#if 0
	/* NOTE: This is commented out because dlopen in libdl won't
	 * let us call it unless it's linked in. */
	/* Get pointers into the libdl dlopen, dlsym, and dlerror. */
	_dlopen = make_child_do_dlsym(child_pid, libdl_handle,
		"dlopen");
	if (!_dlopen) {
		FATAL("can't get address of dlopen in libdl\n");
	}
#endif

	_dlerror = make_child_do_dlsym(child_pid, libdl_handle,
		"dlerror");
	if (!_dlerror) {
		FATAL("can't get address of dlerror in libdl\n");
	}

	_dlsym = make_child_do_dlsym(child_pid, libdl_handle,
		"dlsym");
	if (!_dlsym) {
		FATAL("can't get address of dlsym in libdl\n");
	}

#if 0
	_dlerror = dlsym(lib_handle, "dlerror");
	if (dlerror() != NULL) {
		fprintf(stderr, "can't find dlerror: %s\n", dlerror());
		exit(1);
	}
#endif

	/*ct_printf("dlopen=0x%x dlsym=0x%x dlerror=0x%x\n", _dlopen,
		_dlsym, _dlerror);*/
}

/* Mmap a segment in the child process that we can use to execute
 * any code we want (i.e., a playground). This gives us a nice,
 * predictable place to inject code. Moreover, it saves us the work of 
 * having to save and restore some portion of the child's text segment
 * should we want to inject code. 
 *
 * @bootstrap_code_ptr : 
 * This is the memory location in the child's address space 
 * where we will inject our playground creation code. Therefore,
 * it bootstraps the injection process.
 * */
void* make_child_playground(pid_t pid, void *bootstrap_code_ptr) {
	char original_code_buf[getpagesize()];
	unsigned int do_mmap_o_len = sizeof(do_mmap_o);

	/* Remember the original code in the child's address space. */
	save_code(pid, original_code_buf, bootstrap_code_ptr, getpagesize());
	assert(do_mmap_o_len < getpagesize());

	/* Inject the mmap code into the text segment. */
	inject_code(pid, bootstrap_code_ptr, do_mmap_o, do_mmap_o_len);

	/* Make child execute the bootstrap code. */
	child_playground_addr = (void*)make_child_execute_code(pid, 
			bootstrap_code_ptr);
	assert(child_playground_addr != NULL);

	
	/* Restore the original code in the child's address space. */
	copy_to_child(pid, bootstrap_code_ptr, original_code_buf,
		getpagesize());

	if (child_playground_addr == (void*)-1) {
		FATAL("child's mmap call failed\n");
	}

	return child_playground_addr;
}

/* Make the child dynamically link a library file (in our case, patch
 * files that take the form of library files). Specify the name of the
 * patch library file just as in the call to dlopen(). */
void* make_child_do_dlopen(pid_t pid, char* filename) {
	unsigned char original_code_buf[1024];
	unsigned char buf[sizeof(do_dlopen_o)];
	int filename_str_size = strlen(filename) + 1;
	assert(filename != NULL);

	void* filename_ptr = child_playground_addr;
	assert(filename_ptr != NULL);

	save_code(pid, original_code_buf, child_playground_addr, 1024);

	/* Write the filename string into the child's address space. */
	copy_to_child(pid, filename_ptr, filename, filename_str_size);

	void* call_indir_ptr = ((char*)filename_ptr) + filename_str_size;
	assert(call_indir_ptr != NULL);

	/* Write the address of dlopen into memory so the memory indirect
	   call we are about to execute will be able to see it. */
	assert(_DLOPEN != NULL);
	void* indir_addr = _DLOPEN;
	copy_to_child(pid, call_indir_ptr, &indir_addr, sizeof(indir_addr));

	/* Fill in the dlopen function parameters. */
	create_do_dlopen_o(buf, filename_ptr, call_indir_ptr);

	void* code_inject_ptr = ((char*)call_indir_ptr) + sizeof(indir_addr);
	assert(code_inject_ptr != NULL);

	/* Inject the dlopen invocation code into the playground segment. */
	inject_code(pid, code_inject_ptr, buf, sizeof(do_dlopen_o));

	//void* lib_handle = (void*)make_child_execute_code(pid, code_inject_ptr);
	void* lib_handle = (void*)make_child_execute_code(pid, code_inject_ptr);

	/* Restore the original code in the child's address space. */
	copy_to_child(pid, child_playground_addr, original_code_buf,
		1024);

	return lib_handle;
}

void* make_child_do_dlsym(pid_t pid, void* handle, char *symbol_str) {
	unsigned char buf[sizeof(do_dlsym_o)];
	int symbol_str_size = strlen(symbol_str) + 1;

	assert(handle != NULL);
	assert(symbol_str != NULL);

	char* handle_ptr = (char*)child_playground_addr;
	assert(handle_ptr != NULL);

	/* Write the handle ptr to the child's address space. */
	copy_to_child(pid, (void*)handle_ptr, &handle, sizeof(handle));

	char* symbol_str_ptr = handle_ptr + sizeof(handle);
	assert(symbol_str_ptr != NULL);

	/* Write the symbol string into the child's address space. */
	copy_to_child(pid, symbol_str_ptr, symbol_str, symbol_str_size);

	char* call_indir_ptr = symbol_str_ptr + symbol_str_size;
	assert(call_indir_ptr != NULL);

	/* Write the address of dlsym into the child's address space. */
	assert(_DLSYM != NULL);
	void* indir_addr = _DLSYM;
	copy_to_child(pid, call_indir_ptr, &indir_addr, sizeof(indir_addr));

	create_do_dlsym_o(buf, handle_ptr, symbol_str_ptr, call_indir_ptr);

	char* code_inject_ptr = call_indir_ptr + sizeof(indir_addr);
	assert(code_inject_ptr != NULL);

	/* Inject the dlsym invocation code. */
	inject_code(pid, code_inject_ptr, buf, sizeof(do_dlsym_o));

	void* sym_handle = (void*)make_child_execute_code(pid, code_inject_ptr);

	return sym_handle;
}

/* Make the child call dlerror. If dlerror return a string, then
 * that string will end up in str_buf. */
char* make_child_do_dlerror(pid_t pid) {

	unsigned char buf[sizeof(do_dlerror_o)];

	assert(str_buf != NULL);

	char* call_indir_ptr = (char*)child_playground_addr;
	assert(call_indir_ptr != NULL);

	/* Write the address of dlerror into the child's address space. */
	assert(_DLERROR != NULL);
	void* indir_addr = _DLERROR;
	copy_to_child(pid, call_indir_ptr, &indir_addr, sizeof(indir_addr));

	create_do_dlerror_o(buf, call_indir_ptr);

	char* code_inject_ptr = call_indir_ptr + sizeof(indir_addr);
	assert(code_inject_ptr != NULL);

	/* Inject the dlerror invocation code. */
	inject_code(pid, code_inject_ptr, buf, sizeof(do_dlerror_o));

	void* err_str = (void*)make_child_execute_code(pid, code_inject_ptr);

	/* It's acceptable for dlerror to return NULL (which it will do if
	 * there is no error. */
	if (err_str != NULL) {
		copy_from_child(pid, str_buf, err_str, sizeof(str_buf));

		return str_buf;
	} else {
		return NULL;
	}
}

#if 0
void make_child_load_libdl(pid_t pid) {

	FILE* fp = NULL;

	char filename[] = "/usr/lib/libdl.so";

	if((fp = fopen(filename, "r")) == NULL) {
		error("problem opening function object file\n");
		exit(-1);
	}

	struct stat buf;
	if (stat(filename, &buf) != 0) {
		error("problem getting size of object file name\n");
	}

	/* ASSUMPTION: the pages we get are contiguous. */
	int perm = PROT_EXEC | PROT_READ | PROT_WRITE;
	int size = buf.st_size;
	ct_printf("doing an mmap: size=0x%x perm=0x%x\n", size, perm);
	libdl_addr = (long*)make_child_do_mmap(pid, 0x0, size, perm);
	assert(libdl_addr != NULL);

	ct_printf("reading from lib file into 0x%lx\n", libdl_addr);
	/* Copy the function contents into the new segment. */
	long word;
	long* iaddr = (long*)libdl_addr;
	while (read(fileno(fp), &word, sizeof(long))) {
		if (Ptrace(PTRACE_POKEDATA, pid, iaddr, (void*)word) != 0) {
			error("can't write to new segment\n");
			exit(-1);
		}

		iaddr++;
	}
}
#endif
