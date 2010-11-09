#ifndef DLLOPS_H
#define DLLOPS_H

#define __USE_GNU
#include <stdio.h>
#include <dlfcn.h>


extern void* my_dlsym(void* handle, char* symname);
extern void* my_dlopen(const char* filename, int flag);

#endif
