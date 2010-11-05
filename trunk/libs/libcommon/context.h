#ifndef LIBCOMMON_CONTEXT_H
#define LIBCOMMON_CONTEXT_H

int Context_Get(ucontext_t *uc);
int Context_Set(ucontext_t *uc);
int Context_SetRegs(ucontext_t *uc);

#endif
