#ifndef MISC_H
#define MISC_H

#include <inttypes.h>
#include <strings.h>
#include <limits.h>
#include <time.h>

#include "compiler.h"
#include "debug.h"

/* XXX: these are unsafe with respect to args with side-effects */
#define MIN(x, y) (((x) <= (y)) ? (x) : (y))
#define MAX(x, y) (((x) <= (y)) ? (y) : (x))
#define ROUND_UP(x,y) (((x)+(y)-1)/(y))


extern void get_exe_name(char* buf, size_t len);
extern void construct_ckpt_filename_base(char* path, char* prefix, char* tag, 
	int orig_pid, int orig_pgid, uint64_t epoch, uint64_t vclock, char* filename, int size);
extern void construct_log_filename_base(char* path, char* prefix, char* tag, 
	int orig_pgid, uint64_t epoch, uint64_t vclock, char* filename, int size);
extern void construct_lib_filename_base(char* path, char* prefix, char* tag,
	int orig_pgid, uint64_t epoch, char* filename, int size);
extern int stok(const char* keystring, char project_id);


#define MAX_OPT_KEY_LEN 64
#define MAX_OPT_VALUE_LEN 256
struct Pair {
   char key[MAX_OPT_KEY_LEN];
   char value[MAX_OPT_VALUE_LEN];
};

extern int  MiscOps_CanonizePath(const char *name, char *resolved);
extern void MiscOps_Tokenize(char *str, const char *delim, int *sargc, char **sargv);
extern int
MiscOps_RestoreArgv(char *buf, size_t len, char **argv, int *argc);
extern int
MiscOps_SaveArgv(char *buf, size_t *maxLen, char **argv, int *argc);
extern int  MiscOps_ArgvToStr(char *destStr, size_t destSz, 
               char **argv);
extern int  MiscOps_MakeDir(char *dirName, int makeParents, 
               int makeTemp);
extern const char *
MiscOps_GetNextArg(char *argStrP, char **savePP);
extern int
MiscOps_GetNextSubOpt(char *argStrP, char **savePP, const char *const *subOptTokA);
extern int
MiscOps_ParsePair(char *str, struct Pair *optA, int *maxOptsP);
int
MiscOps_PairLookup(const struct Pair *pairA, const int nrPairs, const char *keystr);
extern ulong   MiscOps_GetTimeInSecs();
extern ulong   MiscOps_GetTimeInMilliSecs();

extern int  EnvVar_Int(char *varName, int *val);
extern int  EnvVar_Bool(char *varName, int trueVal);
extern int  EnvVar_Str(char *varName, char *buf, size_t bufSz);

extern int  CpuOps_Migrate(int tid, int targetCpuId);
extern int  CpuOps_GetNumCpus();

extern void MD5_To64(u64 *hashp, void * buf, size_t bufsz);


static INLINE long
Arg_ParseLong(const char *arg)
{
   if (strcasecmp(arg, "unlimited") == 0 ||
       strcasecmp(arg, "max") == 0) {
      return LONG_MAX;
   } else {
      return atoi(arg);
   }
}

static INLINE int
Arg_ParseBool(const char *arg)
{
   if (strcasecmp(arg, "true") == 0) {
      return 1;
   } else if (strcasecmp(arg, "false") == 0) {
      return 0;
   } else {
      return atoi(arg);
   }
}


typedef unsigned int uuid_t[4];

static INLINE void
MiscOps_GenerateUUID(uuid_t *uuid_ptr)
{
   int i;
   uint *p = (uint*)uuid_ptr;

   srand(time(NULL) ^ gettid());
   for (i = 0; i < sizeof(uuid_t)/sizeof(int); i++) {
      p[i] = rand();
   }
}
#endif
