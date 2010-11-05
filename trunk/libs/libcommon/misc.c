#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <limits.h> /* for PATH_MAX */
#include <dlfcn.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>

#if ! USING_DIET_LIBC
#include <openssl/md5.h>
#else
#include <md5.h>
#define MD5_Init MD5Init
#define MD5_Update MD5Update
#define MD5_Final MD5Final
#endif

#include "errops.h"
#include "misc.h"
#include "debug.h"
#include "bitops.h"

/* Look at /proc/self/cmdline to get the name of the binary that
 * was originally invoked. */
void get_exe_name(char* buf, size_t len) {
	char fstr[32];
	int ret;

	snprintf(fstr, sizeof(fstr), "/proc/self/exe");

	/* readlink() does not append a null-terminator to the end of the result! */
	ret = readlink(fstr, buf, len);

	ASSERT(ret > 0);

	buf[ret] = 0;
}

/* ftok sucks -- collisions very likely. This should be better. */
int stok(const char* keystring, char project_id) {
	MD5_CTX ctx;
	int key;
	unsigned char md[16];

	MD5_Init(&ctx);

	ASSERT(strlen(keystring) > 0);
	MD5_Update(&ctx, (uchar*)keystring, strlen(keystring));

	MD5_Final(md, &ctx);

	key = *((int*)md);

	key = (0x00FFFFFF & key) | ((int)project_id << 24);

	return key;
}

/* Return the canonical absolute name of file NAME.  A canonical name
   does not contain any `.', `..' components nor any repeated path
   separators ('/').  All path components must exist.  If
   RESOLVED is null, the result is malloc'd; otherwise, if the
   canonical name is PATH_MAX chars or more, returns null with `errno'
   set to ENAMETOOLONG; if the name fits in fewer than PATH_MAX chars,
   returns the name in RESOLVED.  If the name cannot be resolved and
   RESOLVED is non-NULL, it contains the path of the first component
   that cannot be resolved.  If the path can be resolved, RESOLVED
   holds the same value as the value returned.  */

int
MiscOps_CanonizePath(const char *name, char *resolved)
{
   char *rpath, *dest; 
   const char *start, *end, *rpath_limit;
   long int path_max;
#if 0
   char *extra_buf = NULL;
   int num_links = 0;
#endif
   int err = 0;

   if (name == NULL)
   {
      /* As per Single Unix Specification V2 we must return an error if
         either parameter is a null pointer.  We extend this to allow
         the RESOLVED parameter to be NULL in case the we are expected to
         allocate the room for the return value.  */
      err = -EINVAL;
      goto error;
   }

   if (name[0] == '\0')
   {
      /* As per Single Unix Specification V2 we must return an error if
         the name argument points to an empty string.  */
      err = -ENOENT;
      goto error;
   }

#ifdef PATH_MAX
   path_max = PATH_MAX;
#else
#error "Unimplemented."
   path_max = pathconf (name, _PC_PATH_MAX);
   if (path_max <= 0)
      path_max = 1024;
#endif

   ASSERT(resolved);

   rpath = resolved;
   rpath_limit = rpath + path_max;

   ASSERT(name[0] == '/');
   rpath[0] = '/';
   dest = rpath + 1;

   for (start = end = name; *start; start = end)
   {
#if 0
      struct stat64 st;
      int n;
#endif

      /* Skip sequence of multiple path-separators.  */
      while (*start == '/')
         ++start;

      /* Find end of path component.  */
      for (end = start; *end && *end != '/'; ++end)
         /* Nothing.  */;

      if (end - start == 0)
         break;
      else if (end - start == 1 && start[0] == '.')
         /* nothing */;
      else if (end - start == 2 && start[0] == '.' && start[1] == '.')
      {
         /* Back up to previous component, ignore if at root already.  */
         if (dest > rpath + 1)
            while ((--dest)[-1] != '/');
      }
      else
      {
#if 0
         size_t new_size;
#endif

         if (dest[-1] != '/')
            *dest++ = '/';

         if (dest + (end - start) >= rpath_limit)
         {
#if 0
            ptrdiff_t dest_offset = dest - rpath;
            char *new_rpath;
#endif

            if (resolved)
            {
               err = -ENAMETOOLONG;
               if (dest > rpath + 1)
                  dest--;
               *dest = '\0';
               goto error;
            }
#if 0
            new_size = rpath_limit - rpath;
            if (end - start + 1 > path_max)
               new_size += end - start + 1;
            else
               new_size += path_max;
            new_rpath = (char *) realloc (rpath, new_size);
            if (new_rpath == NULL)
               goto error;
            rpath = new_rpath;
            rpath_limit = rpath + new_size;

            dest = rpath + dest_offset;
#endif
         }

# define mempcpy(D, S, N) ((void *) ((char *) memcpy (D, S, N) + (N)))
         dest = mempcpy (dest, start, end - start);
         *dest = '\0';

#if 0
         if (__lxstat64 (_STAT_VER, rpath, &st) < 0)
            goto error;

         if (S_ISLNK (st.st_mode))
         {
            char *buf = __alloca (path_max);
            size_t len;

            if (++num_links > MAXSYMLINKS)
            {
               __set_errno (ELOOP);
               goto error;
            }

            n = __readlink (rpath, buf, path_max);
            if (n < 0)
               goto error;
            buf[n] = '\0';

            if (!extra_buf)
               extra_buf = __alloca (path_max);

            len = strlen (end);
            if ((long int) (n + len) >= path_max)
            {
               __set_errno (ENAMETOOLONG);
               goto error;
            }

            /* Careful here, end may be a pointer into extra_buf... */
            memmove (&extra_buf[n], end, len + 1);
            name = end = memcpy (extra_buf, buf, n);

            if (buf[0] == '/')
               dest = rpath + 1;	/* It's an absolute symlink */
            else
               /* Back up to previous component, ignore if at root already: */
               if (dest > rpath + 1)
                  while ((--dest)[-1] != '/');
         }
         else if (!S_ISDIR (st.st_mode) && *end != '\0')
         {
            __set_errno (ENOTDIR);
            goto error;
         }
#endif
      }
   }
   if (dest > rpath + 1 && dest[-1] == '/')
      --dest;
   *dest = '\0';

   ASSERT (resolved == rpath);

error:
   return err;
}

int
EnvVar_Int(char *varName, int *val)
{
   char *valStr;
   int res = 0;

   ASSERT(varName);
   ASSERT(val);

   valStr = getenv(varName);

   if (valStr) {
      *val = atoi(valStr);
      res = 1;
   }

   return res;
}

int
EnvVar_Bool(char *varName, int trueVal)
{
   char *valStr;

   ASSERT(varName);

   valStr = getenv(varName);

   if (valStr) {
      if (atoi(valStr) == trueVal) {
         return 1;
      }
   }

   return 0;
}

int
EnvVar_Str(char *varName, char *buf, size_t bufSz)
{
   char *valStr;

   ASSERT(varName);

   valStr = getenv(varName);

   if (valStr) {
      strncpy(buf, valStr, bufSz);

      return 1;
   }

   return 0;
}

int 
CpuOps_GetNumCpus()
{
   cpumask_t cpuMask;
   int err, count = 0, offset = 0;
   const int tid = gettid();

   memset(&cpuMask, 0xF, sizeof(cpuMask));

   err = syscall(SYS_sched_setaffinity, tid, sizeof(cpumask_t), &cpuMask);
   ASSERT(!err);
   err = syscall(SYS_sched_getaffinity, tid, sizeof(cpumask_t), &cpuMask);
   /* sched_getaffinity returns size of linux's cpumask_t */
   ASSERT(err <= sizeof(cpumask_t));

   while ((offset = Bit_FindNextBit((ulong*)&cpuMask, sizeof(cpuMask), 
               offset)) < sizeof(cpuMask)*BITS_PER_BYTE) {
      /* Found a set bit. */
      DEBUG_MSG(8, "offset=%d count=%d\n", offset, count);
      offset++;
      count++;
   }

   ASSERT_MSG(count <= sizeof(cpuMask)*BITS_PER_BYTE, "count=%d", count);
   return count;
}

int
CpuOps_Migrate(int tid, int targetCpuId)
{
   cpumask_t cpuMask;
   int err;

   ASSERT(targetCpuId < (sizeof(cpuMask)*BITS_PER_BYTE));

   if (!tid) {
      tid = gettid();
   }

   memset(&cpuMask, 0, sizeof(cpuMask));
   Bit_TestSet(targetCpuId, (ulong*)&cpuMask);

   err = syscall(SYS_sched_setaffinity, tid, sizeof(cpumask_t), &cpuMask);

   return err;
}

void
MD5_To64(u64 *hashp, void * buf, size_t bufsz)
{
	MD5_CTX ctx;
	unsigned char md[16];

	MD5_Init(&ctx);

	MD5_Update(&ctx, (uchar*)buf, bufsz);

	MD5_Final(md, &ctx);

   ASSERT(sizeof(*hashp) <= sizeof(md));
   memcpy(hashp, md, sizeof(*hashp));
}

/* Returns -1 if all args were not restored. */
int
MiscOps_RestoreArgv(char *buf, size_t len, char **argv, int *argc)
{
   const int max_argc = *argc - 1; /* need space for the last NULL element */
   char *p = buf;
   int i = 0;

   DEBUG_MSG(5, "len=%d\n", len);

   long rem = len;
   while (rem > 0 && i < max_argc) {
      size_t arglen = strlen(p)+1;

      argv[i] = p;
      DEBUG_MSG(5, "%d: %s %d\n", i, p, arglen);

      p += arglen;
      rem -= arglen;
      i++;
   }

   *argc = i;
   argv[i] = NULL;

   return rem ? -1 : 0;
}

/* Return -1 iff all args were not saved. @argv must be null terminiated */
int
MiscOps_SaveArgv(char *buf, size_t *maxLen, char **argv, int *argc)
{
   int i = 0;
   char *p = buf, *arg;
   size_t len, rem = *maxLen;

   while ((arg = argv[i]) && ((len = strlen(arg)+1) <= rem)) {
      ASSERT_MSG(i < 10000, "Is argv null-terminated?\n");

      strcpy(p, arg);
      p += len;
      ASSERT(*(p-1) == 0);

      rem -= len;
      i++;
   }

   *maxLen = *maxLen - rem;

   *argc = i;

   return (argv[i]) ? -1 : 0;
}


void
MiscOps_Tokenize(char *str, const char *delim, int *sargc, char **sargv)
{
   char *token = NULL, *saveptr = NULL;
   int i = 0;

   ASSERT(sargc);
   ASSERT(*sargc > 0);
   ASSERT(sargv);

   while ((token = strtok_r(str, delim, &saveptr)) && i < *sargc) {
      sargv[i] = token; 
      
      str = NULL;
      ASSERT(saveptr);
      i++;
   }

   *sargc = i;
   sargv[i] = NULL;

   ASSERT(*sargv > 0);
}

static int
MiscOpsSplit2(const char *s, const char delim, struct Pair *optP)
{
   const char *p = strchr(s, delim);

   //printf("s=%s delim=%c\n", s, delim);
   //memset(optP, 0, sizeof(*optP));

   if (p) {
      ASSERT(p >= s);
      strncpy(optP->key, s, MIN(p-s, sizeof(optP->key)));
      strncpy(optP->value, p+1, sizeof(optP->value));

      return 0;
   } 

   return -1;
}

int
MiscOps_ParsePair(char *str, struct Pair *optA, int *maxOptsP)
{
   char *token = NULL, *saveptr = NULL;
   int i = 0;

   while ((token = strtok_r(str, "; ", &saveptr)) && i < *maxOptsP) {
      if (MiscOpsSplit2(token, '=', &optA[i])) {
         return 1;
      }

      str = NULL;
      ASSERT(saveptr);
      i++;
   }

   *maxOptsP = i;

   return 0;
}

int
MiscOps_PairLookup(const struct Pair *pairA, const int nrPairs, const char *keystr)
{
   int i;

   for (i = 0; i < nrPairs; i++) {
      //printf("Considering: %s for %s\n", pairA[i].key, keystr);
      if (strncmp(pairA[i].key, keystr, MAX_OPT_KEY_LEN) == 0) {
         return i;
      }
   }

   return -1;
}

#if 0
int
MiscOps_ArgvToStr(char *destStr, size_t destSz, char **argv)
{
   size_t len = destSz, w;
   char *p = destStr;
   int i = 0;

   while (argv[i] && len > 0) {
      w = snprintf(p, len, "%s ", argv[i]);
      ASSERT_MSG(w > 0 && w <= len, "w=%d len=%d", w, len);

      len -= w;
      p += w;
      i++;
   }

   if (i > 0) {
      *(p-1) = 0;
   } else {
      *p = 0;
   }

   DEBUG_MSG(5, "destStr=%s\n", destStr);

   if (len <= 0) {
      ASSERT(0); /* XXX: make sure we don't lose any elements. */
   }

   return (argv[i] && len == 0) ? -1 /* out of space */ : 0;
}
#endif

static int
MiscOpsMakeParents(char *dirName)
{
   int err;
   char *dirPrefix = malloc(PATH_MAX);
   char *p, *dirCanon = malloc(PATH_MAX);
   char *last;

   ASSERT(dirPrefix);
   ASSERT(dirCanon);

   if ((err = MiscOps_CanonizePath(dirName, dirCanon))) {
      goto out;
   }

   last = strrchr(dirCanon, '/');

   DEBUG_MSG(8, "dirCanon=%s last=%s\n", dirCanon, last);

   p = dirCanon;
   while ((p = strchr(p, '/'))) {
      DEBUG_MSG(9, "p=%s\n", p);

      ASSERT(p >= dirCanon);

      size_t len = (size_t) (p-dirCanon) + 1;
      memcpy(dirPrefix, dirCanon, len);
      dirPrefix[len] = 0;

      DEBUG_MSG(9, "dirPrefix=%s\n", dirPrefix);
      /* Looks like a dir was specified in the command-line. */
      err = syscall(SYS_mkdir, dirPrefix, 0700);
      if (err < 0 && err != -EEXIST) {
         goto out;
      }

      if (p == last) {
         break;
      } else {
         p++;
      }
   }

   err = 0;

out:
   free(dirPrefix);
   dirPrefix = NULL;
   free(dirCanon);
   dirCanon = NULL;

   return err;
}

int
MiscOps_MakeDir(char *dirName, int makeParents, int makeTemp)
{
   int err = 0;

   DEBUG_MSG(9, "dirName=%s\n", dirName);

   if (makeParents) {
      if ((err = MiscOpsMakeParents(dirName))) {
         eprintf("error making parents of '%s'\n", dirName);
         goto out;
      }
   }

   if (makeTemp) {
      DEBUG_MSG(9, "1\n");
      if (!mkdtemp(dirName)) {
         err = -1;
         goto out;
      }
   } else {

      DEBUG_MSG(9, "2\n");
      err = syscall(SYS_mkdir, dirName, 0700);
      if (err < 0 && err != -EEXIST) {
         goto out;
      }
      err = 0;
   }

out:
   return err;
}

static int
MiscOpsLookupStr(const char *strP, const char * const *subOptTokA)
{
   int i = 0;
   const char * const*tokStrP = subOptTokA;

   while (*tokStrP) {
      if (strcmp(strP, *tokStrP) == 0) {
         return i;
      }
      tokStrP++;
      i++;
   }

   return '?';
}

const char *
MiscOps_GetNextArg(char *argStrP, char **savePP)
{
   char *strP;

   ASSERT(argStrP);

   strP = strtok_r(*savePP ? NULL : argStrP, ",", savePP);

   return strP;
}

int
MiscOps_GetNextSubOpt(char *argStrP, char **savePP, const char *const *subOptTokA)
{
   const char *strP;
   int idx = -1;

   ASSERT(argStrP);

   //strP = strtok_r(*savePP ? NULL : argStrP, ",", savePP);
   strP = MiscOps_GetNextArg(argStrP, savePP);
   //DEBUG_MSG(5, "argStrP=%s\n", argStrP);

   if (strP) {
      idx = MiscOpsLookupStr(strP, subOptTokA);
   }

   return idx;
}

ulong
MiscOps_GetTimeInSecs()
{
   struct timeval tv;

   gettimeofday(&tv, NULL);

   return tv.tv_sec;
}

ulong
MiscOps_GetTimeInMilliSecs()
{
   struct timeval tv;

   gettimeofday(&tv, NULL);

   return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}
