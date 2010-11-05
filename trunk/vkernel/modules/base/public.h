/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#pragma once

#define MAX_PLATFORM_LEN   32
#define MAX_TTYNAME        256


struct Session {
   char  dir[PATH_MAX];
   char  tty_name[MAX_TTYNAME];
   char  ctrl_host[256];
   char  ctrl_port[PATH_MAX];

   /* Options. */
   struct TokenBucketSpec optRecSpec;
   struct TokenBucketSpec optClassSpec;
   int      optUseAnnotations;
   int      opt_enable_ipc_tagging;
   int      opt_tty_replay;
};


extern struct Session session;

/* This struct is logged and replayed. */
#define ENV_SHOULD_INHERIT (1 << 2)
struct Environment {
   ulong    auxv[AT_VECTOR_SIZE];
   char     platform[MAX_PLATFORM_LEN];
   /* XXX: should really be MAX_ARG_PAGES in length. */
   char     argList[PATH_MAX];
   size_t   argListLen; 
   int      argListCount;
   char     envList[PATH_MAX*10];
   size_t   envListLen;
   int      envListCount;
   int      flags;

   /* Across all VCPUs. */
   long     recorded_bytes;
   int      is_value_det;
   uint64_t start_vclock;
   uint64_t end_vclock;
};

extern struct Environment env;

extern void ModDebug_Start();
extern int  ModDebug_IsLevel(int lvl);

extern void
ModRecord_OnFileOpen(struct FileStruct *filP);

#define DECL_LINK_PATH(nameP) \
   char ssnLink[256]; \
   snprintf(ssnLink, sizeof(ssnLink), "%s/%d/%s", \
         VK_PROC_DIR, current->realPid, nameP);

extern void    Base_Unlink(const char *nameP);

extern void
Server_NotifyAndEnterControlLoop(const VkEventTag ev);
