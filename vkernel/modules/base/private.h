/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#pragma once

#define DEFAULT_SESSION_TEMPLATE    "XXXXXX"


extern void ModHistory_Append(char *sesPath);
extern int  ModHistory_Lookup(int idx, char *sesPath /* OUT */, 
               size_t bufSz);
extern int  ModHistory_LookupByStr(const char *str, 
               char *sesPath /* OUT */, 
               size_t bufSz);


extern int ModRecord_Init();
extern int ModRecord_Shutdown();
extern int ModReplay_Init();

static INLINE void
ModSession_GetDefaultDir(char *dirPath, size_t bufSz)
{
   char userName[256];

   /* Set the default session path that's multiuser friendly. */
   EnvVar_Str("USER", userName, sizeof(userName));
   if(strlen(userName)) {
      snprintf(dirPath, bufSz, "/tmp/%s-%s/%s", RELEASE_NAME, userName,
            DEFAULT_SESSION_TEMPLATE);
   } else {
      snprintf(dirPath, bufSz, "./%s", DEFAULT_SESSION_TEMPLATE);
   }
}

#define SESSION_FILENAME "saved-env"

static INLINE int
ModSession_Open(const char *sesPath, int shouldCreate)
{
   int fd;
   char tmpPath[256];

   snprintf(tmpPath, sizeof(tmpPath), "%s/%s", sesPath, SESSION_FILENAME);
   fd = open(tmpPath, (shouldCreate ? (O_RDWR | O_CREAT | O_EXCL) : O_RDONLY),
               S_IRUSR);

   return fd;
}

extern int Server_Init();
extern void Server_Shutdown();
extern void Server_OnResumeUser();
extern void Server_OnTaskStart();
extern void Server_OnTaskExit();
extern void Server_OnPreSyscall();
extern void Server_OnPostSyscall();
extern void
Server_OnUserCopy(const int is_write, const struct CopySource *cs_ptr, 
                  const struct IoVec *iov_ptr, const size_t total_len);
extern void
Server_OnFileEvent(VkEventTag tag, struct FileStruct *filp);
