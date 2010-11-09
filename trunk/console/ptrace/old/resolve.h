#pragma once

#include <map>
#include <string>

#include "gdbm.h"

#include "../libcommon/public.h"


using namespace std;

class Db {
private:
   GDBM_FILE db;

public:

   void close() {
      if (db) {
         gdbm_close(db);
         db = NULL;
      }
   }

   int open(string path) {
      close();

      db = gdbm_open ((char*)path.c_str(), 0, GDBM_READER, 
            0666, 0);

      if (!db) {
         FATAL("File %s either doesn't exist or is not a gdbm file.\n",
               path.c_str());
         return 0;
      }

      return 1;
   }

   Db() {
      db = NULL;
   }

   Db(string path) {
      db = NULL;
      open(path);
   }

   ~Db() {
      close();
   }

   class LookupFailedException : public exception {
      virtual const char *what() const throw() {
         return "Key lookup failed";
      }
   } exDbLookupFailed;

   string lookup(string keyStr) {
      ASSERT(db);

      string res;

      datum key, data;
      key.dptr = (char*)keyStr.c_str();
      key.dsize = strlen(keyStr.c_str());

      printf("Looking up %s, size %d\n", keyStr.c_str(), key.dsize);

      data = gdbm_fetch(db, key);
      if (data.dptr) {

         char dataStr[data.dsize + 1];
         memcpy(dataStr, data.dptr, data.dsize);
         dataStr[data.dsize] = 0;

         free(data.dptr);
         data.dptr = NULL;

         res = dataStr;

         return res;
      } else {
         throw exDbLookupFailed;
      }
   }
};

typedef map<string, ulong> VarCache;

class Resolver {

public:
   virtual uchar lookup(string varStr) = 0;
   virtual ~Resolver() { }

protected:
   VarCache varCache;

   virtual ulong resolve(string varStr) = 0;

   void solveFormula(string formula);
};


class DiskResolver : public Resolver {

private:
   Db formDb, varDb;

public:

   DiskResolver(const char* dirPath);
   ~DiskResolver();

   ulong resolve(string varStr);

   uchar lookup(string varStr);
};

extern uchar
Resolve_Solve(Resolver *resP, const struct SymVar *svP);
