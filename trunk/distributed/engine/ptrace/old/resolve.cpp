
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <map>
#include <cstdlib>
#include <boost/foreach.hpp>
#include <boost/tokenizer.hpp>
#include <string>
#include <boost/regex.hpp> 
#include <string> 
#include <iostream> 
#include <boost/progress.hpp>
#include <climits>
#include <sstream>


#include "private.h"

#include "resolve.h"

#include <stp/c_interface.h>


using boost::timer;
using boost::progress_timer;
using boost::progress_display;

using namespace std;
using namespace boost;

typedef map<string, ulong> SolutionMap;

template <class T>
bool from_string(T& t, const std::string& s, std::ios_base& (*f)(std::ios_base&))
{
    std::istringstream iss(s);
    return !(iss >> f >> t).fail();
}

class STP {
private:
   VC vc;

public:
   STP() {
      vc = vc_createValidityChecker();
   }

   ~STP() {
      vc_Destroy(vc);
   }

   int solve(string formula, SolutionMap &solMap) {
      int res = 0;

      ofstream fout;
      string filename = "/tmp/jiti-tmp.stp";
      string result;

      fout.open(filename.c_str(), ios::out | ios::trunc);
      ASSERT(fout.is_open());
      /* STP's parseExpr will complain without the QUERY(FALSE); */
      fout << formula << endl << "QUERY(FALSE);";
      //fout << "AB : BITVECTOR(1); ASSERT(AB = 0bin1);" << endl << "QUERY(FALSE);";
      fout.close();

      Expr e = vc_parseExpr(vc, filename.c_str());
      if (e) {
         if (vc_query(vc, vc_falseExpr(vc)) == 0) {
#if 1
            char *bufP = NULL;
            unsigned long len = 0;

            /* The vc_query seems to be necessary for this to work. */
            vc_printCounterExampleToBuffer(vc, &bufP, &len);
            ASSERT(bufP);
            //cout << "len: " << len << " res: " << bufP << endl;
            result.append(bufP);
            free(bufP); bufP = NULL;

            regex re("ASSERT\\( ([\\w\\d]+)  = 0(b|x)([\\w\\d]+)  \\);");
            //regex re("ASSERT\\(.*\\);");

            string::const_iterator start = result.begin(), end = result.end();
            boost::match_results<std::string::const_iterator> what;
            boost::match_flag_type flags = boost::match_default;
            while (regex_search(start, end, what, re, flags)) {
#if 1
#if 0
               for (uint i = 0; i < what.size(); i++) {
                  cout << what[i] << endl;
               }
#endif
               ulong val;
               if (from_string<ulong>(val, std::string(what[3]), 
                        std::hex)) {
                  solMap[what[1]] = val;
                  //printf("0x%lx\n", val);
                  //cout << val << endl;

               } else {
                  ASSERT(0);
               }
               start = what[0].second;
#endif
            }

#endif
#if 0
            Expr ce = vc_getCounterExample(vc, e);
            cout << vc_counterexample_size(vc) << endl;
            vc_printExpr(vc, ce);
            vc_DeleteExpr(ce);
            //vc_printCounterExample(vc);

            for (int i = 0; i < vc_counterexample_size(vc); i++) {
               Expr childExpr = getChild(ce, i);
               vc_printExpr(vc, childExpr);
            }
#endif
            res = 1;
         }
         vc_DeleteExpr(e);
      }

      return res;
   }
};

void
Resolver::solveFormula(string formula) 
{
   STP stp;

   SolutionMap solMap;
   stp.solve(formula, solMap);

   SolutionMap::iterator it;
   for (it = solMap.begin(); it != solMap.end(); it++) {
      varCache[it->first] = it->second;
   }
}


DiskResolver::DiskResolver(const char* dirPath) {
   string formDbPath(dirPath), varDbPath(dirPath);
   formDbPath.append("/form.gdbm");
   varDbPath.append("/var.gdbm");

   formDb.open(formDbPath);
   varDb.open(varDbPath);
}

DiskResolver::~DiskResolver() {
   formDb.close();
   varDb.close();
}

ulong DiskResolver::resolve(string varStr) {
   string formId = varDb.lookup(varStr);
   //cout << formId << endl;
   string formula = formDb.lookup(formId);
   //cout << formula << endl;
   solveFormula(formula);

   return varCache[varStr];
}

uchar DiskResolver::lookup(string varStr) {
   ulong res;

   VarCache::iterator it;
   if ((it = varCache.find(varStr)) != varCache.end()) {
      printf("STUB: cache hit\n");
      res = it->second;
   } else {
      res = resolve(varStr);
   }

   /* XXX */
   return 0;
}


static INLINE uchar
extractByte(ulong val, int idx)
{
   ASSERT(idx >= 0);

   return (val >> 8*idx) & 0xFF;
}

uchar
Resolve_Solve(Resolver *resP, const struct SymVar *svP)
{
   ASSERT(resP);

   char str[256];
   uchar res = 0;
   ulong val;

   snprintf(str, sizeof(str), "%sv0e%llun%llu",
         svP->isOrigin ? "OV" : "TV", svP->bbExecCount, svP->name);

   printf("STUB: looking up %s\n", str);

   val = resP->lookup(string(str));

   ASSERT((size_t)svP->byte <= sizeof(val));
   res = extractByte(val, svP->byte);

   printf("STUB: val=0x%lx res=%x\n", val, res);

   return res;
}

#define  RUN_TESTS 0
#if RUN_TESTS
static void
ResolveTest(string formDbPath)
{
   cout << "Testing solver..." << endl;

   cout << formDbPath << endl;

   Db formDb(formDbPath);

   for (int i = 1; i < 100; i++) {
      STP stp;
#if 1
      stringstream out;

      out << i;

      string formula = formDb.lookup(out.str());
      SolutionMap solMap;

      if (stp.solve(formula, solMap)) {
         SolutionMap::iterator it;
         for (it = solMap.begin(); it != solMap.end(); it++) {
            cout << it->first << ": " << it->second << endl;
         }
      } else {
         ASSERT(0);
      }
#endif
   }
}
#endif
