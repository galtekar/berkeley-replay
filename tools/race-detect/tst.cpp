#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include <vector>

using namespace std;

typedef pair<int, int> IntPair;

#define SHAREDAREA      __attribute__ ((section (".SHAREDAREA")))

SHAREDAREA int tstVar = 0;

int main()
{
   multimap<int, int> m;
   set<int> s1, s2;
   multimap<int, int>::iterator it;
   vector<int> v(10);
   vector<int>::iterator it_end, vit;

   m.insert(IntPair(1, 1));
   m.insert(IntPair(2, 2));
   m.insert(IntPair(2, 1));

   extern ulong __SHAREDAREA_START, __SHAREDAREA_END, __SHAREDAREA_BRK_START;
   cout << &__SHAREDAREA_START << " " << &__SHAREDAREA_END << " " <<
      &__SHAREDAREA_BRK_START << endl;

   cout << "it1" << endl;
   for (it = m.equal_range(1).first; it != m.equal_range(1).second; it++) {
      cout << it->second << endl;
      s1.insert(it->second);
   }

   cout << "it2" << endl;
   for (it = m.equal_range(2).first; it != m.equal_range(2).second; it++) {
      cout << it->second << endl;
      s2.insert(it->second);
   }

#if 1
   cout << "intersection:" << endl;
   it_end = set_intersection(s1.begin(), s1.end(), s2.begin(), s2.end(),
         v.begin());

   for (vit = v.begin(); vit != it_end; vit++) {
      cout << *vit << " ";
   }
#else
   set_intersection(m.equal_range(1).first, m.equal_range(1).second, 
         m.equal_range(2).first, m.equal_range(2).second,
         ostream_iterator<int>(cout, " "));
#endif

   cout << endl;

   string s;

   s = "test";

   return 0;
}
