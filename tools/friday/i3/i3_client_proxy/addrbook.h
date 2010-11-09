  void init_addrbook(char *filename);
  void init_rulebook();
  ID* lookup_addrbook(char* i3dns);
  ID *match_rules(char* legacydns);
  char* match_rules_spname(char* legacydns);

#define NOREDIRECT 0
#define REDIRECT 1

