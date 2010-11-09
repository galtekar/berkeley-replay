//#include <iostream>
#include <stdio.h>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <string>
#include <assert.h>
#include <regex.h>
#include <strings.h>
#include <stdlib.h>
#include "../i3/debug.h"
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C"
{
#include "../i3/i3.h"
#include "../i3/i3_id.h"
#include "../i3/i3_config.h"
  
  void init_addrbook(char *filename);
  void init_rulebook();
  ID* lookup_addrbook(char* i3dns);
  ID *match_rules(char* legacydns);
  char* match_rules_spname(char* legacydns);

  void convert_str_to_hex(char* source,ID* id);
}

using namespace std;

ID *my_alloc_i3_id()
{
  ID *id;

  if ((id = (ID *)malloc(sizeof(ID))) == NULL)
  {
    printf("my_alloc_i3_id: memory allocation error.\n");
    exit(-1);
  }
  
  return id;
}

void my_printf_i3_id(ID *id, int indent)
{
   char buf[INDENT_BUF_LEN];
   uint i;

  memset(buf, ' ', INDENT_BUF_LEN);
  buf[indent] = 0;

  printf("%s id: ", buf);
  for (i = 0; i < sizeof(ID); i++)
    printf("%02x", (int)(id->x[i])); 
  printf("\n");
}

map<string,ID*>* addrbook;
vector<regex_t*>* rulebook;
vector<ID*>* actions;
vector<string>* spnames;

pthread_t      addr_book_refresh_thrd;
pthread_mutex_t    addr_book_mutex = PTHREAD_MUTEX_INITIALIZER;
int addr_book_sleeptime = 10; // 5 mins
time_t check_time;
char addr_book_file_store[200];

void *addr_book_refresh(void *arg)
{
  do
  {
    int timeleft = addr_book_sleeptime;

    do
    {
      timeleft = sleep(timeleft);
    } while (timeleft != 0);

    init_addrbook(addr_book_file_store);
    
  } while(1);
  
}

int addr_book_lock_mutex()
{
#ifndef __CYGWIN__
  if ( pthread_mutex_lock(&addr_book_mutex) )
  {
    DEBUG(1,"addr_book_lock_mutex: problem with locking mutex\n");
    return 1;
  }
#endif
  return 0;
}

int addr_book_unlock_mutex()
{
#ifndef __CYGWIN__
  
  if ( pthread_mutex_unlock(&addr_book_mutex) )
  {
    DEBUG(1,"addr_book_unlock_mutex: problem with unlocking mutex\n");
    return 1;
  }
#endif

  return 0;
}

// Do we need to read in address book file now?

int file_modified()
{

  // Check modificationt time
  struct stat stat_p;
  if ( stat (addr_book_file_store, &stat_p) != 0)
    return 0;

  if ( stat_p.st_mtime > check_time )
  {
    time(&check_time);
    return 1;
  }

  return 0;
}


void init_addrbook(char* filename)
{

  // Reading the address book for the first time?
  if ( filename != addr_book_file_store )
    time(&check_time);
  else if ( !file_modified())
  {
    return;
  }

  addr_book_lock_mutex();

  if ( addrbook != NULL)
  {
    for(map<string,ID*>::iterator aiter = addrbook->begin(); aiter != addrbook->end(); aiter++)
      delete aiter->second;
    delete addrbook;
  }
  
  addrbook = new map<string,ID*>;
  FILE* addrfile = fopen(filename,"r");
  char name[100];
  char nid[200];
  ID *cnid;

  if ( addrfile == NULL)
  {
    DEBUG(1,"Error opening address book %s\n",filename);
    addr_book_unlock_mutex();
    exit(-1);
  }

  while(!feof(addrfile))
  {
    fscanf(addrfile,"%s %s",name,nid);
    cnid = my_alloc_i3_id();
    
    for(int i=0;i<ID_LEN;i++)
    {
      char str[3];
      if ( (i * 2) < (int) strlen(nid))
	str[0] = nid[i*2];
      else
	str[0] = '0';
      if ( (i * 2 + 1) < (int) strlen(nid))
	str[1] = nid[i*2 + 1];
      else
	str[1] = '0';
      str[2] = 0;
      cnid->x[i] = (unsigned char) strtol(str, NULL, 16);
    }

    if ( !feof(addrfile))
    {
      addrbook->insert(make_pair(string(name),cnid));
    }

  }
  
  fclose(addrfile);

  addr_book_unlock_mutex();

  if ( filename != addr_book_file_store ) // happens only first time
  {
    strcpy(addr_book_file_store,filename);

    if (pthread_create(&addr_book_refresh_thrd, NULL,addr_book_refresh, (void *) NULL))
    {
      DEBUG(1, "Error creating addr book refresh thread !\n");
      return;
    }
  }

}

ID* lookup_addrbook(char* i3dns)
{
  addr_book_lock_mutex();

  map<string,ID*>::iterator miter = addrbook->find(string(i3dns));
  if ( miter == addrbook->end())
  {
    addr_book_unlock_mutex();
    return NULL;
  }
  ID* rid = duplicate_i3_id(miter->second);
  
  addr_book_unlock_mutex();
  
  return rid;
}


ID* find_matching_id(char* server_proxy_name)
{
  char beforeconv[2*ID_LEN+1];
  char name[200];
  
  ID* sid = alloc_i3_id();
  
  sprintf(name,"/parameters/proxy/server_proxy_trigger/server_proxy[@name='%s']",server_proxy_name);
  read_string_par(name,beforeconv,1);
  convert_str_to_hex(beforeconv,sid);

  return sid;
}


void init_rulebook()
{
  rulebook = new vector<regex_t*>;
  actions = new vector<ID*>;
  spnames = new vector<string>;
  
  char name[200];
  char action[50];
  int numrules;
  char** rules;

  rules = read_strings_par("/parameters/legacy_server_rules/rule",&numrules);
  
  for(int i=0;i<numrules;i++)
  {
    char rule[100];
    int j=0;
    regex_t* crule;
    
    sscanf(rules[i],"%s %s",name,action);
    free(rules[i]);
 
    for(int k=0;k<(int)strlen(name);k++)
    {
      if ( name[k] == '.')
      {
	rule[j++] = '\\';
	rule[j++] = '.';
      }
      else if ( name[k] == '*')
      {
	rule[j++] = '.';
	rule[j++] = '*';
      }
      else
	rule[j++] = name[k];
    }

    rule[j] = 0;
    
    crule = new regex_t;
    if (regcomp(crule,rule,REG_EXTENDED))
    {
      printf("Regular expression format not obeyed %s %s\n",name,action);
      exit(-1);
    }

    rulebook->push_back(crule);
    spnames->push_back(action);
    if ( strcmp(action,"NOREDIRECT"))
      actions->push_back(find_matching_id(action));
    else
      actions->push_back(NULL);
  }

  free(rules);
}

ID *match_rules(char* legacydns)
{
  vector<ID*>::iterator aiter = actions->begin();
  
  for(vector<regex_t*>::iterator riter = rulebook->begin(); riter != rulebook->end(); riter++)
  {
    regmatch_t *matched; 
    matched = new regmatch_t;
    if ( !regexec(*riter,legacydns,1,matched,0) && matched[0].rm_so == 0 && matched[0].rm_eo == (int) strlen(legacydns) )
    {
      if ( *aiter != NULL )
	return duplicate_i3_id(*aiter);
      else
	return NULL;
    }
    
    aiter++;
  }

  printf("No default rule!\n");
  exit(-1);
}

char *match_rules_spname(char* legacydns)
{
  vector<string>::iterator niter = spnames->begin(); 
  
  for(vector<regex_t*>::iterator riter = rulebook->begin(); riter != rulebook->end(); riter++)
  {
    regmatch_t *matched; 
    matched = new regmatch_t;
    if ( !regexec(*riter,legacydns,1,matched,0) && matched[0].rm_so == 0 && matched[0].rm_eo == (int) strlen(legacydns) )
    {
      const char* orig = niter->c_str();
      char* copy = (char*) malloc(strlen(orig));
      strcpy(copy,orig);
      return copy;
    }
    
    niter++;
  }

  printf("No default rule!\n");
  exit(-1);
}



  
  
  
