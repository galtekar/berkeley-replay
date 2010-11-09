#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <ctype.h>
#include "debug.h"

#include "debug.h"
#include "i3.h"
#include "i3_id.h"
#include "i3_trigger.h"

xmlDocPtr doc;
char cname[500] = "i3-client-proxy.xml";
char aname[500] = "i3_addr_book.txt";

#ifdef __CYGWIN__
// convert LF -> CR/LF
int convert(char *filename){
  int c;
  char tempfile[256] = "gen_conf.tmp";
  FILE *in, *out;

  if ((in = fopen(filename, "r")) == NULL) {
    perror("fopen");
    return -1;
  }
  if ((out = fopen(tempfile, "w")) == NULL) {
    perror("fopen");
    return -1;
  }

  while ((c = fgetc(in)) != EOF) {
    if (c == '\r')
      continue;
    if (c == '\n') {
      fputc('\r', out);
      fputc('\n', out);
      continue;
    }
    fputc(c, out);
  }

  fclose(in);
  fclose(out);

  if ((out = fopen(filename, "w")) == NULL) {
    perror("fopen");
    return -1;
  }
  if ((in = fopen(tempfile, "r")) == NULL) {
    perror("fopen");
    return -1;
  }
  
  while ((c = fgetc(in)) != EOF)
    fputc(c, out);
  
  fclose(in);
  fclose(out);

  if (remove(tempfile) < 0) {
    perror("remove");
    return -1;
  }

  return 0;
}
#endif

void get_random_ID(ID *id)
{
  int   i;
     
  for(i=0; i < ID_LEN; i++)
  {
    id->x[i] = (char) (rand() % 255);
  }
}

void get_random_key(Key *id)
{
  int   i;

  for(i=0; i < KEY_LEN; i++)
  {
    id->x[i] = (char) (rand() % 255);
  }
}

void read_parameters(char* filename)
{
  doc = xmlParseFile(filename);
	
  if (doc == NULL )
  {
    DEBUG(1,"XML configuration not parsed successfully (check whether all tags are terminated etc). \n");
    exit(-1);
  }
	
  xmlNodePtr root;
  root = xmlDocGetRootElement(doc);
	
  if (root == NULL)
  {
    DEBUG(1,"Empty XML configuration file\n");
    exit(-1);
  }
	
  if (xmlStrcmp(root->name, (const xmlChar *) "parameters")) {
    DEBUG(1,"Document of the wrong type, root node != parameters\n");
    exit(-1);
  }

}

void release_params()
{
  xmlFreeDoc(doc);
  xmlCleanupParser();
}

xmlXPathObjectPtr getnodeset(xmlChar *xpath)
{
  xmlXPathContextPtr context;
  xmlXPathObjectPtr result;

  context = xmlXPathNewContext(doc);
  result = xmlXPathEvalExpression(xpath, context);
  if(xmlXPathNodeSetIsEmpty(result->nodesetval))
    return NULL;

  xmlXPathFreeContext(context);
  return result;
}

void strip_ws(char* str)
{
  char tstr[200];
  
  int lindex = 0;
  while ( str[lindex] != 0 && isspace(str[lindex]))
    lindex++;

  int rindex = strlen(str)-1;
  while ( rindex >= 0 && isspace(str[rindex]) )
    rindex--;

  if ( lindex == strlen(str))
  {
    strcpy(str,"");
    return;
  }

  str[rindex+1] = 0;
  strcpy(tstr,str+lindex);
  strcpy(str,tstr);
}

xmlNodePtr read_node(char* path)
{
  xmlChar *xpath = xmlCharStrdup(path);
  xmlXPathObjectPtr result = getnodeset(xpath);
  xmlFree(xpath);

  if(xmlXPathNodeSetIsEmpty(result->nodesetval))
  {
    printf("Configuration parameter %s not found in xml file\n",path);
    exit(-1);
  }

  xmlNodeSetPtr nodeset = result->nodesetval;
  
  return nodeset->nodeTab[0];
}

void sprintf_i3_key(char* key,uint8_t* t)
{
  int i;
  
  sprintf(key," ");
  
  for (i = 0; i < KEY_LEN; i++)
    sprintf(key + strlen(key),"%02x", (int)(t[i]));
}

void gen_key(char* key,char* id)
{
  Key lkey,rkey;
  ID myid;
  
  /* generate random ID and make sure public_id bit is set */
  get_random_ID(&myid);
  set_public_id(&myid);

  /* set l-constraint */
  get_random_key(&rkey);
  generate_l_constraint_addr(&rkey,&lkey);
  set_key_id(&myid,&lkey);

  sprintf_i3_key(key,(uint8_t*)(rkey.x));
  sprintf_i3_id(id,&myid);
}


void add_public_trigger(char* name)
{
  char buf1[500],buf2[500];
  read_parameters(cname);
  xmlNodePtr parent = read_node("/parameters/proxy/public_triggers");

  strcpy(buf1,name);
  sprintf(buf1 + strlen(buf1)," ");
  strcpy(buf2,name);
  sprintf(buf2 + strlen(buf2)," ");

  gen_key(buf1 + strlen(buf1),buf2 + strlen(buf2));
  
  xmlNewTextChild (parent, NULL, "trigger", buf1);
  xmlSaveFormatFile(cname, doc, 1);
  xmlFreeDoc(doc);
  xmlCleanupParser();

  FILE* fd = fopen(aname,"a");
  fprintf(fd,"%s\r\n",buf2);
  fclose(fd);

#ifdef __CYGWIN__
  convert(aname);
  convert(cname);
#endif

  printf("Address Book Entry: %s\n",buf2);
}

void add_i3server(char* name)
{
  char buf1[500];
  read_parameters(cname);
  xmlNodePtr parent = read_node("/parameters/i3_server");
  xmlNewTextChild (parent, NULL, "addr", name);
  xmlSaveFormatFile(cname, doc, 1);
  xmlFreeDoc(doc);
  xmlCleanupParser();
#ifdef __CYGWIN__
  convert(cname);
#endif

}

int main(int argc,char** argv)
{

  if ( argc <= 1)
  {
    printf("Usage\n ./gen_conf I [xml file] [address book file] \n (or) \n ./gen_conf P foo.i3 [xml file] [address book file] \n (or)\n ./gen_conf S \"x.y.z.w  port# chordid\" [xml file] [address book file] \n");
    return 0;
  }

  srand(getpid() ^time(0));
  aeshash_init();
  xmlKeepBlanksDefault(0);

  if ( !strcmp(argv[1],"I"))
  {
    
    if ( argc >= 3)
      strcpy(cname,argv[2]);
     
    if ( argc >= 4)
      strcpy(aname,argv[3]);
    
    printf("Enter I3 DNS name for your machine. Eg: yourmachine.i3\nYou can enter 0 if you don't want any public triggers\n");
    char name[500];
    
    do
    {
      printf("Enter I3 DNS Name: ");
      scanf("%s",name);
      if ( strcmp(name,"0")) {
	add_public_trigger(name);
	printf("Do you want to add one more I3 DNS name?\n");
	printf("Enter 0 if you don't\n");
      }
    }
    while ( strcmp(name,"0"));

    printf("You can send your address book to those who wish to connect to you\n\n\n");

    printf("Specify I3 server(s) you want to use.\n");
    printf("If you use i3 servers on PlanetLab, select currently running i3 server(s) from\n");
    printf("http://rose.cs.berkeley.edu:8000/i3_status.html\n");
    printf("Enter 0 if you don't add any i3 server.\n");

    char ip[500],port[500],chordid[500];
    
    do
    {
      printf("Enter IP address (e.g. 1.2.3.4): ");
      scanf("%s",ip);

      if ( strcmp(ip,"0"))
      {
	printf("Enter port number (e.g. 1234): ");
	scanf("%s",port);
	printf("Enter 20-byte chordID (e.g. 0123456789abcdef0123456789abcdef01234567): ");
	scanf("%s",chordid);
	sprintf(ip+strlen(ip)," %s %s",port,chordid);
	add_i3server(ip);
	printf("Do you want to add one more I3 server?\n");
	printf("Enter 0 if you don't\n");
      }
    }
    while ( strcmp(ip,"0"));

    printf("Your configuration file has been written successfully\n");
    
  }
  else   if ( !strcmp(argv[1],"P") )
  {

    if ( argc >= 4)
      strcpy(cname,argv[3]);
     
    if ( argc >= 5)
      strcpy(aname,argv[4]);

    if ( argc <= 2)
    {
      printf("Public trigger name required\n");
      return 0;
    }

    add_public_trigger(argv[2]);
  }
  else   if ( !strcmp(argv[1],"S"))
  {

    if ( argc >= 4)
      strcpy(cname,argv[3]);
     
    if ( argc <= 2)
    {
      printf("Server name required\n");
      return 0;
    }

    add_i3server(argv[2]);

  }
  else  
  {
    printf("Usage: ./gen_conf I [xml file] [address book file] \n (or) \n ./gen_conf P foo.i3 [xml file] [address book file] \n (or) ./gen_conf S \"x.y.z.w  port# chordid\" [xml file] [address book file] \n");
    return 0;
  }
  
  return 0;
}
