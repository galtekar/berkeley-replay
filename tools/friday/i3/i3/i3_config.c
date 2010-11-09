#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <ctype.h>
#include "debug.h"
#include "i3_config.h"

xmlDocPtr doc;

void read_parameters(char* filename)
{
  char version[200];
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
  
  read_string_par("/parameters/version",version,1);

  if ( strcmp(version,VER_CONFIG))
  {
    printf("Incorrect version of configuration file. This code uses %s configuration file, your configuration file has version %s, please update.\n",VER_CONFIG,version);
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


void read_string_par(char* path,char* str,int required)
{
  xmlChar *xpath = xmlCharStrdup(path);
  xmlXPathObjectPtr result = getnodeset(xpath);
  xmlFree(xpath);

  required=1;
  
  if ( required && result == NULL )
  {
    printf("%s required in configuration file\n",path);
    exit(-1);
  }

  if ( result == NULL )
    return;

  xmlNodeSetPtr nodeset = result->nodesetval;

  if ( nodeset->nodeNr >= 2 )
  {
    printf("%s should appear atmost once in configuration file\n",path);
    exit(-1);
  }

  xmlChar* resultstr = xmlNodeListGetString(doc, nodeset->nodeTab[0]->xmlChildrenNode, 1);
  strcpy(str,(char*)resultstr);
  strip_ws(str);
  DEBUG(15,"Answer: %s\n",str);
  xmlFree(resultstr);
  xmlXPathFreeObject(result);
}

void read_ushort_par(char* path,unsigned short* us,int required)
{
  char str[200];
  read_string_par(path,str,required);
  *us = (unsigned short) atoi(str);
}

char **read_strings_par(char* path,int* num)
{
  xmlChar *xpath = xmlCharStrdup(path);
  xmlXPathObjectPtr result = getnodeset(xpath);
  xmlFree(xpath);
  
  if ( result == NULL )
  {
    *num=0;
    return NULL;
  }

  xmlNodeSetPtr nodeset = result->nodesetval;
  char** toret = (char**) malloc(nodeset->nodeNr * sizeof(char*));
  *num=nodeset->nodeNr;

  int i;
  for(i=0;i<nodeset->nodeNr;i++)
  {
    xmlChar* resultstr = xmlNodeListGetString(doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);
    toret[i] = strdup((char*)resultstr);
    strip_ws(toret[i]);
    DEBUG(1,"Answer: %s\n",toret[i]);
    xmlFree(resultstr);
  }

  xmlXPathFreeObject (result);
  return toret;
}

int test_main()
{
  char fake[200];
  char** fakes;
  int num;
  
  read_parameters("i3-proxy.xml");
  read_string_par("/parameters/proxy/server_proxy_trigger/server_proxy[@name='sp1']",fake,1);
  printf("%s\n",fake);

  fakes = read_strings_par("/parameters/proxy/public_triggers/trigger",&num);
  printf("Num: %d\n",num);
  int i;
  for(i=0;i<num;i++)
    printf("%s\n",fakes[i]);
  
  return 0;
}


