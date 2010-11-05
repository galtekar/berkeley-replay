/*
 *  * gethostbyname.c - Example of using gethostbyname(3)
 *   * Martin Vidner <mvidner@suse.cz>
 *    */

#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>

struct hostent *he;
struct in_addr a;

int
main (int argc, char **argv)
{
   if (argc != 2)
   {
      fprintf(stderr, "usage: %s hostname\n", argv[0]);
      return 1;
   }
   he = gethostbyname (argv[1]);
   if (he)
   {
      printf("name: %s\n", he->h_name);
      while (*he->h_aliases)
         printf("alias: %s\n", *he->h_aliases++);
      while (*he->h_addr_list)
      {
         bcopy(*he->h_addr_list++, (char *) &a, sizeof(a));
         printf("address: %s\n", inet_ntoa(a));
      }
   }
   else
      herror(argv[0]);
   return 0;
}
