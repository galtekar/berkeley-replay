/***************************************************************************
                          proxy_test.c  -  description
                             -------------------
    begin                : Mon Jul 21 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h> 
#include <sys/errno.h>
#include <sys/utsname.h>
#include <time.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#include <error.h>
#include <pthread.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/route.h>
#include <linux/if_tun.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <netdb.h>
#include <sys/utsname.h>



pthread_t      udp_thrd, tcp_thrd;

struct sockaddr_in   icsi_addr;
struct in_addr       local_addr;

void non_i3_dns_check()
{
   struct hostent      *he;
   struct sockaddr_in  server;

      
   printf("\n Checking DNS-requests:");
   printf("\n www.cnn.com --> ");

   if ((he = gethostbyname("www.cnn.com")) == NULL)
   {
      printf(" error resolving hostname..");
      exit(1);
   }

   memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
   printf(" %s\n", inet_ntoa(server.sin_addr));

   printf("\n www.icsi.berkeley.edu ");

   if ((he = gethostbyname("www.icsi.berkeley.edu")) == NULL)
   {
      printf(" error resolving hostname..");
      exit(1);
   }

   memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
   printf(" --> %s\n", inet_ntoa(server.sin_addr));

   printf("\n www.heise.de ");

   if ((he = gethostbyname("www.heise.de")) == NULL)
   {
      printf(" error resolving hostname..");
      exit(1);
   }

   memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
   printf(" --> %s\n", inet_ntoa(server.sin_addr));

   printf("\n");
}


void i3_dns_check()
{
   struct hostent      *he;
   struct sockaddr_in  server;
   int                 i;


   printf("\n Checking DNS-requests:");
   printf("\n www.icsi.i3 --> ");

   if ((he = gethostbyname("www.icsi.i3")) == NULL)
   {
      printf(" error resolving hostname..");
      exit(1);
   }

   memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
   printf(" %s\n", inet_ntoa(server.sin_addr));

   memcpy(&icsi_addr, &server, sizeof(struct sockaddr_in));

   printf("\n www.test.i3 --> ");

   if ((he = gethostbyname("www.ucb.i3")) == NULL)
   {
      printf(" error resolving hostname..");
      exit(1);
   }

   memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
   printf(" %s\n", inet_ntoa(server.sin_addr));

   printf("\n Checking 'www.icsi.i3' and 'www.ucb.i3' 200 times ('.' = o.k., 'x' = error)\n");

   for (i=0; i<200; i++)
   {   
      if ((he = gethostbyname("www.icsi.i3")) == NULL)
      {
         printf("x");
         exit(1);
      }

      memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
      printf(".");

      if ((he = gethostbyname("www.ucb.i3")) == NULL)
      {
         printf("x");
         exit(1);
      }

      memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
      printf(".");
   }     
   printf("\n");
}


void *tcp_thread (void *arg)
{
   int                  listen_sd, len, i, addrlen, newsock;
   struct sockaddr_in   address, saddr;
   char                 buf[100];
   char                 reply[100];
   char                 adr[50], sadr[50];


   strcpy(reply, "I am fine, thanks! (   )");

   listen_sd = socket(AF_INET, SOCK_STREAM, 0);
   if (listen_sd == -1)
   {
      printf("\n Error creating tcp-socket in tcp_thread()");
      exit(-1);
   }


   address.sin_family = AF_INET;
   address.sin_addr = local_addr;
   address.sin_port = htons(33333);

   if (bind(listen_sd, (struct sockaddr *) &address, sizeof(address)) < 0)
   {
      printf("\n Error binding tcp-socket in tcp_thread()");
      exit(-1);
   }

   memset(buf, 0, 100);

   listen(listen_sd,1);

   addrlen = sizeof(struct sockaddr_in);
   newsock = accept(listen_sd, (struct sockaddr *) &saddr, &addrlen);
   if (newsock < 0)
      printf("\n Error while trying to accept TCP connection\n");

   strcpy(sadr, inet_ntoa(saddr.sin_addr));
   strcpy(adr, inet_ntoa(address.sin_addr));
    
   for (i=0; i<100; i++)
   {
      len = sizeof(struct sockaddr_in);

      len = recv(newsock, buf, 100, 0);

      if (len <= 0)
         printf("\n TCP-Receiver: Error at receiving packet\n");
      else if (memcmp(buf, "How are you?", 12) == 0)
      {
         printf("\n TCP packet %03u: (%s -> %s): %s   ->   ", i+1, sadr, adr, buf);
         sprintf(reply + 20, "%03u)", i+1);
         send(newsock, reply, 25, 0);
      }
      else
         printf("\n Error receiving the test tcp-packet: buf = %s", buf);
   }

   close(newsock);
   close(listen_sd);
   printf("\n Receiver closed TCP-connections\n");

   pthread_exit((void *) 0);
}



void tcp_check()
{
   int                  send_sd, len, i;
   struct sockaddr_in   address, saddr;
   char                 sendbuf[100], recvbuf[100];
   char                 adr[50], sadr[50];


   if (pthread_create(&tcp_thrd, NULL, tcp_thread, (void *) NULL))
	{
		printf("\n Error creating tcp_thread !\n");
      exit(-1);
	}
   
   memset(sendbuf, 0, 100);
   strcpy(sendbuf, "How are you?");

   send_sd = socket(AF_INET, SOCK_STREAM, 0);
   if (send_sd == -1)
   {
      printf("\n Error creating tcp-socket in tcp_check()");
      exit(-1);
   }

   saddr.sin_family = AF_INET;
   saddr.sin_addr.s_addr = inet_addr("10.0.0.2");
   saddr.sin_port = htons(33333);

   address.sin_family = AF_INET;
   address.sin_addr = local_addr;
   address.sin_port = htons(44444);

   if (bind(send_sd, (struct sockaddr *) &address, sizeof(address))<0)
   {
      printf("\n Error binding tcp-socket in tcp_check()");
      exit(-1);
   }

   if (connect(send_sd, (struct sockaddr *)&saddr, sizeof(saddr)))
   {
      printf("\n Error opening TCP connection in tcp_check(). \n");
      exit(-1);
   }

   strcpy(sadr, inet_ntoa(saddr.sin_addr));
   strcpy(adr, inet_ntoa(address.sin_addr));
   
   for (i=0; i<100; i++)
   {
      len = sizeof(struct sockaddr_in);
      send(send_sd, sendbuf, 12, 0);

      len = recv(send_sd, recvbuf, 100, 0);
      if (len <= 0)
         printf("\n Error at receiving packet\n");
      else
         printf("(%s -> %s): %s", adr, sadr, recvbuf);
   }

   close(send_sd);

   printf("\n Sender closed TCP-connection\n");
	pthread_join(tcp_thrd, NULL);
}



void *udp_thread (void *arg)
{
   int                  listen_sd, len, i;
   struct sockaddr_in   address, saddr;
   char                 buf[100];
   char                 adr[50], sadr[50];

   


   listen_sd = socket(AF_INET, SOCK_DGRAM, 0);
   if (listen_sd == -1)
   {
      printf("\n Error creating UDP-socket in udp_thread()");
      exit(-1);
   }


   address.sin_family = AF_INET;
   address.sin_addr = local_addr;
   address.sin_port = htons(55555);

   if (bind(listen_sd, (struct sockaddr *) &address, sizeof(address)) < 0)
   {
      printf("\n Error binding udp-socket in udp_thread()");
      exit(-1);
   }

   memset(buf, 0, 100);

   for (i=0; i<10; i++)
   {
      len = sizeof(struct sockaddr_in);
      
      len = recvfrom(listen_sd, buf, 100, 0, (struct sockaddr *) &saddr, (int *) &len);

      if (len <= 0)
         printf("\n UDP-Receiver: Error at receiving packet\n");
      else if (memcmp(buf, "How are you?", 12) == 0)
      {
         strcpy(sadr, inet_ntoa(saddr.sin_addr));
         strcpy(adr, inet_ntoa(address.sin_addr));

         printf("\n Received UDP packet %03u: (%s -> %s): %s  ", i+1, sadr, adr, buf);
      }
      else
         printf("\n Error receiving the test udp-packet: buf = %s", buf);
   }

   close(listen_sd);

   pthread_exit((void *) 0);
}



void udp_check()
{
   int                  send_sd, len, i;
   struct sockaddr_in   saddr;
   char                 sendbuf[100];

   

   if (pthread_create(&udp_thrd, NULL, udp_thread, (void *) NULL))
	{
		printf("\n Error creating udp_thread !\n");
      exit(-1);
	}

//   sleep(1);
   
   memset(sendbuf, 0, 100);
   strcpy(sendbuf, "How are you?");

   send_sd = socket(AF_INET, SOCK_DGRAM, 0);
   if (send_sd == -1)
   {
      printf("\n Error creating udp-socket in udp_check()");
      exit(-1);
   }

   saddr.sin_family = AF_INET;
   saddr.sin_addr.s_addr = inet_addr("10.0.0.3");
   saddr.sin_port = htons(55555);

   len = sizeof(struct sockaddr_in);

   for (i=0; i<10; i++)
   {
      sendto(send_sd, sendbuf, 12, 0, (struct sockaddr *) &saddr, len);
      printf("\n Send UDP-packet to %s", inet_ntoa(saddr.sin_addr));
   }

   close(send_sd);

	pthread_join(udp_thrd, NULL);
}



struct in_addr get_my_addr()
{
   struct hostent *hptr;
   struct utsname myname;
   char str[INET6_ADDRSTRLEN];
   struct sockaddr_in servaddr;

   if (uname(&myname) < 0) {
     printf("uname error.\n");
     exit(-1);
   }

   if ((hptr = gethostbyname(myname.nodename)) == NULL) {
     printf("gethostbyname error\n");
     exit(-1);
   }

   /* get host address -- it has to be an easier way to do it! */
   inet_ntop(hptr->h_addrtype, *(hptr->h_addr_list), str, sizeof(str));
   if (inet_pton(AF_INET, str, &servaddr.sin_addr) < 0)
     printf("inte_pton error\n");

   /* convert addres in host format, as inet_pto returns network format */
   servaddr.sin_addr.s_addr = ntohl(servaddr.sin_addr.s_addr);
   return servaddr.sin_addr;
}


 
int main(int argc, char **argv)
{
    

   printf("\n\n");
   printf("********************************\n");
   printf("** Test programm for i3-proxy **\n");
   printf("********************************\n");

   if (argc != 2)
   {
      printf("Usage: %s i3_server_list.txt \n", argv[0]);
      exit(-1);
   }

   local_addr = get_my_addr();

   local_addr.s_addr = htonl(local_addr.s_addr);
   
   printf("\n Local address: %s\n", inet_ntoa(local_addr));
   
   non_i3_dns_check();
   
   i3_dns_check();

   tcp_check();

   printf("\n TCP-check completed.\n");
                   
   udp_check();

   printf("\n\n Seems to work fine...\n\n");

   return -1;
}
