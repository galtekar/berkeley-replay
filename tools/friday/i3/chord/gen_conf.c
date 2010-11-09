#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/socket.h>
#endif
#include <net/if.h>
#include <netdb.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <string.h>

#include "chord.h"

#define IFNAME_LEN 256
#define MAX_NUM_IFS 16

#define NEWS

/* get_addr: get IP address of server */
ulong get_addr1(char *name)
{
    int i, tempfd, ret;
    struct sockaddr_in tmp_addr;
    char ifname[IFNAME_LEN];
    struct ifreq ifr;

    struct hostent *hptr;
    struct utsname myname;

    if (name == NULL) {
      if (uname(&myname) < 0)
        eprintf("uname failed:");
      name = myname.nodename;
    }

    hptr = gethostbyname(name);
    if (!hptr)
        eprintf("gethostbyname(%s) failed", name);

    for (i = 0; i < hptr->h_length/sizeof(ulong); i++) {
       struct in_addr ia;
       ulong *addrptr;

       addrptr = (ulong *) hptr->h_addr_list[i];
       
       ia.s_addr = *addrptr;
       //printf("Addr %d = %s; ", i, inet_ntoa(ia));
    }
    
    if (*((ulong *) hptr->h_addr) != inet_addr("127.0.0.1"))
        return *((ulong *) hptr->h_addr);

    // if not, ioctl on ethernet interface.
    for (i = 0; i < MAX_NUM_IFS; i++) {
        sprintf(ifname, "eth%d", i);
        strcpy(ifr.ifr_name, ifname);
        
        tempfd = socket(AF_INET, SOCK_DGRAM, 0);

        if (((ret = ioctl(tempfd, SIOCGIFFLAGS, (char *)&ifr)) != -1)) {
            if ((ifr.ifr_flags & IFF_UP) != 0) {
                if ((ret = ioctl(tempfd, SIOCGIFADDR, (char *)&ifr)) != -1) {
                    tmp_addr = *((struct sockaddr_in *) &ifr.ifr_addr);
                    return tmp_addr.sin_addr.s_addr;
                }
            }
        }
    }
    
    return inet_addr("127.0.0.1");
}


void set_loworder_bits(chordID *id)
{
    int i;
#define ID_SERVER_LEN 6
    for (i = ID_SERVER_LEN; i < ID_LEN; i++)
	id->x[i] = 0xff;
}

int main(int argc, char **argv)
{
  int i, j, k, i3_port, validate_port;
  Node *nodes;
  char filename[100], name[100];
  FILE *fp, *fd, *i3clientconf_fd;
#ifdef NEWS
  FILE *newsconf_fd; 
#endif
  struct in_addr ia;
#define MAX_NUM_NODES 1000

  if (argc != 3) {
    fprintf(stderr, "usage: %s server_list cfg_file_name\n", argv[0]);
    exit(-1);
  }
  srandom(getpid() ^ time(0));

  nodes = (Node *) malloc(MAX_NUM_NODES * sizeof(Node));

  fd = fopen(argv[1], "r");
  k = 0;
  while (!feof(fd)) {
    if (k == MAX_NUM_NODES)
      break;

    fscanf(fd, "%s\n", name);
    nodes[k].id = rand_ID();
    //set_loworder_bits(&(nodes[k].id));
    nodes[k].addr = ntohl(get_addr1(name));
    nodes[k].port = 4710 + k;
    k++;
  }
  fclose(fd);

  sprintf(filename, "%s_i3client.conf", argv[2]);
  i3clientconf_fd = fopen(filename, "w");
#ifdef NEWS
  sprintf(filename, "%s_i3news.conf", argv[2]);
  newsconf_fd = fopen(filename, "w");
#endif
  
  for (i = 0; i < k; i++) {
    i3_port = nodes[i].port - 4710 + 5610;
    validate_port = nodes[i].port - 4710 + 7810;
    ia.s_addr = htonl(nodes[i].addr);
    fprintf(i3clientconf_fd, "%s %d\n", inet_ntoa(ia), i3_port);
#ifdef NEWS
    fprintf(newsconf_fd, "%s %d %d ", inet_ntoa(ia), i3_port, validate_port);
    print_id(newsconf_fd, &nodes[i].id);
    fprintf(newsconf_fd, "\n");
#endif

#ifdef NEWS
    sprintf(filename, "%s_%s_%d_%d_%d.cfg",
		argv[2], inet_ntoa(ia), i3_port, validate_port, nodes[i].port);
#else
    sprintf(filename, "%s_%s_%d_%d.cfg",
	    argv[2], inet_ntoa(ia), i3_port, nodes[i].port);
#endif
    fp = fopen(filename, "w");
    fprintf(fp, "%d ", nodes[i].port);
    print_id(fp, &nodes[i].id);
    fprintf(fp, "\n");
    for (j = 0; j < k; j++) {
      if (j == i) continue;
      ia.s_addr = htonl(nodes[j].addr);
      fprintf(fp, "%s:%d ", inet_ntoa(ia), nodes[j].port);
      fprintf(fp, "\n");
    }
    fclose(fp);
  }

  fclose(i3clientconf_fd);
#ifdef NEWS
  fclose(newsconf_fd);
#endif
  return 0;
}
