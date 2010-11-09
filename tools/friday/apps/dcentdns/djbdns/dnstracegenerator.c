#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/unistd.h>

main(int argc, char *argv[]) {
  char usage[] = "dnstracegenerator <index> <stride>";

  if (argc < 3) {
    fprintf(stderr, "Usage: %s\n", usage);
    exit(1);
  }

  int index;
  int stride;

  if (sscanf(argv[1], "%d", &index) <= 0 || index < 1) {
    fprintf(stderr, "Error: index must be a +ve integer.\n");
    exit(1);
  }
  if (sscanf(argv[2], "%d", &stride) <= 0 || index < 1) {
    fprintf(stderr, "Error: stride must be a +ve integer.\n");
    exit(1);
  }

  int day=0;
  int hour;
  int minute;
  double seconds;
  char url[256];
  long lasttime;
  long nexttime;

  if (scanf("%d:%d:%lf %256[^\n]\n", &hour, &minute, &seconds, url) < 4) {
    exit(0);
  }
  nexttime = (long)((day*24*60*60 + hour*60*60 + minute*60 + seconds)*1000);

  int i;
  for (i=0;;i++) {
    if (i%stride == (index-1)) {
      printf("%s\n", url);
      fflush(stdout);	
    }

    lasttime = nexttime;
    if (scanf("%d:%d:%lf %256[^\n]\n", &hour, &minute, &seconds, url) < 4) {
      exit(0);
    }
    nexttime = (long)((day*24*60*60 + hour*60*60 + minute*60 + seconds)*1000);
    if (nexttime < lasttime) {
      day++;
      nexttime = (long)((day*24*60*60 + hour*60*60 + minute*60 + seconds)*1000);
    }

    struct timeval delay;
    delay.tv_sec = (nexttime-lasttime)/1000;
    delay.tv_usec = 1000*((nexttime-lasttime)%1000);

    if (select(0, (fd_set *)0, (fd_set *)0, (fd_set *)0, &delay) < 0) {
      fprintf(stderr, "Error: select failed.\n");
      exit(1);    
    }
  }
}
