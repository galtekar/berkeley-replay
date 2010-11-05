#include <sys/wait.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vk.h>

#define BUFSZ 4096

void
Init(int argc, char **argv)
{
   int pfd[2];
   pid_t cpid;
   char default_fname[] = "/bin/ls";
   char *fname = NULL;

   if (argc == 2) {
      fname = argv[1];
   } else {
      fname = default_fname;
   }

   if (pipe(pfd) == -1) { perror("pipe"); exit(EXIT_FAILURE); }

   cpid = fork();
   if (cpid == -1) { perror("fork"); exit(EXIT_FAILURE); }

   if (cpid == 0) {    /* Child reads from pipe */
      char buf[BUFSZ];
      size_t byte_count = 0;
      int res;
      close(pfd[1]);          /* Close unused write end */

      while ((res = read(pfd[0], buf, sizeof(buf))) > 0) {
         VK_CG_ASSERT_SYMBOLIC(buf, res);
         byte_count += res;
         memset(buf, 0, sizeof(buf));
         VK_CG_ASSERT_CONCRETE(buf, res);
      }
      printf("received %d bytes\n", byte_count);

      close(pfd[0]);
      _exit(EXIT_SUCCESS);

   } else {            /* Parent writes argv[1] to pipe */
      close(pfd[0]);          /* Close unused read end */
      char buf[BUFSZ];
      int fd = open(fname, O_RDONLY), res;
      size_t byte_count = 0;

      while ((res = read(fd, buf, sizeof(buf))) > 0) {
         assert(res > 0);
         printf("res=%d\n", res);
         byte_count += res;
         int out_res = write(pfd[1], buf, res);
         printf("out_res=%d\n", out_res);
      }
      printf("sent %d bytes\n", byte_count);
      close(fd);
      close(pfd[1]);          /* Reader will see EOF */
      wait(NULL);             /* Wait for child */
      exit(EXIT_SUCCESS);
   }
}
