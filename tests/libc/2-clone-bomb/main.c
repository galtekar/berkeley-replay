/* Test liblog/libreplay's threading support. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/unistd.h>

#include <sys/types.h>
#include <linux/unistd.h>

static void* start_routine(void* arg) {

   return NULL;
}

int main(int argc, char** argv) {
   int num_threads;
   int i;

   if (argc != 2) {
      num_threads = 1;
   } else {
      num_threads = atoi(argv[1]);
   }

   {
      pthread_t tid[num_threads];

      for (i = 0; i < num_threads; i++) {
         if (pthread_create(&tid[i], NULL, &start_routine, 
                  (void*)&tid[i]) != 0) {
            perror("pthread_create");
            exit(-1);
         }

         if (pthread_join(tid[i], NULL) != 0) {
            perror("pthread_join");
            //exit(-1);
         }
      }

      start_routine(NULL);

#if 0
      for (i = 0; i < num_threads; i++) {
         if (pthread_join(tid[i], NULL) != 0) {
            perror("pthread_join");
            //exit(-1);
         }
      }
#endif
   }

   return 0;
}
