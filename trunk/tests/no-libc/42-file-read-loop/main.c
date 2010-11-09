#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <vk.h>

char buf[4096];

void
Init()
{
   int i, j;
   const char fname[] = "/bin/ls";

   printf("Loading key chunkServer.totalSpace with value 21474836480\n"
    "Loading key chunkServer.chunkDir with value\n");

    printf(
    "/tmp/kfs-galtekar/chunk-3/bin/kfschunk1\n"
    "/tmp/kfs-galtekar/chunk-3/bin/kfschunk2\n");

    printf(
    "Loading key chunkServer.logDir with value\n"
    "/tmp/kfs-galtekar/chunk-3/bin/kfslog\n");

    printf(
    "Using chunk server client port: 30003\n"
    "Using chunk dir = /tmp/kfs-galtekar/chunk-3/bin/kfschunk1\n");

    printf(
    "Using chunk dir = /tmp/kfs-galtekar/chunk-3/bin/kfschunk2\n"
    "Using log dir = /tmp/kfs-galtekar/chunk-3/bin/kfslog\n");

    printf(
    "Total space = 21474836480\n"
    "cleanup on start = 0\n");

    printf(
    "Chunk server rack: 0\n"
    "using cluster key = test-cluster\n");

   for (i = 0; i < 20; i++) {
      int nrBytesRead = 0, len, fd, sum = 0;
      memset(buf, 0, sizeof(buf));
      //VK_CG_ASSERT_CONCRETE(buf, sizeof(buf));

      fd = open(fname, O_RDONLY);

      //printf("buf=0x%x len=0x%x\n", buf, sizeof(buf));
      while ((len = read(fd, buf, sizeof(buf))) > 0) {
         //VK_MARK_DATA_REGION(buf, sizeof(buf));
         //VK_CG_ASSERT_SYMBOLIC(buf, len);

         sum += buf[i];
         nrBytesRead += len;
      }

      printf("Incoming transfer: master ('localhost') client ('127.0.0.1') tag ('0x%x')\n", sum);
      close(fd);
   }
}
