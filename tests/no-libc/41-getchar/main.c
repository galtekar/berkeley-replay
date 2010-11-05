#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <vk.h>

void
Init()
{
   int n1 = getchar();

   printf("n1=%d\n", n1);

   int n2 = getchar();

   printf("n2=%d\n", n2);
}
