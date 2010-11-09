#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main() {
	FILE* fp = NULL;
	void* ret = NULL;

	ret = sbrk(0);

	printf("brk1=0x%x\n", ret);


	fp = fopen("tst.c", "r");

	printf("fp=0x%x\n", fp);

	if (fp) fclose(fp);


	ret = malloc(200);

	printf("%d: ret=0x%x\n", getpid(), ret);

	ret = sbrk(0);

	printf("brk2=0x%x\n", ret);


	return 0;
}
