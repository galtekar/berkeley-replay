#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <assert.h>	// assert
#include <unistd.h>
#include <stdarg.h>

#define __USE_GNU
#include <dlfcn.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "logreplay.h"
#include "log.h"

#define DEBUG 0

/* Array of fast log entry function pointers, indexed
 * by type value. */
void** fastlogentry_table = NULL;
int num_fastlogentries = 0;

static void lprintf(const char* fmt, ...) {
   va_list args;

   printf("[log2xml]: ");

   va_start(args, fmt);
   fprintf(stdout, fmt, args);
   va_end(args);
}

static void init_fastlogentry_lookup_table() {
	int i = 0;

	/* This is a trick to count the number of distinct wrapper definitions
	 * we have so far implemented. */
#undef FASTLOGENTRY
#define FASTLOGENTRY(name, ...) num_fastlogentries++; 
#include "fastlogentries.h"

	/* This is a one-time malloc and is intentionally never freed. */
	fastlogentry_table = malloc(sizeof(void*) * num_fastlogentries);

	/* For each entry, insert a pointer to its log string generating 
		function. */
#undef FASTLOGENTRY
#define FASTLOGENTRY(name, ...) { \
	assert(i < num_fastlogentries); \
	fastlogentry_table[i] = dlsym(RTLD_DEFAULT, "__str_" #name); \
	assert(fastlogentry_table[i] != NULL); \
	i++; \
}
#include "fastlogentries.h"
}

static void log2xml(char* file_start, int file_size, FILE* fp) {
   /* For each entry in the log file, create an XML log entry and write 
    * it to disk. */

   char* bufptr;
   void* entry;
   logentry_header_t* hdrp;
	log_header_t header;
	log_footer_t footer;

   assert(file_start != NULL);
   assert(fp != NULL);

	bufptr = file_start;

	/* The first two words is the starting vclock. */
	header = *((log_header_t*)bufptr); bufptr += sizeof(log_header_t);

	fprintf(fp, "<log>\n<start vc=\"%llu\">\n", header.vclock);

	/* There may be multiple shared memory segment in this file.
	 * Each one starts with a word containing the size of the data
	 * to follow. */
	while (bufptr < (file_start+file_size - sizeof(footer))) {
		int segment_size = -1, pos = 0;

		/* The first word of the segment contains the size of the log in bytes. */
		segment_size = *((int*)bufptr); bufptr += sizeof(int);

		/* All subsequent data comes in the format (logentry_header_t, entry)...*/
		while (pos < segment_size) {
			hdrp = (logentry_header_t*) bufptr;
			bufptr += sizeof(logentry_header_t);
			entry = bufptr;
			bufptr += hdrp->size;
			pos += sizeof(logentry_header_t) + hdrp->size;

			/* Invoke the XML conversion function that corresponds to this
			 * entry (as indicated by hdrp->id), and then write the string
			 * it returns to the output file. */
			{
				char* (*f)(int64_t, char*);
				char* log_str;

				assert(hdrp->id < num_fastlogentries);
				*(void **) (&f) = fastlogentry_table[hdrp->id];

				assert(f != NULL);

				log_str = f(hdrp->vclock, entry);

				//printf("%s\n", log_str);
				fputs(log_str, fp);
			}
		}

		assert(pos == segment_size);
	}

	footer = *((log_footer_t*)bufptr); bufptr += sizeof(log_footer_t);

	assert(bufptr == file_start+file_size);

	/*printf("vclock=%llu %Ld diff=%d\n", finish_vclock, finish_vclock,
	  bufptr - start);*/
	fprintf(fp, "<end why=\"%s\" vc=\"%llu\">\n</log>\n", 
			footer.reason, footer.vclock);
}

void print_usage(int argc, char** argv) {
	printf("Converts a liblog log file to XML.\n");
	printf("usage: %s <input file> [output file]\n", argv[0]);
}


int main(int argc, char** argv) {

	char *in_name, out_name[1024];
	FILE *in, *out;
	char* logptr;
	struct stat sbuf;

	if (argc < 2) {
		print_usage(argc, argv);
		return -1;
	}

	in_name = argv[1];
	assert(in_name != NULL);

	/* If there is no second argument, then use the first argument
	 * as the base filename. */
	if (!argv[2]) {
		sprintf(out_name, "%s.xml", in_name);
	} else {
		strcpy(out_name, argv[2]);
	}

	init_fastlogentry_lookup_table();

	/* Open the input log file. */
	if ((in = fopen(in_name, "rb")) == NULL) {
		perror("fopen");
		lprintf("can't open input file %s\n", in_name);
		return -1;
	}

	/* Open the output log file. */
	if ((out = fopen(out_name, "wb")) == NULL) {
		perror("fopen");
		lprintf("can't open output file %s\n", out_name);
		return -1;
	}

	/* Get some info about the file. */
	fstat(fileno(in), &sbuf);

	/* Mmap the input file. */
	if ((logptr = mmap(NULL, sbuf.st_size, PROT_READ, MAP_PRIVATE, 
					fileno(in), 0)) == MAP_FAILED) {
		perror("mmap");
		lprintf("can't mmap input file\n");
		return -1;
	}

	/* Perform the conversion. */
	log2xml(logptr, sbuf.st_size, out);

	munmap(logptr, sbuf.st_size);

	fsync(fileno(out));

	fclose(in);
	fclose(out);

   return 0;
}
