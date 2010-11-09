#include "logger.h"

static int logLevel;
static FILE* fptr;

void log_to_file(FILE* fp,const char* temp,...){
	va_list ap;
	struct timeval tv;
	struct timezone tz;
	struct tm tm;
	gettimeofday(&tv,&tz);
	gmtime_r(&tv.tv_sec,&tm);
	va_start(ap,temp);
	fprintf(fp,"[%d:%02d:%02d %d]:",tm.tm_hour,tm.tm_min,tm.tm_sec,tv.tv_usec);
	vfprintf(fp,temp,ap);
	va_end(ap);
	fflush(fp);
}

void log_default(int level,char* temp,...){
	va_list ap;
	struct timeval tv;
	struct timezone tz;
	struct tm tm;
	if(level>=logLevel){
		printf("calling gettimeofday\n");
		gettimeofday(&tv,&tz);
		printf("done calling gettimeofday\n");
		gmtime_r(&tv.tv_sec,&tm);
		va_start(ap,temp);
		fprintf(stdout,"[%d:%02d:%02d %d]:",tm.tm_hour,tm.tm_min,tm.tm_sec,tv.tv_usec);
		vfprintf(stdout,temp,ap);
		va_end(ap);
		fflush(fptr);
	}
}

void log_default_notime(int level,char* temp,...){
	va_list ap;
	if(level>=logLevel){
		va_start(ap,temp);
		vfprintf(fptr,temp,ap);
		va_end(ap);
		fflush(fptr);
	}
}

void log_default_dump(int level,char* dump, int size){
	int i;
	if(level>=logLevel){
		for(i=0;i<size;i++)
			fprintf(fptr,"%d:",dump[i]);
	}
}

FILE* init_log(int id, char* host, int port, int level){
	char logFile[FILE_LENGTH];
	char* initString="dnslog";
	char idString[10];
	char portString[10];
	sprintf(idString,"%d",id);
	sprintf(portString,"%d",port);
	strcpy(logFile,initString);
	strcat(logFile,".");
	strcat(logFile,idString);
	strcat(logFile,".");
	strcat(logFile,host);
	strcat(logFile,".");
	strcat(logFile,portString);
	printf("Using log file:%s\n",logFile);
	if((fptr=fopen(logFile,"w"))==NULL){
		perror("Error opening file in logger.c:init_log");
		exit(1);
	}
	logLevel=level;
	return fptr;	
}


int get_log_level(){
	return logLevel;
}
