#include "global.h"



Log::Log ( string filename, Level _level):ofstream (filename.c_str()){
	level = _level;
}

inline Log*  Log::instance (Level _level , int id , char* host , int port ){
	string filename = "";
	if (id >= 0 ){
		filename = "log." + to_string(id) + "." + host + "." + to_string(port) ;
	} 
	static Log l(filename, _level);
	return &l;
}

void Log::print (string s, Level _level, bool time ){
	Log* log = instance ();
	if ( _level >= log->level ){
		if ( time ){
			struct timeval tv;
			struct timezone tz;
			struct tm tm;
			gettimeofday(&tv,&tz);
			gmtime_r(&tv.tv_sec,&tm);
			(*log)	
					<<"["
					<<tm.tm_hour << ":"
					<<tm.tm_min<<":"
					<<tm.tm_sec<<" "
					<<tv.tv_usec
					<<"]";
		}
		(*log) << s;
		(*log).flush();
	}
}

void Log::dump ( unsigned char* c, int size, Log::Level _level){
	Log* log = instance ();
	if ( _level >= log->level ){
		for (int i=0; i  < size-1; i++)
			(*log)<<(unsigned int)c[i]<<":";
		if (size >=0)
			(*log)<<(unsigned int)c[size];	
		(*log).flush();
	}
}

Log::Level Log::get_level(){
	return (instance())->level;
}
