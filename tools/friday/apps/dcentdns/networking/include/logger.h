#ifndef _LOGGER_H
#define _LOGGER_H
#include <stdarg.h>
#include <stdio.h>
#include <ostream>
#include <string>


class Log:public ofstream {
	public:
		typedef enum {
			SILENT 		= 4,
			NORMAL 		= 3,
			VERBOSE 	= 2,
			VVERBOSE	= 1,
			VVVERBOSE	=0} Level;
	private:
		Level level;
		Log ( string filename, Level _level);

	public:
	
	static Log* instance (Level _level = NORMAL, int id = -1, char* host = "localhost", int port = -1);

	static void print (string s, Level _level = NORMAL, bool time = true);

	static void dump ( unsigned char* c, int size, Level _level);
	
	static Level get_level();

};
#endif
