#ifndef GLOBAL_H
#define GLOBAL_H

#define FILE_LENGTH 250
#define KEY_SIZE 1024
#define MAL_LIST_LIMIT 10
//#define SIGNATURE_PAYLOAD_SIZE 128
//#define PK_PAYLOAD_SIZE 140
#define SIGNATURE_PAYLOAD_SIZE 256
#define PK_PAYLOAD_SIZE 270
#define BUFFER_SIZE 500
#define IP_ADDRESS 16
#define MAX_HOPS 15
#define MAX_SHARE 20
#define MAX_COST 100

#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
//#include <efence.h>
#include <iostream>
#include <fstream>
#include <signal.h>
#include <sstream>
using namespace std;
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <string>
#include <queue>
#include <deque>

#include "scheduler.h"
#include "neighbor.h"
#include "message.h"
#include "server.h"
#include "eventq.h"
#include "logger.h"
#include "pv.h"
#include "config.h"
#include "keyedlist.h"
#include "dc.h"
#include "checkpoint.h"
#include "rsa.h"
#include "dnsmessage.h"

unsigned char* new_char(int size);
int* new_int();
template<class type> 
inline std::string to_string( const type & value) {
	std::ostringstream streamOut;
	streamOut << value;
	return streamOut.str();
}

template <class t1, class t2> 
inline ostream& operator << ( ostream &os, const std::map<t1,t2>& m){
//	static Log* log = Log::instance();
	typedef typename std::map<t1,t2>::const_iterator iter;
	for (iter i = m.begin(); i!=m.end(); i++){
		const t1& s1 = i->first;
		const t2& s2 = i->second;
		if ( Log::get_level() <= Log::VVERBOSE)
			os << s1 << "=" << s2 << endl;
		else
			os << s1 << "="<< s2.size()<<endl;
	}
	os.flush();
	return os;
}

template <class t>
inline ostream& operator << (ostream &os, const std::vector<t>& v){
	typedef typename std::vector<t>::const_iterator iter;
	os << "[";
	for (iter i = v.begin(); i!=v.end(); i++)
		os << *i << "," ;
	os << "]";
	os.flush();
	return os;
}

template <class t>
inline ostream& operator << (ostream &os, const std::deque<t>& d){
	typedef typename std::deque<t>::const_iterator iter;
	os << "[";
	for (iter i = d.begin(); i!=d.end(); i++)
		os << *i << "," ;
	os << "]";
	os.flush();
	return os;
}

template <class t>
inline ostream& operator << (ostream &os, const std::set<t>& s){
	typedef typename std::set<t>::const_iterator iter;
	os << "[";
	for (iter i = s.begin(); i!=s.end(); i++)
		os << *i << "," ;
	os << "]";
	os.flush();
	return os;
}
#ifdef EFENCE
#endif

#endif
