#ifndef _CONFIG_H
#define _CONFIG_H
#include "global.h"

class Config{
	private:
		Config ( char* filename );	
	public:
		static string keys[];
	
		map<string, string>* configMap;
		struct timeval pollInterval;
		struct timeval pvInterval;
		char neighborFile[FILE_LENGTH];
		Log::Level level;
		int msgsPerPoll;
		int wakeupTime;
		int fakeId;
		int beaconInterval;
		Scheduler::Type schedulerType;
		int warmupTime;
		int n;
		int routerType;	
		int startRouter;
		int routerInterval;
	
		int malList[MAL_LIST_LIMIT];
		int malListSize;

		int optimization;
		int malFrequency;
		int bufferManagement;
		int singleStart;
		int noCrypto;

		bool testTwoNode;
		bool pathVectorTest;

		long flowComputeInterval;
		int dnsPort;


		static Config* instance (char* filename);
		~Config ();

		void init_server (Server* server);
		void tokenize(const string& str, vector<string>& tokens, const string& delimiters );
		bool get_boolean(map<string,string>* m, string key, bool  defaultValue);
		string get_string(map<string, string>* m, string key);
		int get_int(map<string, string>* map, string key, int defaultValue);
};


#endif
