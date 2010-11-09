#include "global.h"

string Config::keys[]={
	"address",
	"is_malicous",
	"pv_interval",
	"polling_interval",
	"level",
	"neighbor_file",
	"k",
	"msgs_per_poll",
	"wakeup_time",
	"fake_id",
	"beacon_interval",
	"scheduler",
	"warmup_time",
	"router",
	"n",
	"mal_list",
	"single_start",
	"start_router",
	"router_interval",
	"no_crypto",
	"optimization",
	"mal_frequency",
	"test_two_node",
	"path_vector_test",
	"flow_compute_interval",
	"dns_port"
	};



Config::Config(char* filename){
	configMap =  new map<string, string>;

	ifstream inp (filename);
	string key;
	string value;
	while ( ! std::getline (inp, key, '=').eof()){
		std::getline (inp, value);
		(*configMap)[key] = value;
	}
	inp.close();
}

Config* Config::instance (char * filename){
	static Config c (filename);
	return  &c;
}

void Config::init_server(Server* server){
	map<string, string>* m = configMap;
	struct hostent* he;
	int port;
	int id;
	Config* config = server->config;

	if ( m->find("address")!=m->end() ){
		vector<string> tokens;
		string value  = (*m)["address"];
		tokenize (value, tokens, "_");
		id=atoi(tokens[0].c_str());
		he=gethostbyname(tokens[1].c_str());
		port=atoi(tokens[2].c_str());
		printf("My id=%s hostname=%s port=%s.\n", tokens[0].c_str(), tokens[1].c_str(),
			tokens[2].c_str());
		server->address.sin_family=AF_INET;
		server->address.sin_port=htons(port);
		server->address.sin_addr.s_addr = /*htonl(INADDR_ANY);*/ *((in_addr_t *)he->h_addr);
		memset(&(server->address.sin_zero),'\0',8);
		server->id=id;
		memset (server->ip, 0, IP_ADDRESS);
		memcpy (server->ip, inet_ntoa (server->address.sin_addr), IP_ADDRESS);
		server->port = port;

	} else{
		Log::print ("Error: Could not find a value for address\n", Log::SILENT);
		exit(1);
	}
	
	if ( m->find ("pv->interval") != m->end() ){
		vector<string> tokens;
		string value  = (*m)["pv_interval"];
		tokenize (value, tokens, ":");
		config->pvInterval.tv_sec=atoi (tokens[0].c_str());
		config->pvInterval.tv_usec=atoi (tokens[1].c_str());
	} else {
		config->pvInterval.tv_sec=10;
		config->pvInterval.tv_usec=0;
	}

	if ( m->find ("polling_interval") != m->end() ){
		vector<string> tokens;
		string value  = (*m)["polling_interval"];
		tokenize (value, tokens, ":");
		config->pollInterval.tv_sec=atoi (tokens[0].c_str());
		config->pollInterval.tv_usec=atoi(tokens[1].c_str());
	} else {
		config->pollInterval.tv_sec=10;
		config->pollInterval.tv_usec=10000;
	}

	if ( m->find ("level") != m->end () ){
		string value  = (*m)["level"];
		if(value == "vvverbose")
			config->level=Log::VVVERBOSE;
		else if(value == "vverbose")
			config->level=Log::VVERBOSE;
		else if(value == "verbose")
			config->level=Log::VERBOSE;
		else if (value == "silent")
			config->level=Log::SILENT;
		else
			config->level=Log::NORMAL;
	} else {
		config->level=Log::NORMAL;
	}

	if ( m->find ("scheduler") != m->end () ){
		string value  = (*m)["scheduler"];
		if(value == "fifo")
			config->schedulerType = Scheduler::FIFO; 
		else
			config->schedulerType = Scheduler::PRIORITY;
	} else {
		config->schedulerType = Scheduler::PRIORITY;
	}
	
/*	if( m->find("router_type") != m->end () ){
		string value = (*m)["router_type"];
		if( value == "pv" )
			config->routerType=PV;
		else if ( value == "ls" ) 
			config->routerType=LS;
		else if ( value == "dv" )
			config->routerType=DV;
		else
			config->routerType=NONE;
	}
*/
	server->isMalicious=get_boolean(m,"is_malicious",	false);
	server->chain=get_int(m,"chain",1);
	string tmp = get_string(m,"neighbor_file");
	strcpy (config->neighborFile, tmp.c_str() );
	server->k=get_int(m,"k",1);
	config->msgsPerPoll=get_int(m,"msgs_per_poll",1);
	config->wakeupTime=get_int(m,"wakeup_time",2);
	config->fakeId=get_int(m,"fake_id",5000);
	config->beaconInterval=get_int(m,"beacon_interval",30);
	config->warmupTime=get_int(m,"warmup_time",10);
	config->n=get_int(m,"n",-1);
	config->bufferManagement=get_int(m,"buffer_management",0);
	config->singleStart=get_int(m,"single_start",0);
	config->flowComputeInterval = get_int (m, "flow_compute_interval", 20);
	config->dnsPort=get_int (m, "dns_port", 2001);

	config->startRouter=get_int(m,"start_router",35);
	config->routerInterval=get_int(m,"router_interval",30);
	config->optimization=get_int(m,"optimization",0);
	config->malFrequency=get_int(m,"mal_frequency",10);
	config->testTwoNode = get_boolean (m, "test_two_node", false);
	config->pathVectorTest = get_boolean (m, "path_vector_test", false);

	if( m->find("no_crypto") == m->end() ){
		string value = (*m)["no_crypto"];
		if ( value == "true")
			config->noCrypto=1;
		else
			config->noCrypto=0;
	}
	if( m->find("mal_list") == m->end()){
		vector <string> tokens;
		string value = (*m)["mal_list"];
		int count=0;
		tokenize (value, tokens, "," );
		typedef vector<string>::iterator iter;
		for (iter i = tokens.begin(); i!=tokens.end(); i++){
			config->malList[count]=atoi((*i).c_str());
		}
		config->malListSize= tokens.size();
		if (count==MAL_LIST_LIMIT -1 ){
			printf("Exceeded maximum MAL_LIST_LIMIT\n");
		}
	}else{
		config->malListSize=0;
	}		
}


int Config::get_int(map<string, string>* m, string key, int defaultValue){
	int result=defaultValue;
	if ( m->find (key) != m->end ()){
		string value = (*m)[key];
		result = atoi (value.c_str());
	}
	return result;
}

bool Config::get_boolean(map<string,string>* m, string key, bool  defaultValue){
	bool result=defaultValue;
	if ( m->find (key) != m->end ()){
		if ( (*m)[key]=="true")
			result = true;
		else
			result = false;
	}
	return result;
}

string Config::get_string(map<string, string>* m, string key){
	if ( m->find (key) != m->end ()){
		string value = (*m)[key];
		return value.c_str();
	}else{
		Log::print ("Error: Could not find value for key:"+ key + "\n", Log::SILENT);
		exit(1);
	}
}

Config::~Config(){
	configMap->clear();
}

void Config::tokenize(const string& str, vector<string>& tokens, const string& delimiters = ":"){    
	// Skip delimiters at beginning.
	string::size_type lastPos = str.find_first_not_of(delimiters, 0);
	// Find first "non-delimiter".
	string::size_type pos     =	str.find_first_of(delimiters, lastPos);
	while (string::npos	!= pos || string::npos != lastPos) {
		// Found a token,
		// add it to the vector.
		tokens.push_back(str.substr(lastPos, pos - lastPos));
		// Skip delimiters.
		lastPos = str.find_first_not_of(delimiters, pos);
		// Find next "non-delimiter"
		pos	= str.find_first_of(delimiters, lastPos);
	}
}
