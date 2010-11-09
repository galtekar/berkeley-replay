#ifndef _DC_H

#define DC_H

class KeyedId;
class Id;
class Edge;
class Server;

class DataContainer{
		DataContainer ();
		~DataContainer ();
		int nodes;
		int edges;
		map <KeyedId, int>* serializeMap;
		map <int, KeyedId>* deserializeMap;
		set <KeyedId>* knownNodeSet;
		set <KeyedId>* unknownNodeSet;
		set <Edge>* edgeSet;
		map<Id, RSA*>* keyMap;
		map <int, int >* countMap;

		multimap <KeyedId, Neighbor> *tmpNodeMap;
		set<Edge> *tmpEdgeSet;
		set<Message>* dnsCache;

		bool validStream;
		bool topologyChanged;
		stringstream s;
		void set_stream ( set<Edge>* es);
	public:
		static DataContainer* instance ();
		int add_node ( KeyedId& ki , bool known = false);
		void add_edge ( Edge& e);
		void make_known ( KeyedId& ki);

		void delete_node ( KeyedId& ki);
		void delete_edge ( Edge& e);
		void compute_flows ( Server* server);

		bool is_new_node ( KeyedId& ki);
		bool is_new_edge ( Edge& edge);

		set<Edge>* get_edge_set();
		set<KeyedId>* get_known_node_set();
		set<KeyedId>* get_unknown_node_set();
		map<Id, RSA*>* get_key_map();
		string get_edge_string();

		int DataContainer::node_size();
		int DataContainer::edge_size();
		KeyedId* get_node(int i);
		void add_tmp_node (KeyedId& ki, Neighbor& neighbor, int k);
		bool add_dns_message( Message& msg);
};

#endif
