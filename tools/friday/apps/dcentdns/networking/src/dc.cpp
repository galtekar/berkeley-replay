#include "global.h"
#include "maxflow.h"

DataContainer::DataContainer (){
	serializeMap 	= new map <KeyedId,int> ();
	deserializeMap 	= new map <int, KeyedId>();
	knownNodeSet	= new set <KeyedId>();
	unknownNodeSet	= new set <KeyedId>();
	edgeSet			= new set <Edge>();
	keyMap			= new map <Id, RSA*>();
	nodes = 0;
	edges = 0;
	validStream = true;
	topologyChanged = false;

	countMap 		= new map <int, int>();
	tmpNodeMap		= new multimap<KeyedId, Neighbor>;
	tmpEdgeSet		= new set<Edge>;

	dnsCache		= new set<Message>();
}

DataContainer::~DataContainer(){
	delete serializeMap;
	delete deserializeMap;
	delete edgeSet;
	delete knownNodeSet;
	delete unknownNodeSet;
	delete countMap;
	delete dnsCache;
}

DataContainer* DataContainer::instance () {
	static DataContainer f;
	return &f;
}

int DataContainer::add_node ( KeyedId& ki , bool known){
	if (serializeMap->find (ki) != serializeMap->end()){
		return (*serializeMap)[ki];
	}
	nodes++;
	serializeMap->insert (make_pair (ki, nodes));
	deserializeMap->insert ( make_pair ( nodes, ki)); 
	Log::print ("Adding node:" + to_string(ki)  + " mapped to " + to_string(nodes) + " with status " + to_string(known) + "\n", Log::NORMAL);
	if (known) {
		knownNodeSet->insert (ki);
		Log::print ("Node " + to_string(ki) + " is reliable.\n", Log::VERBOSE);
		if (keyMap->find (ki) != keyMap->end())
			keyMap->erase (ki);
		keyMap->insert (make_pair (ki, RSAPublicKey_dup(ki.publicKey)));
	}
	else
		unknownNodeSet->insert(ki);
	return nodes;
}

void DataContainer::add_edge ( Edge& e){
	Log::print ("Entering DataContainer::add_edge \n", Log::VVVERBOSE);
	if ( edgeSet->find (e) == edgeSet->end()){
		int v1,v2;
		if ( (serializeMap->find (e.v1) != serializeMap->end()) ){
			v1 = (*serializeMap)[e.v1];
		} else {
			v1 = add_node (e.v1);
		}
	
		if ( (serializeMap->find (e.v2) != serializeMap->end()) ){
			v2 = (*serializeMap)[e.v2];
		} else {
			v2 = add_node (e.v2);
		}
		Log::print ("Adding edge:" + to_string(e)+"\n" , Log::NORMAL);
		edges ++;
		edgeSet->insert (e);
		topologyChanged = true;
		(*countMap )[v1]++;
		(*countMap )[v2]++;
	//	string str = "a "+ v1 + " " +v2 + " 1";
		string str = "a "+ to_string(v2) + " " +to_string(v1) + " 1";
		s << str <<endl;
	}
	Log::print ("Leaving DataContainer::add_edge \n", Log::VVVERBOSE);
}

void DataContainer::make_known ( KeyedId& ki){
	if (unknownNodeSet->find (ki) != unknownNodeSet->end ()){
		knownNodeSet->insert(ki);
		unknownNodeSet->erase(ki);
	}
}

void DataContainer::delete_node ( KeyedId& ki ){
	if (serializeMap->find (ki) != serializeMap->end()){
		int index = (*serializeMap)[ki];
		nodes--;
		deserializeMap->erase(index);
		serializeMap->erase(ki);
		knownNodeSet->erase(ki);
		unknownNodeSet->erase(ki);
		typedef set<Edge>::iterator iter;
		for (iter i = edgeSet->begin(); i!=edgeSet->end(); i++){
			Edge e = *i;
			if (e.v1 == ki || e.v2 == ki){
				edgeSet->erase(e);
				validStream = false;
			}
		}
	}
}

void DataContainer::delete_edge (Edge& e){
	if (edgeSet->find (e) != edgeSet->end()){
		edgeSet->erase(e);
		edges--;
		validStream = false;
	}
}


void DataContainer::set_stream ( set<Edge>* es){
	s.str("");
	typedef set<Edge>::iterator iter;
	for (iter i = es->begin();
			i!=es->end();
				i++ ){
		int v1 = (*serializeMap)[i->v1];
		int v2 = (*serializeMap)[i->v2];
//		string str = "a "+ v1 + " " +v2 + " 1";
		s << "a " << v2 << " " << v1 << " 1" << endl;
	}
	validStream = true;
}

void DataContainer::compute_flows (Server* server){
	Log::print (" Entering DataContainer::compute_flows\n", Log::VVVERBOSE);
	if ( nodes <=0 || edges <=0 ){
		return;
	}
	map <KeyedId, int>* optimizedNodeMap = server->optimizedNodeMap;
	typedef set<KeyedId>::iterator iter;

	Log::print ( "Count map\n", Log::VERBOSE);
	for (map<int, int>::iterator i = countMap->begin();
				i != countMap->end(); i++){
		int node= i->first;
		int edge= i->second;
		Log::print (""+ to_string(node)+ "=" + to_string(edge) + "\n", Log::VERBOSE);
	}
	string header  = "p max " + to_string(nodes) + " " + to_string(edges) + "\n";
//	string header  = string("p max 1 1");
	header += string("n 1 s\nn 1 t\n");
	stringstream is (stringstream::in|stringstream::out);
	if ( !validStream )
		set_stream (edgeSet);
	is << header;
	is << s.str();
	Log::print ("Input:\n" + is.str(), Log::VERBOSE);
	MaxFlow mf (is);

	set<KeyedId> tmpSet;

	for (iter i = unknownNodeSet->begin();
			i != unknownNodeSet->end();
				i++ ){
		assert ( serializeMap->find (*i) != serializeMap->end() );
		
		int sink = (*serializeMap)[*i];
		Log::print ( "Computing flows to node:" + to_string(*i) + ":" + to_string(sink) + "\n", Log::VERBOSE);
		double flow = mf.run (sink);	
		Log::print ( "Finished computing flows to node:" + to_string(*i) + ":" + to_string(sink) + "\n", Log::VERBOSE);

		if ( flow >= server->k ){
			/* A reliable node */
			knownNodeSet->insert (*i);
			
			Log::print ("Node " + to_string(*i) + " is reliable.\n", Log::VERBOSE);
			// TODO - Add sequence numbers to messages	
			/* 	This id already has a reliable keyed id.
				A newer reliable keyed id for this id => A change in this mapping
				*/
			if (keyMap->find (*i) != keyMap->end())
				keyMap->erase (*i);
			keyMap->insert (make_pair (*i, RSAPublicKey_dup(i->publicKey)));
			optimizedNodeMap->insert (make_pair(*i, 0));
			tmpSet.insert(*i);

			/* 	Don't remove these nodes from the 
			 *  unknownNodeSet because that would
			 *  invalidate the iterator
			 */

		
		} else {
			/*	Don't have k disjoint paths */
			Log::print ("Can't find k disjoint paths to " + to_string(*i) + "\n", Log::VERBOSE);
											
		}
	}
	for ( iter i = tmpSet.begin();
				i != tmpSet.end();
					i++){
		unknownNodeSet->erase (*i);
	}

	Log::print ("Number of verified nodes:" + to_string(knownNodeSet->size()) + "\n", Log::NORMAL);
	Log::print ( "List of verified nodes\n" + to_string (*knownNodeSet) + "\n", Log::VERBOSE);
	Log::print ( "List of unverified nodes\n" + to_string (*unknownNodeSet) + "\n", Log::VERBOSE);
	Log::print ("Number of optimized verified nodes:" + to_string(optimizedNodeMap->size()) + "\n", Log::NORMAL);
	Log::print ("Number of unverified nodes:" + to_string(unknownNodeSet->size()) + "\n", Log::NORMAL);
	Log::print ("Number of edges:" + to_string(edgeSet->size()) + "\n", Log::NORMAL);

	Log::print ("Leaving DataContainer::compute_flows\n", Log::VVVERBOSE);
}

bool DataContainer::is_new_node ( KeyedId& ki) {
	return (serializeMap->find (ki)== serializeMap->end());
}

bool DataContainer::is_new_edge ( Edge& edge){
	return (edgeSet->find (edge)== edgeSet->end());
}

set<Edge>* DataContainer::get_edge_set() {
	return edgeSet;
}

set<KeyedId>* DataContainer::get_known_node_set(){
	return knownNodeSet;
}

map<Id, RSA*>* DataContainer::get_key_map(){
	return keyMap;
}

set<KeyedId>* DataContainer::get_unknown_node_set(){
	return unknownNodeSet;
}

string DataContainer::get_edge_string(){
	if ( !validStream )
		set_stream (edgeSet);
	return s.str();
	
}

int DataContainer::node_size(){
	return nodes;
}

int DataContainer::edge_size(){
	return edges;
}

KeyedId* DataContainer::get_node(int i){
	if ( deserializeMap->find(i) != deserializeMap->end()){
		return &(*deserializeMap)[i];
	}
	return NULL;
}

void DataContainer::add_tmp_node (KeyedId& ki, Neighbor& neighbor, int k){
	tmpNodeMap->insert(make_pair(ki, neighbor));
	if (tmpNodeMap->count(ki) >= k){
		add_node (ki, true);
		tmpNodeMap->erase (ki);
	}
}


bool DataContainer::add_dns_message( Message& msg){
	Log::print ("Entering DataContainer::add_dns_message \n", Log::VERBOSE);
	typedef set<Message>::iterator iter;
	Log::print ("Cache size=" + to_string (dnsCache->size())+"\n", Log::VERBOSE);
	Log::print ("msg.payloadSize=" + to_string(msg.payloadSize) + "\n", Log::VERBOSE);
	Log::print ("msg.payload\n", Log::VERBOSE);
	Log::dump ( msg.payload, msg.payloadSize, Log::VERBOSE);
	for (iter i = dnsCache->begin(); i!=dnsCache->end() ; i++){
		if ( msg.payloadSize == i->payloadSize &&
			(memcmp ( msg.payload, i->payload, i->payloadSize)==0)){
			Log::print ("Not adding message\n", Log::VERBOSE);
			return false;
		} else {
			Log::print ("i->payloadSize=" +  to_string(i->payloadSize) + "\n", Log::VERBOSE);
			Log::print ("i->payload\n", Log::VERBOSE);
			Log::dump ( i->payload, i->payloadSize, Log::VERBOSE);
		}
	}
	Log::print ("Inserting message into dnsCache\n", Log::VERBOSE);
	pair<set<Message>::iterator, bool> p = dnsCache->insert (msg);
	Log::print ("Cache size=" + to_string (dnsCache->size())+"\n", Log::VERBOSE);
	Log::print ("Inserted ? " + to_string(p.second)+  "\n", Log::VERBOSE);
	Log::print ("Leaving DataContainer::add_dns_message \n", Log::VERBOSE);
	return true;
}
