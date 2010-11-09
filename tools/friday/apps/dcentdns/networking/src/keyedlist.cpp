#include "global.h"
#include "pv.h"
#include "keyedlist.h"
#include "rsa.h"
#include "logger.h"

/////CPP

Id::Id (){
	id = -1;
	memset (ip, 0, IP_ADDRESS);
}

Id::Id (const Id& i){
	id = i.id;
	memcpy(ip, i.ip, IP_ADDRESS);
}

Id::Id (int _id, char* _ip){
	id = _id;	
	memset (ip, 0, IP_ADDRESS);
	memcpy (ip, _ip, IP_ADDRESS);
}

Id::~Id(){}

const Id& Id::operator= (const Id& i){
	if (this != &i){
		id = i.id;
		memset (ip, 0, IP_ADDRESS);
		memcpy(ip, i.ip, IP_ADDRESS);
	}
	return *this;
}

bool Id::operator < (const Id& i) const{
	if ( id < i.id )
		return true;
	else 
		return false;
}

bool Id::operator == (const Id& i) const{
	if( id == i.id ){
		return true;
	}else
		return false;
}

void Id::print ( char* caption, int level) {
}


KeyedId::KeyedId(){
	publicKey = NULL;
}

KeyedId::KeyedId(const KeyedId& k):Id(k){
	if (k.publicKey == NULL)
		publicKey = NULL;
	else
		publicKey = RSAPublicKey_dup(k.publicKey);
}

KeyedId::KeyedId (int id, char* ip, RSA* _publicKey):Id(id, ip){
	Log::print ( "Entering KeyedId::KeyedId\n", Log::VVVERBOSE);
	if (_publicKey==NULL){
		publicKey = NULL;
	}
	else{
		publicKey = RSAPublicKey_dup (_publicKey);
	}
	Log::print ( "Leaving KeyedId::KeyedId\n", Log::VVVERBOSE);
}

const KeyedId& KeyedId::operator= (const KeyedId& k){
	if (this!= &k){
		id = k.id;
		memset (ip, 0, IP_ADDRESS);
		delete_rsa (&publicKey);
		memcpy(ip, k.ip, IP_ADDRESS);
		if (k.publicKey == NULL)
			publicKey = NULL;
		else
			publicKey = RSAPublicKey_dup(k.publicKey);

	}
	return *this;
}

bool KeyedId::operator < (const KeyedId& k) const{
	Log::print ( "Entering  KeyedId::<\n", Log::VVVERBOSE);
	unsigned char buf1[KEY_SIZE];
	unsigned char buf2[KEY_SIZE];
	for (int i=0;i<KEY_SIZE;i++)
		buf1[i]=buf2[i]=0;
	if ( id < k.id )
		return true;
	else if ( id > k.id )
		return false;
	else{
		if ( publicKey == NULL ){
			if ( k.publicKey == NULL)
				return false;
			else 
				return true;
		}else{
			if ( k.publicKey == NULL )
				return true;
			else{ 
				public_key_to_char(publicKey, buf1, KEY_SIZE);
				public_key_to_char(k.publicKey, buf2, KEY_SIZE);
				int out=memcmp(buf1,buf2, KEY_SIZE);
				if(out<0)
					return true;
				else
					return false;
			}
		}	
	}
}
	
bool KeyedId::operator == (const KeyedId& k) const{
	unsigned char buf1[KEY_SIZE];
	unsigned char buf2[KEY_SIZE];
	Log::print ( "Entering  KeyedId::==\n", Log::VVVERBOSE);
	for (int i=0;i<KEY_SIZE;i++)
		buf1[i]=buf2[i]=0;
	if( id == k.id ){
		if( publicKey==NULL|| k.publicKey==NULL){
			Log::print ( "result=true\n", Log::VVVERBOSE);
			return true;
		}
		public_key_to_char(publicKey, buf1, KEY_SIZE);
		public_key_to_char(k.publicKey, buf2, KEY_SIZE);
		int result=memcmp(buf1,buf2, KEY_SIZE);
		if(result==0) {
			Log::print ( "result=true\n", Log::VVVERBOSE);
			return true;
		} else {
			Log::print ( "result=false\n", Log::VVVERBOSE);
			return false;
		}
	}	
	Log::print ( "result=false\n", Log::VVVERBOSE);
	return false;
}

KeyedId::~KeyedId (){
	delete_rsa (&publicKey);	
}

void KeyedId::print (char* caption, int level){
}


PVElement* KeyedId::get_pve(){
	unsigned char buf[KEY_SIZE];
	for (int i=0;i<KEY_SIZE;i++)
		buf[i]=0;

	int keySize  = public_key_to_char(publicKey, buf, KEY_SIZE);
	PVElement* pve = new PVElement ( PVElement::PK, id, ip, buf, keySize);
	return pve;
}


Edge::Edge(){}

Edge::Edge (const Edge& e){
	v1 = e.v1;
	v2 = e.v2;
}

Edge::Edge (KeyedId _v1, KeyedId _v2){
	v1 = _v1;
	v2 = _v2;
}

Edge::~Edge(){}

const Edge& Edge::operator= (const Edge& e){
	if (this != &e){
		v1 = e.v1;
		v2 = e.v2;
	}
	return *this;
}

bool Edge::operator < (const Edge& e ) const{
	if (v1 < e.v1)
		return true;
	else if ( e.v1 < v1)
		return false;
	if (v2 < e.v2)
		return true;
	else
		return false;
}

bool Edge::operator == (const Edge& e ) const{
	bool result1 = (v1 == e.v1);
	bool result2 = (v2 == e.v2);

	if (result1 && result2)
		return true;
	else
		return false;
}

Path::Path(){
}

Path::Path(	const Path& p){
	v = p.v;
}

Path::Path (vector<KeyedId>& _v){
	v = _v;
}

Path::~Path(){}

const Path& Path::operator= (const Path& p){
	if (this != &p){
		v = p.v;		
	}
	return *this;
}



bool Path::operator < (const Path& p) const{
	return v < p.v;
}

bool Path::operator== (const Path& p) const{
	return v == p.v;
}

void Path::add_element (KeyedId& e){
	v.push_back(e);
}

void Path::print (char* caption, int level){
	for ( viter i=v.begin(); i!=v.end(); i++){
		(*i).print(caption, level);
	}
}

int Path::count_new_nodes ( set<KeyedId>* s){
	int count = 0;
	for ( viter i=v.begin(); i!=v.end(); i++){
		KeyedId e = *i;
		if ( s->find (e) == s->end()) {
			count++;
			s->insert (e);
		}	
	}
	return count;
}

int Path::count_new_edges (set<Edge>* s){
	int count = 0;
	for ( viter i=v.begin(); (i+1)!=v.end(); i++){
		Edge e = Edge(*i, *(i+1));
		if ( s->find (e) == s->end()) {
			count++;
			s->insert (e);
		}
	}
	return count;
}

KeyedId* Path::get_first_node(){
	KeyedId* ki = NULL;
	if (v.size() > 0)
		ki = &v.front();

	return ki;
}	

bool Path::is_present ( KeyedId& e ){
	viter i = find ( v.begin(), v.end(), e);
	return (i!=v.end());
}

bool Path::intersects (Path& p ){
	typedef vector<KeyedId>::iterator viter;
	for ( viter i=p.v.begin()+1; i!=p.v.end()-1; i++){
		viter j = find ( v.begin()+1, v.end()-1, *i);
		if ( j!=v.end() )
			return true;
	}
	return false;
}



PathList::PathList():paths(){
}

PathList::PathList (Path& pv){
	paths.push_back(pv);
}

PathList::PathList (const PathList& _pl){
	paths = _pl.paths;
}

const PathList& PathList::operator = (PathList &_pl){
	if ( this != &_pl ){
		paths = _pl.paths;
	}
	return *this; 
}

PathList::~PathList(){}

void PathList::add_path ( Path& pv ){
	for (viter i = paths.begin(); i!=paths.end(); i++){
		if (*i==pv)
			return;
	}
	paths.push_back (pv);
}

PathList* PathList::found_disjoint ( int k ){
	Log::print ( "Entering PathList::found_disjoint\n", Log::VVVERBOSE);

	typedef vector<KeyedId>::iterator viter;
	/*	index is used to store each of the possible combinations of paths .
		i.e. index stores each each combination C(n,k)
		*/
	int n = size();
	int index[k];
	
	for(int i=0;i<k-1;i++)
		index[i]=i;
	
	/* Always include the most recent path found*/
	index[k-1]=n-1;
	
	while(index[0]<n-k+1){
			
		/* 	Stores all the nodes seen in the 
			current combination of paths chosen*/
		for ( int j=0 ; j<k; j++){
			Log::print ( ":" + to_string(index[j]), Log::VVVERBOSE);
		}
		Log::print ("\n", Log::VVVERBOSE);
			
		set<KeyedId> tmpSet;
		bool flag = true;
		for ( int j=0; j<k && flag; j++){
			Path* p = &paths[index[j]];
			for (viter i = p->v.begin(); i!=p->v.end(); i++){
				/* Discount the nodes at the beginning and the end */
				if ( i==p->v.begin() || (i+1)==p->v.end())
					continue;
				Log::print (":" + to_string(*i) , Log::VVVERBOSE);
				if (tmpSet.find(*i)==tmpSet.end())
					tmpSet.insert(*i);
				else{
					flag = false;
					break;
				}
			}
			Log::print ( "\n", Log::VVVERBOSE);
			Log::print ( "j=" + to_string(j) + "\tflag=" + to_string(flag) + "\n", Log::VVVERBOSE);
		}
		if (flag){
			PathList* result  = new PathList();
			for ( int j=0; j<k ; j++){
				Path* p = &paths[index[j]];
				result->add_path(*p);
			}
			return result;
		}
		/*	Generate the next combination*/
		int i;
		for( i=k-2;i>=0 && index[i]>=n-k+i;i--);
		index[i]++;
		for(i++;i<k-1;i++)
			index[i]=index[i-1]+1;
	
	}
	Log::print ( "Leaving PathList::found_disjoint\n", Log::VVVERBOSE);
	return NULL;
}

const int PathList::size () const{
	return paths.size();
}


