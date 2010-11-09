#ifndef _KEYEDLIST_H
#define _KEYEDLIST_H
#include <iterator>

class Id{
	public:
		int id;
		char ip[IP_ADDRESS];
		Id();
		Id (const Id& i);
		Id (int _id, char* _ip);
		const Id& operator = (const Id&	i);
		bool operator < (const Id& i) const;
		bool operator == (const Id & i) const;
		virtual ~Id();

		void print (char* caption, int level);
		friend ostream& operator<< (ostream& os, const Id& _id){
			//return os<< "("<<_id.id<<","<<_id.ip<<")";
			return os<< "("<<_id.id<<")";
		}
	
};

class KeyedId: public Id{
	public:
		RSA* publicKey;
		KeyedId ();
		KeyedId (const KeyedId& k);
		KeyedId (int id, char* ip, RSA* publicKey);
		const KeyedId& operator= (const KeyedId& k);
		bool operator < (const KeyedId& k) const;
		bool operator == (const KeyedId& k) const;
		~KeyedId();

		void print (char* caption, int level);
//		friend ostream& operator<< (ostream& os, const KeyedId& keyedId);
		PVElement* get_pve();
};



class Edge{
	public:
		KeyedId v1,v2;
		Edge ();
		Edge (KeyedId v1, KeyedId v2);
		Edge ( const Edge& e);
		const Edge& operator= (const Edge& e);
		bool operator < ( const Edge& e) const;
		bool operator == (const Edge& e) const;
		~Edge ();

		void print (char* caption, int level);
		friend ostream& operator<< (ostream& os, const Edge& edge){
			return os<<"["<<edge.v1<<"-"<<edge.v2<<"]";
		}

};

class Path{
	public:
		vector<KeyedId> v;
		typedef vector<KeyedId>::iterator viter;
		Path();
		Path (const Path& p);
		Path (vector<KeyedId>& _v);
		const Path& operator= (const Path& p);
		bool operator < (const Path& p) const;
		bool operator == (const Path& p) const;
		~Path();

		void add_element (KeyedId& e);
		int count_new_nodes ( set<KeyedId>* s);
		int count_new_edges ( set<Edge>* s);
		bool is_present (KeyedId& e);
		bool intersects (Path& p);
		KeyedId* get_first_node();

		void print ( char* caption, int level);
		friend ostream& operator<< (ostream& os, const Path& path){
			os <<"[";
			copy (path.v.begin(), path.v.end(), ostream_iterator<KeyedId>(os, "-"));
			os <<"]";
			return os;
		}

};


class PathList{
	public:
		vector<Path> paths;
		typedef vector<Path>::iterator viter;
		PathList ();
		PathList (const PathList& _pl);
		const PathList& operator = (PathList &_pl);
		PathList (Path& path);
		void add_path( Path& pv);
		PathList* found_disjoint (int k);
		const int size () const;
		~PathList ();
		
		void print ( char* caption, int level);
		friend ostream& operator<< (ostream& os, const PathList& pathList){
			os << pathList.paths.size() <<" paths"<<endl;
			copy (pathList.paths.begin(), pathList.paths.end(), ostream_iterator<Path>(os, "\n"));
			os.flush();
			return os;
		}

};

#endif
