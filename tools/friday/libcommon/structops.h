#ifndef STRUCTOPS_H
#define STRUCTOPS_H

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#define MAX_STRING_SIZE 256
#define MAX_STRINGS 10

struct hostent_flat {
   char h_name[MAX_STRING_SIZE] ;
   char h_aliases[MAX_STRINGS][MAX_STRING_SIZE] ;
   int num_h_aliases;
   int h_addrtype ;
   int h_length ;
   char h_addr_list[MAX_STRINGS][MAX_STRING_SIZE] ;
   int num_h_addr_list;
};

struct passwd_flat {
	char pw_name[MAX_STRING_SIZE] ;
	char pw_passwd[MAX_STRING_SIZE] ;
	__uid_t pw_uid ;
	__gid_t pw_gid ;
	char pw_gecos[MAX_STRING_SIZE] ;
	char pw_dir[MAX_STRING_SIZE] ;
	char pw_shell[MAX_STRING_SIZE] ;
};

struct flock_flat {
   short l_type ;
   short l_whence ;
   __off_t l_start ;
   __off_t l_len ;
   __pid_t l_pid ;
};

struct servent_flat {
	char s_name[MAX_STRING_SIZE] ;
	char s_aliases[MAX_STRINGS][MAX_STRING_SIZE] ;
	int num_s_aliases;
	int s_port ;
	char s_proto[MAX_STRING_SIZE] ;
};

struct protoent_flat {
	char p_name[MAX_STRING_SIZE] ;
	char p_aliases[MAX_STRINGS][MAX_STRING_SIZE] ;
	int num_p_aliases;
	int p_proto ;
};

struct group_flat {
	char gr_name[MAX_STRING_SIZE] ;
	char gr_passwd[MAX_STRING_SIZE] ;
	__gid_t gr_gid ;
	char gr_mem[MAX_STRINGS][MAX_STRING_SIZE] ;
	int num_gr_mem;
};

extern void struct_encode_hostent(struct hostent* s, struct hostent_flat* sf);
extern void struct_decode_hostent(struct hostent* sf, struct hostent_flat* s);
extern void struct_encode_passwd(struct passwd* s, struct passwd_flat* sf);
extern void struct_decode_passwd(struct passwd* sf, struct passwd_flat* s);
extern void struct_encode_flock(struct flock* sf, struct flock_flat* s);
extern void struct_decode_flock(struct flock* sf, struct flock_flat* s);
extern void struct_encode_servent(struct servent *orig , struct servent_flat *flat );
extern void struct_decode_servent(struct servent *orig , struct servent_flat *flat );
extern void struct_encode_protoent(struct protoent *orig , struct protoent_flat *flat );
extern void struct_decode_protoent(struct protoent *orig , struct protoent_flat *flat );
extern void struct_decode_group(struct group *orig , struct group_flat *flat );
extern void struct_encode_group(struct group *orig , struct group_flat *flat );
#endif
