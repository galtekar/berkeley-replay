#include <string.h>
#include <assert.h>

#include "structops.h"
#include "gcc.h"

#define STRARRAY_ENCODE(flat, orig, num) { \
	int i = 0; \
	while (orig[i] != NULL) { \
		strncpy(flat[i], orig[i], MAX_STRING_SIZE); \
		i++; \
		assert(i < MAX_STRINGS); \
	} \
	num = i; \
}

#define STRARRAY_DECODE(orig, flat, num) { \
	int i = 0; \
	while (i < num) { \
		strncpy(orig[i], flat[i], MAX_STRING_SIZE); \
		i++; \
	} \
}

void HIDDEN struct_decode_hostent(struct hostent *orig , struct hostent_flat *flat ) 
{ 

	{
		strncpy(orig->h_name, flat->h_name, MAX_STRING_SIZE);
		STRARRAY_DECODE(orig->h_aliases, flat->h_aliases, flat->num_h_aliases);
		orig->h_addrtype = flat->h_addrtype;
		orig->h_length = flat->h_length;
		//STRARRAY_DECODE(orig->h_addr_list, flat->h_addr_list, flat->num_h_addr_list);
		{
			int i = 0; 
			while (i < flat->num_h_addr_list) { 
				memcpy(orig->h_addr_list[i], flat->h_addr_list[i], flat->h_length); 
				i++; 
			} 
		}
	}
}

void HIDDEN struct_encode_hostent(struct hostent *orig , struct hostent_flat *flat ) 
{ 

	{
		strncpy(flat->h_name, orig->h_name, MAX_STRING_SIZE);
		STRARRAY_ENCODE(flat->h_aliases, orig->h_aliases, flat->num_h_aliases);
		flat->h_addrtype = orig->h_addrtype;
		flat->h_length = orig->h_length;
		//STRARRAY_ENCODE(flat->h_addr_list, orig->h_addr_list, flat->num_h_addr_list);
		{
			int i = 0;
			while (orig->h_addr_list[i] != NULL) {
				assert(i < MAX_STRINGS);
				assert(orig->h_length <= MAX_STRING_SIZE);
				memcpy(flat->h_addr_list[i], orig->h_addr_list[i], orig->h_length);
				i++;
			}
			flat->num_h_addr_list = i;
		}
	}
}

void HIDDEN struct_encode_passwd(struct passwd* s, struct passwd_flat* sf) {
	strncpy(sf->pw_name, s->pw_name, MAX_STRING_SIZE);
	strncpy(sf->pw_passwd, s->pw_passwd, MAX_STRING_SIZE);
	sf->pw_uid = s->pw_uid;
	sf->pw_gid = s->pw_gid;
	strncpy(sf->pw_gecos, s->pw_gecos, MAX_STRING_SIZE);
	strncpy(sf->pw_dir, s->pw_dir, MAX_STRING_SIZE);
	strncpy(sf->pw_shell, s->pw_shell, MAX_STRING_SIZE);
}

/* The assumption here is that the flat and non-flat versions are
 * in statically allocated memory. */
void HIDDEN struct_decode_passwd(struct passwd* s, struct passwd_flat* sf) {
	s->pw_name = sf->pw_name;
	s->pw_passwd = sf->pw_passwd;
	s->pw_uid = sf->pw_uid;
	s->pw_gid = sf->pw_gid;
	s->pw_gecos = sf->pw_gecos;
	s->pw_dir = sf->pw_dir;
	s->pw_shell = sf->pw_shell;
}

void HIDDEN struct_decode_flock(struct flock *orig , struct flock_flat *flat )
{

	{
		orig->l_type = flat->l_type;
		orig->l_whence = flat->l_whence;
		orig->l_start = flat->l_start;
		orig->l_len = flat->l_len;
		orig->l_pid = flat->l_pid;
	}
}
void HIDDEN struct_encode_flock(struct flock *orig , struct flock_flat *flat )
{

	{
		flat->l_type = orig->l_type;
		flat->l_whence = orig->l_whence;
		flat->l_start = orig->l_start;
		flat->l_len = orig->l_len;
		flat->l_pid = orig->l_pid;
	}
}

void HIDDEN struct_decode_servent(struct servent *orig , struct servent_flat *flat )
{
	{
		strncpy(orig->s_name, flat->s_name, MAX_STRING_SIZE);
		STRARRAY_DECODE(orig->s_aliases, flat->s_aliases, flat->num_s_aliases);
		orig->s_port = flat->s_port;
		strncpy(orig->s_proto, flat->s_proto, MAX_STRING_SIZE);
	}
}

void HIDDEN struct_encode_servent(struct servent *orig , struct servent_flat *flat )
{
	{
		strncpy(flat->s_name, orig->s_name, MAX_STRING_SIZE);
		STRARRAY_ENCODE(flat->s_aliases, orig->s_aliases, flat->num_s_aliases);
		flat->s_port = orig->s_port;
		strncpy(flat->s_proto, orig->s_proto, MAX_STRING_SIZE);
	}
}

void HIDDEN struct_decode_protoent(struct protoent *orig , struct protoent_flat *flat ) 
{
	{
		strncpy(orig->p_name, flat->p_name, MAX_STRING_SIZE);
		STRARRAY_DECODE(orig->p_aliases, flat->p_aliases, flat->num_p_aliases);
		orig->p_proto = flat->p_proto;
	}
}
void HIDDEN struct_encode_protoent(struct protoent *orig , struct protoent_flat *flat ) 
{
	{
		strncpy(flat->p_name, orig->p_name, MAX_STRING_SIZE);
		STRARRAY_ENCODE(flat->p_aliases, orig->p_aliases, flat->num_p_aliases);
		flat->p_proto = orig->p_proto;
	}
}

void HIDDEN struct_decode_group(struct group *orig , struct group_flat *flat )
{ 
	{
		strncpy(orig->gr_name, flat->gr_name, MAX_STRING_SIZE);
		strncpy(orig->gr_passwd, flat->gr_passwd, MAX_STRING_SIZE);
		orig->gr_gid = flat->gr_gid;
		STRARRAY_DECODE(orig->gr_mem, flat->gr_mem, flat->num_gr_mem);
	}  
}

void HIDDEN struct_encode_group(struct group *orig , struct group_flat *flat )
{ 

	{
		strncpy(flat->gr_name, orig->gr_name, MAX_STRING_SIZE);
		strncpy(flat->gr_passwd, orig->gr_passwd, MAX_STRING_SIZE);
		flat->gr_gid = orig->gr_gid;
		STRARRAY_ENCODE(flat->gr_mem, orig->gr_mem, flat->num_gr_mem);
	}
}
