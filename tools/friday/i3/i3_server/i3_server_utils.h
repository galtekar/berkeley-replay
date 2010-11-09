int is_id_local(ID *id,srv_context* ctx);
struct in_addr get_my_addr();

i3_option *create_i3_option_req_cache();
i3_option *create_i3_option_sender(srv_context *ctx);
i3_header *replace_stack(i3_header *hdr, i3_addr *to);
     
void nat_translate_sender_ip_option(char* option,i3_addr* to_addr);
void checkoptions(char *pkt,char* natted,char* insert,char* remove,char* data,i3_addr* real_addr);
