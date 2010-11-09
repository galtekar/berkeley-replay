#ifndef HEX_OPS_H
#define HEX_OPS_H

extern void hex_decode(char* out_buf, const size_t out_size, const void* in_buf, size_t size);
extern void hex_encode(void* out_buf, const size_t out_size, const char* in_buf, size_t size);

#endif
