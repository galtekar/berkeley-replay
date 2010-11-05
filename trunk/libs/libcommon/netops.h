#pragma once


extern ssize_t 
NetOps_SendAll(int fd, const void* buf, size_t len, int flags);

extern ssize_t 
NetOps_ReadAll(int fd, void* buf, size_t len, int flags);

extern ssize_t
NetOps_Pack(void *buf, size_t buf_len, const char *fmt, ...);

extern ssize_t
NetOps_Unpack(const void *buf, size_t buf_len, const char *fmt, ...);

extern int
NetOps_GetLocalAddr();
