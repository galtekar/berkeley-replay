#ifndef FDOPS_H
#define FDOPS_H

extern ssize_t safe_write(int fd, void* buf, size_t len);

extern ssize_t safe_read(int fd, void* buf, size_t len);

#endif
