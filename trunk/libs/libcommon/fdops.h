#pragma once

#ifdef __cplusplus
extern "C" {
#endif

extern int fd2path(int fd, char* buf, int bufsiz);

extern dev_t fd2dev(int fd);

extern ino_t fd2inode(int fd);

#ifdef __cplusplus
}
#endif
