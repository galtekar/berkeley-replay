#pragma once

extern const struct FileOps BadSock_Fops;

struct SockStruct {
   int fd, orig_fd;

   int family, type, protocol;

   ino_t ino;

   const struct SockOps *ops;

   tsock_socket_info_t tsock;
};
extern struct SockStruct* Sock_GetStruct(struct InodeStruct *inodp);
