#pragma once


extern int  Epoll_RealToVirt(struct EpollStruct *ep, 
                struct epoll_event *vevents, int maxevents, 
                struct epoll_event *revents, int revCount);
extern void Epoll_Release(struct FileStruct *);
