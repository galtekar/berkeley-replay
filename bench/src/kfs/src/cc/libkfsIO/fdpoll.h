//---------------------------------------------------------- -*- Mode: C++ -*-
// $Id: fdpoll.h 326 2009-04-25 00:45:50Z sriramsrao $
//
// Created 2009/03/11
// Author: Mike Ovsiannikov
//
// Copyright 2008,2009 Quantcast Corp.
//
// This file is part of Kosmos File System (KFS).
//
// Licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.
//
// 
//----------------------------------------------------------------------------

#ifndef FDPOLL_H
#define FDPOLL_H

namespace KFS
{
class FdPoll
{
public:
    enum OpType
    {
        kOpTypeNone  = 0x00,
        kOpTypeIn    = 0x01,
        kOpTypeOut   = 0x02,
        kOpTypePri   = 0x04,
        kOpTypeError = 0x08,
        kOpTypeHup   = 0x10
    };
    typedef int Fd;

    FdPoll();
    ~FdPoll();
    int Add(
        Fd    inFd,
        int   inOpType,
        void* inUserDataPtr = 0);
    int Set(
        Fd    inFd,
        int   inOpType,
        void* inUserDataPtr = 0);
    int In(
        Fd    inFd,
        void* inUserDataPtr = 0)
        { return Set(inFd, kOpTypeIn, inUserDataPtr); }
    int Out(
        Fd    inFd,
        void* inUserDataPtr = 0)
        { return Set(inFd, kOpTypeOut, inUserDataPtr); }
    int Io(
        Fd    inFd,
        void* inUserDataPtr = 0)
        { return Set(inFd, kOpTypeIn  + kOpTypeOut, inUserDataPtr); }
    int Remove(
        Fd inFd);
    int Poll(
        int inMaxEventCountHint,
        int inWaitMilliSec);
    bool Next(
        int&   outOpType,
        void*& outUserDataPtr);
private:
    class Impl;
    Impl& mImpl;

private:
    FdPoll(const FdPoll& inPoll);
    FdPoll operator=(const FdPoll& inPoll);
};
}
#endif /* FDPOLL_H */
