//---------------------------------------------------------- -*- Mode: C++ -*-
// $Id: ClientManager.h 351 2009-05-27 05:40:23Z sriramsrao $
//
// Created 2006/03/28
// Author: Sriram Rao
//
// Copyright 2008 Quantcast Corp.
// Copyright 2006-2008 Kosmix Corp.
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

#ifndef _CLIENTMANAGER_H
#define _CLIENTMANAGER_H

#include <cassert>
#include "libkfsIO/Acceptor.h"
#include "ClientSM.h"

namespace KFS
{

class ClientManager : public IAcceptorOwner {
public:
    ClientManager()
        : mAcceptor(0), mClientCount(0), mIoTimeoutSec(-1), mIdleTimeoutSec(-1)
    {}
    void SetTimeouts(int ioTimeoutSec, int idleTimeoutSec)
    {
        mIoTimeoutSec = ioTimeoutSec;
        mIdleTimeoutSec = idleTimeoutSec;
    }
    virtual ~ClientManager() {
        assert(mClientCount == 0);
        delete mAcceptor;
    };
    void StartAcceptor(int port);
    KfsCallbackObj *CreateKfsCallbackObj(NetConnectionPtr &conn) {
        ClientSM *clnt = new ClientSM(conn);
        assert(mClientCount >= 0);
        mClientCount++;
        return clnt;
    }
    void Remove(ClientSM *clnt) {
        assert(mClientCount > 0);
        mClientCount--;
    }
    int GetIdleTimeoutSec() const {
        return mIoTimeoutSec;
    }
    int GetIoTimeoutSec() const {
        return mIoTimeoutSec;
    }
private:
    Acceptor *mAcceptor;
    int      mClientCount;
    int      mIoTimeoutSec;
    int      mIdleTimeoutSec;
};

extern ClientManager gClientManager;

}

#endif // _CLIENTMANAGER_H
