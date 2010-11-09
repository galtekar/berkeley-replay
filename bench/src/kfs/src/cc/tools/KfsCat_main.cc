//---------------------------------------------------------- -*- Mode: C++ -*-
// $Id: KfsCat_main.cc 353 2009-05-28 21:54:49Z sjakub $ 
//
// Created 2006/10/28
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
// \brief Program that behaves like cat...: 
// Kfscat -p <kfsConfig file> [filename1...n]
// and output the files in the order of appearance to stdout.
//
//----------------------------------------------------------------------------

#include <iostream>    
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fstream>
#include "libkfsClient/KfsClient.h"

#include "KfsToolsCommon.h"

using std::cout;
using std::endl;
using std::ifstream;
using std::string;
using namespace KFS;

KfsClient *gKfsClient;
static ssize_t DoCat(const char *pahtname);

int
main(int argc, char **argv)
{
    string serverHost = "";
    int port = -1;
    bool help = false;
    bool verboseLogging = false;
    char optchar;

    getEnvServer(serverHost, port);
    
    KFS::MsgLogger::Init(NULL);

    while ((optchar = getopt(argc, argv, "hs:p:v")) != -1) {
        switch (optchar) {
            case 'h':
                help = true;
                break;
            case 'v':
                verboseLogging = true;
                break;
            case 's':
                parseServer(optarg, serverHost, port);
                break;
            case 'p':
                port = atoi(optarg);
                break;
            default:
                KFS_LOG_ERROR("Unrecognized flag %c", optchar);
                help = true;
                break;
        }
    }

    if (help || (serverHost == "") || (port < 0)) {
        cout << "Usage: " << argv[0] << " -s <meta server name> -p <port>"
             << " [filename1...n]" << endl;
        exit(0);
    }

    if (verboseLogging) {
	KFS::MsgLogger::SetLevel(log4cpp::Priority::DEBUG);
    } else {
	KFS::MsgLogger::SetLevel(log4cpp::Priority::INFO);
    } 

    gKfsClient = KfsClient::Instance();
    gKfsClient->Init(serverHost, port);
    if (!gKfsClient->IsInitialized()) {
        cout << "kfs client failed to initialize...exiting" << endl;
        exit(0);
    }

    int i = 1;
    while (i < argc) {
	if ((strncmp(argv[i], "-p", 2) == 0) || (strncmp(argv[i], "-s", 2) == 0)) {
            i += 2;
            continue;
        }
        // cout << "Cat'ing: " << argv[i] << endl;
        DoCat(argv[i]);
        i++;
    }
}

ssize_t
DoCat(const char *pathname)
{
    const int mByte = 1024 * 1024;
    char dataBuf[mByte];
    int res, fd;    
    kfsOff_t bytesRead = 0;
    KfsFileStat statBuf;

    fd = gKfsClient->Open(pathname, O_RDONLY);
    if (fd < 0) {
        cout << "Open failed: " << fd << endl;
        return -ENOENT;
    }

    gKfsClient->Stat(pathname, statBuf);

    while (1) {
        res = gKfsClient->Read(fd, dataBuf, mByte);
        if (res <= 0)
            break;
        cout << dataBuf;
        bytesRead += res;
        if (bytesRead >= statBuf.size)
            break;
    }
    gKfsClient->Close(fd);

    return bytesRead;
}
    
