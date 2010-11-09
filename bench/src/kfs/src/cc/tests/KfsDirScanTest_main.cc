//---------------------------------------------------------- -*- Mode: C++ -*-
// $Id: KfsDirScanTest_main.cc 353 2009-05-28 21:54:49Z sjakub $
//
// Created 2008/07/16
//
// Copyright 2008 Quantcast Corporation.  All rights reserved.
// Quantcast PROPRIETARY and CONFIDENTIAL.
//
// \brief Test that evaluates readdirplus() followed by calls to get attributes.
//----------------------------------------------------------------------------

#include <iostream>    
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fstream>
#include "libkfsClient/KfsClient.h"
#include "common/log.h"

using std::cout;
using std::endl;
using std::ifstream;
using std::vector;
using std::string;
using namespace KFS;

KfsClientPtr gKfsClient;

void dirListPlusAttr(const string &kfspathname);

int
main(int argc, char **argv)
{
    char optchar;
    const char *metaserver = NULL;
    int port = -1;
    string kfspathname = "";
    bool help = false;

    KFS::MsgLogger::Init(NULL);

    while ((optchar = getopt(argc, argv, "m:p:d:")) != -1) {
        switch (optchar) {
            case 'm':
                metaserver = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'd':
                kfspathname = optarg;
                break;
            default:
                cout << "Unrecognized flag: " << optchar << endl;
                help = true;
                break;
        }
    }
    
    if (help || !metaserver || (port < 0)) {
        cout << "Usage: " << argv[0] << " -m <metaserver host> -p <port> -d <path>" << endl;
        exit(-1);
    }

    gKfsClient = getKfsClientFactory()->GetClient(metaserver, port);
    if (!gKfsClient) {
        cout << "KFS client failed to initialize...exiting" << endl;
        exit(-1);
    }
    dirListPlusAttr(kfspathname);
    exit(0);
}

void dirListPlusAttr(const string &kfspathname)
{
    if (gKfsClient->IsFile(kfspathname)) {
        cout << kfspathname << " is a file..." << endl;
        return;
    }

    vector<KfsFileAttr> fattrs;

    if (gKfsClient->ReaddirPlus(kfspathname, fattrs) < 0) {
        cout << "unable to do readdirplus on " << kfspathname << endl;
        return;
    }

    KFS_LOG_VA_INFO("Done getting readdirplus on %s (%d entries)", kfspathname.c_str(), fattrs.size());

    uint32_t replicas;
    for (uint32_t i = 0; i < fattrs.size(); i++) {
        string abspath = kfspathname + "/" + fattrs[i].filename;

        if (gKfsClient->IsFile(abspath))
            replicas = gKfsClient->GetReplicationFactor(abspath);
    }

    KFS_LOG_VA_INFO("Done getting replication factor for all entries on %s", kfspathname.c_str());

    KfsFileStat statbuf;
    uint64_t dirsz = 0;

    for (uint32_t i = 0; i < fattrs.size(); i++) {
        string abspath = kfspathname + "/" + fattrs[i].filename;

        if (gKfsClient->IsFile(abspath)) {
            int res = gKfsClient->Stat(abspath, statbuf);
            if (res == 0)
                dirsz += statbuf.size;
        }
    }

    KFS_LOG_VA_INFO("Dirsize on %s: %ld", kfspathname.c_str(), dirsz);
    
}
