//---------------------------------------------------------- -*- Mode: C++ -*-
// $Id: Replicator.cc 351 2009-05-27 05:40:23Z sriramsrao $
//
// Created 2007/01/17
// Author: Sriram Rao
//
// Copyright 2008 Quantcast Corp.
// Copyright 2007-2008 Kosmix Corp.
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
// \brief Code for dealing with a replicating a chunk.  The metaserver
//asks a destination chunkserver to obtain a copy of a chunk from a source
//chunkserver; in response, the destination chunkserver pulls the data
//down and writes it out to disk.  At the end replication, the
//destination chunkserver notifies the metaserver.
//
//----------------------------------------------------------------------------

#include "Replicator.h"
#include "ChunkServer.h"
#include "Utils.h"
#include "libkfsIO/Globals.h"
#include "libkfsIO/Checksum.h"

#include <string>
#include <sstream>

#include "common/log.h"
#include <boost/scoped_array.hpp>
using boost::scoped_array;

using std::string;
using std::ostringstream;
using std::istringstream;
using namespace KFS;
using namespace KFS::libkfsio;


Replicator::Replicator(ReplicateChunkOp *op) :
    mFileId(op->fid), mChunkId(op->chunkId), 
    mChunkVersion(op->chunkVersion), 
    mOwner(op), mDone(false),  mOffset(0), mChunkMetadataOp(0), 
    mReadOp(0), mWriteOp(op->chunkId, op->chunkVersion)
{
    mReadOp.chunkId = op->chunkId;
    mReadOp.chunkVersion = op->chunkVersion;
    mReadOp.clnt = this;
    mWriteOp.clnt = this;
    mChunkMetadataOp.clnt = this;
    mWriteOp.Reset();
    mWriteOp.isFromReReplication = true;
    SET_HANDLER(&mReadOp, &ReadOp::HandleReplicatorDone);
}

Replicator::~Replicator()
{

}


void
Replicator::Start(RemoteSyncSMPtr &peer)
{
#ifdef DEBUG
    verifyExecutingOnEventProcessor();
#endif

    mPeer = peer;

    mChunkMetadataOp.seq = mPeer->NextSeqnum();
    mChunkMetadataOp.chunkId = mChunkId;

    SET_HANDLER(this, &Replicator::HandleStartDone);

    mPeer->Enqueue(&mChunkMetadataOp);
}

int
Replicator::HandleStartDone(int code, void *data)
{
#ifdef DEBUG
    verifyExecutingOnEventProcessor();
#endif

    if (mChunkMetadataOp.status < 0) {
        Terminate();
        return 0;
    }


    mChunkSize = mChunkMetadataOp.chunkSize;
    mChunkVersion = mChunkMetadataOp.chunkVersion;

    if ((mChunkSize < 0) || (mChunkSize > CHUNKSIZE)) {
        KFS_LOG_VA_INFO("Invalid chunksize: %ld", (long)mChunkSize);
        Terminate();
        return 0;
    }

    mReadOp.chunkVersion = mWriteOp.chunkVersion = mChunkVersion;

    // set the version to a value that will never be used; if
    // replication is successful, we then bump up the counter.
    if (gChunkManager.AllocChunk(mFileId, mChunkId, 0, true) < 0) {
        Terminate();
        return -1;
    }

    KFS_LOG_VA_INFO("Starting re-replication for chunk %ld with size %ld",
                    (long)mChunkId, (long)mChunkSize);
    Read();
    return 0;
}

void
Replicator::Read()
{
    ReplicatorPtr self = shared_from_this();

#ifdef DEBUG
    verifyExecutingOnEventProcessor();
#endif

    if (mOffset == (off_t) mChunkSize) {
        KFS_LOG_VA_INFO("Offset: %ld is past end of chunk %ld", (long)mOffset, (long)mChunkSize);
        mDone = true;
        Terminate();
        return;
    }

    if (mOffset > (off_t) mChunkSize) {
        KFS_LOG_VA_INFO("Offset: %ld is well past end of chunk %ld", (long)mOffset, (long)mChunkSize);
        mDone = false;
        Terminate();
        return;
    }

    SET_HANDLER(this, &Replicator::HandleReadDone);

    mReadOp.seq = mPeer->NextSeqnum();
    mReadOp.status = 0;
    mReadOp.offset = mOffset;
    mReadOp.numBytesIO = 0;
    mReadOp.checksum.clear();
    // read an MB 
    mReadOp.numBytes = 1 << 20;
    mPeer->Enqueue(&mReadOp);
}

int
Replicator::HandleReadDone(int code, void *data)
{

#ifdef DEBUG
    verifyExecutingOnEventProcessor();
#endif

    if (mReadOp.status < 0) {
        KFS_LOG_VA_INFO("Read from peer %s failed with error: %d",
                        mPeer->GetLocation().ToString().c_str(), (int)mReadOp.status);
        Terminate();
        return 0;
    }

    delete mWriteOp.dataBuf;
    
    mWriteOp.Reset();

    mWriteOp.dataBuf = new IOBuffer();
    mWriteOp.numBytes = mReadOp.dataBuf->BytesConsumable();
    mWriteOp.dataBuf->Move(mReadOp.dataBuf, mWriteOp.numBytes);
    mWriteOp.offset = mOffset;
    mWriteOp.isFromReReplication = true;

    // align the writes to checksum boundaries
    if ((mWriteOp.numBytes >= CHECKSUM_BLOCKSIZE) &&
        (mWriteOp.numBytes % CHECKSUM_BLOCKSIZE) != 0)
        // round-down so to speak; whatever is left will be picked up by the next read
        mWriteOp.numBytes = (mWriteOp.numBytes / CHECKSUM_BLOCKSIZE) * CHECKSUM_BLOCKSIZE;

    SET_HANDLER(this, &Replicator::HandleWriteDone);

    if (gChunkManager.WriteChunk(&mWriteOp) < 0) {
        // abort everything
        Terminate();
        return -1;
    }
    return 0;
}

int
Replicator::HandleWriteDone(int code, void *data)
{
    ReplicatorPtr self = shared_from_this();

#ifdef DEBUG
    verifyExecutingOnEventProcessor();
#endif

    assert((code == EVENT_CMD_DONE) || (code == EVENT_DISK_WROTE));

    if (mWriteOp.status < 0) {
        KFS_LOG_VA_INFO("Write failed with error: %d", (int)mWriteOp.status);
        Terminate();
        return 0;
    }

    mOffset += mWriteOp.numBytesIO;

    Read();
    return 0;
}

void
Replicator::Terminate()
{
#ifdef DEBUG
    verifyExecutingOnEventProcessor();
#endif
    int res = -1;
    if (mDone) {
        KFS_LOG_VA_INFO("Replication for %lld finished from %s",
                        mChunkId, mPeer->GetLocation().ToString().c_str());

        // now that replication is all done, set the version appropriately
        gChunkManager.ChangeChunkVers(mFileId, mChunkId, mChunkVersion);

        SET_HANDLER(this, &Replicator::HandleReplicationDone);        

        res = gChunkManager.WriteChunkMetadata(mChunkId, &mWriteOp);
        if (res == 0) {
            return;
        } else if (res > 0) {
            res = -1;
        }
    } 
    HandleReplicationDone(EVENT_CMD_DONE, &res);
}

// logging of the chunk meta data finished; we are all done
int
Replicator::HandleReplicationDone(int code, void *data)
{
    gChunkManager.ReplicationDone(mChunkId);
    const int status = data ? *reinterpret_cast<int*>(data) : 0;
    mOwner->status = status >= 0 ? 0 : -1;
    if (status < 0) {
        KFS_LOG_VA_INFO(
            "Replication for %lld failed from %s, status = %d; cleaning up",
            mChunkId, mPeer->GetLocation().ToString().c_str(), status);
        gChunkManager.DeleteChunk(mChunkId);
    }
    // Notify the owner of completion
    mOwner->HandleEvent(EVENT_CMD_DONE, status >= 0 ? &mChunkVersion : 0);
    return 0;
}



