/**
 * Copyright (C) 2008 Doug Judd (Zvents, Inc.)
 * 
 * This file is part of Hypertable.
 * 
 * Hypertable is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version.
 * 
 * Hypertable is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <cassert>

#include <boost/algorithm/string.hpp>

extern "C" {
#include <string.h>
}

#include "Common/Error.h"
#include "Common/Logger.h"
#include "Common/System.h"

#include "AsyncComm/Protocol.h"

#include "Hypertable/Lib/CompressorFactory.h"
#include "Hypertable/Lib/Key.h"

#include "BlockCompressionHeaderCellStore.h"
#include "CellStoreScannerV0.h"
#include "CellStoreV0.h"
#include "FileBlockCache.h"

const char CellStoreV0::DATA_BLOCK_MAGIC[10]           = { 'D','a','t','a','-','-','-','-','-','-' };
const char CellStoreV0::INDEX_FIXED_BLOCK_MAGIC[10]    = { 'I','d','x','F','i','x','-','-','-','-' };
const char CellStoreV0::INDEX_VARIABLE_BLOCK_MAGIC[10] = { 'I','d','x','V','a','r','-','-','-','-' };

namespace {
   const uint32_t MAX_APPENDS_OUTSTANDING = 3;
}

using namespace Hypertable;

CellStoreV0::CellStoreV0(Filesystem *filesys) : m_filesys(filesys), m_filename(), m_fd(-1), m_index(),
   m_compressor(0), m_buffer(0), m_fix_index_buffer(0), m_var_index_buffer(0),
   m_outstanding_appends(0), m_offset(0), m_last_key(0), m_file_length(0), m_disk_usage(0), m_file_id(0), m_uncompressed_blocksize(0) {
      m_file_id = FileBlockCache::get_next_file_id();
      assert(sizeof(float) == 4);
   }



CellStoreV0::~CellStoreV0() {
   int error;
   delete m_compressor;
   if (m_fd != -1) {
      if ((error = m_filesys->close(m_fd)) != Error::OK) {
         HT_ERRORF("Problem closing HDFS client - %s", Error::get_text(error));
      }
   }
}


BlockCompressionCodec *CellStoreV0::create_block_compression_codec() {
   return CompressorFactory::create_block_codec(
         (BlockCompressionCodec::Type)m_trailer.compression_type);
}



void CellStoreV0::get_timestamp(Timestamp &timestamp) {
   timestamp = m_trailer.timestamp;
}


const char *CellStoreV0::get_split_row() {
   if (m_split_row != "")
      return m_split_row.c_str();
   return 0;
}


CellListScanner *CellStoreV0::create_scanner(ScanContextPtr &scanContextPtr) {
   CellStorePtr cellStorePtr(this);
   return new CellStoreScannerV0(cellStorePtr, scanContextPtr);
}


int CellStoreV0::create(const char *fname, uint32_t blocksize, const std::string &compressor) {
   m_buffer.reserve(blocksize*4);

   m_fd = -1;
   m_offset = 0;
   m_last_key = 0;
   m_fix_index_buffer.reserve(blocksize);
   m_var_index_buffer.reserve(blocksize);

   m_uncompressed_data = 0.0;
   m_compressed_data = 0.0;

   m_trailer.clear();
   m_trailer.blocksize = blocksize;
   m_uncompressed_blocksize = blocksize;

   m_filename = fname;

   m_start_row = "";
   m_end_row = Key::END_ROW_MARKER;

   if (compressor.empty())
      m_trailer.compression_type = BlockCompressionCodec::LZO;

   m_trailer.compression_type = CompressorFactory::parse_block_codec_spec(
         compressor, m_compressor_args);
   m_compressor = CompressorFactory::create_block_codec(
         (BlockCompressionCodec::Type)m_trailer.compression_type,
         m_compressor_args);

   return m_filesys->create(m_filename, true, -1, -1, -1, &m_fd);
}


int CellStoreV0::add(const ByteString32T *key, const ByteString32T *value, uint64_t real_timestamp) {
   int error;
   EventPtr eventPtr;
   DynamicBuffer zBuffer(0);

   (void)real_timestamp;

   if (m_buffer.fill() > m_uncompressed_blocksize) {
      BlockCompressionHeaderCellStore header(DATA_BLOCK_MAGIC);

      add_index_entry(m_last_key, m_offset);

      m_uncompressed_data += (float)m_buffer.fill();
      m_compressor->deflate(m_buffer, zBuffer, header);
      m_compressed_data += (float)zBuffer.fill();
      m_buffer.clear();

      uint64_t llval = ((uint64_t)m_trailer.blocksize * (uint64_t)m_uncompressed_data) / (uint64_t)m_compressed_data;
      m_uncompressed_blocksize = (uint32_t)llval;

      if (m_outstanding_appends >= MAX_APPENDS_OUTSTANDING) {
         if (!m_sync_handler.wait_for_reply(eventPtr)) {
            HT_ERRORF("Problem writing to HDFS file '%s' : %s", m_filename.c_str(), Hypertable::Protocol::string_format_message(eventPtr).c_str());
            return -1;
         }
         m_outstanding_appends--;
      }

      size_t  zlen;
      uint8_t *zbuf = zBuffer.release(&zlen);

      if ((error = m_filesys->append(m_fd, zbuf, zlen, &m_sync_handler)) != Error::OK) {
         HT_ERRORF("Problem writing to HDFS file '%s' : %s", m_filename.c_str(), Error::get_text(error));
         return -1;
      }
      m_outstanding_appends++;
      m_offset += zlen;
   }

   size_t keyLen = sizeof(int32_t) + key->len;
   size_t valueLen = sizeof(int32_t) + value->len;

   m_buffer.ensure( keyLen + valueLen );

   m_last_key = (ByteString32T *)m_buffer.addNoCheck(key, keyLen);
   m_buffer.addNoCheck(value, valueLen);

   m_trailer.total_entries++;

   return 0;
}



int CellStoreV0::finalize(Timestamp &timestamp) {
   EventPtr eventPtr;
   int error = -1;
   uint8_t *zbuf;
   size_t zlen;
   DynamicBuffer zBuffer(0);
   size_t len;
   uint8_t *base;

   if (m_buffer.fill() > 0) {
      BlockCompressionHeaderCellStore header(DATA_BLOCK_MAGIC);

      add_index_entry(m_last_key, m_offset);

      m_uncompressed_data += (float)m_buffer.fill();
      m_compressor->deflate(m_buffer, zBuffer, header);
      m_compressed_data += (float)zBuffer.fill();
      zbuf = zBuffer.release(&zlen);

      if (m_outstanding_appends >= MAX_APPENDS_OUTSTANDING) {
         if (!m_sync_handler.wait_for_reply(eventPtr)) {
            HT_ERRORF("Problem writing to HDFS file '%s' : %s", m_filename.c_str(), Protocol::string_format_message(eventPtr).c_str());
            goto abort;
         }
         m_outstanding_appends--;
      }

      if ((error = m_filesys->append(m_fd, zbuf, zlen, &m_sync_handler)) != Error::OK) {
         HT_ERRORF("Problem writing to HDFS file '%s' : %s", m_filename.c_str(), Protocol::string_format_message(eventPtr).c_str());
         goto abort;
      }
      m_outstanding_appends++;
      m_offset += zlen;
   }

   m_trailer.fix_index_offset = m_offset;
   m_trailer.timestamp = timestamp;
   m_trailer.compression_ratio = m_compressed_data / m_uncompressed_data;
   m_trailer.version = 0;

   /**
    * Chop the Index buffers down to the exact length
    */
   base = m_fix_index_buffer.release(&len);
   m_fix_index_buffer.reserve(len);
   m_fix_index_buffer.addNoCheck(base, len);
   delete [] base;
   base = m_var_index_buffer.release(&len);
   m_var_index_buffer.reserve(len);
   m_var_index_buffer.addNoCheck(base, len);
   delete [] base;

   /**
    * Write fixed index
    */
   {
      BlockCompressionHeaderCellStore header(INDEX_FIXED_BLOCK_MAGIC);
      m_compressor->deflate(m_fix_index_buffer, zBuffer, header);
      zbuf = zBuffer.release(&zlen);
   }

   if (m_filesys->append(m_fd, zbuf, zlen, &m_sync_handler) != Error::OK)
      goto abort;
   m_outstanding_appends++;
   m_offset += zlen;

   /**
    * Write variable index + trailer
    */
   {
      BlockCompressionHeaderCellStore header(INDEX_VARIABLE_BLOCK_MAGIC);
      m_trailer.var_index_offset = m_offset;
      m_compressor->deflate(m_var_index_buffer, zBuffer, header, m_trailer.size());
   }

   /**
    * Set up m_index map
    */
   uint32_t offset;
   ByteString32T *key;
   m_fix_index_buffer.ptr = m_fix_index_buffer.buf;
   m_var_index_buffer.ptr = m_var_index_buffer.buf;
   for (size_t i=0; i<m_trailer.index_entries; i++) {
      // variable portion
      key = (ByteString32T *)m_var_index_buffer.ptr;
      m_var_index_buffer.ptr += sizeof(int32_t) + key->len;
      // fixed portion (e.g. offset)
      memcpy(&offset, m_fix_index_buffer.ptr, sizeof(offset));
      m_fix_index_buffer.ptr += sizeof(offset);
      m_index.insert(m_index.end(), IndexMapT::value_type(key, offset));
      if (i == m_trailer.index_entries/2) {
         record_split_row((ByteString32T *)m_var_index_buffer.ptr);
      }
   }

   // deallocate fix index data
   delete [] m_fix_index_buffer.release();

   // write filter_offset (empty for now)
   m_trailer.filter_offset = m_offset + zBuffer.fill();

   // 
   m_trailer.serialize(zBuffer.ptr);
   zBuffer.ptr += m_trailer.size();

   zbuf = zBuffer.release(&zlen);

   if (m_filesys->append(m_fd, zbuf, zlen) != Error::OK)
      goto abort;
   m_outstanding_appends++;
   m_offset += zlen;

   /** close file for writing **/
   if (m_filesys->close(m_fd) != Error::OK)
      goto abort;

   /** Set file length **/
   m_file_length = m_offset;

   /** Re-open file for reading **/
   if ((error = m_filesys->open(m_filename, &m_fd)) != Error::OK)
      goto abort;

   m_disk_usage = (uint32_t)m_file_length;

   error = 0;

abort:
   delete m_compressor;
   m_compressor = 0;

   return error;
}



/**
 *
 */
void CellStoreV0::add_index_entry(const ByteString32T *key, uint32_t offset) {

   size_t keyLen = sizeof(int32_t) + key->len;
   m_var_index_buffer.ensure( keyLen );
   memcpy(m_var_index_buffer.ptr, key, keyLen);
   m_var_index_buffer.ptr += keyLen;

   // Serialize offset into fix index buffer
   m_fix_index_buffer.ensure(sizeof(offset));
   memcpy(m_fix_index_buffer.ptr, &offset, sizeof(offset));
   m_fix_index_buffer.ptr += sizeof(offset);

   m_trailer.index_entries++;
}



/**
 *
 */
int CellStoreV0::open(const char *fname, const char *start_row, const char *end_row) {
   int error = 0;

   m_start_row = (start_row) ? start_row : "";
   m_end_row = (end_row) ? end_row : Key::END_ROW_MARKER;

   m_fd = -1;

   m_filename = fname;

   /** Get the file length **/
   if ((error = m_filesys->length(m_filename, (int64_t *)&m_file_length)) != Error::OK)
      goto abort;

   if (m_file_length < m_trailer.size()) {
      HT_ERRORF("Bad length of CellStore file '%s' - %lld", m_filename.c_str(), m_file_length);
      goto abort;
   }

   /** Open the HDFS file **/
   if ((error = m_filesys->open(m_filename, &m_fd)) != Error::OK)
      goto abort;

   /**
    * Read and deserialize trailer
    */
   {
      uint32_t len;
      uint8_t *trailer_buf = new uint8_t [ m_trailer.size() ];

      if ((error = m_filesys->pread(m_fd, m_file_length-m_trailer.size(), m_trailer.size(), trailer_buf, &len)) != Error::OK) {
         HT_ERRORF("Problem reading trailer for CellStore file '%s' - %s", m_filename.c_str(), Error::get_text(error));
         delete [] trailer_buf;
         goto abort;
      }

      if (len != m_trailer.size()) {
         HT_ERRORF("Problem reading trailer for CellStore file '%s' - only read %d of %d bytes",
               m_filename.c_str(), len, m_trailer.size());
         delete [] trailer_buf;
         goto abort;
      }

      m_trailer.deserialize(trailer_buf);
      delete [] trailer_buf;
   }

   /** Sanity check trailer **/
   if (m_trailer.version != 0) {
      HT_ERRORF("Unsupported CellStore version (%d) for file '%s'", m_trailer.version, fname);
      goto abort;
   }
   if (!(m_trailer.fix_index_offset < m_trailer.var_index_offset &&
            m_trailer.var_index_offset < m_file_length)) {
      HT_ERRORF("Bad index offsets in CellStore trailer fix=%lld, var=%lld, length=%lld, file='%s'",
            m_trailer.fix_index_offset, m_trailer.var_index_offset, m_file_length, fname);
      goto abort;
   }

   return Error::OK;

abort:
   return Error::LOCAL_IO_ERROR;
}


int CellStoreV0::load_index() {
   int error = -1;
   uint8_t *buf = 0;
   uint32_t amount;
   uint8_t *vbuf = 0;
   uint8_t *fEnd;
   uint8_t *vEnd;
   uint32_t len;
   BlockCompressionHeaderCellStore header;
   DynamicBuffer input(0);

   m_compressor = create_block_compression_codec();

   amount = (m_file_length-m_trailer.size()) - m_trailer.fix_index_offset;
   buf = new uint8_t [ amount ];

   /** Read index data **/
   if ((error = m_filesys->pread(m_fd, m_trailer.fix_index_offset, amount, buf, &len)) != Error::OK)
      goto abort;

   if (len != amount) {
      HT_ERRORF("Problem loading index for CellStore '%s' : tried to read %d but only got %d", m_filename.c_str(), amount, len);
      goto abort;
   }

   /** inflate fixed index **/
   {
      input.buf = buf;
      input.ptr = buf + (m_trailer.var_index_offset - m_trailer.fix_index_offset);
      if ((error = m_compressor->inflate(input, m_fix_index_buffer, header)) != Error::OK) {
         HT_ERRORF("Fixed index decompression error - %s", Error::get_text(error));
         goto abort;
      }
      if (!header.check_magic(INDEX_FIXED_BLOCK_MAGIC)) {
         error = Error::BLOCK_COMPRESSOR_BAD_MAGIC;
         goto abort;
      }
   }

   vbuf = buf + (m_trailer.var_index_offset-m_trailer.fix_index_offset);
   amount = (m_file_length-m_trailer.size()) - m_trailer.var_index_offset;

   /** inflate variable index **/ 
   {
      input.buf = vbuf;
      input.ptr = vbuf + amount;
      if ((error = m_compressor->inflate(input, m_var_index_buffer, header)) != Error::OK) {
         HT_ERRORF("Variable index decompression error - %s", Error::get_text(error));
         goto abort;
      }
      if (!header.check_magic(INDEX_VARIABLE_BLOCK_MAGIC)) {
         error = Error::BLOCK_COMPRESSOR_BAD_MAGIC;
         goto abort;
      }
   }

   m_index.clear();

   ByteString32T *key;
   uint32_t offset;

   // record end offsets for sanity checking and reset ptr
   fEnd = m_fix_index_buffer.ptr;
   m_fix_index_buffer.ptr = m_fix_index_buffer.buf;
   vEnd = m_var_index_buffer.ptr;
   m_var_index_buffer.ptr = m_var_index_buffer.buf;

   for (size_t i=0; i< m_trailer.index_entries; i++) {

      assert(m_fix_index_buffer.ptr < fEnd);
      assert(m_var_index_buffer.ptr < vEnd);

      // Deserialized cell key (variable portion)
      key = (ByteString32T *)m_var_index_buffer.ptr;
      m_var_index_buffer.ptr += sizeof(int32_t) + key->len;

      // Deserialize offset
      memcpy(&offset, m_fix_index_buffer.ptr, sizeof(offset));
      m_fix_index_buffer.ptr += sizeof(offset);

      m_index.insert(m_index.end(), IndexMapT::value_type(key, offset));

   }

   /**
    * Compute disk usage
    */
   {
      uint32_t start = 0;
      uint32_t end = (uint32_t)m_file_length;
      ByteString32T *start_key = Create(m_start_row.c_str(), strlen(m_start_row.c_str()));
      ByteString32T *end_key = Create(m_end_row.c_str(), strlen(m_end_row.c_str()));
      CellStoreV0::IndexMapT::const_iterator iter, mid_iter, end_iter;

      iter = m_index.upper_bound(start_key);
      start = (*iter).second;

      if ((end_iter = m_index.lower_bound(end_key)) == m_index.end())
         end = m_file_length;
      else
         end = (*iter).second;

      m_disk_usage = end - start;

      Destroy(start_key);
      Destroy(end_key);

      size_t i=0;
      for (mid_iter=iter; iter!=end_iter; ++iter,++i) {
         if ((i%2)==0)
            ++mid_iter;
      }
      if (mid_iter != m_index.end())
         record_split_row((*mid_iter).first);

   }

   error = 0;

abort:
   input.buf = 0;
   delete m_compressor;
   m_compressor = 0;
   delete [] m_fix_index_buffer.release();
   delete [] buf;
   return error;
}


/**
 *
 */
void CellStoreV0::display_block_info() {
   ByteString32T *last_key = 0;
   uint32_t last_offset = 0;
   uint32_t block_size;
   size_t i=0;
   for (IndexMapT::const_iterator iter = m_index.begin(); iter != m_index.end(); iter++) {
      if (last_key) {
         block_size = (*iter).second - last_offset;
         cout << i << ": offset=" << last_offset << " size=" << block_size << " row=" << (const char *)last_key->data << endl;
         i++;
      }
      last_offset = (*iter).second;
      last_key = (*iter).first;
   }
   if (last_key) {
      block_size = m_trailer.filter_offset - last_offset;
      cout << i << ": offset=" << last_offset << " size=" << block_size << " row=" << (const char *)last_key->data << endl;
   }
}


void CellStoreV0::record_split_row(const ByteString32T *key) {
   std::string split_row = (const char *)key->data;
   if (split_row > m_start_row && split_row < m_end_row)
      m_split_row = split_row;
   //cout << "record_split_row = " << m_split_row << endl;
}
