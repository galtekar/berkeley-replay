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
#include <string>
#include <vector>

extern "C" {
#include <poll.h>
#include <string.h>
}

#include <boost/algorithm/string.hpp>

#include "Common/Error.h"
#include "Common/FileUtils.h"
#include "Common/md5.h"

#include "Hypertable/Lib/CommitLog.h"
#include "Hypertable/Lib/CommitLogReader.h"


#include "CellStoreV0.h"
#include "Global.h"
#include "MergeScanner.h"
#include "MetadataNormal.h"
#include "MetadataRoot.h"
#include "Range.h"


using namespace Hypertable;
using namespace std;


Range::Range(MasterClientPtr &master_client_ptr, TableIdentifierT &identifier, SchemaPtr &schemaPtr, RangeT *range, uint64_t soft_limit) : CellList(), m_mutex(), m_master_client_ptr(master_client_ptr), m_schema(schemaPtr), m_maintenance_in_progress(false), m_last_logical_timestamp(0), m_hold_updates(false), m_update_counter(0), m_added_inserts(0) {
   AccessGroup *ag;

   memset(m_added_deletes, 0, 3*sizeof(int64_t));

   if (soft_limit == 0 || soft_limit > Global::rangeMaxBytes)
      m_disk_limit = Global::rangeMaxBytes;
   else
      m_disk_limit = soft_limit;

   m_split_timestamp.logical = 0;
   m_split_timestamp.real = 0;

   Copy(identifier, m_identifier);

   m_start_row = range->startRow;
   m_end_row = range->endRow;

   m_is_root = (m_identifier.id == 0 && *range->startRow == 0 && !strcmp(range->endRow, Key::END_ROOT_ROW));

   m_column_family_vector.resize( m_schema->get_max_column_family_id() + 1 );

   list<Schema::AccessGroup *> *agList = m_schema->get_access_group_list();

   for (list<Schema::AccessGroup *>::iterator agIter = agList->begin(); agIter != agList->end(); agIter++) {
      ag = new AccessGroup(m_identifier, m_schema, (*agIter), range);
      m_access_group_map[(*agIter)->name] = ag;
      m_access_group_vector.push_back(ag);
      for (list<Schema::ColumnFamily *>::iterator cfIter = (*agIter)->columns.begin(); cfIter != (*agIter)->columns.end(); cfIter++)
         m_column_family_vector[(*cfIter)->id] = ag;
   }

   /**
    * Read the cell store files from METADATA and 
    */
   if (m_is_root) {
      MetadataRoot metadata(m_schema);
      load_cell_stores(&metadata);
   }
   else {
      MetadataNormal metadata(m_identifier, m_end_row);
      load_cell_stores(&metadata);
   }

   return;
}


/**
*/
Range::~Range() {
   Free(m_identifier);
   for (size_t i=0; i<m_access_group_vector.size(); i++)
      delete m_access_group_vector[i];
}



/**
 *
 */
void Range::load_cell_stores(Metadata *metadata) {
   int error;
   AccessGroup *ag;
   CellStorePtr cellStorePtr;
   uint32_t csid;
   const char *base, *ptr, *end;
   std::vector<std::string> csvec;
   std::string ag_name;
   std::string files;
   std::string file_str;

   metadata->reset_files_scan();

   while (metadata->get_next_files(ag_name, files)) {
      csvec.clear();

      if ((ag = m_access_group_map[ag_name]) == 0) {
         HT_ERRORF("Unrecognized access group name '%s' found in METADATA for table '%s'", ag_name.c_str(), m_identifier.name);
         continue;
      }

      ptr = base = (const char *)files.c_str();
      end = base + strlen(base);
      while (ptr < end) {

         while (*ptr != ';' && ptr < end)
            ptr++;

         file_str = std::string(base, ptr-base);
         boost::trim(file_str);

         if (file_str != "")
            csvec.push_back(file_str);

         ++ptr;
         base = ptr;
      }

      for (size_t i=0; i<csvec.size(); i++) {

         HT_INFOF("drj Loading CellStore %s", csvec[i].c_str());

         cellStorePtr = new CellStoreV0(Global::dfs);

         if (!extract_csid_from_path(csvec[i], &csid)) {
            HT_ERRORF("Unable to extract cell store ID from path '%s'", csvec[i].c_str());
            continue;
         }
         if ((error = cellStorePtr->open(csvec[i].c_str(), m_start_row.c_str(), m_end_row.c_str())) != Error::OK) {
            // this should throw an exception
            HT_ERRORF("Problem opening cell store '%s', skipping...", csvec[i].c_str());
            continue;
         }
         if ((error = cellStorePtr->load_index()) != Error::OK) {
            // this should throw an exception
            HT_ERRORF("Problem loading index of cell store '%s', skipping...", csvec[i].c_str());
            continue;
         }

         ag->add_cell_store(cellStorePtr, csid);
      }

   }

}



/**
*/
bool Range::extract_csid_from_path(std::string &path, uint32_t *csidp) {
   const char *base;

   if ((base = strrchr(path.c_str(), '/')) == 0 || strncmp(base, "/cs", 3))
      *csidp = 0;
   else
      *csidp = atoi(base+3);

   return true;
}


/**
 * TODO: Make this more robust
 */
int Range::add(const ByteString32T *key, const ByteString32T *value, uint64_t real_timestamp) {
   Key keyComps;

   HT_EXPECT(keyComps.load(key), Error::FAILED_EXPECTATION);

   if (keyComps.column_family_code >= m_column_family_vector.size()) {
      HT_ERRORF("Bad column family (%d)", keyComps.column_family_code);
      return Error::RANGESERVER_INVALID_COLUMNFAMILY;
   }

   if (keyComps.timestamp <= m_last_logical_timestamp) {
      if (keyComps.flag == FLAG_INSERT) {
         HT_ERRORF("Problem adding key/value pair, key timestmap %llu <= %llu", keyComps.timestamp, m_last_logical_timestamp);
         return Error::RANGESERVER_TIMESTAMP_ORDER_ERROR;
      }
   }
   else
      m_last_logical_timestamp = keyComps.timestamp;

   if (keyComps.flag == FLAG_DELETE_ROW) {
      for (AccessGroupMapT::iterator iter = m_access_group_map.begin(); iter != m_access_group_map.end(); iter++) {
         (*iter).second->add(key, value, real_timestamp);
      }
   }
   else
      m_column_family_vector[keyComps.column_family_code]->add(key, value, real_timestamp);

   if (keyComps.flag == FLAG_INSERT)
      m_added_inserts++;
   else
      m_added_deletes[keyComps.flag]++;

   return Error::OK;
}


CellListScanner *Range::create_scanner(ScanContextPtr &scanContextPtr) {
   bool return_deletes = scanContextPtr->spec ? scanContextPtr->spec->return_deletes : false;
   cout << flush;
   MergeScanner *mscanner = new MergeScanner(scanContextPtr, return_deletes);
   for (AccessGroupMapT::iterator iter = m_access_group_map.begin(); iter != m_access_group_map.end(); iter++) {
      if ((*iter).second->include_in_scan(scanContextPtr))
         mscanner->add_scanner((*iter).second->create_scanner(scanContextPtr));
   }
   return mscanner;
}


uint64_t Range::disk_usage() {
   uint64_t usage = 0;
   for (size_t i=0; i<m_access_group_vector.size(); i++)
      usage += m_access_group_vector[i]->disk_usage();
   return usage;
}


/**
 *
 */
const char *Range::get_split_row() {
   std::vector<std::string> split_rows;
   for (size_t i=0; i<m_access_group_vector.size(); i++)
      m_access_group_vector[i]->get_split_rows(split_rows, false);

   /**
    * If we didn't get at least one row from each Access Group, then try again
    * the hard way (scans CellCache for middle row)
    */
   if (split_rows.size() < m_access_group_vector.size()) {
      for (size_t i=0; i<m_access_group_vector.size(); i++)
         m_access_group_vector[i]->get_split_rows(split_rows, true);
   }
   sort(split_rows.begin(), split_rows.end());

   /**
     cout << "Dumping split rows for " << m_identifier.name << "[" << m_start_row << ".." << m_end_row << "]" << endl;
     for (size_t i=0; i<split_rows.size(); i++)
     cout << "Range::get_split_row [" << i << "] = " << split_rows[i] << endl;
     */

   /**
    * If we still didn't get a good split row, try again the *really* hard way
    * by collecting all of the cached rows, sorting them and then taking the middle.
    */
   if (split_rows.size() > 0) {
      boost::mutex::scoped_lock lock(m_mutex);    
      m_split_row = split_rows[split_rows.size()/2];
      if (m_split_row <= m_start_row || m_split_row >= m_end_row) {
         split_rows.clear();
         for (size_t i=0; i<m_access_group_vector.size(); i++)
            m_access_group_vector[i]->get_cached_rows(split_rows);
         if (split_rows.size() > 0) {
            sort(split_rows.begin(), split_rows.end());
            m_split_row = split_rows[split_rows.size()/2];
            if (m_split_row <= m_start_row || m_split_row >= m_end_row) {
               HT_FATALF("Unable to determine split row for range %s[%s..%s]", m_identifier.name, m_start_row.c_str(), m_end_row.c_str());
               DUMP_CORE;
            }
         }
         else {
            HT_FATALF("Unable to determine split row for range %s[%s..%s]", m_identifier.name, m_start_row.c_str(), m_end_row.c_str());
            DUMP_CORE;
         }
      } 
   }
   else {
      HT_FATALF("Unable to determine split row for range %s[%s..%s]", m_identifier.name, m_start_row.c_str(), m_end_row.c_str());
      DUMP_CORE;
   }
   return m_split_row.c_str();
}



/**
 *  
 */
void Range::get_compaction_priority_data(std::vector<AccessGroup::CompactionPriorityDataT> &priority_data_vector) {
   size_t next_slot = priority_data_vector.size();

   {
      boost::mutex::scoped_lock lock(m_mutex);
      priority_data_vector.resize( priority_data_vector.size() + m_access_group_vector.size() );
   }

   for (size_t i=0; i<m_access_group_vector.size(); i++) {
      m_access_group_vector[i]->get_compaction_priority_data(priority_data_vector[next_slot]);
      next_slot++;
   }
}



void Range::do_split() {
   std::string splitLogDir;
   char md5DigestStr[33];
   int error;
   std::string old_start_row;
   TableMutatorPtr mutator_ptr;
   KeySpec key;
   std::string metadata_key_str;

   assert(m_maintenance_in_progress);

   // This should never happen...
   if (m_is_root) {
      HT_ERROR("Split scheduled for root METADATA range");
      m_maintenance_in_progress = false;
      return;
   }

   // this call sets m_split_row
   get_split_row();

   /**
    * Create Split LOG
    */
   md5_string(m_split_row.c_str(), md5DigestStr);
   md5DigestStr[24] = 0;
   std::string::size_type pos = Global::logDir.rfind("primary", Global::logDir.length());
   assert (pos != std::string::npos);
   splitLogDir = Global::logDir.substr(0, pos) + md5DigestStr;

   // Create split log dir
   if ((error = Global::logDfs->mkdirs(splitLogDir)) != Error::OK) {
      HT_ERRORF("Problem creating DFS log directory '%s'", splitLogDir.c_str());
      exit(1);
   }

   /**
    *  Update METADATA with split information
    */
   if ((error = Global::metadata_table_ptr->create_mutator(mutator_ptr)) != Error::OK) {
      // TODO: throw exception
      HT_ERROR("Problem creating mutator on METADATA table");
      return;
   }

   metadata_key_str = std::string("") + (uint32_t)m_identifier.id + ":" + m_end_row;
   key.row = metadata_key_str.c_str();
   key.row_len = metadata_key_str.length();
   key.column_qualifier = 0;
   key.column_qualifier_len = 0;

   try {
      key.column_family = "SplitPoint";
      mutator_ptr->set(0, key, (uint8_t *)m_split_row.c_str(), m_split_row.length());
      key.column_family = "SplitLogDir";
      mutator_ptr->set(0, key, (uint8_t *)splitLogDir.c_str(), splitLogDir.length());
      mutator_ptr->flush();
   }
   catch (Hypertable::Exception &e) {
      // TODO: propagate exception
      HT_ERRORF("Problem updating METADATA with split info (row key = %s) - %s", metadata_key_str.c_str(), e.what());
      return;
   }

   /**
    * Atomically obtain timestamp and install split log
    */
   {
      boost::mutex::scoped_lock lock(m_maintenance_mutex);
      PropertiesPtr props_ptr(0);

      /** block updates **/
      m_hold_updates = true;
      while (m_update_counter > 0)
         m_update_quiesce_cond.wait(lock);

      {
         boost::mutex::scoped_lock lock(m_mutex);
         m_split_timestamp.logical = m_scanner_timestamp_controller.get_oldest_update_timestamp();
         if (m_split_timestamp.logical == 0 || m_timestamp.logical < m_split_timestamp.logical)
            m_split_timestamp = m_timestamp;
         else
            m_split_timestamp.real = Global::log->get_timestamp();
         old_start_row = m_start_row;
      }

      m_split_log_ptr = new CommitLog(Global::dfs, splitLogDir, props_ptr);

      /** unblock updates **/
      m_hold_updates = false;
      m_maintenance_finished_cond.notify_all();
   }


   /**
    * Perform major compactions
    */
   {
      for (size_t i=0; i<m_access_group_vector.size(); i++)
         m_access_group_vector[i]->run_compaction(m_split_timestamp, true);
   }


   /**
    * Create second-level METADATA entry for new range and update second-level
    * METADATA entry for existing range to reflect the shrink 
    */
   try {
      std::string files;
      metadata_key_str = std::string("") + (uint32_t)m_identifier.id + ":" + m_split_row;
      key.row = metadata_key_str.c_str();
      key.row_len = metadata_key_str.length();
      key.column_qualifier = 0;
      key.column_qualifier_len = 0;

      key.column_family = "StartRow";
      mutator_ptr->set(0, key, (uint8_t *)old_start_row.c_str(), old_start_row.length());
      key.column_family = "SplitLogDir";
      mutator_ptr->set(0, key, (uint8_t *)splitLogDir.c_str(), splitLogDir.length());

      key.column_family = "Files";
      for (size_t i=0; i<m_access_group_vector.size(); i++) {
         key.column_qualifier = m_access_group_vector[i]->get_name();
         key.column_qualifier_len = strlen(m_access_group_vector[i]->get_name());
         m_access_group_vector[i]->get_files(files);
         mutator_ptr->set(0, key, (uint8_t *)files.c_str(), files.length());
      }

      metadata_key_str = std::string("") + (uint32_t)m_identifier.id + ":" + m_end_row;
      key.row = metadata_key_str.c_str();
      key.row_len = metadata_key_str.length();
      key.column_qualifier = 0;
      key.column_qualifier_len = 0;

      key.column_family = "StartRow";
      mutator_ptr->set(0, key, (uint8_t *)m_split_row.c_str(), m_split_row.length());
      key.column_family = "SplitLogDir";
      mutator_ptr->set(0, key, 0, 0);
      mutator_ptr->flush();
   }
   catch (Hypertable::Exception &e) {
      // TODO: propagate exception
      HT_ERRORF("Problem updating METADATA with new range information (row key = %s) - %s", metadata_key_str.c_str(), e.what());
      DUMP_CORE;
   }


   /**
    * If this is a METADATA range, then update the ROOT range
    */
   if (m_identifier.id == 0) {
      try {
         // new range
         metadata_key_str = std::string("0:") + m_split_row;
         key.row = metadata_key_str.c_str();
         key.row_len = metadata_key_str.length();
         key.column_qualifier = 0;
         key.column_qualifier_len = 0;
         key.column_family = "StartRow";
         mutator_ptr->set(0, key, (uint8_t *)old_start_row.c_str(), old_start_row.length());

         // existing range
         metadata_key_str = std::string("0:") + m_end_row;
         key.row = metadata_key_str.c_str();
         key.row_len = metadata_key_str.length();
         mutator_ptr->set(0, key, (uint8_t *)m_split_row.c_str(), m_split_row.length());
         mutator_ptr->flush();
      }
      catch (Hypertable::Exception &e) {
         // TODO: propagate exception
         HT_ERRORF("Problem updating ROOT METADATA range (new=%s, existing=%s) - %s", m_split_row.c_str(), m_end_row.c_str(), e.what());
         DUMP_CORE;
      }
   }


   /**
    *  Do the split
    */
   {
      boost::mutex::scoped_lock lock(m_maintenance_mutex);

      // block updates
      m_hold_updates = true;
      while (m_update_counter > 0)
         m_update_quiesce_cond.wait(lock);

      /*** At this point, there are no running updates ***/

      {
         boost::mutex::scoped_lock lock(m_mutex);
         m_start_row = m_split_row;
         m_split_timestamp.clear();
         m_split_row = "";
         // Shrink this range's access groups
         for (size_t i=0; i<m_access_group_vector.size(); i++)
            m_access_group_vector[i]->shrink(m_start_row);
      }

      // unblock updates
      m_hold_updates = false;
      m_maintenance_finished_cond.notify_all();
   }

   // close split log
   if ((error = m_split_log_ptr->close(Global::log->get_timestamp())) != Error::OK) {
      HT_ERRORF("Problem closing split log '%s' - %s", m_split_log_ptr->get_log_dir().c_str(), Error::get_text(error));
   }
   m_split_log_ptr = 0;

   /**
    *  Notify Master of split
    */
   {
      RangeT range;

      range.startRow = old_start_row.c_str();
      range.endRow = m_start_row.c_str();

      // update the latest generation, this should probably be protected
      m_identifier.generation = m_schema->get_generation();

      HT_INFOF("Reporting newly split off range %s[%s..%s] to Master", m_identifier.name, range.startRow, range.endRow);
      cout << flush;
      if (m_disk_limit < Global::rangeMaxBytes) {
         m_disk_limit *= 2;
         if (m_disk_limit > Global::rangeMaxBytes)
            m_disk_limit = Global::rangeMaxBytes;
      }
      if ((error = m_master_client_ptr->report_split(m_identifier, range, m_disk_limit)) != Error::OK) {
         HT_ERRORF("Problem reporting split (table=%s, start_row=%s, end_row=%s) to master.",
               m_identifier.name, range.startRow, range.endRow);
      }
   }

   HT_INFOF("Split Complete.  New Range end_row=%s", m_start_row.c_str());

   m_maintenance_in_progress = false;
}


void Range::do_compaction(bool major) {
   run_compaction(major);
   m_maintenance_in_progress = false;
}


void Range::run_compaction(bool major) {
   Timestamp timestamp;

   {
      boost::mutex::scoped_lock lock(m_maintenance_mutex);

      /** block updates **/
      m_hold_updates = true;
      while (m_update_counter > 0)
         m_update_quiesce_cond.wait(lock);

      {
         boost::mutex::scoped_lock lock(m_mutex);
         timestamp = m_timestamp;
      }

      /** unblock updates **/
      m_hold_updates = false;
      m_maintenance_finished_cond.notify_all();
   }

   /**
    * The following code ensures that pending updates that have not been
    * committed on this range do not get included in the compaction scan
    *
    * NOTE: Ideally, the real time of the start of the oldest outstanding
    * update should be tracked and used here, but I don't feel like doing
    * that now.  For now we just use the most recent update's real time.
    * This may result in edge cases where the commit log garbage collection
    * compaction is less than optimal.
    */
   uint64_t temp_timestamp = m_scanner_timestamp_controller.get_oldest_update_timestamp();
   if (temp_timestamp != 0 && temp_timestamp < timestamp.logical)
      timestamp.logical = temp_timestamp;

   for (size_t i=0; i<m_access_group_vector.size(); i++)
      m_access_group_vector[i]->run_compaction(timestamp, major);

}


/**
 * 
 */
void Range::dump_stats() {
   std::string range_str = (std::string)m_identifier.name + "[" + m_start_row + ".." + m_end_row + "]";
   uint64_t collisions = 0;
   uint64_t cached = 0;
   for (size_t i=0; i<m_access_group_vector.size(); i++) {
      collisions += m_access_group_vector[i]->get_collision_count();
      cached += m_access_group_vector[i]->get_cached_count();
   }
   cout << "STAT\t" << range_str << "\tadded inserts\t" << m_added_inserts << endl;
   cout << "STAT\t" << range_str << "\tadded row deletes\t" << m_added_deletes[0] << endl;
   cout << "STAT\t" << range_str << "\tadded cf deletes\t" << m_added_deletes[1] << endl;
   cout << "STAT\t" << range_str << "\tadded cell deletes\t" << m_added_deletes[2] << endl;
   cout << "STAT\t" << range_str << "\tadded total\t" << (m_added_inserts + m_added_deletes[0] + m_added_deletes[1] + m_added_deletes[2]) << endl;
   cout << "STAT\t" << range_str << "\tcollisions\t" << collisions << endl;
   cout << "STAT\t" << range_str << "\tcached\t" << cached << endl;
   cout << flush;
}


void Range::lock() {
   for (AccessGroupMapT::iterator iter = m_access_group_map.begin(); iter != m_access_group_map.end(); iter++)
      (*iter).second->lock();
}


void Range::unlock(uint64_t real_timestamp) {
   // This is a performance optimization to maintain the logical timestamp without excessive locking
   {
      boost::mutex::scoped_lock lock(m_mutex);
      m_timestamp.logical = m_last_logical_timestamp;
      m_timestamp.real = real_timestamp;
   }
   for (AccessGroupMapT::iterator iter = m_access_group_map.begin(); iter != m_access_group_map.end(); iter++)
      (*iter).second->unlock();
}



/**
*/
int Range::replay_split_log(string &log_dir, uint64_t real_timestamp) {
   int error;
   CommitLogReaderPtr commit_log_reader_ptr = new CommitLogReader(Global::dfs, log_dir);
   BlockCompressionHeaderCommitLog header;
   const uint8_t *base, *ptr, *end;
   size_t len;
   ByteString32T *key, *value;
   size_t nblocks = 0;
   size_t count = 0;

   commit_log_reader_ptr->initialize_read(0);

   while (commit_log_reader_ptr->next_block(&base, &len, &header)) {

      if (strcmp(m_identifier.name, header.get_tablename())) {
         HT_ERRORF("Table name mis-match in split log replay \"%s\" != \"%s\"", m_identifier.name, header.get_tablename());
         return Error::RANGESERVER_CORRUPT_COMMIT_LOG;
      }

      ptr = base;
      end = base + len;

      while (ptr < end) {
         key = (ByteString32T *)ptr;
         ptr += Length(key);
         value = (ByteString32T *)ptr;
         ptr += Length(value);
         add(key, value, real_timestamp);
         count++;
      }
      nblocks++;
   }

   {
      boost::mutex::scoped_lock lock(m_mutex);
      HT_INFOF("Replayed %d updates (%d blocks) from split log '%s' into %s[%s..%s]",
            count, nblocks, log_dir.c_str(), m_identifier.name, m_start_row.c_str(), m_end_row.c_str());
   }

   m_added_inserts = 0;
   memset(m_added_deletes, 0, 3*sizeof(int64_t));

   error = commit_log_reader_ptr->last_error();

   return Error::OK;
}


/**
 *
 */
void Range::increment_update_counter() {
   boost::mutex::scoped_lock lock(m_maintenance_mutex);
   while (m_hold_updates)
      m_maintenance_finished_cond.wait(lock);
   m_update_counter++;
}


/**
 *
 */
void Range::decrement_update_counter() {
   boost::mutex::scoped_lock lock(m_maintenance_mutex);
   m_update_counter--;
   if (m_hold_updates && m_update_counter == 0)
      m_update_quiesce_cond.notify_one();
}


/**
*/
uint64_t Range::get_latest_timestamp() {
   boost::mutex::scoped_lock lock(m_mutex);
   return m_timestamp.logical;
}


/**
*/
uint64_t Range::get_scan_timestamp() {
   boost::mutex::scoped_lock lock(m_mutex);
   uint64_t timestamp = m_scanner_timestamp_controller.get_oldest_update_timestamp();
   if (timestamp != 0 && timestamp <= m_timestamp.logical)
      return timestamp;
   return m_timestamp.logical;
}


