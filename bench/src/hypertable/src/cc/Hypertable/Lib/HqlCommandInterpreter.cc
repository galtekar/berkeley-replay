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
#include <cstdio>
#include <cstring>

#include <boost/progress.hpp>
#include <boost/timer.hpp>
#include <boost/thread/xtime.hpp>

extern "C" {
#include <time.h>
}

#include "Common/Error.h"
#include "Common/FileUtils.h"

#include "Client.h"
#include "HqlCommandInterpreter.h"
#include "HqlHelpText.h"
#include "HqlParser.h"
#include "Key.h"
#include "LoadDataSource.h"

using namespace Hypertable;
using namespace Hypertable::HqlParser;

HqlCommandInterpreter::HqlCommandInterpreter(Client *client) : m_client(client), m_timestamp_output_format(TIMESTAMP_FORMAT_DEFAULT) {
   return;
}

void HqlCommandInterpreter::execute_line(std::string &line) {
   int error;
   std::string schema_str;
   std::string out_str;
   hql_interpreter_state state;
   hql_interpreter interp(state);
   parse_info<> info;
   Schema *schema;

   info = parse(line.c_str(), interp, space_p);

   if (info.full) {

      if (state.command == COMMAND_SHOW_CREATE_TABLE) {
         if ((error = m_client->get_schema(state.table_name, schema_str)) != Error::OK)
            throw Exception(error, std::string("Problem fetching schema for table '") + state.table_name + "' from master");
         schema = Schema::new_instance(schema_str.c_str(), strlen(schema_str.c_str()), true);
         if (!schema->is_valid())
            throw Exception(Error::BAD_SCHEMA, schema->get_error_string());
         schema->render_hql_create_table(state.table_name, out_str);
         cout << out_str << flush;
      }
      else if (state.command == COMMAND_HELP) {
         const char **text = HqlHelpText::Get(state.str);
         if (text) {
            for (size_t i=0; text[i]; i++)
               cout << text[i] << endl;
         }
         else
            cout << endl << "no help for '" << state.str << "'" << endl << endl;
      }
      else if (state.command == COMMAND_CREATE_TABLE) {
         schema = new Schema();
         schema->set_compressor(state.table_compressor);
         for (Schema::AccessGroupMapT::const_iterator ag_iter = state.ag_map.begin(); ag_iter != state.ag_map.end(); ag_iter++)
            schema->add_access_group((*ag_iter).second);
         if (state.ag_map.find("default") == state.ag_map.end()) {
            Schema::AccessGroup *ag = new Schema::AccessGroup();
            ag->name = "default";
            schema->add_access_group(ag);
         }
         for (Schema::ColumnFamilyMapT::const_iterator cf_iter = state.cf_map.begin(); cf_iter != state.cf_map.end(); cf_iter++) {
            if ((*cf_iter).second->ag == "")
               (*cf_iter).second->ag = "default";
            schema->add_column_family((*cf_iter).second);
         }
         const char *error_str = schema->get_error_string();
         if (error_str)
            throw Exception(Error::HQL_PARSE_ERROR, error_str);
         schema->render(schema_str);

         if ((error = m_client->create_table(state.table_name, schema_str.c_str())) != Error::OK)
            throw Exception(error, std::string("Problem creating table '") + state.table_name + "'");
      }
      else if (state.command == COMMAND_DESCRIBE_TABLE) {
         if ((error = m_client->get_schema(state.table_name, schema_str)) != Error::OK)
            throw Exception(error, std::string("Problem fetching schema for table '") + state.table_name + "' from master");
         cout << schema_str << endl;
      }
      else if (state.command == COMMAND_SELECT) {
         TablePtr table_ptr;
         TableScannerPtr scanner_ptr;
         ScanSpecificationT scan_spec;
         CellT cell;
         uint32_t nsec;
         time_t unix_time;
         struct tm tms;

         scan_spec.rowLimit = state.scan.limit;
         scan_spec.max_versions = state.scan.max_versions;
         for (size_t i=0; i<state.scan.columns.size(); i++)
            scan_spec.columns.push_back(state.scan.columns[i].c_str());
         if (state.scan.row != "") {
            scan_spec.startRow = state.scan.row.c_str();
            scan_spec.startRowInclusive = true;
            scan_spec.endRow = state.scan.row.c_str();
            scan_spec.endRowInclusive = true;
            scan_spec.rowLimit = 1;
         }
         else {
            scan_spec.startRow = (state.scan.start_row == "") ? 0 : state.scan.start_row.c_str();
            scan_spec.startRowInclusive = state.scan.start_row_inclusive;
            scan_spec.endRow = (state.scan.end_row == "") ? Key::END_ROW_MARKER : state.scan.end_row.c_str();
            scan_spec.endRowInclusive = state.scan.end_row_inclusive;
         }
         scan_spec.interval.first  = state.scan.start_time;
         scan_spec.interval.second = state.scan.end_time;
         scan_spec.return_deletes = state.scan.return_deletes;

         if ((error = m_client->open_table(state.table_name, table_ptr)) != Error::OK)
            throw Exception(error, std::string("Problem opening table '") + state.table_name + "'");

         if ((error = table_ptr->create_scanner(scan_spec, scanner_ptr)) != Error::OK)
            throw Exception(error, std::string("Problem creating scanner on table '") + state.table_name + "'");

         while (scanner_ptr->next(cell)) {
            if (state.scan.display_timestamps) {
               if (m_timestamp_output_format == TIMESTAMP_FORMAT_USECS) {
                  printf("%llu\t", (long long unsigned int)cell.timestamp);
               }
               else {
                  nsec = cell.timestamp % 1000000000LL;
                  unix_time = cell.timestamp / 1000000000LL;
                  gmtime_r(&unix_time, &tms);
                  printf("%d-%02d-%02d %02d:%02d:%02d.%09d\t", tms.tm_year+1900, tms.tm_mon+1, tms.tm_mday, tms.tm_hour, tms.tm_min, tms.tm_sec, nsec);
               }
            }
            if (!state.scan.keys_only) {
               if (cell.column_family) {
                  printf("%s\t%s", cell.row_key, cell.column_family);
                  if (*cell.column_qualifier)
                     printf(":%s", cell.column_qualifier);
               }
               else
                  printf("%s", cell.row_key);
               if (cell.flag != FLAG_INSERT)
                  printf("\t%s\tDELETE\n", std::string((const char *)cell.value, cell.value_len).c_str());
               else
                  printf("\t%s\n", std::string((const char *)cell.value, cell.value_len).c_str());
            }
            else
               printf("%s\n", cell.row_key);
         }
      }
      else if (state.command == COMMAND_LOAD_DATA) {
         TablePtr table_ptr;
         TableMutatorPtr mutator_ptr;
         LoadDataSource *lds;
         uint64_t timestamp;
         KeySpec key;
         uint8_t *value;
         uint32_t value_len;
         uint32_t consumed;
         uint64_t file_size;
         uint64_t total_values_size = 0;
         uint64_t total_rowkey_size = 0;
         string start_msg;
         uint64_t insert_count = 0;
         boost::xtime start_time, finish_time;
         double elapsed_time;
         bool into_table = true;
         bool display_timestamps = false;
         FILE *outfp = 0;

         boost::xtime_get(&start_time, boost::TIME_UTC);

         if (state.table_name == "") {
            if (state.output_file == "")
               throw Exception(Error::HQL_PARSE_ERROR, "LOAD DATA INFILE ... INTO FILE - bad filename");
            outfp = fopen(state.output_file.c_str(), "w");
            into_table = false;
         }
         else {
            if ((error = m_client->open_table(state.table_name, table_ptr)) != Error::OK)
               throw Exception(error, std::string("Problem opening table '") + state.table_name + "'");

            if ((error = table_ptr->create_mutator(mutator_ptr)) != Error::OK)
               throw Exception(error, std::string("Problem creating mutator on table '") + state.table_name + "'");
         }

         boost::trim_if(state.str, boost::is_any_of("'\""));

         if (!FileUtils::exists(state.str.c_str()))
            throw Exception(Error::FILE_NOT_FOUND, state.str);

         file_size = FileUtils::size(state.str.c_str());

         printf("\nLoading ");
         if (file_size > 1000000000000LL)
            printf("%3lld,", file_size/1000000000000LL);
         if (file_size > 1000000000LL)
            printf("%3lld,", (file_size%1000000000000LL) / 1000000000LL);
         if (file_size > 1000000LL)
            printf("%3lld,", (file_size%1000000000LL) / 1000000LL);
         if (file_size > 1000LL)
            printf("%3lld,", (file_size%1000000LL) / 1000LL);
         printf("%3lld", file_size % 1000LL);
         printf(" bytes of input data...\n");
         fflush(stdout);

         boost::progress_display show_progress( file_size );

         lds = new LoadDataSource(state.str, state.row_key_column, state.timestamp_column);

         if (!into_table) {
            display_timestamps = lds->has_timestamps();
            if (display_timestamps)
               fprintf(outfp, "timestamp\trowkey\tcolumnkey\tvalue\n");
            else
               fprintf(outfp, "rowkey\tcolumnkey\tvalue\n");
         }

         while (lds->next(0, &timestamp, &key, &value, &value_len, &consumed)) {
            if (value_len > 0) {
               insert_count++;
               total_values_size += value_len;
               total_rowkey_size += key.row_len;
               if (into_table) {
                  try {
                     mutator_ptr->set(timestamp, key, value, value_len);
                  }
                  catch (Hypertable::Exception &e) {
                     cerr << "error: " << Error::get_text(e.code()) << " - " << e.what() << endl;
                  }
               }
               else {
                  if (display_timestamps)
                     fprintf(outfp, "%llu\t%s\t%s\t%s\n", (long long unsigned int)timestamp, (const char *)key.row, key.column_family, (const char *)value);
                  else
                     fprintf(outfp, "%s\t%s\t%s\n", (const char *)key.row, key.column_family, (const char *)value);
               }
            }
            show_progress += consumed;
         }

         delete lds;

         if (into_table)
            mutator_ptr->flush();
         else
            fclose(outfp);

         boost::xtime_get(&finish_time, boost::TIME_UTC);

         if (start_time.sec == finish_time.sec)
            elapsed_time = (double)(finish_time.nsec - start_time.nsec) / 1000000000.0;
         else {
            elapsed_time = finish_time.sec - start_time.sec;
            elapsed_time += ((1000000000.0 - (double)start_time.nsec) + (double)finish_time.nsec) / 1000000000.0;
         }

         if (show_progress.count() < file_size)
            show_progress += file_size - show_progress.count();

         printf("Load complete.\n");
         printf("\n");
         printf("  Elapsed time:  %.2f s\n", elapsed_time);
         printf("Avg value size:  %.2f bytes\n", (double)total_values_size / insert_count);
         printf("  Avg key size:  %.2f bytes\n", (double)total_rowkey_size / insert_count);
         printf("    Throughput:  %.2f bytes/s\n", (double)file_size / elapsed_time);
         printf(" Total inserts:  %llu\n", (long long unsigned int)insert_count);
         printf("    Throughput:  %.2f inserts/s\n", (double)insert_count / elapsed_time);
         if (mutator_ptr)
            printf("       Resends:  %llu\n", (long long unsigned int)mutator_ptr->get_resend_count());
         printf("\n");

         /*
            printf("Load complete (%.2fs elapsed_time, %.2f bytes/s, %.2f inserts/s)\n",
            elapsed_time, (double)file_size / elapsed_time, (double)insert_count / elapsed_time);
            */

      }
      else if (state.command == COMMAND_INSERT) {
         TablePtr table_ptr;
         TableMutatorPtr mutator_ptr;
         KeySpec key;
         char *column_qualifier;
         std::string tmp_str;

         if ((error = m_client->open_table(state.table_name, table_ptr)) != Error::OK)
            throw Exception(error, std::string("Problem opening table '") + state.table_name + "'");

         if ((error = table_ptr->create_mutator(mutator_ptr)) != Error::OK)
            throw Exception(error, std::string("Problem creating mutator on table '") + state.table_name + "'");

         for (size_t i=0; i<state.inserts.size(); i++) {
            key.row = state.inserts[i].row_key.c_str();
            key.row_len = state.inserts[i].row_key.length();
            key.column_family = state.inserts[i].column_key.c_str();
            if ((column_qualifier = strchr(state.inserts[i].column_key.c_str(), ':')) != 0) {
               *column_qualifier++ = 0;
               key.column_qualifier = column_qualifier;
               key.column_qualifier_len = strlen(column_qualifier);
            }
            else {
               key.column_qualifier = 0;
               key.column_qualifier_len = 0;
            }
            try {
               mutator_ptr->set(state.inserts[i].timestamp, key, (uint8_t *)state.inserts[i].value.c_str(), (uint32_t)state.inserts[i].value.length());
            }
            catch (Hypertable::Exception &e) {
               cerr << "error: " << Error::get_text(e.code()) << " - " << e.what() << endl;
            }
         }
         mutator_ptr->flush();
      }
      else if (state.command == COMMAND_DELETE) {
         TablePtr table_ptr;
         TableMutatorPtr mutator_ptr;
         KeySpec key;
         char *column_qualifier;
         std::string tmp_str;

         if ((error = m_client->open_table(state.table_name, table_ptr)) != Error::OK)
            throw Exception(error, std::string("Problem opening table '") + state.table_name + "'");

         if ((error = table_ptr->create_mutator(mutator_ptr)) != Error::OK)
            throw Exception(error, std::string("Problem creating mutator on table '") + state.table_name + "'");

         memset(&key, 0, sizeof(key));
         key.row = state.delete_row.c_str();
         key.row_len = state.delete_row.length();

         if (state.delete_time != 0)
            state.delete_time++;

         if (state.delete_all_columns) {
            try {
               mutator_ptr->set_delete(state.delete_time, key);
            }
            catch (Hypertable::Exception &e) {
               cerr << "error: " << Error::get_text(e.code()) << " - " << e.what() << endl;
               return;
            }
         }
         else {
            for (size_t i=0; i<state.delete_columns.size(); i++) {
               key.column_family = state.delete_columns[i].c_str();
               if ((column_qualifier = strchr(state.delete_columns[i].c_str(), ':')) != 0) {
                  *column_qualifier++ = 0;
                  key.column_qualifier = column_qualifier;
                  key.column_qualifier_len = strlen(column_qualifier);
               }
               else {
                  key.column_qualifier = 0;
                  key.column_qualifier_len = 0;
               }
               try {
                  mutator_ptr->set_delete(state.delete_time, key);
               }
               catch (Hypertable::Exception &e) {
                  cerr << "error: " << Error::get_text(e.code()) << " - " << e.what() << endl;
               }
            }
         }
         mutator_ptr->flush();
      }
      else if (state.command == COMMAND_SHOW_TABLES) {
         std::vector<std::string> tables;
         if ((error = m_client->get_tables(tables)) != Error::OK)
            throw Exception(error, std::string("Problem obtaining table list"));
         if (tables.empty())
            cout << "Empty set" << endl;
         else {
            for (size_t i=0; i<tables.size(); i++)
               cout << tables[i] << endl;
         }
      }
      else if (state.command == COMMAND_DROP_TABLE) {
         if ((error = m_client->drop_table(state.table_name, state.if_exists)) != Error::OK)
            throw Exception(error, std::string("Problem droppint table '") + state.table_name + "'");
      }
   }
   else
      throw Exception(Error::HQL_PARSE_ERROR, std::string("parse error at: ") + info.stop);

}


void HqlCommandInterpreter::set_timestamp_output_format(std::string format) {
   if (format == "default")
      m_timestamp_output_format = TIMESTAMP_FORMAT_DEFAULT;
   else if (format == "usecs")
      m_timestamp_output_format = TIMESTAMP_FORMAT_USECS;
   else {
      assert(!"invalid timestamp format");
   }
}
