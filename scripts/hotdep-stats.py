#!/usr/bin/env python2.6
#
# author: Gautam Altekar
# $Id: replay_console.py,v 1.54 2006/10/04 04:10:31 galtekar Exp $
#
# vim:ts=4:sw=4:expandtab

"""Script for processing BDR's formgen results and printing our useful
stats. Relies on BFD utils such as addr2line. """

import sys, commands, subprocess, os
from os.path import join, getsize

#####
# Produces a control and data plane function profile given taint flow
# analysis results.

def is_library(obj_path):
   cmd_out = commands.getoutput("readelf -h %s"%(obj_path))
   if cmd_out.find("EXEC") != -1:
      return False
   return True

library_cache_by_path = {}
def is_library_cached(obj_path):
   if obj_path in library_cache_by_path:
      return library_cache_by_path[obj_path]
   else:
      res = is_library(obj_path)
      library_cache_by_path[obj_path] = res
      return res

def calc_addr_by_off(obj_name, off_str):
   if is_library_cached(obj_name):
      addr = int(off_str, 0)
   else:
      addr = int(off_str, 0) + 0x8048000
   return addr


def build_func_names(filename):
   loc_by_obj = {}
   f = open(filename)
   for line in f.readlines():
      columns = line.split(' ')
      if len(columns) > 3 and columns[2] == '[Prof]':
         obj_name = columns[3]
         addr = calc_addr_by_off(obj_name, columns[4])
         if obj_name in loc_by_obj:
            loc_by_obj[obj_name][str(addr)] = None
         else:
            loc_by_obj[obj_name] = { str(addr) : None }
   f.close()

   for obj_name in loc_by_obj:
      cmd = ["addr2line", "-C", "-f", "-e", "%s"%(obj_name)]
      child = subprocess.Popen(cmd, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      input_str = ""
      for k in loc_by_obj[obj_name]:
         input_str += "0x%x\n"%(int(k, 0))
      
      (cmd_out,cmd_err) = child.communicate(input_str)

      cmd_list = cmd_out.split('\n')
      i = 0
      for k in loc_by_obj[obj_name]:
         assert(loc_by_obj[obj_name][k] == None)
         loc_by_obj[obj_name][k] = cmd_list[i]
         i += 2
      child.wait()
   return loc_by_obj



def process_line(columns, loc_by_obj, map):
   obj_name = columns[3]
   nr_exec = int(columns[6])

   addr = calc_addr_by_off(obj_name, columns[4])
   func_name = loc_by_obj[obj_name][str(addr)]
   combined_name = obj_name + "##" + func_name
   if combined_name in map:
      map[combined_name] += nr_exec
   else:
      map[combined_name] = nr_exec

def is_func_name_template(name):
   template_prefixes = ["std::", "__gnu_cxx::", "bool __gnu_cxx::", \
         "void std::", "bool std::", "void boost::",
         "boost::", "_Dequeue_iterator", "scoped_lock", "~scoped_lock",
         "intrusive_ptr", "~intrusive_ptr", "_lzo1x", "lzo1x", "Hypertable::fletcher32",
         "Hypertable::adler32"]
   for prefix in template_prefixes:
      if name.startswith(prefix):
         return True
   return False

def pretty_print_map(str, map):
   total_nr_dyn_insns = 0.0
   lib_dyn_insns = 0.0
   main_dyn_insns = 0.0
   nr_funcs = 0
   for (k,v) in map.iteritems():
      total_nr_dyn_insns += v
      (obj_path, func_name) = k.split('##')
      is_library = library_cache_by_path[obj_path]
      #print "[", func_name, "]"
      if is_library or is_func_name_template(func_name):
         lib_dyn_insns += v
      else:
         main_dyn_insns += v
   #sys.exit(0)

   print str, ": %d functions"%(len(map))
   print "%f insns executed total"%(total_nr_dyn_insns)
   if total_nr_dyn_insns > 0:
      print "%f in library, %f in main"%(lib_dyn_insns /
            total_nr_dyn_insns * 100, main_dyn_insns / total_nr_dyn_insns
            * 100)

   cum_nr_dyn_insns = 0.0
   for (k,v) in sorted(map.iteritems(), key=lambda (k,v): (v,k),
         reverse=True):
      cum_nr_dyn_insns += v
      percentile = cum_nr_dyn_insns / total_nr_dyn_insns * 100.0
      print k, v, percentile

      if percentile <= 90:
         nr_funcs += 1

   print "%d functions in 90th percentile"%(nr_funcs)

def do_work(filename):

   cp_by_func = {}
   dp_by_func = {}

   loc_by_obj = build_func_names(filename)

   f = open(filename)
   for line in f.readlines():
      columns = line.split(' ')
      if len(columns) > 3 and columns[2] == '[Prof]':
         nr_constraints = int(columns[5])

         if nr_constraints > 0:
            process_line(columns, loc_by_obj, dp_by_func)
         else:
            assert(nr_constraints == 0)
            process_line(columns, loc_by_obj, cp_by_func)
            #print obj_name, hex(addr), func_name
   f.close()

   print "-"*78
   print "Results for:", filename
   print "-"*78
   pretty_print_map("Control Plane", cp_by_func)
   pretty_print_map("Data Plane", dp_by_func)

RESULT_FILENAME = "dbg-rep.1"

def process_dir(dirname):
   for root, dirs, files in os.walk(dirname):
      #print (root, dirs, files)
      if RESULT_FILENAME in files:
         do_work(join(root, RESULT_FILENAME))

##### Main work.
if __name__ == "__main__":
   for dir in sys.argv[1:]:
      process_dir(dir)
