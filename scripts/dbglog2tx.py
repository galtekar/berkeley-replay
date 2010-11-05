#! /usr/bin/env python

"""Used to convert the output of the debug log from bdr with tainting turned on into a format where 
   given an original IP, the translated Vex IR is displayed. Run as follows:
      ./dbglog2tx.py session-id 
   where the place where the dbg-log.1 is located is /tmp/bdr-"username"/session-id/dbg-log.1
"""

import sys
import commands
import time

def usage(code,msg = ''):
    print _doc_
    if msg: print msg
    sys.exit(code)


def main(session_id=""):

    session_id = sys.argv[1]
    if session_id == "":
        usage(-1,"session-id not specified")
    path_dbg_log = "/tmp/bdr-" + commands.getoutput("whoami") + "/" + session_id + "/dbg-log.1"

    dbg_log_file = open(path_dbg_log,'r')

    cur_instr = "";
    cur_instr_ip = "";
    cur_instr_len = "";
    cur_instr_count = 0;

    for line in dbg_log_file:

        if ( line.find("lifetime:translation") == -1 ):
            continue

        line = line.replace("lifetime:translation:","")
        line = line.replace("TaintMapInstrument","")
        line = line.replace("------ IMark(","IMark ")
        line = line.replace("------","")
        line = line.replace("|","")
        line = line.strip()

        if ( line.find("IMark") != -1):
            if ( cur_instr != ""):
                print "IP: " + cur_instr_ip + " Len= " + str(cur_instr_len) + " Instr " + cur_instr
            cur_instr = ""
            cur_instr_count = 0
            cur_instr_ip = (line.split())[1].replace(",","")
            cur_instr_len = (line.split())[2].replace(")","")
        else:
            cur_instr_count = cur_instr_count + 1
            cur_instr = cur_instr +  " [" + str(cur_instr_count) + "] " + line

    dbg_log_file.close()

main()
