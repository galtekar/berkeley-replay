/**
 * Copyright (C) 2007 Doug Judd (Zvents, Inc.)
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

#include <iostream>
#include <fstream>
#include <string>

extern "C" {
#include <poll.h>
#include <sys/types.h>
#include <unistd.h>
}

#include "Common/InetAddr.h"
#include "Common/System.h"
#include "Common/Usage.h"

#include "AsyncComm/ApplicationQueue.h"
#include "AsyncComm/Comm.h"
#include "AsyncComm/ConnectionHandlerFactory.h"

#include "ConnectionHandler.h"
#include "Master.h"

using namespace Hypertable;
using namespace std;


namespace {
  const char *usage[] = {
    "usage: Hypertable.Master [OPTIONS]",
    "",
    "OPTIONS:",
    "  --config=<file>   Read configuration from <file>.  The default config file is",
    "                    \"conf/hypertable.cfg\" relative to the toplevel install directory",
    "  --pidfile=<fname> Write the process ID to <fname> upon successful startup",
    "  --help            Display this help text and exit",
    "  --verbose,-v      Generate verbose output",
    ""
    "This program is the Hypertable master server.",
    (const char *)0
  };
  const int DEFAULT_PORT              = 38050;
  const int DEFAULT_WORKERS           = 20;


  /**
   *
   */
  class HandlerFactory : public ConnectionHandlerFactory {
  public:
    HandlerFactory(Comm *comm, ApplicationQueuePtr &appQueuePtr, MasterPtr &master_ptr) : m_comm(comm), m_app_queue_ptr(appQueuePtr), m_master_ptr(master_ptr) { return; }
    virtual void get_instance(DispatchHandlerPtr &dhp) {
      dhp = new ConnectionHandler(m_comm, m_app_queue_ptr, m_master_ptr);
    }
  private:
    Comm                *m_comm;
    ApplicationQueuePtr  m_app_queue_ptr;
    MasterPtr            m_master_ptr;
  };

}


/**
 * 
 */
int main(int argc, char **argv) {
  string configFile = "";
  string pidFile = "";
  PropertiesPtr props_ptr;
  bool verbose = false;
  MasterPtr master_ptr;
  int port, reactorCount, workerCount;
  Comm *comm;
  ApplicationQueuePtr app_queue_ptr;
  ConnectionManagerPtr connManagerPtr;
  struct sockaddr_in listenAddr;

  System::initialize(argv[0]);
  
  if (argc > 1) {
     for (int i=1; i<argc; i++) {
        if (!strncmp(argv[i], "--config=", 9))
           configFile = &argv[i][9];
        if (!strncmp(argv[i], "--pidfile=", 10))
           pidFile = &argv[i][10];
        else if (!strcmp(argv[i], "--verbose") || !strcmp(argv[i], "-v"))
           verbose = true;
        else
           Usage::dump_and_exit(usage);
     }
  }

  if (configFile == "")
     configFile = System::installDir + "/conf/hypertable.cfg";

  props_ptr = new Properties(configFile);

  if (verbose)
     props_ptr->set("Hypertable.Verbose", "true");

  port         = props_ptr->get_int("Hypertable.Master.Port", DEFAULT_PORT);
  reactorCount = props_ptr->get_int("Hypertable.Master.Reactors", System::get_processor_count());
  workerCount  = props_ptr->get_int("Hypertable.Master.Workers", DEFAULT_WORKERS);

  ReactorFactory::initialize(reactorCount);

  comm = new Comm();
  connManagerPtr = new ConnectionManager(comm);

  if (verbose) {
     cout << "CPU count = " << System::get_processor_count() << endl;
     cout << "Hypertable.Master.Port=" << port << endl;
     cout << "Hypertable.Master.Workers=" << workerCount << endl;
     cout << "Hypertable.Master.Reactors=" << reactorCount << endl;
  }

  app_queue_ptr = new ApplicationQueue(workerCount);
  master_ptr = new Master(connManagerPtr, props_ptr, app_queue_ptr);

  InetAddr::initialize(&listenAddr, INADDR_ANY, port);
  ConnectionHandlerFactoryPtr chfPtr(new HandlerFactory(comm, app_queue_ptr, master_ptr));
  comm->listen(listenAddr, chfPtr);

  if (pidFile != "") {
     fstream filestr (pidFile.c_str(), fstream::out);
     filestr << getpid() << endl;
     filestr.close();
  }

  master_ptr->join();

  delete comm;
  return 0;
}
