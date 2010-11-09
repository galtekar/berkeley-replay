#include <windows.h>
#include <winsvc.h>
#include <windowsx.h>
#include <shellapi.h>
#include <sys/stat.h>

#include "i3_client_api.h"
#include "i3_proxy.h"

CHAR szKey[MAX_PATH];

SERVICE_STATUS g_srv_status = {
  SERVICE_WIN32_OWN_PROCESS,
  SERVICE_START_PENDING,
  SERVICE_ACCEPT_STOP,
  NO_ERROR,
  NO_ERROR,
  0,
  0
};

char SERVICE_NAME[255] = "i3 proxy";
char DISPLAY_NAME[255] = "i3 proxy";

SERVICE_STATUS_HANDLE g_srv_status_handle;


void WINAPI Handler (DWORD ctrl)
{
  switch (ctrl)
    {
    case SERVICE_CONTROL_STOP:
      g_srv_status.dwCurrentState = SERVICE_STOP_PENDING;
      g_srv_status.dwWin32ExitCode = 0;
      g_srv_status.dwCheckPoint = 0;
      g_srv_status.dwWaitHint = 0;
      break;
    case SERVICE_CONTROL_INTERROGATE:
      break;
    default:
      break;
    }
    SetServiceStatus (g_srv_status_handle, &g_srv_status);
}

void strip_filename(char *filename)
{
  int i, len;

  len = strlen(filename);

  // strip off filename and get path
  for (i = len - 1; i >=0; i--) {
    if (filename[i] != '\\') {
      filename[i] = 0;
    } else {
      break;
    }
  }

  i = 0;
  while (filename[i] != 0) {
    if (filename[i] == '\\')
      filename[i] = '/';
    i++;
  }
}

void init_reg()
{
  CHAR svcPath[MAX_PATH];
  CHAR szImagePath[MAX_PATH];
  CHAR szBuf[MAX_PATH];
  HKEY hKey, hSubKey;
  DWORD retCode, rv, dwKeyType;
  DWORD dwBufLen = MAX_PATH;
  DWORD status = 0;
  int i;

  retCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\",
			 0, KEY_READ, &hKey);
  if (retCode != ERROR_SUCCESS)
    return;

  for (i = 0, retCode = ERROR_SUCCESS; retCode == ERROR_SUCCESS; i++) {
    retCode = RegEnumKey(hKey, i, svcPath, MAX_PATH);
    if (retCode == ERROR_SUCCESS) {
      lstrcpy(szKey, "System\\CurrentControlSet\\Services\\");
      lstrcat(szKey, svcPath);
      
      if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKey, 0,
		       KEY_QUERY_VALUE | KEY_SET_VALUE, &hSubKey) == ERROR_SUCCESS) {
	dwBufLen = MAX_PATH;
	rv = RegQueryValueEx(hSubKey, "ImagePath", NULL,
			     &dwKeyType, szImagePath, &dwBufLen);
	
	if (rv == ERROR_SUCCESS
	    && (dwKeyType == REG_SZ
		|| dwKeyType == REG_EXPAND_SZ) && dwBufLen) {
	  lstrcpy(szBuf, szImagePath);
	  CharLower(szBuf);
	  if (strstr(szBuf, "\\i3_client_proxy") != NULL) {
	    RegSetValueEx(hSubKey, "ProxyStatus", 0,
			  REG_DWORD, (BYTE *) &status, sizeof(status));
	    break;
	  }
	}
	RegCloseKey(hSubKey);
      }
    }
  }
  RegCloseKey(hKey);
  return;
}

void update_status(DWORD status)
{
  HKEY hKey;

  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKey, 0,
		   KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
    RegSetValueEx(hKey, "ProxyStatus", 0,
		  REG_DWORD, (BYTE *) &status, sizeof(status));
    RegCloseKey(hKey);
  }
  return;
}
    

void WINAPI ServiceMain (DWORD ac, char **av)
{
  char path[MAX_PATH];
  DWORD status = 0;
  DWORD ret;

  g_srv_status_handle = RegisterServiceCtrlHandler (SERVICE_NAME, Handler);
  if (!g_srv_status_handle)
    return;
  g_srv_status.dwCurrentState = SERVICE_START_PENDING;
  g_srv_status.dwCheckPoint = 0;
  g_srv_status.dwWaitHint = 1000;
  SetServiceStatus (g_srv_status_handle, &g_srv_status);

  /* initialization process */
  
  if (!GetModuleFileName (0, path, MAX_PATH))
    return;

  strip_filename(path);
  chdir(path);

  if (freopen("proxy_error.log", "w", stderr) == NULL)
    return;
  if (freopen("proxy.log", "w", stdout) == NULL)
    return;
  init_reg();
  init_i3_proxy(ac, av);
  
  /* notify that the service has been started */
  g_srv_status.dwCurrentState = SERVICE_RUNNING;
  g_srv_status.dwCheckPoint = 0;
  g_srv_status.dwWaitHint = 0;
  SetServiceStatus (g_srv_status_handle, &g_srv_status);

  while (g_srv_status.dwCurrentState != SERVICE_STOPPED)
    {
      switch (g_srv_status.dwCurrentState)
        {
        case SERVICE_STOP_PENDING:
          g_srv_status.dwCurrentState = SERVICE_STOPPED;
          SetServiceStatus (g_srv_status_handle, &g_srv_status);
          break;
        default:
	  Sleep(1000);
	  ret = cl_check_status();
	  if (ret >= 0 && ret != status) {
	    status = ret;
	    update_status(status);
	  }
          break;
        }
    }
}

DWORD proxy_install (char *args)
{
  char path[MAX_PATH];
  char wrapper_path[MAX_PATH];
  char ImagePath[MAX_PATH];
  char *cmd;
  struct stat buf;
  SC_HANDLE scm = 0;
  SC_HANDLE srv = 0;
  int rc = 0;
  if (!GetModuleFileName (0, path, MAX_PATH))
    return GetLastError ();
  strcpy(wrapper_path, path);

  if ((cmd = strstr(wrapper_path, "i3_client_proxy.exe")) == NULL) {
    printf("the command name is different from 'i3_client_proxy.exe'\n");
    return -1;
  }
  strcpy(cmd, "i3_run.bat\0");

  if (stat(wrapper_path, &buf) != 0) {
    printf("i3_run.bat does not exist in the same directory\n");
    return -1;
  }
  
  sprintf(ImagePath, "\"%s\" \"%s\" -X %s", wrapper_path, path, args);
  scm = OpenSCManager (0, 0, SC_MANAGER_ALL_ACCESS);
  if (!scm)
    return GetLastError ();
  srv = CreateService (scm, SERVICE_NAME, DISPLAY_NAME, SERVICE_ALL_ACCESS,
                       SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                       ImagePath, 0, 0, 0, 0, 0);

  if (!srv)
    rc = GetLastError ();
  else
    CloseServiceHandle (srv);
  CloseServiceHandle (scm);
  return rc;
}

DWORD proxy_remove ()
{
  SC_HANDLE scm = 0;
  SC_HANDLE srv = 0;
  int rc = 0;
  scm = OpenSCManager (0, 0, SC_MANAGER_ALL_ACCESS);
  if (!scm)
    return GetLastError ();
  srv = OpenService (scm, SERVICE_NAME, DELETE);
  if (!srv)
    rc = GetLastError ();
  else
    {
      if (!DeleteService (srv))
        rc = GetLastError ();
      CloseServiceHandle (srv);
    }
  CloseServiceHandle (scm);
  return rc;
}

DWORD proxy_start (BOOL cold_start)
{
  SC_HANDLE scm = 0;
  SC_HANDLE srv = 0;
  SERVICE_STATUS st;
  memset (&st, 0, sizeof (st));
  int rc = 0;
  if (!(scm = OpenSCManager (0, 0, SC_MANAGER_ALL_ACCESS)))
    return GetLastError ();

  if (!(srv = OpenService (scm, SERVICE_NAME, SERVICE_START|SERVICE_QUERY_STATUS)))
    return GetLastError ();

  if (cold_start) {
    char *args[3] = {"-c"};
    if (!StartService(srv, 1, (LPCTSTR*) &args))
      return GetLastError();
  } else if (!StartService (srv, 0, 0))
    return GetLastError();

  if (!QueryServiceStatus (srv, &st))
    return GetLastError ();

  {
    DWORD old;
    while (st.dwCurrentState == SERVICE_START_PENDING)
      {
	old = st.dwCheckPoint;
	Sleep (st.dwWaitHint);
	if (!QueryServiceStatus (srv, &st))
	  {
	    rc = GetLastError ();
	    break;
	  }
      }
    if (rc)
      ;
    else if (st.dwCurrentState == SERVICE_RUNNING)
      printf ("i3 proxy service has been successfully started\n");
    else
      printf ("i3 proxy service status is %d\n", (int)st.dwCurrentState);
  }
  if (srv)
    CloseServiceHandle (srv);
  if (scm)
    CloseServiceHandle (scm);
  return rc;
}

DWORD proxy_stop ()
{
  SC_HANDLE scm = 0;
  SC_HANDLE srv = 0;
  SERVICE_STATUS st;
  memset (&st, 0, sizeof (st));
  int rc = 0;
  if (!(scm = OpenSCManager (0, 0, SC_MANAGER_ALL_ACCESS)))
    rc = GetLastError ();
  else if (!(srv = OpenService (scm, SERVICE_NAME, SERVICE_STOP)))
    rc = GetLastError ();
  else if (!ControlService (srv, SERVICE_CONTROL_STOP, &st))
    rc = GetLastError ();
  else
    printf ("i3 proxy service has been stopped\n");
  if (srv)
    CloseServiceHandle (srv);
  if (scm)
    CloseServiceHandle (scm);
  return rc;
}


int main (int argc, char *argv[])
{
  int i;
  int rc;
  char *error_buf;

  if (argc > 1) {
    for (i = 1; i < argc; i++) {
      if (strcmp(argv[i], "-h") == 0) {
	usage(argv[0]);
	exit(0);
      } else if (strcmp(argv[i], "-I") == 0) {
	char args[MAX_DNS_NAME_LEN] = "";
	if (argc > i + 1)
	  strcpy(args, argv[i+1]);
	if ((rc = proxy_install(args))) {
	  if (rc != -1) {
	    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
			  FORMAT_MESSAGE_IGNORE_INSERTS,NULL,rc,
			  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),(LPTSTR) &error_buf,0,NULL);
	    printf("%s\n", error_buf);
	  }
	} else {
	  printf("i3 proxy has been successfully installed as a service.\n");
	}
	exit(0);
      } else if (strcmp(argv[i], "-R") == 0) {
	if ((rc = proxy_remove())) {
	  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,NULL,rc,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),(LPTSTR) &error_buf,0,NULL);
	  printf("%s\n", error_buf);
	} else {
	  printf("i3 proxy service has been successfully uninstalled.\n");
	}
	exit(0);
      } else if (strcmp(argv[i], "-S") == 0) {
	if ((rc = proxy_start(0))) {
	  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,NULL,rc,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),(LPTSTR) &error_buf,0,NULL);
	  printf("%s\n", error_buf);
	}
	exit(0);
      } else if (strcmp(argv[i], "-C") == 0) {
	if ((rc = proxy_start(1))) {
	  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,NULL,rc,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),(LPTSTR) &error_buf,0,NULL);
	  printf("%s\n", error_buf);
	}
	exit(0);
      } else if (strcmp(argv[i], "-E") == 0) {
	if ((rc = proxy_stop())) {
	  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,NULL,rc,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),(LPTSTR) &error_buf,0,NULL);
	  printf("%s\n", error_buf);
	}
	exit(0);
      } else if (strcmp(argv[i], "-X") == 0) {
	SERVICE_TABLE_ENTRY ent[] = { { SERVICE_NAME, ServiceMain }, { 0, 0 }, };
	StartServiceCtrlDispatcher (ent);
	exit(0);
      }
      i++;
    }
  }
  init_i3_proxy(argc, argv);
  exit(0);
}
