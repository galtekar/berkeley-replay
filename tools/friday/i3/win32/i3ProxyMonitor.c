#ifndef STRICT
#define STRICT
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <objbase.h>
#include <shlobj.h>
#include <stdlib.h>
#include <stdio.h>
#include "i3ProxyMonitor.h"

#define WM_TRAYMESSAGE         (WM_APP+1)
#define WM_TIMER_REFRESH       10
#define WM_TIMER_RESCAN        11
#define REFRESH_TIME           1000
#define RESCAN_TIME            20000

LPSTR           g_ServiceName;
DWORD           g_dwPid = 0;
BOOL            g_ServiceFound = FALSE;
CHAR            g_i3ProxyKey[MAX_PATH];
DWORD           g_i3ProxyStatus = 0;

CHAR           *g_szTitle;
CHAR           *g_WindowClass;
HICON           g_iconStop;
HICON           g_iconRun;
HICON           g_iconNosrv;
HICON           g_iconDisconnect;
UINT            g_taskbarRestart;
DWORD           g_dwTimeout = 10000;
HWND            g_hwndMain;
HCURSOR         g_hCursorHourglass;
HCURSOR         g_hCursorArrow;

CRITICAL_SECTION g_mutex;

BOOL            g_cold_start = 0;

void
ErrorMessage(LPCSTR szError)
{
    LPVOID          lpMsgBuf = NULL;

    if (szError)
	MessageBox(NULL, szError, "Error", MB_OK | MB_ICONEXCLAMATION);
    else {
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		      FORMAT_MESSAGE_FROM_SYSTEM |
		      FORMAT_MESSAGE_IGNORE_INSERTS,
		      NULL, GetLastError(), 0, (LPSTR) & lpMsgBuf, 0,
		      NULL);
	MessageBox(NULL, (LPCSTR) lpMsgBuf, "Error",
		   MB_OK | MB_ICONEXCLAMATION);
	LocalFree(lpMsgBuf);
    }
}

static          VOID
ShowNotifyIcon(HWND hWnd, DWORD dwMessage)
{
    NOTIFYICONDATA  nid;

    memset(&nid, 0, sizeof(nid));
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hWnd;
    nid.uID = 0xFF;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYMESSAGE;

    if (dwMessage == NIM_DELETE) {
	nid.hIcon = NULL;
    } else {
	if (g_ServiceFound) {
	    if (g_dwPid == SERVICE_RUNNING) {
	        if (g_i3ProxyStatus >= 1) {
		  nid.hIcon = g_iconRun;
		  sprintf(nid.szTip, "i3 proxy service running");
		} else {
		  nid.hIcon = g_iconDisconnect;
		  sprintf(nid.szTip, "unable to contact i3 servers");
		}
	    } else {
		nid.hIcon = g_iconStop;
		sprintf(nid.szTip, "i3 proxy service is not running");
	    }
	} else {
	    nid.hIcon = g_iconNosrv;
	    sprintf(nid.szTip, "i3 proxy service is not installed");
	}
    }
    Shell_NotifyIcon(dwMessage, &nid);
}

void
appendMenuItem(HMENU hMenu, UINT uMenuId, LPSTR szName,
	       BOOL fDefault, BOOL fEnabled)
{
    MENUITEMINFO    mii;

    memset(&mii, 0, sizeof(MENUITEMINFO));
    mii.cbSize = sizeof(MENUITEMINFO);
    mii.fMask = MIIM_ID | MIIM_TYPE | MIIM_STATE;
    if (lstrlen(szName)) {
	mii.fType = MFT_STRING;
	mii.wID = uMenuId;
	if (fDefault) {
	    mii.fState = MFS_DEFAULT;
	}
	if (!fEnabled) {
	    mii.fState |= MFS_DISABLED;
	}
	mii.dwTypeData = szName;
    } else {
	mii.fType = MFT_SEPARATOR;
    }
    InsertMenuItem(hMenu, uMenuId, FALSE, &mii);
}

void
appendServiceMenu(HMENU hMenu, UINT uMenuId, BOOL fRunning)
{
    appendMenuItem(hMenu, IDM_SM_START + uMenuId, "&Start", FALSE,
		   !fRunning);
    appendMenuItem(hMenu, IDM_SM_STOP + uMenuId, "S&top", FALSE, fRunning);
    appendMenuItem(hMenu, IDM_SM_COLDSTART + uMenuId, "&Coldstart", FALSE,
		   !fRunning);
}

void
ShowTryPopupMenu(HWND hWnd)
{
    HMENU           hMenu = CreatePopupMenu();
    POINT           pt;

    if (hMenu) {
	appendMenuItem(hMenu, IDC_SMANAGER, "Open &Services", FALSE, TRUE);
	appendMenuItem(hMenu, 0, "", FALSE, TRUE);
	appendMenuItem(hMenu, IDM_EXIT, "E&xit", FALSE, TRUE);

	if (!SetForegroundWindow(hWnd))
	    SetForegroundWindow(NULL);

	GetCursorPos(&pt);
	TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON,
		       pt.x, pt.y, 0, hWnd, NULL);
	DestroyMenu(hMenu);
    }
}

void
ShowTryServiceMenu(HWND hWnd)
{
    HMENU           hMenu = CreatePopupMenu();
    POINT           pt;

    if (g_ServiceFound) {
	appendServiceMenu(hMenu, 0, g_dwPid == SERVICE_RUNNING);
	SetForegroundWindow(hWnd);
	GetCursorPos(&pt);
	TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON,
		       pt.x, pt.y, 0, hWnd, NULL);
	DestroyMenu(hMenu);
    }
}

BOOL
i3ControlService(DWORD dwCommand)
{
    CHAR            szBuf[MAX_PATH];
    CHAR            szMsg[MAX_PATH];
    BOOL            retValue;
    SC_HANDLE       hService, hSCM;
    SERVICE_STATUS  ss;
    int             retcode;
    DWORD dwStartTime = GetTickCount();

    hSCM = OpenSCManager("\\\\.", NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
	return FALSE;
    }

    hService = OpenService(hSCM, g_ServiceName,
			   SERVICE_QUERY_STATUS | SERVICE_START |
			   SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL);
    if (hService != NULL) {
	retValue = FALSE;
	SetCursor(g_hCursorHourglass);

	switch (dwCommand) {
	case SERVICE_CONTROL_STOP:
	  if (!ControlService(hService, SERVICE_CONTROL_STOP, &ss))
	    break;
	  
	  while (QueryServiceStatus(hService, &ss)) {
	    if ( ss.dwCurrentState == SERVICE_STOPPED ) {
	      retValue = TRUE;
	      break;
	    }

	    if ( GetTickCount() - dwStartTime > g_dwTimeout )
	      break;

	    Sleep( ss.dwWaitHint );
	  }
	  break;
	  
	case SERVICE_CONTROL_CONTINUE:
	    if (g_cold_start) {
		char           *svcargs[3] = { "-c" };
		retcode =
		    StartService(hService, 1, (LPCTSTR *) & svcargs);
	    } else
		retcode = StartService(hService, 0, NULL);

	    if (retcode) {
		while (QueryServiceStatus(hService, &ss)) {
		  if ( ss.dwCurrentState == SERVICE_RUNNING ) {
		    retValue = TRUE;
		    break;
		  }
	      
		  if ( GetTickCount() - dwStartTime > g_dwTimeout )
		    break;

		  Sleep( ss.dwWaitHint );
		}
	    }
	    break;
	default:
	  break;
	}
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCM);
	if (!retValue)
	    ErrorMessage("The requested operation has failed!");

	SetCursor(g_hCursorArrow);
	return retValue;
    } else {
	g_ServiceFound = FALSE;
    }
    CloseServiceHandle(hSCM);
    return FALSE;
}


BOOL
IsServiceRunning()
{
    HWND            hWnd;
    SC_HANDLE       hService;
    SC_HANDLE       hSCM;
    SERVICE_STATUS  ss;
    HKEY            hKey;
    DWORD           status, dwKeyType, dwsize = sizeof(status);
    

    hSCM = OpenSCManager("\\\\.", NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
	return FALSE;
    }

    hService = OpenService(hSCM, g_ServiceName,
			     SERVICE_QUERY_STATUS);
    if (hService != NULL) {
	if (QueryServiceStatus(hService, &ss))
	    g_dwPid = ss.dwCurrentState;
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCM);
	if (g_dwPid == SERVICE_RUNNING) {
	  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, g_i3ProxyKey, 0,
			   KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
	    RegQueryValueEx(hKey, "ProxyStatus", NULL,
			    &dwKeyType, (BYTE *) &g_i3ProxyStatus, &dwsize);
	    RegCloseKey(hKey);
	  }
	  return TRUE;
	} else
	  return FALSE;
    } else {
        g_ServiceFound = FALSE;
	CloseServiceHandle(hSCM);
	return FALSE;
    }
}

void
GetServiceStatus()
{
    CHAR            szKey[MAX_PATH];
    CHAR            svcPath[MAX_PATH];
    CHAR            szImagePath[MAX_PATH];
    CHAR            szBuf[MAX_PATH];
    HKEY            hKey,
                    hSubKey;
    DWORD           retCode,
                    rv,
                    dwKeyType;
    DWORD           dwBufLen = MAX_PATH;
    int             i;

    g_ServiceFound = FALSE;

    retCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\",
			   0, KEY_READ, &hKey);
    if (retCode != ERROR_SUCCESS) {
	ErrorMessage(NULL);
	return;
    }
    for (i = 0, retCode = ERROR_SUCCESS; retCode == ERROR_SUCCESS; i++) {
	retCode = RegEnumKey(hKey, i, svcPath, MAX_PATH);
	if (retCode == ERROR_SUCCESS) {
	    lstrcpy(szKey, "System\\CurrentControlSet\\Services\\");
	    lstrcat(szKey, svcPath);

	    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKey, 0,
			     KEY_QUERY_VALUE, &hSubKey) == ERROR_SUCCESS) {
		dwBufLen = MAX_PATH;
		rv = RegQueryValueEx(hSubKey, "ImagePath", NULL,
				     &dwKeyType, szImagePath, &dwBufLen);

		if (rv == ERROR_SUCCESS
		    && (dwKeyType == REG_SZ
			|| dwKeyType == REG_EXPAND_SZ) && dwBufLen) {
		    lstrcpy(szBuf, szImagePath);
		    CharLower(szBuf);
		    if (strstr(szBuf, "\\i3_client_proxy") != NULL) {
		      lstrcpy(g_i3ProxyKey, szKey);
		      g_ServiceName = strdup(svcPath);
		      g_ServiceFound = TRUE;
		      break;
		    }
		}
		RegCloseKey(hSubKey);
	    }
	}
    }
    RegCloseKey(hKey);
    if (g_ServiceFound)
	IsServiceRunning();

    return;
}

LRESULT         CALLBACK
WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (message == g_taskbarRestart) {
	/*
	 * restore the tray icon on shell restart 
	 */
	ShowNotifyIcon(hWnd, NIM_ADD);
	return DefWindowProc(hWnd, message, wParam, lParam);
    }
    switch (message) {
    case WM_CREATE:
	GetServiceStatus();
	ShowNotifyIcon(hWnd, NIM_ADD);
	SetTimer(hWnd, WM_TIMER_REFRESH, REFRESH_TIME, NULL);
	SetTimer(hWnd, WM_TIMER_RESCAN, RESCAN_TIME, NULL);
	break;

    case WM_TIMER:
	switch (wParam) {
	case WM_TIMER_RESCAN:
	    EnterCriticalSection(&g_mutex);
	    GetServiceStatus();
	    ShowNotifyIcon(hWnd, NIM_MODIFY);
	    LeaveCriticalSection(&g_mutex);
	    break;

	case WM_TIMER_REFRESH:
	    {
		EnterCriticalSection(&g_mutex);
		if (!g_ServiceFound) {
		    GetServiceStatus();
		    ShowNotifyIcon(hWnd, NIM_MODIFY);
		} else {
		    IsServiceRunning();
		    ShowNotifyIcon(hWnd, NIM_MODIFY);
		}
		LeaveCriticalSection(&g_mutex);
	    }
	    break;
	}
	break;

    case WM_QUIT:
	ShowNotifyIcon(hWnd, NIM_DELETE);
	PostQuitMessage(0);
	break;

    case WM_TRAYMESSAGE:
	switch (lParam) {
	case WM_LBUTTONUP:
	    ShowTryServiceMenu(hWnd);
	    break;

	case WM_RBUTTONUP:
	    ShowTryPopupMenu(hWnd);
	    break;
	}
	break;

    case WM_COMMAND:
	if ((LOWORD(wParam) & IDM_SM_START) == IDM_SM_START) {
	    i3ControlService(SERVICE_CONTROL_CONTINUE);
	    return TRUE;
	}
	if ((LOWORD(wParam) & IDM_SM_COLDSTART) == IDM_SM_COLDSTART) {
	    g_cold_start = TRUE;
	    i3ControlService(SERVICE_CONTROL_CONTINUE);
	    g_cold_start = FALSE;
	    return TRUE;
	} else if ((LOWORD(wParam) & IDM_SM_STOP) == IDM_SM_STOP) {
	    i3ControlService(SERVICE_CONTROL_STOP);
	    return TRUE;
	}
	switch (LOWORD(wParam)) {
	case IDC_SMANAGER:
	    ShellExecute(NULL, "open", "services.msc", "/s", NULL,
			 SW_NORMAL);
	    return TRUE;

	case IDM_EXIT:
	    ShowNotifyIcon(hWnd, NIM_DELETE);
	    PostQuitMessage(0);
	    return TRUE;
	}

    default:
	return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return FALSE;
}

HWND
CreateMainWindow(HINSTANCE hInstance)
{
    HWND            hWnd = NULL;
    WNDCLASSEX      wc;

    wc.cbSize = sizeof(WNDCLASSEX);

    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = (WNDPROC) WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon =
	(HICON) LoadImage(hInstance, MAKEINTRESOURCE(IDI_I3PROXYMON),
			  IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
    wc.hCursor = g_hCursorArrow;
    wc.hbrBackground = (HBRUSH) (COLOR_WINDOW + 1);
    wc.lpszMenuName = 0;
    wc.lpszClassName = g_WindowClass;
    wc.hIconSm =
	(HICON) LoadImage(hInstance, MAKEINTRESOURCE(IDI_I3PROXYMON),
			  IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);

    if (RegisterClassEx(&wc)) {
	hWnd = CreateWindow(g_WindowClass, g_szTitle,
			    0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);
    }
    return hWnd;

}


int             WINAPI
WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	LPSTR lpCmdLine, int nCmdShow)
{
    MSG             msg;
    HANDLE          hMutex;
    int             i;
    DWORD           d;

    g_szTitle = "i3 Proxy Monitor";
    g_WindowClass = "i3ProxyMonClass";

    g_iconStop = LoadImage(hInstance, MAKEINTRESOURCE(IDI_ICOSTOP),
			  IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    g_iconRun = LoadImage(hInstance, MAKEINTRESOURCE(IDI_ICORUN),
			 IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    g_iconNosrv = LoadImage(hInstance, MAKEINTRESOURCE(IDI_ICONOSRV),
			   IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    g_iconDisconnect = LoadImage(hInstance, MAKEINTRESOURCE(IDI_ICODISCONNECT),
				 IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    g_hCursorHourglass = LoadImage(NULL, MAKEINTRESOURCE(OCR_WAIT),
				   IMAGE_CURSOR, LR_DEFAULTSIZE,
				   LR_DEFAULTSIZE, LR_SHARED);
    g_hCursorArrow = LoadImage(NULL, MAKEINTRESOURCE(OCR_NORMAL),
			       IMAGE_CURSOR, LR_DEFAULTSIZE,
			       LR_DEFAULTSIZE, LR_SHARED);

    hMutex = CreateMutex(NULL, FALSE, "I3PRXMON_MUTEX");
    if ((hMutex == NULL) || (GetLastError() == ERROR_ALREADY_EXISTS)) {
	ErrorMessage("i3 proxy monitor is already started");
	if (hMutex) {
	    CloseHandle(hMutex);
	}
	return 0;
    }

    CoInitialize(NULL);
    InitCommonControls();
    g_hwndMain = CreateMainWindow(hInstance);
    g_taskbarRestart = RegisterWindowMessage("TaskbarCreated");
    InitializeCriticalSection(&g_mutex);
    if (g_hwndMain != NULL) {
	while (GetMessage(&msg, NULL, 0, 0) == TRUE) {
	    TranslateMessage(&msg);
	    DispatchMessage(&msg);
	}
    }
    DeleteCriticalSection(&g_mutex);
    CloseHandle(hMutex);
    DestroyCursor(g_hCursorHourglass);
    DestroyCursor(g_hCursorArrow);
    DestroyIcon(g_iconStop);
    DestroyIcon(g_iconRun);
    CoUninitialize();
    return 0;
}
