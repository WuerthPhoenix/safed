// NTService.cpp
//
// Implementation of CNTService

#include "NTServApp.h"
#include <stdio.h>
#include "NTService.h"
#include "LogUtils.h"
#include "Version.h"

// NOTE: FOR DFAT TESTING ONLY
//#define DEBUG_TO_FILE 1


// static variables

extern int USB_ENABLED;
extern char Hostname[];
extern void check_usb_enabled();
extern USBCache *USBMsg, *USBMsgHead, *USBMsgTail;
extern HANDLE hUSBMutex;
CNTService* CNTService::m_pThis = NULL;

CNTService::CNTService(const char* szServiceName)
{
    // copy the address of the current object so we can access it from
    // the static member callback functions. 
    // WARNING: This limits the application to only one CNTService object. 
    m_pThis = this;
    
    // Set the default service name and version
    strncpy_s(m_szServiceName, _countof(m_szServiceName), szServiceName, _TRUNCATE);
    m_iMajorVersion = 1;
    m_iMinorVersion = 0;
    m_hEventSource = NULL;

    // set up the initial service status 
    m_hServiceStatus = NULL;
    m_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    m_Status.dwCurrentState = SERVICE_STOPPED;
    m_Status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    m_Status.dwWin32ExitCode = 0;
    m_Status.dwServiceSpecificExitCode = 0;
    m_Status.dwCheckPoint = 0;
    m_Status.dwWaitHint = 0;
    m_bIsRunning = FALSE;
}

CNTService::~CNTService()
{
    LogExtOnlyDebugMsg(WARNING_LOG,"CNTService::~CNTService()");
    if (m_hEventSource) {
        ::DeregisterEventSource(m_hEventSource);
    }
}

////////////////////////////////////////////////////////////////////////////////////////
// Default command line argument parsing

// Returns TRUE if it found an arg it recognised, FALSE if not
// Note: processing some arguments causes output to stdout to be generated.
BOOL CNTService::ParseStandardArgs(int argc, char* argv[])
{
	DEBUGSET=0;
    // See if we have any command line args we recognise
    if (argc <= 1) return FALSE;

    if (_stricmp(argv[1], "-v") == 0) {

        // Spit out version info
        printf("%s Version %d.%d\n",
               m_szServiceName, m_iMajorVersion, m_iMinorVersion);
        printf("The service is %s installed\n",
               IsInstalled() ? "currently" : "not");
        return TRUE; // say we processed the argument

    } else if (_stricmp(argv[1], "-i") == 0) {

        // Request to install.
        if (IsInstalled()) {
            printf("%s is already installed\n", m_szServiceName);
        } else {
            // Try and install the copy that's running
            if (Install()) {
                printf("%s installed\n", m_szServiceName);
            } else {
                printf("%s failed to install. Error %d\n", m_szServiceName, GetLastError());
            }
        }
        return TRUE; // say we processed the argument

    } else if (_stricmp(argv[1], "-u") == 0) {

        // Request to uninstall.
        if (!IsInstalled()) {
            printf("%s is not installed\n", m_szServiceName);
        } else {
            // Try and remove the copy that's installed
            if (Uninstall()) {
                // Get the executable file path
                char szFilePath[_MAX_PATH];
                ::GetModuleFileName(NULL, szFilePath, _countof(szFilePath));
                printf("%s removed.\n",
                       m_szServiceName);
            } else {
                printf("Could not remove %s. Error %d\n", m_szServiceName, GetLastError());
            }
        }
        return TRUE; // say we processed the argument
    } else if (_strnicmp(argv[1], "-d", 2) == 0) {
		int l;
		//see if we are trying to set the debug level
		if ((l = atoi(&argv[1][2])) > 0) DEBUGSET = l;
		if (DEBUGSET < 0 || DEBUGSET > 9) DEBUGSET=9;
		setSAFEDDEBUG(this->DEBUGSET);
        return FALSE; // say we didn't processed the argument so that we still run the main loop
    }
    // Don't recognise the args
    return FALSE;
}

////////////////////////////////////////////////////////////////////////////////////////
// Install/uninstall routines

// Test if the service is currently installed
BOOL CNTService::IsInstalled()
{
    BOOL bResult = FALSE;

    // Open the Service Control Manager
    SC_HANDLE hSCM = ::OpenSCManager(NULL, // local machine
                                     NULL, // ServicesActive database
                                     SC_MANAGER_ALL_ACCESS); // full access
    if (hSCM) {

        // Try to open the service
        SC_HANDLE hService = ::OpenService(hSCM,
                                           m_szServiceName,
                                           SERVICE_QUERY_CONFIG);
        if (hService) {
            bResult = TRUE;
            ::CloseServiceHandle(hService);
        }

        ::CloseServiceHandle(hSCM);
    }
    
    return bResult;
}

BOOL CNTService::Install()
{

	// Open the Service Control Manager
    SC_HANDLE hSCM = ::OpenSCManager(NULL, // local machine
                                     NULL, // ServicesActive database
                                     SC_MANAGER_ALL_ACCESS); // full access
    if (!hSCM) return FALSE;

    // Get the executable file path
    char szFilePath[_MAX_PATH];
    ::GetModuleFileName(NULL, szFilePath, _countof(szFilePath));

    // Create the service
    SC_HANDLE hService = ::CreateService(hSCM,
                                         m_szServiceName,
                                         m_szServiceName,
                                         SERVICE_ALL_ACCESS,
										 SERVICE_WIN32_OWN_PROCESS,
                                         //SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS,
                                         SERVICE_AUTO_START,       
                                         SERVICE_ERROR_NORMAL,
                                         szFilePath,
                                         NULL,
                                         NULL,
                                         "\0\0",
                                         NULL,
                                         NULL);
    if (!hService) {
        ::CloseServiceHandle(hSCM);
        return FALSE;
    }

    // make registry entries to support logging messages
    // Add the source name as a subkey under the Application
    // key in the EventLog service portion of the registry.
    char szKey[256];
    HKEY hKey = NULL;
	_snprintf_s(szKey,_countof(szKey),_TRUNCATE,"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s",m_szServiceName);

    if (::RegCreateKey(HKEY_LOCAL_MACHINE, szKey, &hKey) != ERROR_SUCCESS) {
        ::CloseServiceHandle(hService);
        ::CloseServiceHandle(hSCM);
        return FALSE;
    }



    // Add the Event ID message-file name to the 'EventMessageFile' subkey.
    ::RegSetValueEx(hKey,
                    "EventMessageFile",
                    0,
                    REG_EXPAND_SZ, 
                    (CONST BYTE*)szFilePath,
                    (int)strlen(szFilePath) + 1);     


    // Set the supported types flags.
    DWORD dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    ::RegSetValueEx(hKey,
                    "TypesSupported",
                    0,
                    REG_DWORD,
                    (CONST BYTE*)&dwData,
                     sizeof(DWORD));

    ::RegCloseKey(hKey);

    LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_INSTALLED, m_szServiceName);

    // tidy up
    ::CloseServiceHandle(hService);
    ::CloseServiceHandle(hSCM);
    return TRUE;
}

BOOL CNTService::Uninstall()
{
    // Open the Service Control Manager
    SC_HANDLE hSCM = ::OpenSCManager(NULL, // local machine
                                     NULL, // ServicesActive database
                                     SC_MANAGER_ALL_ACCESS); // full access
    if (!hSCM) return FALSE;

    BOOL bResult = FALSE;
    SC_HANDLE hService = ::OpenService(hSCM,
                                       m_szServiceName,
                                       DELETE);
    if (hService) {
        if (::DeleteService(hService)) {
            LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_REMOVED, m_szServiceName);
            bResult = TRUE;
        } else {
            LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_NOTREMOVED, m_szServiceName);
        }
        ::CloseServiceHandle(hService);
    }
    
    ::CloseServiceHandle(hSCM);
    return bResult;
}

///////////////////////////////////////////////////////////////////////////////////////
// Logging functions

// This function makes an entry into the application event log
void CNTService::LogEvent(WORD wType, DWORD dwID,
                          const char* pszS1,
                          const char* pszS2,
                          const char* pszS3)
{
    const char* ps[3];
    ps[0] = pszS1;
    ps[1] = pszS2;
    ps[2] = pszS3;

    int iStr = 0;
    for (int i = 0; i < 3; i++) {
        if (ps[i] != NULL) iStr++;
    }
        
    // Check the event source has been registered and if
    // not then register it now
    if (!m_hEventSource) {
        m_hEventSource = ::RegisterEventSource(NULL,  // local machine
                                               m_szServiceName); // source name
    }

    if (m_hEventSource) {
        ::ReportEvent(m_hEventSource,
                      wType,
                      0,
                      dwID,
                      NULL, // sid
                      iStr,
                      0,
                      ps,
                      NULL);
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Service startup and registration

BOOL CNTService::StartService()
{
    SERVICE_TABLE_ENTRY st[] = {
        {m_szServiceName, ServiceMain},
        {NULL, NULL}
    };
#ifdef DEBUG_TO_FILE
	setSAFEDDEBUG(9);
#endif
	LogExtOnlyDebugMsg(ERROR_LOG,"[StartService] NetEye Safed Debug: %d", getSAFEDDEBUG());
    LogExtOnlyDebugMsg(WARNING_LOG,"Calling StartServiceCtrlDispatcher()");
    BOOL b = ::StartServiceCtrlDispatcher(st);
    LogExtOnlyDebugMsg(WARNING_LOG,"Returned from StartServiceCtrlDispatcher()");
    return b;
}

// static member function (callback)
void CNTService::ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
    // Get a pointer to the C++ object
    CNTService* pService = m_pThis;
    
    pService->DebugMsg("Entering CNTService::ServiceMain()");
    // Register the control request handler
    pService->m_Status.dwCurrentState = SERVICE_START_PENDING;
	//HandlerEx function not supported under NT4
	check_usb_enabled();
	if (IsNT5plus() && USB_ENABLED) pService->m_hServiceStatus = RegisterServiceCtrlHandlerEx(pService->m_szServiceName, (LPHANDLER_FUNCTION_EX)HandlerEx, 0);
	else pService->m_hServiceStatus = RegisterServiceCtrlHandler(pService->m_szServiceName, Handler);
    if (pService->m_hServiceStatus == NULL) {
        pService->LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_CTRLHANDLERNOTINSTALLED);
        return;
    }
	if (IsNT5plus() && USB_ENABLED) {
		DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;
		ZeroMemory( &NotificationFilter, sizeof(NotificationFilter) );
		NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
		NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
		pService->hDevNotify_size = sizeof(GUID_DEVINTERFACE_LIST)/sizeof(GUID) + 1;
		pService->hDevNotify = new HDEVNOTIFY[pService->hDevNotify_size];
		pService->hDevNotify[0] = RegisterDeviceNotification(pService->m_hServiceStatus, &NotificationFilter, DEVICE_NOTIFY_SERVICE_HANDLE | DEVICE_NOTIFY_ALL_INTERFACE_CLASSES);
		if( !pService->hDevNotify[0] ) {
			pService->DebugMsg("Can't register all device notifications: %d", GetLastError()); 
			// For the time being, this is not a detrimental event, at least not until it is better tested
			//return FALSE;
		}
		for(int i=0; i<sizeof(GUID_DEVINTERFACE_LIST)/sizeof(GUID); i++) {
			NotificationFilter.dbcc_classguid = GUID_DEVINTERFACE_LIST[i];
			pService->hDevNotify[i + 1] = RegisterDeviceNotification(pService->m_hServiceStatus, &NotificationFilter, DEVICE_NOTIFY_SERVICE_HANDLE);
			if( !pService->hDevNotify[i + 1] ) {
				pService->DebugMsg("Can't register device notification: %d", GetLastError()); 
				// For the time being, this is not a detrimental event, at least not until it is better tested
				//return FALSE;
			}
		}
	}
    // Start the initialisation
    if (pService->Initialize()) {

        // Do the real work. 
        // When the Run function returns, the service has stopped.
        pService->m_bIsRunning = TRUE;
        pService->m_Status.dwWin32ExitCode = 0;
        pService->m_Status.dwCheckPoint = 0;
        pService->m_Status.dwWaitHint = 0;
        pService->Run();
    }

    // Tell the service manager we are stopped
    pService->SetStatus(SERVICE_STOPPED);

    pService->DebugMsg("Leaving CNTService::ServiceMain()");
}

///////////////////////////////////////////////////////////////////////////////////////////
// status functions

void CNTService::SetStatus(DWORD dwState)
{
    LogExtOnlyDebugMsg(WARNING_LOG,"CNTService::SetStatus(%lu, %lu)",	m_hServiceStatus, dwState);
    m_Status.dwCurrentState = dwState;
    ::SetServiceStatus(m_hServiceStatus, &m_Status);
}

///////////////////////////////////////////////////////////////////////////////////////////
// Service initialization

BOOL CNTService::Initialize()
{
    LogExtOnlyDebugMsg(WARNING_LOG,"Entering CNTService::Initialize()");

    // Start the initialization
    SetStatus(SERVICE_START_PENDING);
    
    // Perform the actual initialization
    BOOL bResult = OnInit(); 
    
    // Set final state
    m_Status.dwWin32ExitCode = GetLastError();
    m_Status.dwCheckPoint = 0;
    m_Status.dwWaitHint = 0;
    if (!bResult) {
        LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_FAILEDINIT);
        SetStatus(SERVICE_STOPPED);
        return FALSE;    
    }
    
    LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_STARTED);
    SetStatus(SERVICE_RUNNING);

    LogExtOnlyDebugMsg(WARNING_LOG,"Leaving CNTService::Initialize()");
    return TRUE;
}

///////////////////////////////////////////////////////////////////////////////////////////////
// main function to do the real work of the service

// This function performs the main work of the service. 
// When this function returns the service has stopped.
void CNTService::Run()
{
    LogExtOnlyDebugMsg(WARNING_LOG,"Entering CNTService::Run()");

    while (m_bIsRunning) {
        // LogExtOnlyDebugMsg(WARNING_LOG,"Sleeping...");
        Sleep(5000);
    }

    // nothing more to do
    LogExtOnlyDebugMsg(WARNING_LOG,"Leaving CNTService::Run()");
}

//////////////////////////////////////////////////////////////////////////////////////
// Control request handlers

// static member function (callback) to handle commands from the
// service control manager
void WINAPI CNTService::Handler(DWORD dwOpcode)
{
    // Get a pointer to the object
    CNTService* pService = m_pThis;
    
    pService->DebugMsg("CNTService::Handler(%lu)", dwOpcode);
    switch (dwOpcode) {
    case SERVICE_CONTROL_STOP: // 1
        pService->SetStatus(SERVICE_STOP_PENDING);
        pService->OnStop();
        pService->m_bIsRunning = FALSE;
        pService->LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_STOPPED);
		pService->SetStatus(SERVICE_STOPPED);
        break;

    case SERVICE_CONTROL_PAUSE: // 2
        pService->OnSignal();
		pService->OnPause();
        break;

    case SERVICE_CONTROL_CONTINUE: // 3
        pService->OnSignal();
		pService->OnContinue();
        break;

    case SERVICE_CONTROL_INTERROGATE: // 4
        pService->OnInterrogate();
		pService->OnSignal();
        break;

    case SERVICE_CONTROL_SHUTDOWN: // 5
		pService->DebugMsg("CNTService::Handler - Calling Shutdown");
        pService->SetStatus(SERVICE_STOP_PENDING);
        pService->OnShutdown();
        pService->m_bIsRunning = FALSE;
        pService->LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_STOPPED);
		pService->SetStatus(SERVICE_STOPPED);
		pService->m_bIsRunning = FALSE;
        break;

    default:
		pService->OnSignal();
        if (dwOpcode >= SERVICE_CONTROL_USER) {
            if (!pService->OnUserControl(dwOpcode)) {
                pService->LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_BADREQUEST);
            }
        } else {
            pService->LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_BADREQUEST);
        }
        break;
    }

    // Report current status
    pService->DebugMsg("Updating status (%lu, %lu)",
                       pService->m_hServiceStatus,
                       pService->m_Status.dwCurrentState);
    ::SetServiceStatus(pService->m_hServiceStatus, &pService->m_Status);
}

DWORD WINAPI CNTService::HandlerEx(DWORD dwOpcode, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    // Get a pointer to the object
    CNTService* pService = m_pThis;
	PDEV_BROADCAST_HDR pHdr;
    
    pService->DebugMsg("CNTService::HandlerEx(%lu, %lu, -, -)", dwOpcode, dwEventType);
    switch (dwOpcode) {
    case SERVICE_CONTROL_STOP: // 1
		pService->DebugMsg("CNTService::HandlerEx - Calling Stop");
		for(int i=0; i<pService->hDevNotify_size; i++) {
			if (!UnregisterDeviceNotification(pService->hDevNotify[i])) {
				pService->DebugMsg("UnregisterDeviceNotification failed: %d", GetLastError());
			}
		}
        pService->SetStatus(SERVICE_STOP_PENDING);
        pService->OnStop();
        pService->m_bIsRunning = FALSE;
        pService->LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_STOPPED);
		pService->SetStatus(SERVICE_STOPPED);
        break;

    case SERVICE_CONTROL_PAUSE: // 2
        pService->OnSignal();
		pService->OnPause();
        break;

    case SERVICE_CONTROL_CONTINUE: // 3
		pService->OnSignal();
		pService->OnContinue();
        break;

    case SERVICE_CONTROL_INTERROGATE: // 4
		pService->OnInterrogate();
		pService->OnSignal();
        break;

    case SERVICE_CONTROL_SHUTDOWN: // 5
		pService->DebugMsg("CNTService::HandlerEx - Calling Shutdown");
		for(int i=0; i<pService->hDevNotify_size; i++) {
			if (!UnregisterDeviceNotification(pService->hDevNotify[i])) {
				pService->DebugMsg("UnregisterDeviceNotification failed: %d", GetLastError());
			}
		}
        pService->SetStatus(SERVICE_STOP_PENDING);
        pService->OnShutdown();
        pService->m_bIsRunning = FALSE;
        pService->LogEvent(EVENTLOG_INFORMATION_TYPE, EVMSG_STOPPED);
		pService->SetStatus(SERVICE_STOPPED);
		pService->m_bIsRunning = FALSE;
        break;

	case SERVICE_CONTROL_DEVICEEVENT: // B
		pService->DebugMsg("CNTService::HandlerEx - DEVICEEVENT");
		::SetServiceStatus(pService->m_hServiceStatus, &pService->m_Status);
		pHdr = (PDEV_BROADCAST_HDR)lpEventData;
		PDEV_BROADCAST_DEVICEINTERFACE pDevInf;
		PDEV_BROADCAST_HANDLE pDevHnd;
		PDEV_BROADCAST_OEM pDevOem;
		PDEV_BROADCAST_PORT pDevPort;
		PDEV_BROADCAST_VOLUME pDevVolume;
		char dev_name[512];
		memset(dev_name,0,512);

		switch( pHdr->dbch_devicetype ) {
			case DBT_DEVTYP_DEVICEINTERFACE:
				pDevInf = (PDEV_BROADCAST_DEVICEINTERFACE)pHdr;
				pService->FriendlyName(pDevInf, dwEventType, dev_name, _countof(dev_name));
				switch (dwEventType) {
					case DBT_DEVICEARRIVAL:
						pService->OnDeviceArrive(dev_name);
						break;
					case DBT_DEVICEREMOVECOMPLETE:
						pService->OnDeviceRemove(dev_name);
						break;
					default:
						break;
				};
				break;

			case DBT_DEVTYP_HANDLE:
				pDevHnd = (PDEV_BROADCAST_HANDLE)pHdr;
				pService->DebugMsg("DBT_DEVTYP_HANDLE");
				break;

			case DBT_DEVTYP_OEM:
				pDevOem = (PDEV_BROADCAST_OEM)pHdr;
				pService->DebugMsg("DBT_DEVTYP_OEM");
				break;

			case DBT_DEVTYP_PORT:
				pDevPort = (PDEV_BROADCAST_PORT)pHdr;
				pService->DebugMsg("DBT_DEVTYP_PORT");
				break;

			case DBT_DEVTYP_VOLUME:
				pDevVolume = (PDEV_BROADCAST_VOLUME)pHdr;
				pService->DebugMsg("DBT_DEVTYP_VOLUME");
				break;
		};
		break;

    default:
		pService->OnSignal();
        if (dwOpcode >= SERVICE_CONTROL_USER) {
            if (!pService->OnUserControl(dwOpcode)) {
                pService->LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_BADREQUEST);
            }
        } else {
            pService->LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_BADREQUEST);
        }
        break;
    }

    // Report current status
    pService->DebugMsg("Updating status (%lu, %lu)",
                       pService->m_hServiceStatus,
                       pService->m_Status.dwCurrentState);
    ::SetServiceStatus(pService->m_hServiceStatus, &pService->m_Status);
	return NO_ERROR;
}

// Called when the service is first initialized
BOOL CNTService::OnInit()
{
    LogExtOnlyDebugMsg(WARNING_LOG,"CNTService::OnInit()");
	return TRUE;
}

// Called when the service control manager wants to stop the service
void CNTService::OnStop()
{
    LogExtOnlyDebugMsg(WARNING_LOG,"CNTService::OnStop()");
}

// called when the service is interrogated
void CNTService::OnInterrogate()
{
    LogExtOnlyDebugMsg(WARNING_LOG,"CNTService::OnInterrogate()");
}

// called when the service is paused
void CNTService::OnPause()
{
    LogExtOnlyDebugMsg(WARNING_LOG,"CNTService::OnPause()");
}

// called when the service is continued
void CNTService::OnContinue()
{
    LogExtOnlyDebugMsg(WARNING_LOG,"CNTService::OnContinue()");
}

// called when the service is shut down
void CNTService::OnShutdown()
{
    LogExtOnlyDebugMsg(WARNING_LOG,"CNTService::OnShutdown()");
}

// called for any other service signal
void CNTService::OnSignal()
{
    LogExtOnlyDebugMsg(WARNING_LOG,"CNTService::OnSignal()");
}

// called when the service gets a user control message
BOOL CNTService::OnUserControl(DWORD dwOpcode)
{
    LogExtOnlyDebugMsg(WARNING_LOG,"CNTService::OnUserControl(%8.8lXH)", dwOpcode);
    return FALSE; // say not handled
}

void CNTService::FriendlyName (PDEV_BROADCAST_DEVICEINTERFACE pDevInf, DWORD dwEventType, char *dev_name, int size) {
	char dev_id[512];
	char dev_class[64];
	char rep = '\0', *temp;
	int i, found=0;
	DWORD dwFlag;
	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA spDevInfoData;

	WideCharToMultiByte( CP_ACP, 0,(WCHAR *)pDevInf->dbcc_name+4,-1, dev_id, 511, NULL, NULL );
	LogExtOnlyDebugMsg(WARNING_LOG,"PRE dev name: %s", dev_id);
	i=strlen(dev_id) - 1;

	while (dev_id[i] && i >= 0) {
		if (dev_id[i] == '#') {
			dev_id[i] = rep;
			rep = '\\';
		} else {
			dev_id[i] = toupper(dev_id[i]);
		}
		i--;
	}
	strncpy_s(dev_class,_countof(dev_class),dev_id,_TRUNCATE);
	temp = strstr(dev_class,"\\");
	if (temp) *temp = '\0';
	LogExtOnlyDebugMsg(WARNING_LOG,"dev ID: %s", dev_id);
	LogExtOnlyDebugMsg(WARNING_LOG,"dev class: %s", dev_class);

	if (DBT_DEVICEARRIVAL != dwEventType) dwFlag = DIGCF_ALLCLASSES;
	else dwFlag = (DIGCF_ALLCLASSES | DIGCF_PRESENT);
	hDevInfo = SetupDiGetClassDevs(NULL,dev_class,NULL,dwFlag);
	if( INVALID_HANDLE_VALUE == hDevInfo ) {
		LogExtOnlyDebugMsg(WARNING_LOG,"Error grabbing class information");
		_snprintf_s(dev_name,size,_TRUNCATE,"Unknown class: %s",dev_id);
		return;
	}

	//pService->DebugMsg("FindDevice()");
	spDevInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	for(int i=0; SetupDiEnumDeviceInfo(hDevInfo, i, &spDevInfoData); i++) {
		DWORD nSize=0 ;
		TCHAR buf[MAX_PATH];

		if ( !SetupDiGetDeviceInstanceId(hDevInfo, &spDevInfoData, buf, _countof(buf), &nSize) ) {
			LogExtOnlyDebugMsg(WARNING_LOG,"Error in SetupDiGetDeviceInstanceId(): %d", GetLastError());
			_snprintf_s(dev_name,size,_TRUNCATE,"Unknown instance: %s",dev_id);
			break;
		}
		LogExtOnlyDebugMsg(DEBUG_LOG,"Found device: %s || %s",buf,dev_id);
		if ( !strncmp(dev_id, buf, _countof(dev_id)) ) {
			// OK, device found
			found = 1;
			break;
		}
	}

	if (found) {
		// OK, device found
		LogExtOnlyDebugMsg(WARNING_LOG,"Device match found!!");
		DWORD DataT;
		TCHAR buf[MAX_PATH];
		DWORD nSize = 0;
		strncpy_s(dev_name,size,"",_TRUNCATE);

		// get Friendly Name or Device Description
		if ( SetupDiGetDeviceRegistryProperty(hDevInfo, &spDevInfoData, 
			SPDRP_FRIENDLYNAME, &DataT, (PBYTE)buf, _countof(buf), &nSize) ) {
			LogExtOnlyDebugMsg(WARNING_LOG,"Friendly name: %s", buf);
			_snprintf_s(dev_name,size,_TRUNCATE,"%s ", buf);
		}
		if ( SetupDiGetDeviceRegistryProperty(hDevInfo, &spDevInfoData, 
			SPDRP_DEVICEDESC, &DataT, (PBYTE)buf, _countof(buf), &nSize) ) {
			LogExtOnlyDebugMsg(WARNING_LOG,"Description: %s", buf);
			_snprintf_s(dev_name,size,_TRUNCATE,"%s(%s)", dev_name, buf);
		}
		if (!strlen(dev_name)) _snprintf_s(dev_name, size,_TRUNCATE, "No details available: %s", dev_id);
	}
	SetupDiDestroyDeviceInfoList(hDevInfo);
}
// called when a device arrives
void CNTService::OnDeviceArrive(char *msg)
{
	struct tm ptmTime;
	time_t ttime;
	errno_t err;
	DWORD usbwait;
	LogExtOnlyDebugMsg(WARNING_LOG,"CNTService::OnDeviceArrive(%s)", msg);
	USBMsg = (USBCache *)malloc(sizeof(USBCache));
	if (USBMsg) {
		memset(USBMsg,0,sizeof(USBCache));
		ttime=time(NULL);
		err=localtime_s(&ptmTime,&ttime);
		if (err) {
			LogExtOnlyDebugMsg(INFORMATION_LOG,"USB: localtime_s error");
			free(USBMsg);
			return;
		}
		
		strftime(USBMsg->SubmitTime, _countof(USBMsg->SubmitTime),"%a %b %d %H:%M:%S %Y", &ptmTime);
		_snprintf_s(USBMsg->szTempString,_countof(USBMsg->szTempString),_TRUNCATE,"Received a device interface ARRIVAL notification for device: %s", msg);
		USBMsg->ShortEventID=USB_ARRIVAL;
		USBMsg->next = NULL;

		usbwait = WaitForSingleObject(hUSBMutex,500);
		if(usbwait == WAIT_OBJECT_0) {
			if (USBMsgTail) {
				USBMsgTail->next = USBMsg;
			}
			USBMsgTail = USBMsg;
			if (!USBMsgHead) {
				LogExtOnlyDebugMsg(INFORMATION_LOG,"USB: Creating head pointer", msg);
				USBMsgHead = USBMsg;
			}
			LogExtOnlyDebugMsg(INFORMATION_LOG,"USB: Message added and waiting", msg);
		} else if(usbwait == WAIT_ABANDONED) {
			LogExtOnlyDebugMsg(WARNING_LOG,"Found abandoned mutex, releasing");
			ReleaseMutex(hUSBMutex);
		} else {
			LogExtOnlyDebugMsg(WARNING_LOG,"Failed to create USB notification message");
			free(USBMsg);
		}
		if (!ReleaseMutex(hUSBMutex)) {
			LogExtOnlyDebugMsg(WARNING_LOG,"Failed to release mutex (arrival): [%d]",GetLastError());
		}
	} else {
			LogExtOnlyDebugMsg(WARNING_LOG,"Failed to alloate USB notification message");
	}
}

// called when a device is removed
void CNTService::OnDeviceRemove(char *msg)
{
	struct tm ptmTime;
	time_t ttime;
	errno_t err;
	DWORD usbwait;
    LogExtOnlyDebugMsg(WARNING_LOG,"CNTService::OnDeviceRemove(%s)", msg);
	USBMsg = (USBCache *)malloc(sizeof(USBCache));
	if (USBMsg) {
		memset(USBMsg,0,sizeof(USBCache));
		ttime=time(NULL);
		err=localtime_s(&ptmTime, &ttime);
		if (err) {
			LogExtOnlyDebugMsg(INFORMATION_LOG,"USB: localtime_s error");
			free(USBMsg);
			return;
		}
		strftime(USBMsg->SubmitTime, _countof(USBMsg->SubmitTime),"%a %b %d %H:%M:%S %Y", &ptmTime);
		_snprintf_s(USBMsg->szTempString,_countof(USBMsg->szTempString),_TRUNCATE,"Received a device interface REMOVAL notification for device: %s", msg);
		USBMsg->ShortEventID=USB_REMOVAL;
		USBMsg->next = NULL;

		usbwait = WaitForSingleObject(hUSBMutex,500);
		if(usbwait == WAIT_OBJECT_0) {
			if (USBMsgTail) {
				USBMsgTail->next = USBMsg;
			}
			USBMsgTail = USBMsg;
			if (!USBMsgHead) {
				LogExtOnlyDebugMsg(INFORMATION_LOG,"USB: Creating head pointer", msg);
				USBMsgHead = USBMsg;
			}
			LogExtOnlyDebugMsg(INFORMATION_LOG,"USB: Message added and waiting", msg);
		} else if(usbwait == WAIT_ABANDONED) {
			LogExtOnlyDebugMsg(WARNING_LOG,"Found abandoned mutex, releasing");
			ReleaseMutex(hUSBMutex);
		} else {
			free(USBMsg);
			LogExtOnlyDebugMsg(WARNING_LOG,"Failed to create USB notification message");
		}
		if (!ReleaseMutex(hUSBMutex)) {
			LogExtOnlyDebugMsg(WARNING_LOG,"Failed to release mutex (removal): [%d]",GetLastError());
		}
	} else {
			LogExtOnlyDebugMsg(WARNING_LOG,"Failed to alloate USB notification message");
	}
}
////////////////////////////////////////////////////////////////////////////////////////////
// Debugging support

void CNTService::DebugMsg(const char* pszFormat, ...){
	EXPANDINPUT;
	LogMsg(2,TRUE, buf);
}

