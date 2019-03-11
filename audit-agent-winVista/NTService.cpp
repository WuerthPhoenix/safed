// NTService.cpp
//
// Implementation of CNTService

#include "NTServApp.h"
#include <stdio.h>
#include "NTService.h"
#include "LogUtils.h"
#include "Version.h"
#include <aclapi.h>

// NOTE: FOR DFAT TESTING ONLY
//#define DEBUG_TO_FILE 1


// static variables
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
    } else if (_stricmp(argv[1], "-s") == 0) {
		ModifyVistaDefaultAuditing("C:\\Windows",1);
		return TRUE;
	} else if (_stricmp(argv[1], "-r") == 0) {
		ModifyVistaDefaultAuditing("C:\\Windows",0);
		return TRUE;
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

BOOL CNTService::ModifyVistaDefaultAuditing(string dir, int remove)
{
	PSECURITY_DESCRIPTOR pSD = NULL;
	HANDLE hToken;
	PACL mySacl=NULL;
	DWORD ret=0;

	TOKEN_PRIVILEGES tp;
	LUID luid;

	if ( !LookupPrivilegeValue(NULL,SE_SECURITY_NAME,&luid)) {
		printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
		return FALSE; 
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Enable the privilege or disable all privileges.
	OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	if ( !AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL)) { 
		  printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
		  return FALSE; 
	} 

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		  printf("The token does not have the specified privilege. \n");
		  return FALSE;
	} 

	//recurse through the dir
	WIN32_FIND_DATA findData;
	char Match[32], Replace[32];
	if (remove){
		strncpy_s(Match,_countof(Match),"Everyone",_TRUNCATE);
		strncpy_s(Replace,_countof(Replace),"ANONYMOUS LOGON",_TRUNCATE);
	} else {
		strncpy_s(Match,_countof(Match),"ANONYMOUS LOGON",_TRUNCATE);
		strncpy_s(Replace,_countof(Replace),"Everyone",_TRUNCATE);
	}

	HANDLE hFind=FindFirstFile((dir+"\\*.*").c_str(), &findData);

	if (hFind == INVALID_HANDLE_VALUE) {
		return TRUE;
	}

	// iterate over file names in directory
	do {
		string sFileName(findData.cFileName);

		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			// Directory
			if (sFileName != "." && sFileName != "..") {
				// descent recursively
				if (!ModifyVistaDefaultAuditing(dir+"\\"+sFileName, remove)) return FALSE;
			}
		} else {
			// File
			// grab and modify the file SACL
			ret = GetNamedSecurityInfo((char *)(dir+"\\"+findData.cFileName).c_str(),SE_FILE_OBJECT,SACL_SECURITY_INFORMATION,NULL,NULL,NULL,&mySacl,&pSD);
			if (ret == ERROR_SUCCESS && mySacl != NULL && mySacl->AceCount > 0) {
				int SetNewAcl=0;
				PACL pNewAcl;
				ACL_SIZE_INFORMATION aclSizeInfo;
				ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
				aclSizeInfo.AclBytesInUse = sizeof(ACL);
				
				if (!GetAclInformation(mySacl,(LPVOID)&aclSizeInfo,sizeof(ACL_SIZE_INFORMATION),AclSizeInformation)) {
					printf("Can't find ACL info, exiting\n");
					return FALSE;
				}
				pNewAcl = (PACL)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,aclSizeInfo.AclBytesInUse);
				if (!pNewAcl) {
					printf("Can't allocate new ACL, exiting\n");
					return FALSE;
				}
				if (!InitializeAcl(pNewAcl,aclSizeInfo.AclBytesInUse,ACL_REVISION)) {
					printf("Can't allocate new ACL, exiting\n");
					return FALSE;
				}
				//printf("Checking: %s[%d]\n",(char *)(dir+"\\"+findData.cFileName).c_str(),mySacl->AceCount);
				for (int i=0; i< mySacl->AceCount; i++) {
					PVOID pAce;//PACE_HEADER?
					SID *pAceSid, *pNewAceSid=NULL;
					DWORD dwCbName = 0;
					DWORD dwCbDomainName = 0;
					SID_NAME_USE SidNameUse;
					TCHAR bufName[MAX_PATH]="";
					TCHAR bufDomain[MAX_PATH]="";
					ACCESS_MASK mask;
					SYSTEM_AUDIT_ACE *SA_Ace;
					TCHAR bufNewDomain[MAX_PATH];
					DWORD dwNewCbDomainName = 0;
					DWORD dwSidSize = 0;
					dwNewCbDomainName = _countof(bufNewDomain);
					BOOL bSuccess;
					
					if (GetAce(mySacl,i,&pAce)) {
						if (((ACE_HEADER *)pAce)->AceType != SYSTEM_AUDIT_ACE_TYPE) {
							printf("ACE ERROR: not SYSTEM_AUDIT_ACE_TYPE\n");
							continue;
						}
						SA_Ace = (SYSTEM_AUDIT_ACE *)pAce;
						pAceSid = (SID *)(&SA_Ace->SidStart);
						mask = SA_Ace->Mask;
						dwCbName = _countof(bufName);
						dwCbDomainName = _countof(bufDomain);

						bSuccess = LookupAccountSid(NULL, pAceSid, bufName, &dwCbName, bufDomain, &dwCbDomainName, &SidNameUse);
						if (!bSuccess) {
							printf("Failed to grab SID [%d]", GetLastError());
							return FALSE;
						}
						//printf("ACE of %s\\%s: %d\n", bufDomain, bufName, mask);
						if (!strcmp(bufName,Match)) {
							bSuccess = LookupAccountName(NULL, Replace, NULL, &dwSidSize, bufNewDomain, &dwNewCbDomainName,&SidNameUse);
							if (!bSuccess && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
								pNewAceSid = (SID *)malloc(dwSidSize);
								if (!pNewAceSid) {
									printf("memory failed\n");
									if (pNewAcl) HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);
									return FALSE;
								}
								bSuccess = LookupAccountName(NULL, Replace, pNewAceSid, &dwSidSize, bufNewDomain, &dwNewCbDomainName,&SidNameUse);
								if (bSuccess) {
									if (!AddAuditAccessAce(pNewAcl,ACL_REVISION,mask,pNewAceSid,TRUE,TRUE)) {
										printf("Failed to updated ACL[%d]\n",GetLastError());
										free(pNewAceSid);
										if (pNewAcl) HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);
										return FALSE;
									}
									SetNewAcl=1;
								} else {
									printf("FAILED: %d\n", GetLastError());
									//printf("\n");
								}
								free(pNewAceSid);
							} else {
								printf("FAILED to find %s\n",Replace);
							}
						} else {
							if (!AddAce(pNewAcl,ACL_REVISION,MAXDWORD,pAce,((PACE_HEADER)pAce)->AceSize)) {
								printf("Couldn't add ACE to acl [%d]\n",GetLastError());
								if (pNewAcl) HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);
								return FALSE;
							}
						}
					} else {
						printf("ACE error %d:%d[%d]\n",mySacl->AceCount,i,GetLastError());
						return FALSE;
					}
				}
				if (SetNewAcl && pNewAcl) {
					ret = SetNamedSecurityInfo((char *)(dir+"\\"+findData.cFileName).c_str(),SE_FILE_OBJECT,SACL_SECURITY_INFORMATION,NULL,NULL,NULL,pNewAcl);
					if (ret == ERROR_SUCCESS) {
						printf("Fixed: %s\n",(char *)(dir+"\\"+findData.cFileName).c_str());
					} else {
						printf("Failed to fix: %s\n",(char *)(dir+"\\"+findData.cFileName).c_str());
					}
				}
				if (pNewAcl) HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);
			} else {
				if (ret) printf("fail %d %s\n", ret,(char *)(dir+"\\"+findData.cFileName).c_str());
				//else printf("NO SACL: %s\n",(char *)(dir+"\\"+findData.cFileName).c_str());
			}
			if (pSD) LocalFree(pSD);
		}
	} while (FindNextFile(hFind, &findData));
	return TRUE;
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
	setSAFEDDEBUG(4);
#endif
	DebugMsg("[StartService] NetEye Safed Debug: %d", getSAFEDDEBUG());
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
	pService->m_hServiceStatus = RegisterServiceCtrlHandler(pService->m_szServiceName, Handler);
    if (pService->m_hServiceStatus == NULL) {
        pService->LogEvent(EVENTLOG_ERROR_TYPE, EVMSG_CTRLHANDLERNOTINSTALLED);
        return;
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

////////////////////////////////////////////////////////////////////////////////////////////
// Debugging support


void CNTService::DebugMsg(const char* pszFormat, ...){
	EXPANDINPUT;
	//LogMsg(2,TRUE, buf);
	LogMsg(2,FALSE, buf);
}

