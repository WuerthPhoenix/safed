// ntservice.h
//
// Definitions for CNTService
//

#ifndef _NTSERVICE_H_
#define _NTSERVICE_H_

#include "ntservmsg.h" // Event message ids
#include <winsvc.h>
#include <setupapi.h>
#include <Dbt.h>
#include "support.h"
#include <time.h>
#include <string>

using namespace std;

#define SERVICE_CONTROL_USER 128
#define DEVICE_NOTIFY_ALL_INTERFACE_CLASSES  0x00000004


class CNTService
{
public:
    CNTService(const char* szServiceName);
    virtual ~CNTService();
    BOOL ParseStandardArgs(int argc, char* argv[]);
    BOOL IsInstalled();
    BOOL Install();
    BOOL Uninstall();
    BOOL ModifyVistaDefaultAuditing(string dir,int remove);
    void LogEvent(WORD wType, DWORD dwID,
                  const char* pszS1 = NULL,
                  const char* pszS2 = NULL,
                  const char* pszS3 = NULL);
    BOOL StartService();
    void SetStatus(DWORD dwState);
    BOOL Initialize();
    virtual void Run();
	virtual BOOL OnInit();
    virtual void OnStop();
    virtual void OnInterrogate();
    virtual void OnPause();
    virtual void OnContinue();
    virtual void OnShutdown();
	virtual void OnSignal();
	void OnDeviceArrive(char *msg);
	void OnDeviceRemove(char *msg);
	void FriendlyName (PDEV_BROADCAST_DEVICEINTERFACE pDevInf, DWORD dwEventType, char *dev_name, int size);

    virtual BOOL OnUserControl(DWORD dwOpcode);
    void DebugMsg(const char* pszFormat, ...);
    
    // static member functions
    static void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv);
	static void WINAPI Handler(DWORD dwOpcode);
    // data members
    char m_szServiceName[64];
    int m_iMajorVersion;
    int m_iMinorVersion;
    SERVICE_STATUS_HANDLE m_hServiceStatus;
    SERVICE_STATUS m_Status;
    BOOL m_bIsRunning;
	HDEVNOTIFY *hDevNotify;
	int hDevNotify_size;

	int DEBUGSET;

    // static data
    static CNTService* m_pThis; // nasty hack to get object ptr

private:
    HANDLE m_hEventSource;

};

#endif // _NTSERVICE_H_
