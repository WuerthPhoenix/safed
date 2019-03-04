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
	static DWORD WINAPI HandlerEx(DWORD dwOpcode, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);
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

static const GUID GUID_DEVINTERFACE_LIST[] = 
{
	// GUID_DEVINTERFACE_USB_DEVICE
	{ 0xA5DCBF10, 0x6530, 0x11D2, { 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED } },

	// GUID_DEVINTERFACE_DISK
	{ 0x53f56307, 0xb6bf, 0x11d0, { 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b } },

	// GUID_DEVINTERFACE_HID, 
	{ 0x4D1E55B2, 0xF16F, 0x11CF, { 0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30 } },
			 
	// GUID_NDIS_LAN_CLASS
	{ 0xad498944, 0x762f, 0x11d0, { 0x8d, 0xcb, 0x00, 0xc0, 0x4f, 0xc3, 0x35, 0x8c } }
	
	//// GUID_DEVINTERFACE_COMPORT
	//{ 0x86e0d1e0, 0x8089, 0x11d0, { 0x9c, 0xe4, 0x08, 0x00, 0x3e, 0x30, 0x1f, 0x73 } },

	//// GUID_DEVINTERFACE_SERENUM_BUS_ENUMERATOR
	//{ 0x4D36E978, 0xE325, 0x11CE, { 0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18 } },

	//// GUID_DEVINTERFACE_PARALLEL
	//{ 0x97F76EF0, 0xF883, 0x11D0, { 0xAF, 0x1F, 0x00, 0x00, 0xF8, 0x00, 0x84, 0x5C } },

	//// GUID_DEVINTERFACE_PARCLASS
	//{ 0x811FC6A5, 0xF728, 0x11D0, { 0xA5, 0x37, 0x00, 0x00, 0xF8, 0x75, 0x3E, 0xD1 } }
};
#endif // _NTSERVICE_H_
