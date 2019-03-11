#include "SafedWMIUSB.h"
#include "LogUtils.h"
#include <time.h>
#include "Safed.h"


// WMI x USB

IEnumWbemClassObject* pEnumerator;
IWbemClassObject *pclsObj = NULL;
IWbemClassObject *pclsObjTI = NULL;
IWbemServices *pSvc = NULL;
IWbemLocator *pLoc = NULL;

ThreadStruct	w_g_Info;
extern char			Hostname[100];
//shared event queue
extern HANDLE hMutex;
extern MsgCache *EventHead;
extern MsgCache *EventTail;
extern MsgCache *EventCurrent;
extern int EventCount;


std::string format_error(unsigned __int32 hr)
{
  std::stringstream ss;
  ss << std::hex << hr;
  return ss.str();
}

//http://www.codeproject.com/Articles/10539/Making-WMI-Queries-In-C?display=Print
//http://msdn.microsoft.com/en-us/library/aa390424(v=vs.85).aspx
//http://msdn.microsoft.com/en-us/library/aa390425%28v=VS.85%29.aspx
//"select * from __InstanceOperationEvent within 1 where TargetInstance ISA \'Win32_PnPEntity\' and TargetInstance.Description=\'USB Mass Storage Device\'"
int InitWMI(char* WMIcondition )
{

    HRESULT hres;

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hres))
    {
		LogExtMsg(ERROR_LOG,"WMIUSB> Failed to initialize COM library. Error code = 0x%x", format_error(hres));
        return 0;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    hres =  CoInitializeSecurity(
        NULL, 
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
        );

                      
    if (FAILED(hres))
    {
		LogExtMsg(ERROR_LOG,"WMIUSB> Failed to initialize security. Error code = 0x%x", format_error(hres));
        CoUninitialize();
        return 0;                    // Program has failed.
    }
    
    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator *pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,             
        0, 
        CLSCTX_INPROC_SERVER, 
        IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres))
    {
 		LogExtMsg(ERROR_LOG,"WMIUSB> Failed to create IWbemLocator object. Error code = 0x%x", format_error(hres));
        CoUninitialize();
        return 0;                 // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices *pSvc = NULL;
 
    // Connect to the root\cimv2 namespace with
    // the current user and obtain pointer pSvc
    // to make IWbemServices calls.
    hres = pLoc->ConnectServer(
         _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
         NULL,                    // User name. NULL = current user
         NULL,                    // User password. NULL = current
         0,                       // Locale. NULL indicates current
         NULL,                    // Security flags.
         0,                       // Authority (for example, Kerberos)
         0,                       // Context object 
         &pSvc                    // pointer to IWbemServices proxy
         );
    
    if (FAILED(hres))
    {
 		LogExtMsg(ERROR_LOG,"WMIUSB> Could not connec. Error code = 0x%x", format_error(hres));
        pLoc->Release();     
        CoUninitialize();
        return 0;                // Program has failed.
    }

 	LogExtMsg(INFORMATION_LOG,"WMIUSB> Connected to ROOT\\CIMV2 WMI namespace.");


    // Step 5: --------------------------------------------------
    // Set security levels on the proxy -------------------------

    hres = CoSetProxyBlanket(
       pSvc,                        // Indicates the proxy to set
       RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
       RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
       NULL,                        // Server principal name 
       RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
       RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
       NULL,                        // client identity
       EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
		LogExtMsg(ERROR_LOG,"WMIUSB> Could not set proxy blanket. Error code = 0x%x", format_error(hres));
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        return 0;               // Program has failed.
    }

	    // Step 6: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----

    // For example, get the name of the operating system
	char WMIQuery[1024] = "select * from __InstanceOperationEvent within 1 where TargetInstance ISA \'Win32_PnPEntity\' ";
	if(WMIcondition){
		strncat_s(WMIQuery,_countof(WMIQuery),WMIcondition,_TRUNCATE);
		//WMIcondition  - "and TargetInstance.Description=\'USB Mass Storage Device\'"
	}
 
    hres = pSvc->ExecNotificationQuery(
        bstr_t("WQL"), 
        //bstr_t("select * from __InstanceOperationEvent within 1 where TargetInstance ISA \'Win32_PnPEntity\' and TargetInstance.Description=\'USB Mass Storage Device\'"),
        bstr_t(WMIQuery),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator);
    
    if (FAILED(hres))
    {
		LogExtMsg(ERROR_LOG,"WMIUSB> Query for operating system name failed. Error code = 0x%x", format_error(hres));
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 0;               // Program has failed.
    }
	LogExtMsg(INFORMATION_LOG,"WMIUSB> InitWMI Done.");

    return 1;   
}

int TerminateWMI(){

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    if(!pclsObjTI) pclsObj->Release();
    if(!pclsObj) pclsObj->Release();
    CoUninitialize();

    return 1;  
}


int PutWMIUSBToQueue(char* msg, char* Time, DWORD EventID){
	MsgCache *ecur;
	ecur = (MsgCache *)malloc(sizeof(MsgCache));
	if (ecur) {
		strncpy_s(ecur->Hostname,_countof(ecur->Hostname),Hostname,_TRUNCATE);
		ecur->criticality=0;
		ecur->SafedCounter=0;
		strncpy_s(ecur->SubmitTime,_countof(ecur->SubmitTime),Time,_TRUNCATE);
		ecur->ShortEventID = EventID;
		strncpy_s(ecur->SourceName, 100, "Security",_TRUNCATE);
		strncpy_s(ecur->EventLogSourceName, _countof(ecur->EventLogSourceName), "USB",_TRUNCATE);
		strncpy_s(ecur->UserName, 256, "UNKNOWN",_TRUNCATE);
		strncpy_s(ecur->SIDType, 100, "N/A",_TRUNCATE);
		strncpy_s(ecur->szCategoryString, 256, "None",_TRUNCATE);
		ecur->DataString[0] = '\0';
		strncpy_s(ecur->szTempString, _countof(ecur->szTempString), msg,_TRUNCATE);
		ecur->EventLogCounter=0;
		ecur->seenflag=0;
		ecur->next=NULL;
		ecur->prev=NULL;
		ecur->EventLogLevel=TYPE_SUCCESS;
		strncpy_s(ecur->EventLogType,_countof(ecur->EventLogType),"Success Audit",_TRUNCATE);
		
		DWORD dwWaitRes = WaitForSingleObject(hMutex,1000);
		if (dwWaitRes == WAIT_OBJECT_0) {
			if (EventTail) {
				ecur->prev = EventTail;
				EventTail->next = ecur;
			}
			EventTail = ecur;
			if (!EventHead) EventHead = ecur;
		} else {
			LogExtMsg(INFORMATION_LOG,"WMIUSB> FAILED WAIT");
		}
		EventCount++;
		ReleaseMutex(hMutex);		
    }		


	LogExtMsg(ERROR_LOG," WMIUSB> WMIString to send: %s", msg);
	return 1;
}


//put it in a thread
void GetInfoWMI(HANDLE event){
    ULONG uReturn = 0;
	HRESULT hr;
	HRESULT hrexit = WBEM_S_NO_ERROR;
	char WMIUSBString[1024];
	w_g_Info.bTerminate = FALSE;
	char timestr[100] = "";
	char tmp[1024] = "";
	DWORD EventID = 0;
	int error = 0;
	while ( (hrexit == WBEM_S_TIMEDOUT || hrexit == WBEM_S_NO_ERROR ) && !w_g_Info.bTerminate)
	{
	    hrexit = pEnumerator->Next(2000L, 1L, //max 2s timeout before stopping thread with w_g_Info.bTerminate
			&pclsObj, &uReturn);

		if ( SUCCEEDED( hr ) && ( hr != WBEM_S_FALSE ) ){
			LogExtMsg(INFORMATION_LOG,"WMIUSB> Next got Info.");
		}else{
			error = 1;
			LogExtMsg(ERROR_LOG,"WMIUSB> Next got Error. Error code = 0x%x", format_error(hr));
		}

		if(0 == uReturn)
		{
			LogExtMsg(INFORMATION_LOG,"WMIUSB>  Nothing from WMI USB Next. Continue.");
			continue;
		}
		_variant_t vtProp;
		_variant_t vtPnPEntity;
		_snprintf_s(WMIUSBString,_countof(WMIUSBString),_TRUNCATE,"");
		
		// Get the value of the Name property
		hr = pclsObj->Get(L"__Class", 0, &vtProp, 0, 0);
		if ( SUCCEEDED( hr ) ) {
			_bstr_t classe = vtProp;
			if ( classe == _bstr_t( L"__InstanceCreationEvent" ) ){
				strncat_s(WMIUSBString,_countof(WMIUSBString),"Device inserted. ",_TRUNCATE);	
				EventID = USB_INSERTED;
				LogExtMsg(INFORMATION_LOG,"WMIUSB>  Device inserted..");
			}else if(classe == _bstr_t( L"__InstanceDeletionEvent" )){
				strncat_s(WMIUSBString,_countof(WMIUSBString),"Device removed. ",_TRUNCATE);
				EventID = USB_REMPOVED;
				LogExtMsg(INFORMATION_LOG,"WMIUSB>  Device removed..");
			}else {
				strncat_s(WMIUSBString,_countof(WMIUSBString),"Device modified. ",_TRUNCATE);
				EventID = USB_MODIFIED;
				LogExtMsg(INFORMATION_LOG,"WMIUSB>  Device modified.");
			}
		}else{
			error = 1;
			LogExtMsg(INFORMATION_LOG,"WMIUSB>  No Info retrieved.");
		}

		hr = pclsObj->Get( L"TIME_CREATED", 0, &vtProp, NULL, NULL );
		if ( SUCCEEDED( hr ) ) {
			_bstr_t time = vtProp;
			//strncat_s(WMIUSBString,_countof(WMIUSBString)," Time : ",_TRUNCATE);
			__time64_t long_time = vtProp;
			// Get time as 64-bit integer.
			_time64( &long_time ); 
			// Convert to local time
			struct tm ptmTime;
			errno_t err = localtime_s(&ptmTime, &long_time);
		    if(!err) {
				strftime(timestr, _countof(timestr),"%a %b %d %H:%M:%S %Y", &ptmTime);
				//strncat_s(WMIUSBString,_countof(WMIUSBString),timestr,_TRUNCATE);
				LogExtMsg(INFORMATION_LOG,"WMIUSB> Time: %s", timestr);
			}else{
				strncat_s(WMIUSBString,_countof(WMIUSBString),time,_TRUNCATE);
				LogExtMsg(ERROR_LOG,"WMIUSB> Time Format Error. Error code = 0x%x", format_error(hr));
			}
		}else{
			error = 1;
			LogExtMsg(ERROR_LOG,"WMIUSB> No Time. Error code = 0x%x", format_error(hr));
		}


		hr = pclsObj->Get(L"TargetInstance", 0, &vtProp, 0, 0);
		if ( SUCCEEDED( hr ) ) {
			IUnknown* str = vtProp;
			if ( SUCCEEDED( hr ) ) {		  
				hr = str->QueryInterface( IID_IWbemClassObject, (void **)&pclsObjTI );
				if ( !SUCCEEDED( hr ) ) {
					LogExtMsg(INFORMATION_LOG,"WMIUSB>  Fatal Error for WMI USB. No TargetInstance found 0x%x", format_error(hr));
				}
				hr = pclsObjTI->Get( L"Name", 0, &vtPnPEntity, NULL, NULL );
				if ( SUCCEEDED( hr ) ) {
					_bstr_t name = vtPnPEntity;
					strncat_s(WMIUSBString,_countof(WMIUSBString)," Name : ",_TRUNCATE);
					strncat_s(WMIUSBString,_countof(WMIUSBString),name,_TRUNCATE);
				}else{
					error = 1;
					LogExtMsg(ERROR_LOG,"WMIUSB> No Name. Error code = 0x%x", format_error(hr));
				}

				hr = pclsObjTI->Get( L"Description", 0, &vtPnPEntity, NULL, NULL );
				if ( SUCCEEDED( hr ) ) {
					_bstr_t name = vtPnPEntity;
					strncat_s(WMIUSBString,_countof(WMIUSBString)," Description : ",_TRUNCATE);
					strncat_s(WMIUSBString,_countof(WMIUSBString),name,_TRUNCATE);
				}else{
					error = 1;
					LogExtMsg(ERROR_LOG,"No Description. Error code = 0x%x", format_error(hr));
				}

				hr = pclsObjTI->Get( L"DeviceID", 0, &vtPnPEntity, NULL, NULL );
				if ( SUCCEEDED( hr ) ) {
					_bstr_t name = vtPnPEntity;
					strncat_s(WMIUSBString,_countof(WMIUSBString)," DeviceID : ",_TRUNCATE);
					strncat_s(WMIUSBString,_countof(WMIUSBString),name,_TRUNCATE);
				}else{
					error = 1;
					LogExtMsg(ERROR_LOG,"WMIUSB> No DeviceID. Error code = 0x%x", format_error(hr));
				}

				hr = pclsObjTI->Get( L"Manufacturer", 0, &vtPnPEntity, NULL, NULL );
				if ( SUCCEEDED( hr ) ) {
					_bstr_t name = vtPnPEntity;
					strncat_s(WMIUSBString,_countof(WMIUSBString)," Manufacturer : ",_TRUNCATE);
					strncat_s(WMIUSBString,_countof(WMIUSBString),name,_TRUNCATE);
				}else{
					error = 1;
					LogExtMsg(ERROR_LOG,"WMIUSB> No Manufacturer. Error code = 0x%x", format_error(hr));
				}

				hr = pclsObjTI->Get( L"PNPDeviceID", 0, &vtPnPEntity, NULL, NULL );
				if ( SUCCEEDED( hr ) ) {
					_bstr_t name = vtPnPEntity;
					strncat_s(WMIUSBString,_countof(WMIUSBString)," PNPDeviceID : ",_TRUNCATE);
					strncat_s(WMIUSBString,_countof(WMIUSBString),name,_TRUNCATE);
				}else{
					LogExtMsg(ERROR_LOG,"WMIUSB> No PNPDeviceID. Error code = 0x%x", format_error(hr));
				}
			}else{
				error = 1;
				LogExtMsg(ERROR_LOG,"WMIUSB> QueryInterface failed Error code = 0x%x", format_error(hr));
			}
			str->Release();
		}else{
			error = 1;
			LogExtMsg(ERROR_LOG,"WMIUSB> No TargetInstance retrieved. Error code = 0x%x", format_error(hr));
		}
         
		VariantClear(&vtPnPEntity);
		VariantClear(&vtProp);
		pclsObjTI->Release();
		pclsObj->Release();

    	if(!error)PutWMIUSBToQueue(WMIUSBString, timestr, EventID);

	}
	LogExtMsg(INFORMATION_LOG,"WMI USB Thread Closing"); 
	SetEvent(event);
	w_g_Info.bTerminate = FALSE;
	_endthread();
}



int TerminateWMIUSBThread(){
	w_g_Info.bTerminate = TRUE;
	while(w_g_Info.bTerminate){
		Sleep(100);
	}
	return(1);
}	

BOOL isNotClosedWMIUSBThread(){
	return w_g_Info.bTerminate;
}

int StartWMIUSBThread(HANDLE event)
{
	int threadid=0;
	
	threadid = (int)_beginthread(GetInfoWMI,0,event);
	LogExtMsg(INFORMATION_LOG,"DEBUG: Starting WMI USB thread %d..",threadid);
	if(threadid==-1) {
		LogExtMsg(ERROR_LOG,"Error in WMI USB  thread creation");
		return(0);
	}
	return(1);
}