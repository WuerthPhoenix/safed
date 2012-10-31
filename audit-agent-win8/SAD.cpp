#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "support.h"
#include "RegKeyUtilities.h"
#include "LogUtils.h"
#include "SAD.h"
#include <process.h>



char sadStatus[200] = "";
char* systemAdministrators = NULL;
DWORD isVBS = 0;

void setIsVBS(DWORD _isVBS){
	isVBS = _isVBS;
}
void initSADStatus(){
	sadStatus[0]='\0';
}
void writeSADStatus(char * str){
	if(str)
		_snprintf_s(sadStatus,_countof(sadStatus),_TRUNCATE,str);
}

void deinitSAD(){
	if(systemAdministrators)free(systemAdministrators);
}
char* getSAStr(){
	return systemAdministrators;
} 
char* getSADStatus(){
	return sadStatus;
}


int GetAdmins(BOOL block, PROCESS_INFORMATION* piProcessInfo){

	STARTUPINFO         siStartupInfo;
    memset(&siStartupInfo, 0, sizeof(siStartupInfo));
    memset(piProcessInfo, 0, sizeof(*piProcessInfo));
    siStartupInfo.cb = sizeof(siStartupInfo);
    HANDLE hToken    = NULL;
    HANDLE hTokenDup = NULL;
	char dir[MAX_PATH] = "" ;
	char windir[MAX_PATH] = "" ;
	char cmd[MAX_PATH + 20] = "" ;
	char cmdexe[MAX_PATH + 20] = "" ;
	GetModuleFileName(NULL, dir, MAX_PATH);
	char* pos = strstr(dir,"Safed.exe");
	if(!pos){
		pos = strstr(dir,"SnareCore.exe");
	}
	dir[strlen(dir) - strlen(pos)]='\0';
	GetWindowsDirectory(windir, MAX_PATH) ;
	if(isVBS){
		_snprintf_s(cmd,_countof(cmd),_TRUNCATE,"Cscript.exe \"%sGetLocalAdmins.vbs\" True",dir);
		_snprintf_s(cmdexe,_countof(cmdexe),_TRUNCATE,"%s\\system32\\Cscript.exe",windir);
	}else{
		if(getUselogfile() && (getDwLogLevel() >=  DEBUG_LOG)){
			_snprintf_s(cmd,_countof(cmd),_TRUNCATE,"ADQuery.exe -debug \"-logfile=%s\"",getLogfilename());
		}else if(getSAFEDDEBUG() && (getSAFEDDEBUG() >= DEBUG_LOG)){
			_snprintf_s(cmd,_countof(cmd),_TRUNCATE,"ADQuery.exe -debug");	
		}else{
			_snprintf_s(cmd,_countof(cmd),_TRUNCATE,"ADQuery.exe");
		}
		_snprintf_s(cmdexe,_countof(cmdexe),_TRUNCATE,"%s\\ADQuery.exe",dir);

	}


	if(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY|TOKEN_DUPLICATE, TRUE,&hToken)){
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY|TOKEN_DUPLICATE, &hToken)){
				LogExtMsg(DEBUG_LOG,"ERROR when OpenProcessToken %d", GetLastError());
				return 0;
			}

	}
	if(!DuplicateTokenEx ( hToken,TOKEN_IMPERSONATE|TOKEN_READ|TOKEN_ASSIGN_PRIMARY|TOKEN_DUPLICATE,NULL,
		SecurityImpersonation, TokenPrimary, &hTokenDup)){
			LogExtMsg(DEBUG_LOG,"ERROR when DuplicateTokenEx %d", GetLastError());
	
			return 0;
	
	}
	CloseHandle( hToken );
	int ret = CreateProcessAsUser(hTokenDup,cmdexe,     // Application name
					cmd,// Application arguments
                     0,
                     0,
                     FALSE,
                     CREATE_NO_WINDOW,//CREATE_DEFAULT_ERROR_MODE,//CREATE_NEW_CONSOLE,//CREATE_NO_WINDOW,
                     0,
                     0,                              // Working directory
                     &siStartupInfo,
                     piProcessInfo);
	RevertToSelf( );

	if(!ret){
		LogExtMsg(DEBUG_LOG,"ERROR when CreateProcessAsUser %d", GetLastError());
		CloseHandle(hTokenDup);
		return ret;
	}

	ret = 0;
	if(block){
		int retval = WaitForSingleObject(piProcessInfo->hProcess,INFINITE);
		if(retval != WAIT_OBJECT_0)ret = 0;
		else ret = 1;
		CloseHandle(piProcessInfo->hProcess);
		CloseHandle(piProcessInfo->hThread);
		piProcessInfo->dwProcessId = 0;
	}else{
		ret = 1;
	}
    CloseHandle(hTokenDup);
    return ret;
}



char* ReadAdmins(){
	HKEY hKey;
	char objective_buffer[2]="";
	DWORD  dw_objective_bytes = 2;
	DWORD dwRegType = REG_SZ;
	char str_objective_to_read[20] = "Objective"; 
	int o_return_val = 0;
	long error_type=0;
	char* s_admins = NULL;
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, SYS_ADMIN_KEY_NAME, 0, KEY_READ,&hKey ) == ERROR_SUCCESS )	{
		error_type = RegQueryValueEx(hKey, str_objective_to_read, NULL, &dwRegType,  (LPBYTE) objective_buffer, &dw_objective_bytes );
		if ( error_type == ERROR_MORE_DATA ) {
			 s_admins = (char*)malloc(dw_objective_bytes);
			 error_type = RegQueryValueEx(hKey, str_objective_to_read, NULL, &dwRegType,  (LPBYTE) s_admins, &dw_objective_bytes );
			 if ( error_type == ERROR_SUCCESS ) {
					// Reject any str_objective that is longer than 1056 chars
				 char* p = strstr(s_admins,"|#DONE");
				 if (p) {
						*p = '\0';
				  } else {
						// reject the str_objective and return immediately
						if(s_admins)free(s_admins);
						RegCloseKey(hKey);
						return NULL;
				  }
			 } else {
			  // Retain this error value as 4, since the error control in the other routines
			  // look for errors in the range 1 to 3.
			  if(s_admins)free(s_admins);
			  RegCloseKey(hKey);
			  return NULL;
			}
	  }else{
			  RegCloseKey(hKey);
			  return NULL;
	  
	  }
	  // Close the registry key when done
	  RegCloseKey(hKey);
	}	
	return s_admins;
}




void deleteSAObjectives(){
	HKEY hKey;
	int cnt = 0;
	char labelkey[20]="";
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, OBJECTIVE_KEY_NAME, 0, KEY_ALL_ACCESS,&hKey ) == ERROR_SUCCESS ){
		while(true){
			cnt--;
			_snprintf_s(labelkey,20,_TRUNCATE,"Objective%d",cnt);
			if(RegDeleteValue(hKey, labelkey) != ERROR_SUCCESS )
				break;
		}
		RegCloseKey(hKey);
	}
}
BOOL splitSAObjective(){
	char labelkey[20]="";
	char strobj[SIZE_OF_AN_OBJECTIVE]="";
	char strgm[(SIZE_OF_GENERALMATCH - 1) + 1]="";
	int cnt = 0;
	char* current = systemAdministrators;
	int len = strlen(current);
	BOOL ret = TRUE;
	while(len > (SIZE_OF_GENERALMATCH - 1)){
		char* index = current + (SIZE_OF_GENERALMATCH - 1);
		while (*index != '|')index= index - 1;

		strncpy(strgm, current, index - current);
		strgm[index - current] = '\0';
		cnt--;
		_snprintf(labelkey,20,"Objective%d",cnt);
		_snprintf_s(strobj,SIZE_OF_AN_OBJECTIVE,_TRUNCATE,"1\t31\t32\t%s\t*%s*\t0\t*\t0\t0",LOGON_LOGOFF_EVENTS,strgm);

		if(MyWriteProfileString("Objective", labelkey, strobj)){
			ret = ret && TRUE;
		}else 
			ret = ret && FALSE;
		current = index + 1;
		len = strlen(current);
	}

	strncpy(strgm, current, len);
	strgm[len] = '\0';
	cnt--;
	_snprintf_s(labelkey,20,_TRUNCATE,"Objective%d",cnt);
	_snprintf_s(strobj,SIZE_OF_AN_OBJECTIVE,_TRUNCATE,"1\t31\t32\t%s\t*%s*\t0\t*\t0\t0",LOGON_LOGOFF_EVENTS,strgm);
	if(MyWriteProfileString("Objective", labelkey, strobj) && MyWriteProfileDWORD("SysAdmin", "TotalASObjectives", cnt*(-1))){
		ret = ret && TRUE;
	}else 
		ret = ret && FALSE;

	return ret;
}
BOOL setSAObjectives(){
	char * adms = ReadAdmins();
	BOOL ret = FALSE;
	if(adms){
		if(systemAdministrators){
			free(systemAdministrators);
		}
		systemAdministrators = adms;
		deleteSAObjectives();
		ret = splitSAObjective();
	}
	LogExtMsg(ERROR_LOG,"SA Objectives setting exit %d!",ret);

	return ret;
}

void getstrdate(DWORD date, char * out){
	time_t current = date;
	tm newtime;
	localtime_s(&newtime,&current);
	syslogdate(out,&newtime);
}

//Terminates the SAD each time an apply is done or a schedule is fired
void TerminateSAProcess(PROCESS_INFORMATION* piProcessInfo){
	if(piProcessInfo && piProcessInfo->dwProcessId){
		UINT uExitCode = 0;
		LogExtMsg(DEBUG_LOG,"Terminating SA discovery");
		TerminateProcess(piProcessInfo, uExitCode);
		CloseHandle(piProcessInfo->hProcess);
		CloseHandle(piProcessInfo->hThread);
		piProcessInfo->dwProcessId = 0;

	}	
}


int checkEndOfASDiscoveryProcess(PROCESS_INFORMATION* piProcessInfo){
	int ret = 0;
	if(piProcessInfo && piProcessInfo->dwProcessId){
			DWORD dwExitCode = 0;
			if(GetExitCodeProcess(piProcessInfo->hProcess,&dwExitCode)){
				if (dwExitCode != STILL_ACTIVE) {
					CloseHandle(piProcessInfo->hProcess);
					CloseHandle(piProcessInfo->hThread);
					piProcessInfo->dwProcessId = 0;
					LogExtMsg(DEBUG_LOG,"SA discovery process terminated!");
					ret = 1;
				}
			}else{
				CloseHandle(piProcessInfo->hProcess);
				CloseHandle(piProcessInfo->hThread);
				piProcessInfo->dwProcessId = 0;
				LogExtMsg(WARNING_LOG,"GetExitCodeProcess for SA discovery process failed %d", GetLastError());
				ret = -1;
			}
	}
	LogExtMsg(DEBUG_LOG,"SA discovery process is running...!");
	return ret;

}

BOOL  updateSA(DWORD start, DWORD* delta){
	DWORD tmp = time(NULL);
	*delta = tmp - start;
	BOOL ret = setSAObjectives();
	MyWriteProfileDWORD("SysAdmin","LastTimeDiscovery",start);
	MyWriteProfileDWORD("SysAdmin","LastDurationDiscovery",*delta);
	return ret;
}




BOOL LoadSAObjective(DWORD dwForceNextTime, int dwTimesADay, DWORD dwNextTimeDiscovery, PROCESS_INFORMATION* piProcessInfo, DWORD* start){
	char sdate[16] = "";
	char tdate[16] = "";
	*start = time(NULL);
	getstrdate(*start, sdate);
	_snprintf_s(sadStatus,_countof(sadStatus),_TRUNCATE,"The system administrators discovery is running...[Started %s]\n", sdate);
	BOOL ret = setSAObjectives();
	DWORD tmp = MyGetProfileDWORD("SysAdmin","LastTimeDiscovery",0);
	DWORD delta = MyGetProfileDWORD("SysAdmin","LastDurationDiscovery",0);
	BOOL block = !ret;//ret = FALSE if the SA objectives are not correct or the SA discovery hasn't been done yet

	if(dwForceNextTime || block ){// SA discovery is requested or see above comment...

		LogExtMsg(INFORMATION_LOG,"Run SA discovery ...forced: %d ; read failed SA data or first execution: %d!", dwForceNextTime, block);
		if(GetAdmins(block, piProcessInfo) && block){
			LogExtMsg(INFORMATION_LOG,"Run SA discovery process...finished");
			ret = updateSA(*start, &delta);//only if SAD is finished
		}else{ 
			if(block){ 
					LogExtMsg(ERROR_LOG,"Run SA discovery process...failed");
			}
		}
	

	}else{
		getstrdate(tmp, sdate);//report saved date
	}

	if(block || !dwForceNextTime){//only if SAD is finished or no discovery is required prepare the web string
		if (dwNextTimeDiscovery <= *start )
			tmp = dwNextTimeDiscovery + dwTimesADay;//we are here due to schedule time
		else
			tmp = dwNextTimeDiscovery;//first SAD execution. when starting dwNextTimeDiscovery is initialized with the next scheduled time

		getstrdate(tmp, tdate);
		if(!ret)
			_snprintf_s(sadStatus,_countof(sadStatus),_TRUNCATE,"The system administrators discovery is failed! [Started: %s; Last Dutation: %d(s); Next scheduled:  %s]\n", sdate, delta, tdate);
		else
			_snprintf_s(sadStatus,_countof(sadStatus),_TRUNCATE,"The system administrators discovery is done! [Started: %s; Last Dutation: %d(s); Next scheduled:  %s]\n", sdate, delta, tdate);
		
	}

	return ret;

}






