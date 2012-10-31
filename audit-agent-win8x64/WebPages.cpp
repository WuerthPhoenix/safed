//
//
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <lm.h>
#include <iads.h>
#include <tchar.h>
#include <comdef.h>
#include <activeds.h>

#include <windows.h>
#include <Adshlp.h>
#include <comutil.h>
#include <dsrole.h>
#include <time.h>
#include <sys/stat.h>

#include "LogUtils.h"

#include "WebPages.h"
#include "Version.h"

#include "support.h"
#include "RegKeyUtilities.h"
#include "MD5.h"

#include "webserver.h"

extern int IsNT5plus();

extern HANDLE hMutex,hMutexFile;
extern MsgCache *MCHead, *MCTail;

extern BOOL GetOutputFile(char* filename, char* date);
extern BOOL GetFileName(char* filename, char* date, BOOL cache);
extern DWORD GetTotalSavedLogs (FILE * fp);
extern void	GetSavedLogsAt (FILE * fp, char* line, int position);
extern void	SendToAll(char *buf, int nSize);

extern DWORD dwMaxMsgSize;


extern char socketStatus[600];
extern char sadStatus[200];
extern char initStatus[16384];
extern char e_initStatus[16384];
extern char* systemAdministrators;

extern DWORD WEBSERVER_TLS;

char setConfigStatus[80] = "";
char getConfigStatus[80] = "";
char lastConnectionStatus[80] = "";


#define LSC_MSG "Last set of configuration from NetEye server"
#define LGC_MSG "Last get of configuration from NetEye server"
#define LCS_MSG "Last connection from NetEye server"

#define snprintf_s _snprintf_s
#define UGBUFFER     10240


// Make sure we return the size, or zero (for strings).
// Note that for the most part, the socket will be ignored
int HandleWebPages(char *HTTPBuffer,char *HTTPOutputBuffer,int size, SOCKET http_socket, gnutls_session session_https, char* fromServer, HANDLE event)
{
	int returncode=0, refreshflag=0;
	char *ArgPosition;
	char TBuffer[2048]="";
	
	LogExtMsg(INFORMATION_LOG,"HandleWebPages");
	
	if(!HTTPBuffer || !HTTPOutputBuffer) {
		return(0);
	}
	if(fromServer && strlen(fromServer) > 0){
		_snprintf_s(lastConnectionStatus,_countof(lastConnectionStatus),_TRUNCATE,"%s %s\n", LCS_MSG, fromServer);
	}else{
		_snprintf_s(lastConnectionStatus,_countof(lastConnectionStatus),_TRUNCATE,"");	
	}

	// Stuff without the header/footer
	if(!strcmp(HTTPBuffer,"/logo.gif")) {
		return(LogoImage(HTTPBuffer,HTTPOutputBuffer,size));
	} else if(!strcmp(HTTPBuffer,"/critical.gif")) {
		return(ImageCrit(HTTPBuffer,HTTPOutputBuffer,size));
	} else if(!strcmp(HTTPBuffer,"/priority.gif")) {
		return(ImagePri(HTTPBuffer,HTTPOutputBuffer,size));
	} else if(!strcmp(HTTPBuffer,"/warning.gif")) {
		return(ImageWarn(HTTPBuffer,HTTPOutputBuffer,size));
	} else if(!strcmp(HTTPBuffer,"/info.gif")) {
		return(ImageInfo(HTTPBuffer,HTTPOutputBuffer,size));
	} else if(!strcmp(HTTPBuffer,"/clear.gif")) {
		return(ImageClear(HTTPBuffer,HTTPOutputBuffer,size));
	} else if(!strcmp(HTTPBuffer,"/status.gif")) {
		return(ImageStatus(HTTPBuffer,HTTPOutputBuffer,size));
	}else if(!strcmp(HTTPBuffer,"/cfg.gif")) {
		return(ImageCfg(HTTPBuffer,HTTPOutputBuffer,size));
	}else if(!strcmp(HTTPBuffer,"/cfg.gif")) {
		return(ImageCfg(HTTPBuffer,HTTPOutputBuffer,size));
	}else if(!strcmp(HTTPBuffer,"/cfg.gif")) {
		return(ImageCfg(HTTPBuffer,HTTPOutputBuffer,size));
	}else if(!strcmp(HTTPBuffer,"/save.gif")) {
		return(ImageSave(HTTPBuffer,HTTPOutputBuffer,size));
	}else if(!strcmp(HTTPBuffer,"/search.gif")) {
		return(ImageSearch(HTTPBuffer,HTTPOutputBuffer,size));
	}else if(!strcmp(HTTPBuffer,"/list.gif")) {
		return(ImageList(HTTPBuffer,HTTPOutputBuffer,size));
	} else if(!strcmp(HTTPBuffer,"/arrow.gif")) {
		return(ImageArrow(HTTPBuffer,HTTPOutputBuffer,size));
	} else {
		char * pBuffer=HTTPOutputBuffer;
		int length=0;
		int psize=0;
		
		LogExtMsg(INFORMATION_LOG,"Processing Request");

		ArgPosition=strstr(HTTPBuffer,"?");
		// No arguments passed?
		if(!ArgPosition) {
			// Set argument position to the beginning of the buffer.
			ArgPosition=HTTPBuffer;
		} else {
			ArgPosition++;
		}

		if(!strcmp(HTTPBuffer,"/License")) {
			DisplayTextHeader(http_socket, session_https);
			ShowLicense(http_socket, session_https);
			return(-1);
		} else if(!strcmp(HTTPBuffer,"/GetConfig")) {
			DisplayTextHeader(http_socket, session_https);
			GetConfig(http_socket, session_https, fromServer);
			return(-1);
		}  else if(!strcmp(HTTPBuffer,"/GetSysAdmin")) {
			DisplayTextHeader(http_socket, session_https);
			GetSysAdmin(http_socket, session_https);
			return(-1);
		}  else if(!strcmp(HTTPBuffer,"/GetCustomLogs")) {
			DisplayTextHeader(http_socket, session_https);
			GetCustomLogs(http_socket, session_https);
			return(-1);
		} /*else if(!strncmp(HTTPBuffer,"/RegDump",8)) {
			// DisplayTextHeader(http_socket, session_https);
			DumpRegistry(http_socket,session_https ArgPosition,TBuffer,_countof(TBuffer));
			if(!strlen(TBuffer)) {
				return(-1);
			}
		}*/
		if(!strncmp(HTTPBuffer,"/eventlog",9)) refreshflag=1;

		if(!strcmp(HTTPBuffer,"/restart"))
			returncode=DefaultHeader(HTTPBuffer,pBuffer,size, refreshflag, FALSE);
		else
			returncode=DefaultHeader(HTTPBuffer,pBuffer,size, refreshflag, TRUE);
		length=(int)strlen(HTTPOutputBuffer);
		
		pBuffer+=length;
		psize=size-length;
		if(psize < 0) {
			psize=0;
		}

		// Web pages
		if(!strcmp(HTTPBuffer,"/network")) {
			returncode+=Network_Config(ArgPosition,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/network?",9)) {
			strncpy_s(pBuffer,psize,"Nothing here yet",_TRUNCATE);
		} else if(!strcmp(HTTPBuffer,"/sysadmin")) {
			returncode+=SysAdmin_Config(ArgPosition,pBuffer,psize);
		}else if(!strncmp(HTTPBuffer,"/setsysadmin",12)) {
			returncode+=SysAdmin_Set(ArgPosition,pBuffer,psize);
		} else if(!strcmp(HTTPBuffer,"/config")) {
			returncode+=Config(ArgPosition,pBuffer,psize);
		} else if(!strcmp(HTTPBuffer,"/certs")) {
			returncode+=Certs(ArgPosition,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/setconfig",10)) {
			returncode+=SetConfig(ArgPosition,pBuffer,psize,fromServer);
		} else if(!strncmp(HTTPBuffer,"/setca",6)) {
			char* fname = getCAFILE();
			if(!fname || (strlen(fname) == 0))
				setCurrentDir();
			returncode+=SetCertificate(ArgPosition,pBuffer,psize,getCAFILE());
		} else if(!strncmp(HTTPBuffer,"/setcert",8)) {
			char* fname = getCERT_FILE();
			if(!fname || (strlen(fname) == 0))
				setCurrentDir();
			returncode+=SetCertificate(ArgPosition,pBuffer,psize,getCERT_FILE());
		} else if(!strncmp(HTTPBuffer,"/setkey",7)) {
			char* fname = getKEY_FILE();
			if(!fname || (strlen(fname) == 0))
				setCurrentDir();
			returncode+=SetCertificate(ArgPosition,pBuffer,psize, getKEY_FILE());
		} else if(!strcmp(HTTPBuffer,"/remote")) {
			returncode+=Remote_Config(ArgPosition,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/setremote",10)) {
			returncode+=Remote_Set(ArgPosition,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/safed/objective",16)) {
			returncode+=Objective_Config(ArgPosition,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/safed/setobjective",19)) {
			returncode+=Objective_Display(HTTPBuffer,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/safed/changeobjective",22)) {
			returncode+=Objective_Result(HTTPBuffer,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/log/objective",14)) {
			returncode+=E_Objective_Config(ArgPosition,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/log/setobjective",17)) {
			returncode+=E_Objective_Display(HTTPBuffer,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/log/changeobjective",20)) {
			returncode+=E_Objective_Result(HTTPBuffer,pBuffer,psize);
		} else if (!strncmp(HTTPBuffer, "/log", 4)) {
			returncode += Log_Config(ArgPosition, pBuffer, psize);
		} else if (!strncmp(HTTPBuffer, "/setlog", 7)) {
			returncode += Log_Display(HTTPBuffer, pBuffer, psize);
		} else if (!strncmp(HTTPBuffer, "/changelog", 10)) {
			returncode += Log_Result(HTTPBuffer, pBuffer, psize);
		} else if(!strcmp(HTTPBuffer,"/restart")) {
			returncode+=Restart(HTTPBuffer,pBuffer,psize,event);
		} else if(!strncmp(HTTPBuffer,"/restart?",10)) {
			returncode+=Restart(HTTPBuffer,pBuffer,psize);
			//strncpy_s(pBuffer,psize,"Nothing here yet",_TRUNCATE);
		} else if(!strncmp(HTTPBuffer,"/setnetwork",11)) {
			returncode+=Network_Set(HTTPBuffer,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/status",6)) {
			returncode+=Status_Page(ArgPosition,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/safedlog",9)) {
			returncode+=SafedLog_Page(ArgPosition,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/eventlog",9)) {
			returncode+=Current_Events(ArgPosition,pBuffer,psize);
		}else if(!strncmp(HTTPBuffer,"/dailylog",9)) {
			returncode+=Daily_Events(ArgPosition,pBuffer,psize,FALSE);
		}else if(!strncmp(HTTPBuffer,"/geteventlogat",14)) {
			returncode+=Daily_Events(ArgPosition,pBuffer,psize,TRUE);
		} else if(strlen(TBuffer)) {
			strncpy_s(pBuffer,psize,TBuffer,_TRUNCATE);
		} else if(!strcmp(HTTPBuffer,"/")) {
			returncode=+Status_Page(ArgPosition,pBuffer,psize);
		} else {
			// Here: Consider returning a 404 instead.
			// returncode=+Status_Page(ArgPosition,pBuffer,psize);
			LogExtMsg(INFORMATION_LOG,"No page - sending a 404");
			Display404(http_socket, session_https);
			return(-1);
		}
		pBuffer='\0';
		pBuffer = HTTPOutputBuffer;
		length=(int)strlen(HTTPOutputBuffer);
		pBuffer+=length;
		psize=size-length;
		if(psize < 0) {
			psize=0;
		}

		returncode+=DefaultFooter(HTTPBuffer,pBuffer,psize);



	}




	return(returncode);
}


// This page will be usefull for debug information
int SafedLog_Page(char *source, char *dest, int size)
{
	FILE * OutputFile=(FILE *)NULL;
	DWORD dwWaitFile=0;
	char filename[MAX_PATH]="";
	BOOL usefile = FALSE;
	DWORD nLogs = 0;
	char *psource=source, Variable[100]="", Argument[100]="", number_s[100]="", file_s[255]="", fileO_s[255]="";
	int numberorig = 0;
	int number = 0;
	int numberFrom = 0;
	int numberTo = 0;
	int total = 0;
	int MAX = 1000;
	int MAXLINE = 200;
	int next = -1;
	int numberoffiles=0;
	struct stat stats;

	char** filelist = GetAllFileNames(&numberoffiles,FALSE);
	int cnt = 0;

	char* line = (char*)malloc(dwMaxMsgSize*sizeof(char)); 
	if (line)line[0]='\0';
	else {
		LogExtMsg(DEBUG_LOG,"NO MEMORY LEFT!!!");
		return 1;
	}

	while((psource=GetNextArgument(psource,Variable,_countof(Variable)-1,Argument,_countof(Argument)-1)) != (char *)NULL) 
	{	

		if (strstr(Variable,"Next") != NULL) {
			next = 1;
		}
		if (strstr(Variable,"Previous") != NULL) {
			next = 0;
		}
		if (strstr(Variable,"Last") != NULL) {
			next = -1;
		}


		if (strstr(Variable,"numberW") != NULL) {
			strncpy_s(number_s,_countof(number_s),Argument,_TRUNCATE);
			number = atoi(number_s);
		}
		if (strstr(Variable,"numberO") != NULL) {
			strncpy_s(number_s,_countof(number_s),Argument,_TRUNCATE);
			numberorig = atoi(number_s);
		}
		if (strstr(Variable,"numberFrom") != NULL) {
			strncpy_s(number_s,_countof(number_s),Argument,_TRUNCATE);
			numberFrom = atoi(number_s);
		}
		if (strstr(Variable,"numberTo") != NULL) {
			strncpy_s(number_s,_countof(number_s),Argument,_TRUNCATE);
			numberTo = atoi(number_s);
		}
		
		if (strstr(Variable,"thefile") != NULL) {
			strncpy_s(file_s,_countof(file_s),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"thefileO") != NULL) {
			strncpy_s(fileO_s,_countof(fileO_s),Argument,_TRUNCATE);
		}
	}

	if((number < 1) || (number > MAX)){
		number = MAX;
	}
	if(numberFrom < 1) numberFrom = 1;
	if(numberTo < numberFrom) numberTo = numberFrom;



	if(strlen(file_s) == 0){
		if(numberoffiles > 0){
			snprintf_s(file_s,_countof(file_s),_TRUNCATE,"%s",filelist[numberoffiles - 1]);
			usefile = TRUE;
		}
	}else{
		for(cnt = 0; cnt < numberoffiles; cnt++){
			if(!strcmp(filelist[cnt],file_s)){
				usefile = TRUE;
				break;
			}
		}	
	}
	strcpy(filename,file_s);

	snprintf_s(dest,size,_TRUNCATE,"<HTML><BODY><form method=get action=safedlog><H2><CENTER>Logs for %s",file_s);
	if(usefile){
		GetFullFileNames(filename, FALSE);
		if (!stat(filename, &stats)){
			snprintf_s(dest,size,_TRUNCATE,"%s %d bytes",dest,stats.st_size);
		}
		dwWaitFile = WaitForSingleObject(getLogMutex(),500);
		if(dwWaitFile == WAIT_OBJECT_0) {
			fopen_s(&OutputFile,filename,"r");
			if(usefile && OutputFile) {
					nLogs = GetTotalSavedLogs(OutputFile);
					fclose(OutputFile);
			}
		}
		ReleaseMutex(getLogMutex());	
		
	}
	snprintf_s(dest,size,_TRUNCATE,"%s</CENTER></H2><BR/><br/><CENTER><textarea rows=\"30\" cols=\"100\" readonly=\"readonly\" style=\"background-color: rgb(231,231,231)\">\n",dest);


	if(next == 1){
		if(numberTo - numberFrom == numberorig)numberFrom = numberTo;
	}else if(next == 0){
		numberFrom = numberFrom >number? numberFrom - number: 1;
	}else{
		if(nLogs > 0){
			numberFrom = (nLogs/number)*number + 1;
			if(numberFrom == nLogs) numberFrom = numberFrom - number;
		}else{
			numberFrom = 1;
		}
	}
	if((strlen(file_s) > 0) && (strlen(fileO_s) > 0) && strcmp(file_s,fileO_s)){
		if(nLogs > 0){
			numberFrom = (nLogs/number)*number + 1;
			if(numberFrom == nLogs) numberFrom = numberFrom - number;
		}else{
			numberFrom = 1;
		}
	}

	numberorig = number;

	numberFrom = numberFrom - 1;
	numberTo = numberFrom + number;
	strcpy(fileO_s,file_s);

	//printf("============ %d  %d  %d  %s  %s\n",number, numberFrom, numberTo, file_s, fileO_s);
	//snprintf_s(dest,size,_TRUNCATE,"<HTML><BODY><form method=get action=safedlog><H2><CENTER>Logs for %s</CENTER></H2><BR/><br/><CENTER><textarea rows=\"%d\" cols=\"100\" readonly=\"readonly\" style=\"background-color: rgb(231,231,231)\">\n",file_s,number);

	if(usefile){
		dwWaitFile = WaitForSingleObject(getLogMutex(),500);
		if(dwWaitFile == WAIT_OBJECT_0) {
			fopen_s(&OutputFile,filename,"r");
			if(OutputFile) {
					nLogs = GetTotalSavedLogs(OutputFile);
					fclose(OutputFile);
			}
			fopen_s(&OutputFile,filename,"r");
			if(OutputFile) {
				GetSavedLogsAt(OutputFile, line, numberFrom);//place it to numberFrom line
				if(strlen(line)){
					if(strlen(line) > MAXLINE){
						line[MAXLINE -2] = '\n';
						line[MAXLINE -1] = '\0';
					}
					snprintf_s(dest,size,_TRUNCATE,"%s%s",dest,line);
					total++;
					for (int i=(numberFrom+1);  i < numberTo ; i++) {
						GetSavedLogsAt(OutputFile, line, 0);// give the next line
						if(strlen(line)){
							if(strlen(line) > MAXLINE){
								line[MAXLINE -2] = '\n';
								line[MAXLINE -1] = '\0';
							}
							snprintf_s(dest,size,_TRUNCATE,"%s%s",dest,line);
							total++;
						}else break;
					}
				}
				fclose(OutputFile);
			}

			ReleaseMutex(getLogMutex());
		}	
	}
	if((total < number) && (next || (numberFrom == 0))){
		numberTo = numberTo - number + total;
	}



	snprintf_s(dest,size, _TRUNCATE,"%s</textarea></CENTER><CENTER><BR/>Shown lines from %d to %d <br/><br/><input type=hidden name=thefileO size=\"8\" value=\"%s\"/><input type=hidden name=numberO size=\"2\" value=\"%d\"/><input type=text name=numberW size=\"4\" value=\"%d\"/> lines per page (max 1000 allowed) for <select name=thefile></CENTER>\n",dest, (numberFrom + 1), (numberFrom + total), fileO_s, numberorig, number);
	for(cnt = 0; cnt < numberoffiles; cnt++){
		if(filelist[cnt]){
			strncat_s(dest,size,"<option",_TRUNCATE);
			if (!strcmp(file_s,filelist[cnt])) {
				strncat_s(dest,size," selected>",_TRUNCATE);
			} else {
				strncat_s(dest,size,">",_TRUNCATE);
			}
			strncat_s(dest,size,filelist[cnt],_TRUNCATE);
			free(filelist[cnt]);
		}
	}

	snprintf_s(dest,size, _TRUNCATE,"%s</select><input type=hidden name=numberFrom size=12 value=\"%d\"/><input type=hidden name=numberTo size=12 value=\"%d\"/></CENTER>\n",dest, (numberFrom + 1), numberTo + 1);
	strncat_s(dest,size,"<br/><CENTER><input type=submit name=btnPrevious value=\"Previous\"/><input type=submit name=btnNext value=\"Next\"/><input type=submit name=btnLast value=\"Last\"/></CENTER></form>", _TRUNCATE );

	if (line) free(line);
	if(filelist)free(filelist);
	return(0);
}


// This page will be usefull for debug information
int Status_Page(char *source, char *dest, int size)
{
#ifdef _M_X64
	snprintf_s(dest,size,_TRUNCATE,"<HTML><BODY><H2><CENTER>SafedAgent Version %s Status Page</H2></CENTER><P><center><font color=green>SafedAgent for Windows x86-64 is currently active.</font></CENTER><P>",SAFED_VERSION);
#elif _M_IA64
	snprintf_s(dest,size,_TRUNCATE,"<HTML><BODY><H2><CENTER>SafedAgent Version %s Status Page</H2></CENTER><P><center><font color=green>SafedAgent for Windows x86-64 is currently active.</font></CENTER><P>",SAFED_VERSION);
#else
	BOOL f64 = FALSE;
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle(TEXT("kernel32")),"IsWow64Process");
  
    if (NULL != fnIsWow64Process) {
        if (!fnIsWow64Process(GetCurrentProcess(),&f64)) {
            // handle error
			f64 = FALSE;
        }
    }

	snprintf_s(dest,size,_TRUNCATE,"<HTML><BODY><H2><CENTER>SafedAgent Version %s Status Page</H2></CENTER><P>" \
		                           "<center><font color=green>SafedAgent for Windows x86-32 is currently active.</font></CENTER><P>" ,SAFED_VERSION);
#endif
	if(!setConfigStatus || strlen(setConfigStatus) == 0){
		char lastsettime[25] = "";
		if(MyGetProfileString("Status","LastSetTime",lastsettime,sizeof(lastsettime))){
				_snprintf_s(setConfigStatus,_countof(setConfigStatus),_TRUNCATE,"%s %s\n", LSC_MSG, lastsettime);
		}
	}
	char* pos=strstr(socketStatus,"down!");
	char color[6]="green";
	if(pos){
		strcpy(color,"red");
	}	
	pos=strstr(sadStatus,"failed!");
	char color2[6]="green";
	if(pos){
		strcpy(color2,"red");
	}	

	snprintf_s(dest,size,_TRUNCATE,"%s<center><b><font color=%s size=-1>%s</font></b></center><p>" \
		                           "<center><font color=%s size=-1>%s</font></center><p>" \
		                           "<center><font color=\"red\" size=-1>%s</font></center></center><p>" \
		                           "<center><font color=\"red\" size=-1>%s</font></center></center><p>" \
		                           "<center><font size=-1>%s</font></center><p>" \
		                           "<center><font size=-1>%s</font></center><p>" \
								   "<center><font size=-1>%s</font></center></BODY></HTML>" \
								   ,dest,color,socketStatus,color2,sadStatus, initStatus, e_initStatus, lastConnectionStatus,setConfigStatus,getConfigStatus);

	return(0);
}

int Network_Config(char *source, char *dest, int size)
{
	//All strncpy_s or strncat_s functions in this routine have been designed avoid overflows
	Reg_Config config_struct;
	Reg_Network network_struct;
	DWORD dw_config_error,dw_network_error;
	char *str_facility[] = {"Kernel","User","Mail","Daemon","Auth","Syslog","Lpr","News","UUCP","Cron","Authpriv","Ftp","Local0","Local1","Local2","Local3","Local4","Local5","Local6","Local7"};
	char *str_priority[] = {"Emergency","Alert","Critical","Error","Warning","Notice","Information","Debug","DYNAMIC"};
	char *str_protocol[] = {"UDP", "TCP", "TLS"};
	char *str_log[] = {"NONE", "ERROR", "WARNING","INFORMATION", "DEBUG"};
	UINT i,i_SyslogFacility,i_SyslogPriority;
		
	dw_config_error = Read_Config_Registry(&config_struct);
	dw_network_error = Read_Network_Registry(&network_struct);

	// This function will display the form used to set the audit configuration
	// The result of the form will be sent to "network_set"
	strncpy_s(dest,size,"<form name=netform method=get action=setnetwork><h2><center>SafedAgent Network Configuration</h2>",_TRUNCATE);

	// Will display an error if unable to completely read from the registry
	if ((dw_network_error > 0) || (dw_config_error > 0)) {
		dw_network_error += WEB_READ_NETWORK_ERROR_CODE;
		dw_config_error += WEB_READ_CONFIG_ERROR_CODE;

		_snprintf_s(dest,size,_TRUNCATE,"%s<br><b>NOTE: Some errors were encountered in reading the registry. Default values " \
					"may be used.<br> Report error: %d.%d</b><br>",dest,dw_network_error,dw_config_error);
	}

	strncat_s(dest,size,"<br>The following network configuration parameters of the SafedAgent unit is set to the following values:<br><br>" \
				"<table  width=70% border=0>" \
				"<tr bgcolor=#E7E5DD><td>Override detected DNS Name with: </td>" \
				"<td><input type=text name=str_ClientName size=25 value=\"",_TRUNCATE);
	
	strncat_s(dest,size,config_struct.str_ClientName,_TRUNCATE);
	strncat_s(dest,size,"\"></td></tr>",_TRUNCATE);


	// Here: Two alternatives: Allow a user-supplied comma-separated list, or
	// alternatively, add a new element for each new system?
	strncat_s(dest,size,"<tr bgcolor=#DEDBD2><td>Destination SafedAgent Server address </td><td><input type=text name=str_Destination size=25 value=\"",_TRUNCATE);
	strncat_s(dest,size,network_struct.str_Destination,_TRUNCATE);
	strncat_s(dest,size,"\"></td></tr>",_TRUNCATE);

	_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#E7E5DD><td>Destination Port</td><td><input type=text name=dw_DestPort size=8 value=\"%d\" onMouseover=\"ddrivetip(\'514 is the default rsyslog port  \')\" onMouseout=\"hideddrivetip()\"></td></tr>",dest,network_struct.dw_DestPort);


	strncat_s(dest,size,"<tr bgcolor=#E7E5DD><td>Protocol Type</td><td><select name=dw_SocketType>",_TRUNCATE);
	for (i = SOCKETTYPE_UDP; i <= SOCKETTYPE_TCP_TLS; i++)
	{
		strncat_s(dest,size,"<option",_TRUNCATE);
		if (i == network_struct.dw_SocketType) {
			strncat_s(dest,size," selected>",_TRUNCATE);
		} else {
			strncat_s(dest,size,">",_TRUNCATE);
		}
		strncat_s(dest,size,str_protocol[i],_TRUNCATE);
	}
	strncat_s(dest,size,"</select></td></tr>",_TRUNCATE);


	_snprintf_s(dest,size,_TRUNCATE,
		"%s<tr bgcolor=#E7E5DD><td>Perform a scan of ALL objectives, and display the maximum criticality?</td><td><input type=checkbox name=dw_CritAudit%s></td></tr>"
		"<tr bgcolor=#DEDBD2><td>Allow SafedAgent to automatically set audit configuration?</td><td><input type=checkbox name=dw_Audit%s></td></tr>"
		"<tr bgcolor=#E7E5DD><td>Allow SafedAgent to automatically set file audit configuration?</td><td><input type=checkbox name=dw_FileAudit%s></td></tr><tr bgcolor=#FFFFFF><td><br></td><td><br></td></tr>"
		"<tr bgcolor=#DEDBD2><td>Export NetEye Cache data to a file?</td><td><input type=checkbox name=dw_FileExport%s></td></tr>"
		"<tr bgcolor=#E7E5DD><td>Number of Cache files</td><td><input type=text size=5  name=dw_NumberFiles value=\"%d\"></td></tr><tr bgcolor=#FFFFFF><td><br></td><td><br></td></tr>"
		"<tr bgcolor=#DEDBD2><td>Number of Safed Log files</td><td><input type=text size=5  name=dw_NumberLogFiles value=\"%d\"></td></tr>",
		dest,
		(config_struct.dw_CritAudit != 0?" checked":""),
		(config_struct.dw_Audit != 0?" checked":""),
		(config_struct.dw_FileAudit != 0?" checked":""),
		(config_struct.dw_FileExport != 0?" checked":""),
		 config_struct.dw_NumberFiles,
		 config_struct.dw_NumberLogFiles);

	_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#E7E5DD><td>Log level</td><td><select name=dw_LogLevel>",dest);
	for (i = NONE_LOG; i <= DEBUG_LOG; i++)
	{
		_snprintf_s(dest,size,_TRUNCATE,"%s<option",dest);
		if (i == config_struct.dw_LogLevel) {
			_snprintf_s(dest,size,_TRUNCATE,"%s selected>",dest);
		} else {
			_snprintf_s(dest,size,_TRUNCATE,"%s>",dest);
		}
		_snprintf_s(dest,size,_TRUNCATE,"%s%s",dest,str_log[i]);
	}
	_snprintf_s(dest,size,_TRUNCATE,"%s</select></td></tr>",dest);

	_snprintf_s(dest,size,_TRUNCATE,
		"%s<tr bgcolor=#FFFFFF><td><br></td><td><br></td></tr>"
		"<tr bgcolor=#E7E5DD><td>Max Message Size</td><td><input type=text size=7  name=dw_MaxMsgSize value=\"%d\"></td></tr><tr bgcolor=#FFFFFF><td><br></td><td><br></td></tr>",
		dest,
		network_struct.dw_MaxMsgSize);



	// First 3 bits = facility (eg: emerg, alert, etc.)
	// Rest = priority. Note that there is a gap between ftp and local1.
	i_SyslogPriority = (UINT)network_struct.dw_SyslogDest & 7;
	i_SyslogFacility = (UINT)network_struct.dw_SyslogDest >> 3;
	if(i_SyslogFacility > 11) { 
		i_SyslogFacility = i_SyslogFacility - 4;
	}

	if(network_struct.dw_DynamicCritic) {
		i_SyslogPriority=8;
	}

	//Need to convert this next section to YES or NO
	strncat_s(dest,size,"<tr bgcolor=#DEDBD2><td>Enable SYSLOG Header?</td><td><input type=checkbox name=dw_Syslog",_TRUNCATE);
	if (network_struct.dw_Syslog != 0) {
		strncat_s(dest,size," checked",_TRUNCATE);
	}
	strncat_s(dest,size,"></td></tr>",_TRUNCATE);

	strncat_s(dest,size,"<tr bgcolor=#E7E5DD><td>SYSLOG Facility </td><td><select name=SyslogFacility>",_TRUNCATE);
	for (i = 0; i <= 19; i++)
	{
		strncat_s(dest,size,"<option",_TRUNCATE);
		if (i == i_SyslogFacility) {
			strncat_s(dest,size," selected>",_TRUNCATE);
		} else {
			strncat_s(dest,size,">",_TRUNCATE);
		}
		strncat_s(dest,size,str_facility[i],_TRUNCATE);
	}
	strncat_s(dest,size,"</select></td></tr>",_TRUNCATE);

	strncat_s(dest,size,"<tr bgcolor=#DEDBD2><td>SYSLOG Priority </td><td><select name=SyslogPriority>",_TRUNCATE);
	for (i = 0; i <= 8; i++) {
		strncat_s(dest,size,"<option",_TRUNCATE);
		if (i == i_SyslogPriority) {
			strncat_s(dest,size," selected>",_TRUNCATE);
		} else {
			strncat_s(dest,size,">",_TRUNCATE);
		}
		strncat_s(dest,size,str_priority[i],_TRUNCATE);
	}
	
	strncat_s(dest,size,"</select></td></tr>" \
		         "</table><br>" \
				 /*"<input type=button value=\"Change Configuration\" onclick=\"if(netform.dw_Audit.checked==false){ if(confirm(\'SafedAgent will NOT set automatically audit configuration!!\')){ netform.submit()} else { netform.reset()}}else{netform.submit()}\">    " \*/
				 "<input type=submit value=\"Change Configuration\" />    " \
				 "<input type=reset value=\"Reset Form\"/></form>",_TRUNCATE);
	
	return(0);
}


int SysAdmin_Config(char *source, char *dest, int size)
{
	//All strncpy_s or strncat_s functions in this routine have been designed avoid overflows
	Reg_SysAdmin sysadmin_struct;
	DWORD dw_sysadmin_error;
		
	dw_sysadmin_error = Read_SysAdmin_Registry(&sysadmin_struct);

	// This function will display the form used to set the audit configuration
	// The result of the form will be sent to "sysadmin_set"
	strncpy_s(dest,size,"<form method=get action=setsysadmin><h2><center>SafedAgent System Administrator Logging Configuration</h2>",_TRUNCATE);

	// Will display an error if unable to completely read from the registry
	if (dw_sysadmin_error > 0) {
		dw_sysadmin_error += WEB_READ_SYSADMIN_ERROR_CODE;

		_snprintf_s(dest,size,_TRUNCATE,"%s<br><b>NOTE: Some errors were encountered in reading the registry. Default values " \
					"may be used.<br> Report error: %d.</b><br>",dest,dw_sysadmin_error);
	}

	strncat_s(dest,size,"<br>The following system administrator logging configuration parameters of the SafedAgent unit is set to the following values:<br><br>" \
				"<table  width=70% border=0>",_TRUNCATE);


	//Need to convert this next section to YES or NO
	strncat_s(dest,size,"<tr bgcolor=#DEDBD2><td>Enable System Administrator Logging?<br><i>It is recommended to not use other Logon/Logoff filters together with this check!</i></td><td><input type=checkbox name=dw_SysAdminEnable",_TRUNCATE);
	if (sysadmin_struct.dw_SysAdminEnable != 0) {
		strncat_s(dest,size," checked",_TRUNCATE);
	}
	strncat_s(dest,size," onMouseover=\"ddrivetip(\'It is recommended to not use other Logon/Logoff filters together with this check!\')\" onMouseout=\"hideddrivetip()\"></td></tr>",_TRUNCATE);
	_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#E7E5DD><td>Times a day</td><td><input type=text size=7  name=dw_TimesADay value=\"%d\"></td></tr>",dest,sysadmin_struct.dw_TimesADay);

	strncat_s(dest,size,"<tr bgcolor=#DEDBD2><td>Force Next System Administrator Discovery?</td><td><input type=checkbox name=dw_ForceSysAdmin",_TRUNCATE);
	if (sysadmin_struct.dw_ForceSysAdmin != 0) {
		strncat_s(dest,size," checked",_TRUNCATE);
	}	
	strncat_s(dest,size,"></td></tr><tr bgcolor=#E7E5DD><td>Use VBS System Administrator Discovery?</td><td><input type=checkbox name=dw_VBS",_TRUNCATE);
	if (sysadmin_struct.dw_VBS != 0) {
		strncat_s(dest,size," checked",_TRUNCATE);
	}	
	strncat_s(dest,size,"></td></tr><tr bgcolor=#DEDBD2><td>Use System Administrator Filter as a Last?</td><td><input type=checkbox name=dw_LastSA",_TRUNCATE);
	if (sysadmin_struct.dw_LastSA != 0) {
		strncat_s(dest,size," checked",_TRUNCATE);
	}	

	strncat_s(dest,size,"></td></tr></table><br>" \
				 "<input type=submit value=\"Change Configuration\">    " \
				 "<input type=reset value=\"Reset Form\"></form>",_TRUNCATE);

	return(0);
}



int SysAdmin_Set(char *source, char *dest, int size)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	char *psource=source;
	char Variable[100]="",  time_a_day[100]="";
	char Argument[100]="";
	Reg_SysAdmin sysadmin_struct;
	DWORD dw_error_sysadmin = 1;

	if(!source || !dest || !size) {
		return(0);
	}

	// This function will display that the remote audit configurations have been changed, or there have been errors
	strncpy_s(dest,size,"<h2><center>SafedAgent System Administrator Logging Configuration</h2>",_TRUNCATE);

	sysadmin_struct.dw_SysAdminEnable = 0;
	sysadmin_struct.dw_TimesADay = 1;
	sysadmin_struct.dw_ForceSysAdmin = 0;
	sysadmin_struct.dw_VBS = 0;
	sysadmin_struct.dw_LastSA = 0;

	while((psource=GetNextArgument(psource,Variable,_countof(Variable),Argument,_countof(Argument))) != (char *)NULL) 
	{	

		if (strstr(Variable,"dw_SysAdminEnable") != NULL) {
			if (strcmp(Argument,"on") == 0)
				sysadmin_struct.dw_SysAdminEnable = 1;
		}
		if (strstr(Variable,"dw_TimesADay") != NULL) {
			strncpy_s(time_a_day,_countof(time_a_day),Argument,_TRUNCATE);
			sysadmin_struct.dw_TimesADay = atoi(time_a_day);
		}
		if (strstr(Variable,"dw_ForceSysAdmin") != NULL) {
			if (strcmp(Argument,"on") == 0)
				sysadmin_struct.dw_ForceSysAdmin = 1;
		}
		if (strstr(Variable,"dw_VBS") != NULL) {
			if (strcmp(Argument,"on") == 0)
				sysadmin_struct.dw_VBS = 1;
		}
		if (strstr(Variable,"dw_LastSA") != NULL) {
			if (strcmp(Argument,"on") == 0)
				sysadmin_struct.dw_LastSA = 1;
		}

	}

	dw_error_sysadmin = Write_SysAdmin_Registry(&sysadmin_struct);

	if (dw_error_sysadmin != 0) {
		strncat_s(dest,size,"Values have NOT been changed.",_TRUNCATE);
	} else {
		strncat_s(dest,size,"Values have been changed.",_TRUNCATE);
	}
	return(0);

}



int Network_Set(char *source, char *dest, int size)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	char *psource=source;
	char Variable[100]="", cache_size[100]="", web_port[100]="", number_files[100]="",log_levels[100]="",number_logfiles[100]="", msg_size[100]="", protocol[10] = "", syslog_fac[100]="",syslog_pri[100]="";
	char Argument[100]="";
	char *str_facility[] = {"Kernel","User","Mail","Daemon","Auth","Syslog","Lpr","News","UUCP","Cron","Authpriv","Ftp","Local0","Local1","Local2","Local3","Local4","Local5","Local6","Local7"};
	char *str_priority[] = {"Emergency","Alert","Critical","Error","Warning","Notice","Information","Debug"};
	char *str_protocol[] = {"UDP", "TCP", "TLS"};
	char *str_log[] = {"NONE", "ERROR", "WARNING","INFORMATION", "DEBUG"};
	Reg_Network network_struct;
	Reg_Config config_struct;
	Reg_Remote remote_struct;
	DWORD dw_error_network = 1,dw_error_config = 1,dw_SyslogClass = 0, dw_error = 0;
	int i,error=0;

	if(!source || !dest || !size) {
		return(0);
	}

	dw_error = Read_Remote_Registry(&remote_struct);
	// This function will display that the remote audit configurations have been changed, or there have been errors
	strncpy_s(dest,size,"<h2><center>SafedAgent Network Configuration</h2>",_TRUNCATE);

	// Note that all the possible variables do NOT have to be in the URL. The ones that are selected
	// via a checkbox will not be listed if the checkbox has been deselected.
	// Checking is limited to ensuring the Detsination port in the range 1-65535.
	// The variable associated with the checkbox (dw_Syslog) must be
	// exactly "on" or it will be defaulted to "off".

	network_struct.dw_DestPort = -1;
	network_struct.dw_SocketType=SOCKETTYPE_UDP;	// UDP
	network_struct.dw_Syslog = 0;
	network_struct.dw_MaxMsgSize = 0;
	config_struct.dw_Audit = 0;
	config_struct.dw_FileAudit = 0;
	config_struct.dw_FileExport = 0;
	config_struct.dw_NumberFiles = 0;
	config_struct.dw_NumberLogFiles = 0;
	config_struct.dw_LogLevel = 0;


	while((psource=GetNextArgument(psource,Variable,_countof(Variable),Argument,_countof(Argument))) != (char *)NULL) 
	{	
		if (strstr(Variable,"str_ClientName") != NULL) {
			strncpy_s(config_struct.str_ClientName,_countof(config_struct.str_ClientName),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"str_Destination") != NULL) {
			strncpy_s(network_struct.str_Destination,_countof(network_struct.str_Destination),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"dw_DestPort") != NULL)	{
			strncpy_s(web_port,_countof(web_port),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"dw_SocketType") != NULL)	{
			strncpy_s(protocol,_countof(protocol),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"SyslogPriority") != NULL) {
			strncpy_s(syslog_pri,_countof(syslog_pri),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"SyslogFacility") != NULL) {
			strncpy_s(syslog_fac,_countof(syslog_fac),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"dw_Syslog") != NULL) {
			if (strcmp(Argument,"on") == 0)
				network_struct.dw_Syslog = 1;
		}
		if (strstr(Variable,"dw_Audit") != NULL) {
			if (strcmp(Argument,"on") == 0)
				config_struct.dw_Audit = 1;
		}
		if (strstr(Variable,"dw_FileAudit") != NULL) {
			if (strcmp(Argument,"on") == 0)
				config_struct.dw_FileAudit = 1;
		}
		if (strstr(Variable,"dw_FileExport") != NULL) {
			if (strcmp(Argument,"on") == 0)
				config_struct.dw_FileExport = 1;
		}
		if (strstr(Variable,"dw_NumberFiles") != NULL)	{
			strncpy_s(number_files,_countof(number_files),Argument,_TRUNCATE);
			config_struct.dw_NumberFiles = atoi(number_files);
		}
		if (strstr(Variable,"dw_NumberLogFiles") != NULL)	{
			strncpy_s(number_logfiles,_countof(number_logfiles),Argument,_TRUNCATE);
			config_struct.dw_NumberLogFiles = atoi(number_logfiles);
		}
		if (strstr(Variable,"dw_LogLevel") != NULL)	{
			strncpy_s(log_levels,_countof(log_levels),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"dw_MaxMsgSize") != NULL)	{
			strncpy_s(msg_size,_countof(msg_size),Argument,_TRUNCATE);
			network_struct.dw_MaxMsgSize = atoi(msg_size);
		}
		if (strstr(Variable,"dw_CritAudit") != NULL) {
			if (strcmp(Argument,"on") == 0)
				config_struct.dw_CritAudit = 1;
		}

	}

	for (i = 0; i <= 7; i++) {
		if (strstr(syslog_pri,str_priority[i]) != NULL) {
			network_struct.dw_SyslogDest = i;
			break;
		}
	}
	for (i = 0; i <= 20; i++) {
		if (strstr(syslog_fac,str_facility[i]) != NULL) {
			dw_SyslogClass = i;
			break;
		}
	}

	if(network_struct.dw_SyslogDest > 7) {
		network_struct.dw_SyslogDest=0;
		network_struct.dw_DynamicCritic=1;
	} else {
		network_struct.dw_DynamicCritic=0;
	}

	if(dw_SyslogClass > 11) {
		dw_SyslogClass = dw_SyslogClass + 4;
	}
	network_struct.dw_SyslogDest = network_struct.dw_SyslogDest | (dw_SyslogClass << 3);

	network_struct.dw_DestPort = atoi(web_port);
	if ((network_struct.dw_DestPort < 1) || (network_struct.dw_DestPort > 65535)) {
		strncat_s(dest,size,"The Destination Port value must be between 1 and 65535. Use the 'back' button to change the value.",_TRUNCATE);
		error=1;
	}

	if(!strncmp(protocol, str_protocol[SOCKETTYPE_TCP],3)){
		network_struct.dw_SocketType = SOCKETTYPE_TCP;
	}else if(!strncmp(protocol, str_protocol[SOCKETTYPE_TCP_TLS],3)){
		network_struct.dw_SocketType = SOCKETTYPE_TCP_TLS;
	}else {
		network_struct.dw_SocketType = SOCKETTYPE_UDP;
	}

	if(!strncmp(log_levels, str_log[ERROR_LOG],5)){
		config_struct.dw_LogLevel = ERROR_LOG;
	}else if(!strncmp(log_levels, str_log[WARNING_LOG],7)){
		config_struct.dw_LogLevel = WARNING_LOG;
	}else  if(!strncmp(log_levels, str_log[INFORMATION_LOG],11)){
		config_struct.dw_LogLevel = INFORMATION_LOG;
	}else  if(!strncmp(log_levels, str_log[DEBUG_LOG],5)){
		config_struct.dw_LogLevel = DEBUG_LOG;
	}else {
		config_struct.dw_LogLevel = NONE_LOG;
	}

	if (!error) {

		dw_error_network = Write_Network_Registry(&network_struct);

		dw_error_config = Write_Config_Registry(&config_struct);
		if ((dw_error_network != 0) || (dw_error_config != 0)) {
			strncat_s(dest,size,"Values have NOT been changed.",_TRUNCATE);
		} else {
			strncat_s(dest,size,"Values have been changed.",_TRUNCATE);
		}
	}
	return(0);

}


int Remote_Config(char *source, char *dest, int size)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	Reg_Remote remote_struct;
	DWORD dw_remote_error;

	dw_remote_error = Read_Remote_Registry(&remote_struct);

	// This function will display the form used to set the remote audit configuration
	strncpy_s(dest,size,"\n<form method=get action=setremote><h2><center>SafedAgent Remote Control Configuration</h2>",_TRUNCATE);

	// Will display an error if unable to completely read from the registry
	if (dw_remote_error > 0)
	{
		dw_remote_error += WEB_READ_REMOTE_ERROR_CODE;
		
		_snprintf_s(dest,size,_TRUNCATE,"%s<br><b>NOTE: Some errors were encountered in reading the registry. Default values " \
					"may be used.<br> Report error: %d</b><br>\n",dest,dw_remote_error);
	}
	strncat_s(dest,size,"<br>The following remote control configuration parameters of the SafedAgent unit is set to the following values:<br><br>" \
		"<table  width=70% border=0>",_TRUNCATE);

	strncat_s(dest,size,"<tr bgcolor=#DEDBD2><td>Restrict remote control of SafedAgent to certain hosts </td><td><input type=checkbox name=dw_Restrict",_TRUNCATE);

	if (remote_struct.dw_Restrict != 0)
		strncat_s(dest,size," checked",_TRUNCATE);
	strncat_s(dest,size,"></td></tr>\n",_TRUNCATE);

	strncat_s(dest,size,"<tr bgcolor=#E7E5DD><td>IP Addresses allowed to remote control SafedAgent <br><i>(max 10 hosts ; separated) </i></td><td><input type=text name=str_RestrictIP size=12 value=\"",_TRUNCATE);
	strncat_s(dest,size,remote_struct.str_RestrictIP,_TRUNCATE);
	strncat_s(dest,size,"\"></td></tr>\n",_TRUNCATE);
	
	_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#DEDBD2><td>Require a password for remote control? </td><td><input type=checkbox name=dw_Password%s></td></tr>\n",dest,(remote_struct.dw_Password != 0?" checked":""));

	_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#E7E5DD><td>Password to allow remote control of SafedAgent </td><td><input type=password name=str_Password size=12 value=\"%s\"></td></tr>\n",dest,remote_struct.str_Password);

	strncat_s(dest,size,"<tr bgcolor=#DEDBD2><td>Change Web Server default (6161) port </td><td><input type=checkbox name=dw_PortChange",_TRUNCATE);

	if (remote_struct.dw_WebPortChange != 0)
		strncat_s(dest,size," checked",_TRUNCATE);
	strncat_s(dest,size,"></td></tr>\n",_TRUNCATE);

	_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#E7E5DD><td>Web Server Port </td><td><input type=text name=dw_WebPort size=8 value=\"%d\"></td></tr>\n",dest,remote_struct.dw_WebPort);
	strncat_s(dest,size,"<tr bgcolor=#DEDBD2><td>HTTPS protocol</td><td><input type=checkbox name=dw_TLS",_TRUNCATE);
	if (remote_struct.dw_TLS != 0)
		strncat_s(dest,size," checked",_TRUNCATE);
	strncat_s(dest,size,"></td></tr>\n",_TRUNCATE);

	strncat_s(dest,size,"</table><br>\n"
						"<input type=submit value=\"Change Configuration\">    "
						"<input type=reset value=\"Reset Form\"></form>",_TRUNCATE);
	
	return(0);
}

int Remote_Set(char *source, char *dest, int size) 
{
	// All strncpy or strncat functions in this routine have been designed avoid overflows
	char *psource=source;
	char Variable[100], web_port[100];
	char Argument[100];
	Reg_Remote remote_struct;
	Reg_Network network_struct;
	DWORD dw_error = 0;
	
	dw_error = Read_Remote_Registry(&remote_struct);
	dw_error = Read_Network_Registry(&network_struct);

	// This function will display that the remote audit configurations have been changed, or there have been errors
	strncpy_s(dest,size,"<h2><center>SafedAgent Remote Control Configuration</h2>",_TRUNCATE);

	// Note that all the possible variables do NOT have to be in the URL. The ones that are selected
	// via a checkbox will not be listed if the checkbox has been deselected.
	// Also be aware that there may not be any arguments for this objective. If a sysadmin does not want
	// remote control, then there will be no arguments.
	// Hence: Checking is limited to Webport in the range 1-65535 only if portchange is "on"
	// The three variable associated with the checkboxes (dw_Allow, dw_Restrict, dw_TLS and dw_PortChange) must be
	// exactly "on" or they will be defaulted to "off".
	// str_RestrictIP can be anything it wants to be, so long as it is within size bounds.

	// Configure the defaults.
	remote_struct.dw_WebPort = -1;
	remote_struct.dw_Password = 0;
	remote_struct.dw_Restrict = 0;
	remote_struct.dw_WebPortChange = 0;
	remote_struct.dw_TLS = 0;

	while((psource=GetNextArgument(psource,Variable,_countof(Variable)-1,Argument,_countof(Argument)-1)) != (char *)NULL) 
	{	
		if (strstr(Variable,"dw_WebPort") != NULL) {
			strncpy_s(web_port,_countof(web_port),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"str_RestrictIP") != NULL) {
			strncpy_s(remote_struct.str_RestrictIP,_countof(remote_struct.str_RestrictIP),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"str_Password") != NULL) {
			if(strcmp(Argument,remote_struct.str_Password)!=0) {
				// Changed
				// mD5 things here.
				strncpy_s(remote_struct.str_Password,_countof(remote_struct.str_Password),MD5String(Argument),_TRUNCATE);
			}
		}
		if (strstr(Variable,"dw_Password") != NULL)	{
			if (strcmp(Argument,"on") == 0) {
				remote_struct.dw_Password = 1;
			} else {
				remote_struct.dw_Password = 0;
			}
		}
		if (strstr(Variable,"dw_Restrict") != NULL)
		{
			if (strcmp(Argument,"on") == 0) {
				remote_struct.dw_Restrict = 1;
			} else {
				remote_struct.dw_Restrict = 0;
			}
		}
		if (strstr(Variable,"dw_PortChange") != NULL)
		{
			if (strcmp(Argument,"on") == 0) {
				remote_struct.dw_WebPortChange = 1;
			} else {
				remote_struct.dw_WebPortChange = 0;
			}
		}
		if (strstr(Variable,"dw_TLS") != NULL)
		{
			if (strcmp(Argument,"on") == 0) {
				remote_struct.dw_TLS = 1;
			} else {
				remote_struct.dw_TLS = 0;
			}
		}
	}

	remote_struct.dw_WebPort = atoi(web_port);
	if ((remote_struct.dw_WebPort < 1) || (remote_struct.dw_WebPort > 65535)) {
		strncat_s(dest,size,"The Web Port value must be between 1 and 65535. Use the 'back' button to change the value.",_TRUNCATE);
	} else {
		// Check remote_struct.str_Password against the existing password.
		
		dw_error = Write_Remote_Registry(&remote_struct);
		if (dw_error != 0)
		{
			strncat_s(dest,size,"Remote Control Values have NOT been changed. Report error: ",_TRUNCATE);
			//**********PUT AN ERROR CODE IN HERE
		} else {
			strncat_s(dest,size,"Remote Control Values have been changed.",_TRUNCATE);
		}
	}
	return(0);
}


int Objective_Config(char *source, char *dest, int size)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	Reg_Objective reg_objective;
	DWORD dw_objective_error = 0;
	int i_objective_count = 0;
	char str_user_match_metachar_remove[SIZE_OF_USERMATCH*2];
	char str_eventid_match_metachar_remove[SIZE_OF_EVENTIDMATCH*2];
	char str_general_match_metachar_remove[SIZE_OF_GENERALMATCH*2];


	strncpy_s(dest,size,"<form method=get action=/safed/setobjective><H2><CENTER>SafedAgent Filtering Objectives Configuration</H2>",_TRUNCATE);
		
	dw_objective_error = Read_Objective_Registry(i_objective_count,&reg_objective);
	if (dw_objective_error == 0)
	{
		strncat_s(dest,size,"<br>The following filtering objectives of the SafedAgent unit are active:<br><br>" \
		"<table  width=100% border=1>",_TRUNCATE);

		strncat_s(dest,size,"<tr bgcolor=#F0F1F5><center><td><b>Action Required</b></td><td><b>Criticality</b></td>" \
			        "<td><b>Event ID Include/Exclude</b></td><td><b>Event ID Match</b></td><td><b>User Include/Exclude</b></td><td><b>User Match</b></td><td><b>General Match Include/Exclude</b></td><td><b>General Match</b>" \
					"</td><td><b>Return</b></td><td><b>Event Src</b></td><td><b>Order</b></td></center></tr>",_TRUNCATE);

		while (dw_objective_error == 0)
		{
			if ((i_objective_count%2) == 0)
				strncat_s(dest,size,"<tr bgcolor=#DEDBD2>",_TRUNCATE);
			else
				strncat_s(dest,size,"<tr bgcolor=#E7E5DD>",_TRUNCATE);

			_snprintf_s(dest,size,_TRUNCATE,"%s<td><input type=submit name=%d value=Delete> <input type=submit name=%d value=Modify></td><td>",dest,i_objective_count,i_objective_count);

			if (_stricmp(reg_objective.str_critic,CRITICAL_TOKEN) == 0) {
				strncat_s(dest,size,"<font color=\"red\">Critical</font>",_TRUNCATE);
			} else if(_stricmp(reg_objective.str_critic,PRIORITY_TOKEN) == 0) {
				strncat_s(dest,size,"<font color=\"orange\">Priority</font>",_TRUNCATE);
			} else if (_stricmp(reg_objective.str_critic,WARNING_TOKEN) == 0) {
				strncat_s(dest,size,"<font color=\"blue\">Warning</font>",_TRUNCATE);
			} else if (_stricmp(reg_objective.str_critic,INFORMATION_TOKEN) == 0) {
				strncat_s(dest,size,"<font color=\"green\">Information</font>",_TRUNCATE);
			} else {
				strncat_s(dest,size,"<font color=\"black\">Clear</font>",_TRUNCATE);
			}
			strncat_s(dest,size,"</td><td>",_TRUNCATE);


			// Debracket the strings in here. For HTML display purposes, the HTML metacharacters
			// need to be replaced. This is done with the "debracket" routine.
			// Note that the new strings are allowed to be twice as long as the real strings

			debracket(reg_objective.str_user_match,str_user_match_metachar_remove,SIZE_OF_USERMATCH*2);
			debracket(reg_objective.str_eventid_match,str_eventid_match_metachar_remove,SIZE_OF_EVENTIDMATCH*2);
			debracket(reg_objective.str_general_match,str_general_match_metachar_remove,SIZE_OF_GENERALMATCH*2);

			if(reg_objective.dw_event_match_type!=0) {
				strncat_s(dest,size,"Exclude",_TRUNCATE);
			} else {
				strncat_s(dest,size,"Include",_TRUNCATE);
			}
			strncat_s(dest,size,"</td><td>      ",_TRUNCATE);

			if (strlen(reg_objective.str_eventid_match) == 0) {
				strncat_s(dest,size,"&nbsp",_TRUNCATE);
			} else {
				strncat_s(dest,size,str_eventid_match_metachar_remove,_TRUNCATE);
			}
			strncat_s(dest,size,"</td><td>      ",_TRUNCATE);

			if(reg_objective.dw_user_match_type!=0) {
				strncat_s(dest,size,"Exclude",_TRUNCATE);
			} else {
				strncat_s(dest,size,"Include",_TRUNCATE);
			}
			strncat_s(dest,size,"</td><td>      ",_TRUNCATE);
			
			if (strlen(reg_objective.str_user_match) == 0) {
				strncat_s(dest,size,"&nbsp",_TRUNCATE);
			} else {
				strncat_s(dest,size,str_user_match_metachar_remove,_TRUNCATE);
			}
			strncat_s(dest,size,"</td><td>",_TRUNCATE);

			if(reg_objective.dw_general_match_type!=0) {
				strncat_s(dest,size,"Exclude",_TRUNCATE);
			} else {
				strncat_s(dest,size,"Include",_TRUNCATE);
			}
			strncat_s(dest,size,"</td><td>",_TRUNCATE);

			if (strlen(reg_objective.str_general_match) == 0) {
				strncat_s(dest,size,"&nbsp",_TRUNCATE);
			} else {
				strncat_s(dest,size,str_general_match_metachar_remove,_TRUNCATE);
			}
			strncat_s(dest,size,"</td><td>",_TRUNCATE);

			if(reg_objective.dw_event_type & TYPE_SUCCESS) {
				strncat_s(dest,size,"Success<br>",_TRUNCATE);
			}
			if(reg_objective.dw_event_type & TYPE_FAILURE) {
				strncat_s(dest,size,"Failure<br>",_TRUNCATE);
			}
			if(reg_objective.dw_event_type & TYPE_ERROR) {
				strncat_s(dest,size,"Error<br>",_TRUNCATE);
			}
			if(reg_objective.dw_event_type & TYPE_INFO) {
				strncat_s(dest,size,"Information<br>",_TRUNCATE);
			}
			if(reg_objective.dw_event_type & TYPE_WARN) {
				strncat_s(dest,size,"Warning<br>",_TRUNCATE);
			}
			strncat_s(dest,size,"</td><td>",_TRUNCATE);

			
			if(reg_objective.dw_eventlog_type & LOG_SEC) {
				strncat_s(dest,size,"Security<br>",_TRUNCATE);
			}
			if(reg_objective.dw_eventlog_type & LOG_SYS) {
				strncat_s(dest,size,"System<br>",_TRUNCATE);
			}
			if(reg_objective.dw_eventlog_type & LOG_APP) {
				strncat_s(dest,size,"Application<br>",_TRUNCATE);
			}
			if(reg_objective.dw_eventlog_type & LOG_DIR) {
				strncat_s(dest,size,"Active Directory Service<br>",_TRUNCATE);
			}
			if(reg_objective.dw_eventlog_type & LOG_DNS) {
				strncat_s(dest,size,"Domain Name Server<br>",_TRUNCATE);
			}
			if(reg_objective.dw_eventlog_type & LOG_REP) {
				strncat_s(dest,size,"Replication Service<br>",_TRUNCATE);
			}
			if(reg_objective.dw_eventlog_type & LOG_CUS) {
				strncat_s(dest,size,"Custom<br>",_TRUNCATE);
			}

			strncat_s(dest,size,"</td><td>",_TRUNCATE);
			if (i_objective_count != 0) {
				_snprintf_s(dest,size,_TRUNCATE,"%s<div align=center style=\"margin-bottom: 5px; border-left: 2px solid #eeeeee; border-top: 2px solid #eeeeee; border-right: 2px solid #aaaaaa; border-bottom: 2px solid #aaaaaa; background-color: #dddddd\"><a href=\"/safed/setobjective?%d=MoveUp\" style=\"font-size: 9px; color: #33aa33; text-decoration: none; display: block;\">&#9650;</a></div>",dest,i_objective_count);
			}

			i_objective_count++;
			dw_objective_error = Read_Objective_Registry(i_objective_count,&reg_objective);

			if (dw_objective_error == 0) {
				_snprintf_s(dest,size,_TRUNCATE,"%s<div align=center style=\"margin-bottom: 5px; border-left: 2px solid #eeeeee; border-top: 2px solid #eeeeee; border-right: 2px solid #aaaaaa; border-bottom: 2px solid #aaaaaa; background-color: #dddddd\"><a href=\"/safed/setobjective?%d=MoveDown\" style=\"font-size: 9px; color: #33aa33; text-decoration: none; display: block;\">&#9660;</a></div>",dest,i_objective_count-1);
			}
			strncat_s(dest,size,"</td></tr>",_TRUNCATE);
		}
		strncat_s(dest,size,"</table><br>",_TRUNCATE);
	} else {
		strncat_s(dest,size,"<br>There are no current filtering objectives active.<br><br>",_TRUNCATE);
	}

	strncat_s(dest,size,"Select this button to add a new objective.  ",_TRUNCATE);
	strncat_s(dest,size,"<input type=submit name=0",_TRUNCATE);
	strncat_s(dest,size," value=Add>",_TRUNCATE);


	return(0);
}


DWORD getCustomLogNames(char CustomLogNameList[MAXCUSTOMLOGS][SIZE_OF_EVENTLOG])
{
   DWORD tot = 0;
   for(int i =0 ; i < MAXCUSTOMLOGS; i++)
		CustomLogNameList[i][0]='\0';
   HKEY hTestKey;
   TCHAR szKeyName[MAX_STRING]="";
	_snprintf_s(szKeyName, _countof(szKeyName),_TRUNCATE,_T("SYSTEM\\CurrentControlSet\\Services\\EventLog"));

   if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
        szKeyName,
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
      )
   {
      tot = QueryKey(hTestKey, CustomLogNameList,MAXCUSTOMLOGS, SIZE_OF_EVENTLOG);
	  for(int i =0 ; i < tot; i++){
		if(!strcmp(CustomLogNameList[i],"Security") || !strcmp(CustomLogNameList[i],"Application")||
			!strcmp(CustomLogNameList[i],"Directory Service") || !strcmp(CustomLogNameList[i],"DNS Server")||
			!strcmp(CustomLogNameList[i],"System") || !strcmp(CustomLogNameList[i],"File Replication Service"))
			CustomLogNameList[i][0]='\0';
	  }
   }
   
   RegCloseKey(hTestKey);
   return tot;
}


int Objective_Display(char *source, char *dest, int size)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	Reg_Objective reg_objective;
	DWORD dw_objective_error = 0, dw_objective_write_error = 0,dw_objective_delete_error = 0;
	int i_objective_count = 0,i_type = 0;
	char *psource=source, Variable[100], Argument[100];
	char str_temp[20], str_temp_objective[10];
	

	//This function will display an existing, or a blank, objective
	strncpy_s(dest,size,"<form method=get action=/safed/changeobjective><h2><center>SafedAgent Filtering Objective Configuration</h2>",_TRUNCATE);

	//Determine whether the objective will be modified or deleted
	while((psource=GetNextArgument(psource,Variable,_countof(Variable)-1,Argument,_countof(Argument)-1)) != (char *)NULL) 
	{
		if (strstr(Argument,"Add") != NULL) {
			strncpy_s(str_temp_objective,_countof(str_temp_objective),"-2",_TRUNCATE);
			i_type = 2;
			break;
		} else {
			sscanf_s(Variable,"%20[^?]?%10[^\n]\n",str_temp,_countof(str_temp),str_temp_objective,_countof(str_temp_objective));
			if (strstr(Argument,"MoveUp") != NULL) {
				i_type = -2;
			} else if (strstr(Argument,"MoveDown") != NULL) {
				i_type = -1;
			} else if (strstr(Argument,"Delete") != NULL) {
				i_type = 0;
			} else if (strstr(Argument,"Modify") != NULL) {
				i_type = 1;
			} else {
				continue;
			}
			break;
		}
	}

	//Extract the objective number. I have to do this stuff, because atoi returns 0 if it cannot convert the string
	if (strcmp(str_temp_objective,"0") == 0)
		i_objective_count = -1;
	else
		i_objective_count = atoi(str_temp_objective);

	//If the objective number could not be successfully extracted, return immediately.
	if (i_objective_count == 0) {
		strncat_s(dest,size,"<br><b>NOTE: It appears the URL is encoded incorrectly.",_TRUNCATE);
		return 0;
	}

	if (i_objective_count == -1)
		i_objective_count = 0;
		
	//If the objective is being modified or added
	if (i_type > 0) {
		if (i_type == 1) {
			dw_objective_error = Read_Objective_Registry(i_objective_count,&reg_objective);
		} else {
			strncpy_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),SUCCESS_TOKEN,_TRUNCATE);
			strncpy_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),SECLOG_TOKEN,_TRUNCATE);
			strncpy_s(reg_objective.str_critic,_countof(reg_objective.str_critic),CRITICAL_TOKEN,_TRUNCATE);
			strncpy_s(reg_objective.str_eventid_match,_countof(reg_objective.str_eventid_match),LOGONOFF_TOKEN,_TRUNCATE);
			//strncpy_s(reg_objective.str_general_match,_countof(reg_objective.str_general_match),"*",_TRUNCATE);
			strncpy_s(reg_objective.str_general_match,_countof(reg_objective.str_general_match),"",_TRUNCATE);
			strncpy_s(reg_objective.str_user_match,_countof(reg_objective.str_user_match),"*",_TRUNCATE);
			strncpy_s(reg_objective.str_user_match_type,_countof(reg_objective.str_user_match_type),INCLUDE,_TRUNCATE);
			strncpy_s(reg_objective.str_event_match_type,_countof(reg_objective.str_event_match_type),INCLUDE,_TRUNCATE);
			strncpy_s(reg_objective.str_general_match_type,_countof(reg_objective.str_general_match_type),INCLUDE,_TRUNCATE);

		}

		// Will display an error if unable to completely read from the registry
		if (dw_objective_error > 0) {
			dw_objective_error += WEB_READ_OBJECTIVE_ERROR_CODE;
	
			_snprintf_s(dest,size,_TRUNCATE,"%s<br><b>NOTE: Some errors were encountered in reading the registry. Default values "
						"may be used.<br> Report error: %d</b><br>",dest,dw_objective_error);
		}

		strncat_s(dest,size,"<br>The following parameters of the SafedAgent objective may be set:<br><br>" \
			"<table  width=100% border=0>",_TRUNCATE);

		//Identify the high level event. Note that there is a table within a table in these radio buttons.
		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#DEDBD2><td>Identify the high level event</td><td><div id=\"hilvl\"><table  width=100%% border=0>"
			"<tr><td><input type=radio name=str_eventid_match value=%s%s>Logon or Logoff  </td>"
			    "<td><input type=radio name=str_eventid_match value=%s%s>Account Administration  </td></tr>"
			"<tr><td><input type=radio name=str_eventid_match value=%s%s>Access a file or directory  </td>"
			    "<td><input type=radio name=str_eventid_match value=%s%s>Change the security policy  </td></tr>"
			"<tr><td><input type=radio name=str_eventid_match value=%s%s>Start or stop a process  </td>"
			    "<td><input type=radio name=str_eventid_match value=%s%s>Restart, shutdown and system  </td></tr>"
			"<tr><td><input type=radio name=str_eventid_match value=%s%s>Use of user rights  </td>"
			    "<td><input type=radio name=str_eventid_match value=%s%s>USB Event  </td>",
			dest,
			LOGONOFF_TOKEN,(strstr(reg_objective.str_eventid_match,LOGONOFF_TOKEN) != NULL?" checked":""),
			MANAGE_TOKEN, (strstr(reg_objective.str_eventid_match,MANAGE_TOKEN) != NULL?" checked":""),
			FILE_TOKEN, (strstr(reg_objective.str_eventid_match,FILE_TOKEN) != NULL?" checked":""),
			SECPOL_TOKEN, (strstr(reg_objective.str_eventid_match,SECPOL_TOKEN) != NULL?" checked":""),
			PROCESS_TOKEN, (strstr(reg_objective.str_eventid_match,PROCESS_TOKEN) != NULL?" checked":""),
			REBOOT_TOKEN, (strstr(reg_objective.str_eventid_match,REBOOT_TOKEN) != NULL?" checked":""),
			USERRIGHTS_TOKEN, (strstr(reg_objective.str_eventid_match,USERRIGHTS_TOKEN) != NULL?" checked":"")
		);
		if (strstr(reg_objective.str_eventid_match,LOGONOFF_TOKEN) ||
			strstr(reg_objective.str_eventid_match,MANAGE_TOKEN) ||
			strstr(reg_objective.str_eventid_match,FILE_TOKEN) ||
			strstr(reg_objective.str_eventid_match,SECPOL_TOKEN) ||
			strstr(reg_objective.str_eventid_match,PROCESS_TOKEN) ||
			strstr(reg_objective.str_eventid_match,REBOOT_TOKEN) ||
			strstr(reg_objective.str_eventid_match,USERRIGHTS_TOKEN) )
		{
			reg_objective.str_eventid_match[0]='\0';
			strncat_s(dest,size,"</tr><tr><td colspan=2><input type=radio name=str_eventid_match id=\"anyevt\" value=Any_Event onMouseover=\"ddrivetip(\'You can filter events through the Event ID Search Term field   \')\" onMouseout=\"hideddrivetip()\">Any event(s) </td></tr></table></div></td></tr>",_TRUNCATE);
		} else {
			strncat_s(dest,size,"</tr></div><tr><td colspan=2><input type=radio name=str_eventid_match id=\"anyevt\" value=Any_Event checked>Any event(s) </td></tr></table></div></td></tr>",_TRUNCATE);
		}
	
		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#E7E5DD><td>Select the Event ID Match Type</td><td>"
			"<input type=radio name=str_event_match_type value=%s%s>Include    "
			"<input type=radio name=str_event_match_type value=%s%s>Exclude    </td></tr>",
			dest,
			INCLUDE, (strstr(reg_objective.str_event_match_type,INCLUDE) != NULL?" checked":""),
			EXCLUDE, (strstr(reg_objective.str_event_match_type,EXCLUDE) != NULL?" checked":"")
		);

		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#E7E5DD><td>Event ID Search Term<br><i>Optional, Comma separated: only used by the 'Any Event' setting above</i></td>"
				"<td><input type=text name=str_eventid_text size=50 value=\"%s\" onMouseover=\"ddrivetip(\'By example 512,513 - Restart and shutdown system \')\" onMouseout=\"hideddrivetip()\"></td></tr>",
			dest,
			reg_objective.str_eventid_match
		);

		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#E7E5DD><td>Select the General Search Type</td><td>"
			"<input type=radio name=str_general_match_type value=%s%s>Include    "
			"<input type=radio name=str_general_match_type value=%s%s>Exclude    </td></tr>",
			dest,
			INCLUDE, (strstr(reg_objective.str_general_match_type,INCLUDE) != NULL?" checked":""),
			EXCLUDE, (strstr(reg_objective.str_general_match_type,EXCLUDE) != NULL?" checked":"")
		);

		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#DEDBD2><td>General Search Term<br><a href=\"http://en.wikipedia.org/wiki/Regular_expression\"><i>Regular expressions accepted</i></a></td>"
			"<td><input type=text name=str_general_match size=50 value=\"%s\" onMouseover=\"ddrivetip(\'Use regular expressions like admin[1,2] to filter the event record payload  \')\" onMouseout=\"hideddrivetip()\" ></td></tr>",
			dest,
			reg_objective.str_general_match
		);



		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#E7E5DD><td>Select the User Match Type</td><td>"
			"<input type=radio name=str_user_match_type value=%s%s>Include    "
			"<input type=radio name=str_user_match_type value=%s%s>Exclude    </td></tr>",
			dest,
			INCLUDE,(strstr(reg_objective.str_user_match_type,INCLUDE) != NULL?" checked":""),
			EXCLUDE,(strstr(reg_objective.str_user_match_type,EXCLUDE) != NULL?" checked":"")
		);

		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#E7E5DD><td>User Search Term<br><i>User Names, comma separated. Wildcards accepted</i></td>"
			"<td><input type=text name=str_user_match size=50 value=\"%s\" onMouseover=\"ddrivetip(\'Use wildcards amin1,admini* to filter the event by User Name  \')\" onMouseout=\"hideddrivetip()\"></td></tr>",dest,reg_objective.str_user_match);

		//Identify the event type to capture. Note that there is a table within a table in these radio buttons.
		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#DEDBD2><td>Identify the event types to be captured</td><td><table  width=100%% border=0>"
			"<tr><td><input type=checkbox name=str_event_type_succ id=succ value=%s%s>Success Audit  </td>"
				"<td><input type=checkbox name=str_event_type_fail id=fail value=%s%s>Failure Audit  </td></tr>"
			"<tr><td><input type=checkbox name=str_event_type_info id=info value=%s%s>Information  </td>"
			    "<td><input type=checkbox name=str_event_type_warn id=warn value=%s%s>Warning  </td></tr>"
			"<tr><td><input type=checkbox name=str_event_type_error id=err value=%s%s>Error  </td></tr>"
			"</table></td></tr>",
			dest,
			SUCCESS_TOKEN, (strstr(reg_objective.str_event_type,SUCCESS_TOKEN) != NULL?" checked":""),
			FAILURE_TOKEN, (strstr(reg_objective.str_event_type,FAILURE_TOKEN) != NULL?" checked":""),
			INFO_TOKEN, (strstr(reg_objective.str_event_type,INFO_TOKEN) != NULL?" checked":""),
			WARN_TOKEN, (strstr(reg_objective.str_event_type,WARN_TOKEN) != NULL?" checked":""),
			ERROR_TOKEN, (strstr(reg_objective.str_event_type,ERROR_TOKEN) != NULL?" checked":"")
		);

	
		//Identify the log type to capture. Note that there is a table within a table in these radio buttons.
		//var alertDiv = document.getElementById(\"alert\");\n"
    //"            alertDiv.style.display = alertDiv.style.display == \"block\" ? \"none\" : \"block\";\n"
		_snprintf_s(dest,size,_TRUNCATE,
			"%s<tr bgcolor=#E7E5DD><td>Identify the event logs <br>(ignored if any objective other <br>than 'Any event(s)' is selected):</td><td><table  width=100%% border=0>"
			//"<tr><td><input type=checkbox name=str_eventlog_type_seclog onClick=\"document.getElementById('anyevt').checked=true;toggleDisabledGroup(document.getElementById('hilvl'));document.getElementById('succ').disabled=false;document.getElementById('fail').disabled=false;\" value=%s%s>Security  </td>"
			"<tr><td><input type=checkbox name=str_eventlog_type_seclog value=%s%s>Security  </td>"
			    "<td><input type=checkbox name=str_eventlog_type_syslog value=%s%s>System  </td></tr>"
			"<tr><td><input type=checkbox name=str_eventlog_type_applog value=%s%s>Application  </td>"
			    "<td><input type=checkbox name=str_eventlog_type_dirlog value=%s%s>Directory Service  </td></tr>"
			"<tr><td><input type=checkbox name=str_eventlog_type_dnslog value=%s%s>DNS Server  </td>"
			    "<td><input type=checkbox name=str_eventlog_type_replog value=%s%s>File Replication  </td></tr>"
			"<tr><td><input type=checkbox name=str_eventlog_type_cuslog value=%s%s>Custom  </td>"
				"<td><select name=str_eventlog_type_value_cuslog>",
			dest,
			SECLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,SECLOG_TOKEN) != NULL?" checked":""),
			SYSLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,SYSLOG_TOKEN) != NULL?" checked":""),
			APPLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,APPLOG_TOKEN) != NULL?" checked":""),
			DIRLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,DIRLOG_TOKEN) != NULL?" checked":""),
			DNSLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,DNSLOG_TOKEN) != NULL?" checked":""),
			REPLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,REPLOG_TOKEN) != NULL?" checked":""),
			CUSLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,CUSLOG_TOKEN) != NULL?" checked":"")
		);
		char CustomLogNameList[MAXCUSTOMLOGS][SIZE_OF_EVENTLOG];//max 100 Event Logs are supported
		DWORD totcustom = getCustomLogNames(CustomLogNameList);
		int selected = 0;
		for (int i = 0; i < totcustom; i++)
		{
			if(strlen(CustomLogNameList[i]) > 0){
				strncat_s(dest,size,"<option",_TRUNCATE);
				if (!strcmp(reg_objective.str_eventlog_type_custom, CustomLogNameList[i])) {
					strncat_s(dest,size," selected>",_TRUNCATE);
					selected = 1;
				} else {
					strncat_s(dest,size,">",_TRUNCATE);
				}
				strncat_s(dest,size,CustomLogNameList[i],_TRUNCATE);
			}
		}
		if((i_type == 1) &&(!selected)){
			strncat_s(dest,size,"<option selected>",_TRUNCATE);
		}
		strncat_s(dest,size,"</select></td></tr>",_TRUNCATE);


		/*if (strstr(reg_objective.str_eventlog_type,SECLOG_TOKEN) == NULL) {
			strncat_s(dest,size,"<script type=\"text/javascript\">toggleDisabledGroup(document.getElementById('hilvl'));</script>",_TRUNCATE);
		}*/

		strncat_s(dest,size,"</table></td></tr>",_TRUNCATE);

		//Determine the criticality level
		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#DEDBD2><td>Select the Alert Level</td><td>"

			"<input type=radio name=str_critic value=%s%s><img src=/critical.gif> Critical    "
			"<input type=radio name=str_critic value=%s%s><img src=/priority.gif> Priority    "
			"<input type=radio name=str_critic value=%s%s><img src=/warning.gif> Warning    "
			"<input type=radio name=str_critic value=%s%s><img src=/info.gif> Information    "
			"<input type=radio name=str_critic value=%s%s><img src=/clear.gif> Clear    "
			"</td></tr>",dest,
			CRITICAL_TOKEN,(strstr(reg_objective.str_critic,CRITICAL_TOKEN) != NULL?" checked":""),
			PRIORITY_TOKEN,(strstr(reg_objective.str_critic,PRIORITY_TOKEN) != NULL?" checked":""),
			WARNING_TOKEN,(strstr(reg_objective.str_critic,WARNING_TOKEN) != NULL?" checked":""),
			INFORMATION_TOKEN,(strstr(reg_objective.str_critic,INFORMATION_TOKEN) != NULL?" checked":""),
			CLEAR_TOKEN,(strstr(reg_objective.str_critic,CLEAR_TOKEN) != NULL?" checked":"")
		);


		_snprintf_s(dest,size,_TRUNCATE,"%s</table><br>"
			"<input type=hidden name=objnumber value=%s>"
			"<input type=submit value=\"Change Configuration\">    "
			"<input type=reset value=\"Reset Form\"></form>",dest,str_temp_objective);
	} else if (i_type == 0) {
		dw_objective_delete_error = Delete_Objective(i_objective_count);
		i_objective_count++;
		dw_objective_error = Read_Objective_Registry(i_objective_count,&reg_objective);
		while (dw_objective_error == 0)
		{
			dw_objective_write_error = Write_Objective_Registry(i_objective_count-1,&reg_objective);
			dw_objective_delete_error = Delete_Objective(i_objective_count);
			i_objective_count++;
			dw_objective_error = Read_Objective_Registry(i_objective_count,&reg_objective);
		}

		if (dw_objective_delete_error == 0) {
			strncpy(source,"/safed/objective", 16);//MM				
			Objective_Config(source,dest,size);//MM
		} else {
			strncat_s(dest,size,"<br>The objective was unable to be deleted.",_TRUNCATE);
			//***REPORT AN ERROR
		}
	} else if (i_type == -1) {
		Reg_Objective reg_obj_swap;
		
		dw_objective_error += Read_Objective_Registry(i_objective_count,&reg_objective);
		dw_objective_error += Read_Objective_Registry(i_objective_count+1,&reg_obj_swap);
		if (dw_objective_error) {
			strncat_s(dest,size,"<br>ERROR: The objective could not be moved (read failure).",_TRUNCATE);
			return(0);
		}
		Write_Objective_Registry(i_objective_count+1,&reg_objective);
		Write_Objective_Registry(i_objective_count,&reg_obj_swap);
		Objective_Config(source,dest,size);//MM
	} else if (i_type == -2) {
		Reg_Objective reg_obj_swap;
		if (i_objective_count == 0) {
			strncat_s(dest,size,"<br>ERROR: This is the first objective, it cannot be moved up.",_TRUNCATE);
			return(0);
		}
		dw_objective_error += Read_Objective_Registry(i_objective_count,&reg_objective);
		dw_objective_error += Read_Objective_Registry(i_objective_count-1,&reg_obj_swap);
		if (dw_objective_error) {
			strncat_s(dest,size,"<br>ERROR: The objective could not be moved (read failure).",_TRUNCATE);
			return(0);
		}
		Write_Objective_Registry(i_objective_count-1,&reg_objective);
		Write_Objective_Registry(i_objective_count,&reg_obj_swap);
		Objective_Config(source,dest,size);//MM
	}
	
	return(0);
}


int Objective_Result(char *source, char *dest, int size)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	Reg_Objective reg_objective, reg_objective_read;
	// DWORD dw_objective_error = -1;
	DWORD dw_objective_error = 0;

	int i_objective_count = 0,i_objective = 0, i_event_type_set = 0, i_event_type_log_set = 0;
	char str_eventid_radio[50]="",str_eventid_text[SIZE_OF_EVENTIDMATCH]="";
	char *psource=source, Variable[100]="", Argument[300]="";

	DWORD dw_FileAudit;
	dw_FileAudit=MyGetProfileDWORD("Config","FileAudit",1);

	strncpy_s(dest,size,"<form method=get action=/safed/setobjective><H2><CENTER>SafedAgent Filtering Objectives Configuration</H2>",_TRUNCATE);

	strncpy_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),"",_TRUNCATE);
	strncpy_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),"",_TRUNCATE);
	strncpy_s(reg_objective.str_eventlog_type_custom,_countof(reg_objective.str_eventlog_type_custom),"",_TRUNCATE);

	while((psource=GetNextArgument(psource,Variable,_countof(Variable)-1,Argument,_countof(Argument)-1)) != (char *)NULL) 
	{	
		if (strstr(Variable,"str_user_match") != NULL) {
			strncpy_s(reg_objective.str_user_match,_countof(reg_objective.str_user_match),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"str_general_match") != NULL) {
			strncpy_s(reg_objective.str_general_match,_countof(reg_objective.str_general_match),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"str_event_type_succ") != NULL) {
			strncat_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),SUCCESS_TOKEN,_TRUNCATE);
			if (i_event_type_set == 1)
				strncat_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),",",_TRUNCATE);
			i_event_type_set = 1;
		}
		if (strstr(Variable,"str_event_type_fail") != NULL) {
			strncat_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),FAILURE_TOKEN,_TRUNCATE);
			if (i_event_type_set == 1)
				strncat_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),",",_TRUNCATE);
			i_event_type_set = 1;
		}
		if (strstr(Variable,"str_event_type_info") != NULL) {
			strncat_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),INFO_TOKEN,_TRUNCATE);
			if (i_event_type_set == 1)
				strncat_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),",",_TRUNCATE);
			i_event_type_set = 1;
		}
		if (strstr(Variable,"str_event_type_warn") != NULL) {
			strncat_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),WARN_TOKEN,_TRUNCATE);
			if (i_event_type_set == 1)
				strncat_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),",",_TRUNCATE);
			i_event_type_set = 1;
		}
		if (strstr(Variable,"str_event_type_error") != NULL) {
			strncat_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),ERROR_TOKEN,_TRUNCATE);
			if (i_event_type_set == 1)
				strncat_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),",",_TRUNCATE);
			i_event_type_set = 1;
		}
		if (strstr(Variable,"str_eventlog_type_value_cuslog") != NULL) {
			strncat_s(reg_objective.str_eventlog_type_custom,_countof(reg_objective.str_eventlog_type_custom),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"str_eventlog_type_cuslog") != NULL) {
			strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),CUSLOG_TOKEN,_TRUNCATE);
			if (i_event_type_log_set == 1)
				strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),",",_TRUNCATE);
			i_event_type_log_set = 1;
		}
		if (strstr(Variable,"str_eventlog_type_seclog") != NULL) {
			strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),SECLOG_TOKEN,_TRUNCATE);
			if (i_event_type_log_set == 1)
				strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),",",_TRUNCATE);
			i_event_type_log_set = 1;
		}
		if (strstr(Variable,"str_eventlog_type_syslog") != NULL) {
			strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),SYSLOG_TOKEN,_TRUNCATE);
			if (i_event_type_log_set == 1)
				strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),",",_TRUNCATE);
			i_event_type_log_set = 1;
		}
		if (strstr(Variable,"str_eventlog_type_applog") != NULL) {
			strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),APPLOG_TOKEN,_TRUNCATE);
			if (i_event_type_log_set == 1)
				strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),",",_TRUNCATE);
			i_event_type_log_set = 1;
		}
		if (strstr(Variable,"str_eventlog_type_dirlog") != NULL) {
			strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),DIRLOG_TOKEN,_TRUNCATE);
			if (i_event_type_log_set == 1)
				strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),",",_TRUNCATE);
			i_event_type_log_set = 1;
		}
		if (strstr(Variable,"str_eventlog_type_dnslog") != NULL) {
			strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),DNSLOG_TOKEN,_TRUNCATE);
			if (i_event_type_log_set == 1)
				strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),",",_TRUNCATE);
			i_event_type_log_set = 1;
		}
		if (strstr(Variable,"str_eventlog_type_replog") != NULL) {
			strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),REPLOG_TOKEN,_TRUNCATE);
			if (i_event_type_log_set == 1)
				strncat_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),",",_TRUNCATE);
			i_event_type_log_set = 1;
		}
		if (strstr(Variable,"str_eventid_match") != NULL) {
			strncpy_s(str_eventid_radio,_countof(str_eventid_radio),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"str_eventid_text") != NULL) {
			strncpy_s(str_eventid_text,_countof(str_eventid_text),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"objnumber") != NULL) {
			i_objective = atoi(Argument);	
		}
		if (strstr(Variable,"str_critic") != NULL) {
			strncpy_s(reg_objective.str_critic,_countof(reg_objective.str_critic),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"str_user_match_type") != NULL) {
			strncpy_s(reg_objective.str_user_match_type,_countof(reg_objective.str_user_match_type),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"str_event_match_type") != NULL) {
			strncpy_s(reg_objective.str_event_match_type,_countof(reg_objective.str_event_match_type),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"str_general_match_type") != NULL) {
			strncpy_s(reg_objective.str_general_match_type,_countof(reg_objective.str_general_match_type),Argument,_TRUNCATE);
		}
	}

	if (strstr(str_eventid_radio,"Any_Event") != NULL) {
		strncpy_s(reg_objective.str_eventid_match,_countof(reg_objective.str_eventid_match),str_eventid_text,_TRUNCATE);
	} else {
		//check for FILE_TOKEN.  If we are told to handle FileAudit, then check for a valid path and apply auditing.
		// otherwise, let the user specify any filter they like
		if (dw_FileAudit && strstr(str_eventid_radio,FILE_TOKEN) != NULL) {
			// Turn on file auditing for the specified general match term.

			if(validate_file_or_directory(reg_objective.str_general_match)) {
				// Set auditing on the file.
				// Enable the SE_SECURITY_NAME privilege.
				if (EnableSecurityName()) {
					AddEveryoneAceToFileSacl(reg_objective.str_general_match,GENERIC_ALL | ACCESS_SYSTEM_SECURITY);
				}
				// "I have recursively set audit on the filepath specified in this objective."
				strncat_s(dest,size,"<br>I have recursively set audit on the filepath specified in this objective.",_TRUNCATE);
			} else {
				// Tell the user something stuffed up.
				dw_objective_error=1;
				strncat_s(dest,size,"<br>The value supplied in the General Search filter, is not a valid file or directory.<P>Please supply a valid entry (eg: C:\\DIR\\TO\\AUDIT).",_TRUNCATE);
			}

		}
		/*if (strstr(str_eventid_radio,"Logon_Logoff") != NULL)
			strncpy_s(reg_objective.str_eventid_match,_countof(reg_objective.str_eventid_match),LOGON_LOGOFF_EVENTS,_TRUNCATE);
		if (strstr(str_eventid_radio,FILE_TOKEN) != NULL)
			strncpy_s(reg_objective.str_eventid_match,_countof(reg_objective.str_eventid_match),FILE_EVENTS,_TRUNCATE);
		if (strstr(str_eventid_radio,PROCESS_TOKEN) != NULL)
			strncpy_s(reg_objective.str_eventid_match,_countof(reg_objective.str_eventid_match),PROCESS_EVENTS,_TRUNCATE);
		if (strstr(str_eventid_radio,USERRIGHTS_TOKEN) != NULL)
			strncpy_s(reg_objective.str_eventid_match,_countof(reg_objective.str_eventid_match),USER_OF_USER_RIGHTS_EVENTS,_TRUNCATE);
		if (strstr(str_eventid_radio,MANAGE_TOKEN) != NULL)
			strncpy_s(reg_objective.str_eventid_match,_countof(reg_objective.str_eventid_match),USER_GROUP_ADMIN_EVENTS,_TRUNCATE);
		if (strstr(str_eventid_radio,SECPOL_TOKEN) != NULL)
			strncpy_s(reg_objective.str_eventid_match,_countof(reg_objective.str_eventid_match),SECURITY_POLICY_EVENTS,_TRUNCATE);
		if (strstr(str_eventid_radio,REBOOT_TOKEN) != NULL)
			strncpy_s(reg_objective.str_eventid_match,_countof(reg_objective.str_eventid_match),RESTART_EVENTS,_TRUNCATE);
		else*/

		strncpy_s(reg_objective.str_eventid_match,_countof(reg_objective.str_eventid_match),str_eventid_radio,_TRUNCATE);
	}

	if(!dw_objective_error) {
		
		//-2 = "Add a new objective", hence we must go to the end of the list.
		if (i_objective == -2)
		{
			dw_objective_error = Read_Objective_Registry(i_objective_count,&reg_objective_read);
			while (dw_objective_error == 0)
			{
				i_objective_count++;
				dw_objective_error = Read_Objective_Registry(i_objective_count,&reg_objective_read);
			}
			i_objective = i_objective_count;
		}

		dw_objective_error = Write_Objective_Registry(i_objective,&reg_objective);
		if (dw_objective_error  == 0){
			strncpy(source,"/safed/objective", 16);//MM				
			Objective_Config(source,dest,size);//MM
		}else
			strncat_s(dest,size,"<br>The objective was unable to be modifed/added.",_TRUNCATE);
			//***REPORT AN ERROR
	}

	return(0);
}


int DefaultHeader(char *source, char *dest, int size, int refreshflag, BOOL image)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	strncpy_s(dest,size,"<HTML><head>" \
	"<title>Wurth Phoenix - Information Technology Security</title>" \
	"<meta name=\"TITLE\" content=\"Wurth Phoenix Srl\">" \
	"<style type=\"text/css\">\n" \
	"body {\n" \
	" font-family: Verdana,Helvetica,sans-serif;\n" \
	" font-size: 10px; font-weight: normal;\n" \
	" margin: 0px;\n" \
	"}\n" \
	"h1 {\n" \
	" font-size: 30px;\n" \
	" font-family: Verdana,Helvetica,sans-serif;\n" \
	" color: white;\n" \
	"}\n" \
	"h2 {\n" \
	" font-size: 30px;\n" \
	" font-family: Verdana,Helvetica,sans-serif;\n" \
	" color: black;\n" \
	"}\n" \
	"font {\n" \
	" font-family: Verdana,Helvetica,sans-serif;\n" \
	" text-decoration: none; font-size: 10px;\n" \
	" font-weight: normal;\n" \
	"}\n" \
	"table {\n" \
	" margin: 0px; padding: 0px;\n" \
	"}\n" \
	"td {\n" \
	" font-size: 75%;\n" \
	"}\n" \
	"#dhtmltooltip{\n" \
	"position: absolute;\n" \
	"left: -300px;\n" \
	"width: 150px;\n" \
	"border: 1px solid black;\n" \
	"padding: 2px;\n" \
	"background-color: lightyellow;\n" \
	"visibility: hidden;\n" \
	"z-index: 100;\n" \
	"filter: progid:DXImageTransform.Microsoft.Shadow(color=gray,direction=135);\n" \
	"}" \
	"#dhtmlpointer{\n" \
	"position:absolute;\n" \
	"left: -300px;\n" \
	"z-index: 101;\n" \
	"visibility: hidden;\n" \
	"}\n" \
	"</style>\n" \
	"<meta HTTP-EQUIV=\"Pragma\" CONTENT=\"no-cache\">\n" \
	"<meta HTTP-EQUIV=\"Expires\" CONTENT=\"-1\">\n",_TRUNCATE);
	if (refreshflag) strncat_s(dest,size,"<meta HTTP-EQUIV=\"Refresh\" CONTENT=\"30\">\n",_TRUNCATE);
	strncat_s(dest,size,"<script type=\"text/javascript\">\n"
    "        function toggleVisible(visDiv) {\n"
    "            visDiv.style.display = visDiv.style.display == \"block\" ? \"none\" : \"block\";\n"
    "        }\n"

    "        function toggleDisabledGroup(el) {\n"
    "            try {\n"
    "                el.disabled = el.disabled ? false : true;\n"
	"                if (el.type == \"checkbox\") {\n"
//	"                    el.checked=false;\n"
	"                }\n"
    "            }\n"
    "            catch(E){}\n"

    "            if (el.childNodes && el.childNodes.length > 0) {\n"
    "                for (var x = 0; x < el.childNodes.length; x++) {\n"
    "                    toggleDisabledGroup(el.childNodes[x]);\n"
    "                }\n"
    "            }\n"
    "        }\n"
	"</script>\n"
	"<script type=\"text/javascript\">\n"
		"var offsetfromcursorX=12\n"
		"var offsetfromcursorY=10\n"
		"var offsetdivfrompointerX=10\n" 
		"var offsetdivfrompointerY=14\n" 
		"document.write('<div id=\"dhtmltooltip\"></div>')\n",_TRUNCATE);
	if (image) strncat_s(dest,size,"document.write('<img id=\"dhtmlpointer\" src=\"/arrow.gif\">')\n",_TRUNCATE);
	strncat_s(dest,size,"var ie=document.all\n"
		"var ns6=document.getElementById && !document.all\n"
		"var enabletip=false\n"
		"if (ie||ns6)\n"
			"var tipobj=document.all? document.all[\"dhtmltooltip\"] : document.getElementById? document.getElementById(\"dhtmltooltip\") : \"\"\n"
		"var pointerobj=document.all? document.all[\"dhtmlpointer\"] : document.getElementById? document.getElementById(\"dhtmlpointer\") : \"\"\n"
		"function ietruebody(){\n"
			"return (document.compatMode && document.compatMode!=\"BackCompat\")? document.documentElement : document.body\n"
		"}\n"
		"function ddrivetip(thetext, thewidth, thecolor){\n"
			"if (ns6||ie){\n"
				"if (typeof thewidth!=\"undefined\") tipobj.style.width=thewidth+\"px\"\n"
				"if (typeof thecolor!=\"undefined\" && thecolor!=\"\") tipobj.style.backgroundColor=thecolor\n"
				"tipobj.innerHTML=thetext\n"
				"enabletip=true\n"
				"return false\n"
			"}\n"
		"}\n"
		"function positiontip(e){\n"
			"if (enabletip){\n"
				"var nondefaultpos=false\n"
				"var curX=(ns6)?e.pageX : event.clientX+ietruebody().scrollLeft;\n"
				"var curY=(ns6)?e.pageY : event.clientY+ietruebody().scrollTop;\n"
				"var winwidth=ie&&!window.opera? ietruebody().clientWidth : window.innerWidth-20\n"
				"var winheight=ie&&!window.opera? ietruebody().clientHeight : window.innerHeight-20\n"
				"var rightedge=ie&&!window.opera? winwidth-event.clientX-offsetfromcursorX : winwidth-e.clientX-offsetfromcursorX\n"
				"var bottomedge=ie&&!window.opera? winheight-event.clientY-offsetfromcursorY : winheight-e.clientY-offsetfromcursorY\n"
				"var leftedge=(offsetfromcursorX<0)? offsetfromcursorX*(-1) : -1000\n"
				"if (rightedge<tipobj.offsetWidth){\n"
					"tipobj.style.left=curX-tipobj.offsetWidth+\"px\"\n"
					"nondefaultpos=true\n"
				"}\n"
				"else if (curX<leftedge)\n"
					"tipobj.style.left=\"5px\"\n"
				"else{\n"
					"tipobj.style.left=curX+offsetfromcursorX-offsetdivfrompointerX+\"px\"\n"
					"pointerobj.style.left=curX+offsetfromcursorX+\"px\"\n"
				"}\n"
				"if (bottomedge<tipobj.offsetHeight){\n"
					"tipobj.style.top=curY-tipobj.offsetHeight-offsetfromcursorY+\"px\"\n"
					"nondefaultpos=true\n"
				"}\n"
				"else{\n"
					"tipobj.style.top=curY+offsetfromcursorY+offsetdivfrompointerY+\"px\"\n"
					"pointerobj.style.top=curY+offsetfromcursorY+\"px\"\n"
				"}\n"
				"tipobj.style.visibility=\"visible\"\n"
				"if (!nondefaultpos)\n"
					"pointerobj.style.visibility=\"visible\"\n"
				"else\n"
					"pointerobj.style.visibility=\"hidden\"\n"
			"}\n"
		"}\n"
		"function hideddrivetip(){\n"
			"if (ns6||ie){\n"
				"enabletip=false\n"
				"tipobj.style.visibility=\"hidden\"\n"
				"pointerobj.style.visibility=\"hidden\"\n"
				"tipobj.style.left=\"-1000px\"\n"
				"tipobj.style.backgroundColor=''\n"
				"tipobj.style.width=''\n"
			"}\n"
		"}\n"
		"document.onmousemove=positiontip\n"
	"</script>\n"
	"</head>" \
	"<body text=black bgcolor=#c3c7d3 link=#000066 vlink=#000044 alink=#000055>" \
	"<table border=0 cellspacing=0 cellpadding=0 columns=3 width=100%>" \
	"<tbody>" \
    "<tr>" \
	"<td height=70 border=0 bgcolor=#E6E6E6 width=250px></td>" \
	"<td height=70 bgcolor=#c3c7d3",_TRUNCATE);
	if (image) strncat_s(dest,size,"><img src=/logo.gif alt=\"Wuerth Phoenix NetEye\" width=70% height=70 hspace=0 vspace=0 border=0 align=Right>" ,_TRUNCATE);
	else strncat_s(dest,size," width=62%>" ,_TRUNCATE);
	strncat_s(dest,size,"</td>" \
	"<td height=70 border=0 bgcolor=#c3c7d3 width=18%></td>" \
    "</tr>" \
    "</tbody>" \
	"</table>" \
	"<table border=0 cellspacing=0 cellpadding=0 columns=2 width=100% height=100%>" \
	"<tbody>" \
    "<tr>" 
      "<td valign=Top width=250px bgcolor=#E6E6E6>" \
		  "<table border=0 cellspacing=0 cellpadding=5 columns=2 width=250px>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/list.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size, "</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/eventlog\" style=\"color:black;text-decoration:none\">Latest Events</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/list.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size, "</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/dailylog\" style=\"color:black;text-decoration:none\">Daily Events</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/cfg.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size, "</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/network\" style=\"color:black;text-decoration:none\">Network Configuration</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/cfg.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size, "</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/sysadmin\" style=\"color:black;text-decoration:none\">System Administrator Configuration</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/cfg.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size,"</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/remote\" style=\"color:black;text-decoration:none\">Remote Control Configuration</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/cfg.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size, "</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/log\" style=\"color:black;text-decoration:none\">LogFile Configuration</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/cfg.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size,"</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/log/objective\" style=\"color:black;text-decoration:none\">LogFile Objectives Configuration</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/cfg.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size,  "</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/safed/objective\" style=\"color:black;text-decoration:none\">EventLog Objectives Configuration</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/status.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size, "</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/status\" style=\"color:black;text-decoration:none\">View Audit Service Status</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<td >" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/status.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size, "</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/safedlog\" style=\"color:black;text-decoration:none\">Safed Log</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<td >" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/save.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size,  "</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/restart\" style=\"color:black;text-decoration:none\">Apply the Latest Audit Configuration</A></font></td>" \
		  "</tr>" \
		  "</table>" \
		  "<br><br><br>" \
		  "<table border=0 cellspacing=0 cellpadding=5 columns=2>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/search.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size, "</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-2><A HREF=\"/GetSysAdmin\" style=\"color:black;text-decoration:none\" target=\"SafedData\">System Administrators</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/search.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size, "</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-2><A HREF=\"/GetCustomLogs\" style=\"color:black;text-decoration:none\" target=\"SafedData\">Custom Event Logs</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/search.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size,"</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-2><A HREF=\"/GetConfig\" style=\"color:black;text-decoration:none\" target=\"_self\">Get Configuration</A></font></td>"\
          "</tr>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/cfg.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size,"</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-2><A HREF=\"/certs\" style=\"color:black;text-decoration:none\" target=\"_self\">Set Certificates</A></font></td>"\
          "</tr>" \
		  "<tr>" \
		  "<td>" ,_TRUNCATE);
	if (image) strncat_s(dest,size,"<img src=/cfg.gif alt=\"\"   align=Right>",_TRUNCATE);
	strncat_s(dest,size, "</td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-2><A HREF=\"/config\" style=\"color:black;text-decoration:none\" target=\"_self\">Set Configuration</A></font></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<td><br></td><td><br></td>" \
		  "</tr>" \
		  "<tr>" \
		  "<td></td>" \
		  "<td><font face=\"Helvetica,Arial,sans-serif\" size=-2><A HREF=\"/License\" style=\"color:black;text-decoration:none\" target=\"SafedData\">About License</A></font></td>" \
		  "</tr>" \
		  "</table>" \
	      
	"</td>" \
    "<td valign=Top bgcolor=#c3c7d3>" \
     "<table cellpadding=0 cellspacing=10 border=0 width=100%>" \
      "<tbody>" \
       "<tr>" \
        "<td valign=Top align=Justify>",_TRUNCATE);
		
	return(0);
}

int DefaultFooter(char *source, char *dest, int size)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	strncpy_s(dest,size,"</td>" \
		"</tr>" \
		"</tbody>" \
		"</table>" \
		//"</td>" 
		//"</tr>" 
		//"</tbody>" 
		//"</table>" 
		"</body><center>" \
		"<BR><BR><FONT SIZE=-1 face=helvetica>" \
		"This site is powered by <A HREF=\"http://www.wuerth-phoenix.com/neteye\">SafedAgent for Windows.</A></FONT>" \
		"</center></html>",_TRUNCATE);

	return(0);
}


int Restart(char *source, char *dest, int size, HANDLE event)
{
	// All strncpy or strncat functions in this routine have been designed avoid overflows
	if(WEBSERVER_TLS)
		strncpy_s(dest,size,"<HTML><HEAD><meta http-equiv=\"REFRESH\" content=\"4;url=/restart?\"></HEAD><BODY><H2><CENTER>Reapply the Latest Configuration</H2><P>SafedAgent Objectives have been reapplied to the running system.</CENTER></BODY></HTML>",_TRUNCATE);
	else
		strncpy_s(dest,size,"<HTML><HEAD><meta http-equiv=\"REFRESH\" content=\"2;url=/restart?\"></HEAD><BODY><H2><CENTER>Reapply the Latest Configuration</H2><P>SafedAgent Objectives have been reapplied to the running system.</CENTER></BODY></HTML>",_TRUNCATE);
		

	// Notify the main thread that we want to reapply config changes
	SetEvent(event);

    return(0);
}

int Restart(char *source, char *dest, int size)
{

	// All strncpy or strncat functions in this routine have been designed avoid overflows
	//strncpy_s(dest,size,"<HTML><BODY><H2><CENTER>Reapply the Latest Configuration</H2><P>SafedAgent Objectives have been reapplied to the running system.</CENTER></BODY></HTML>",_TRUNCATE);
	strncpy_s(dest,size,"<H2><CENTER>Reapply the Latest Configuration</H2><P>SafedAgent Objectives have been reapplied to the running system.",_TRUNCATE);


    return(0);
}

int ShowLocalUsers(SOCKET http_socket, gnutls_session session_https)
{
	int retval;
	char HTTPBuffer[UGBUFFER]="";
	char TempBuffer[UGBUFFER]="";

	DWORD dwEntriesRead=0,dwTotalEntries=0,dwResume=0,dwReturn=0, i=0;
	char szName[255]="",szDesc[255]="";

	char szTextualSid[256];
	DWORD dwBufferLen;
	NET_API_STATUS nasReturn;
	USER_MODALS_INFO_0 *pModBuf = NULL;
	PNET_DISPLAY_USER p;
	long MaxPwdAge;

	if (NetUserModalsGet(NULL, 0, (LPBYTE *)&pModBuf) == NERR_Success) {
		LogExtMsg(INFORMATION_LOG,"Maximum password age (d): %d\n", pModBuf->usrmod0_max_passwd_age/86400);
		MaxPwdAge=pModBuf->usrmod0_max_passwd_age;
	} else {
		LogExtMsg(INFORMATION_LOG,"Could not find MaxPasswordAge");
		MaxPwdAge=-1;
	}
	if (pModBuf) NetApiBufferFree(pModBuf);

	do {
		PNET_DISPLAY_USER pBuf=NULL;
		dwReturn = NetQueryDisplayInformation( NULL, 1, i, 1000, MAX_PREFERRED_LENGTH, &dwEntriesRead, (PVOID *) &pBuf);
		p=pBuf;
		while ( dwEntriesRead ) {
			USER_INFO_2	*UserInfo=NULL;
			
			// Is this a local user account?
			// Convert UniCode to ASCII
			WideCharToMultiByte( CP_ACP, 0,p->usri1_name,-1, szName, _countof(szName)-1, NULL, NULL );
			WideCharToMultiByte( CP_ACP, 0,p->usri1_comment,-1, szDesc, _countof(szDesc)-1, NULL, NULL );
			

			if(szName) {
				// GET SID HERE

				dwBufferLen=_countof(szTextualSid);
				// Obtain the textual representation of the SID.
				GetUserSid(szName,szTextualSid,&dwBufferLen);

			}

			// Get rid of tabs in the Description field
			char * t;
			t=szDesc;
			if(t) {
				while(*t) {
					if(*t == '\t' || *t == '\n' || *t == '\r') { *t=' '; }
					t++;
				}
			}
			snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t%S (%s)\t%s",szName,p->usri1_full_name,szDesc,szTextualSid);

			nasReturn=NetUserGetInfo(NULL,p->usri1_name,2,(LPBYTE *)&UserInfo);
			if (nasReturn == NERR_Success && UserInfo) {
				// ##### ONLY ONE of these is true ############
				//if(UserInfo->usri2_flags & UF_NORMAL_ACCOUNT) {
				//	strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tNORMAL_ACCOUNT",_TRUNCATE);
				//}
				if(UserInfo->usri2_flags & UF_TEMP_DUPLICATE_ACCOUNT) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tTEMP_DUPLICATE_ACCOUNT",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_WORKSTATION_TRUST_ACCOUNT) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tWORKSTATION_TRUST_ACCOUNT",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_SERVER_TRUST_ACCOUNT) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tSERVER_TRUST_ACCOUNT",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_INTERDOMAIN_TRUST_ACCOUNT) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tINTERDOMAIN_TRUST_ACCOUNT",_TRUNCATE);
				}
				//##############
				if(UserInfo->usri2_flags & UF_ACCOUNTDISABLE) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tACCOUNTDISABLE",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_PASSWD_NOTREQD) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tPASSWD_NOTREQD",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_PASSWD_CANT_CHANGE) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tPASSWD_CANT_CHANGE",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_LOCKOUT) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tLOCKOUT",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_DONT_EXPIRE_PASSWD) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tDONT_EXPIRE_PASSWD",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tENCRYPTED_TEXT_PASSWORD_ALLOWED",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_NOT_DELEGATED) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tNOT_DELEGATED",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_SMARTCARD_REQUIRED) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tSMARTCARD_REQUIRED",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_USE_DES_KEY_ONLY) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tUSE_DES_KEY_ONLY",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_DONT_REQUIRE_PREAUTH) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tDONT_REQUIRE_PREAUTH",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_TRUSTED_FOR_DELEGATION) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tTRUSTED_FOR_DELEGATION",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_PASSWORD_EXPIRED) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tPASSWORD_EXPIRED",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tTRUSTED_TO_AUTHENTICATE_FOR_DELEGATION",_TRUNCATE);
				}
				//password age in seconds since last reset:max password age in seconds (const):time when the account will expire in seconds since epoch
				snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t%d:%d:%d:%d\n",HTTPBuffer,UserInfo->usri2_password_age,MaxPwdAge,UserInfo->usri2_acct_expires, UserInfo->usri2_last_logon);
			} else {
				snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t-1:%d:-1:-1\n",HTTPBuffer,MaxPwdAge);
			}
			if(UserInfo) NetApiBufferFree(UserInfo);

			if(WEBSERVER_TLS)
				retval = sendTLS(HTTPBuffer,session_https);
			else
				retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
			i = p->usri1_next_index;
			p++;  // Step to the next one

			dwEntriesRead--;

		}
		if(pBuf) NetApiBufferFree(pBuf);
	} while(dwReturn == ERROR_MORE_DATA);

	// Send a newline to finish off.
	if(WEBSERVER_TLS)
		retval = sendTLS("\n",session_https);
	else
		retval = send(http_socket,"\n",(int)strlen("\n"),0);
	return(0);
}

int ShowDomainUsers(SOCKET http_socket, gnutls_session session_https)
{
	int retval;
	char HTTPBuffer[UGBUFFER]="";

	LPWSTR tPrimaryDC = NULL;
	WCHAR PrimaryDC[256];
	WCHAR *PDC;
	char PDC_cstr[256]="";
	char Domain_cstr[256]="";
	NET_API_STATUS netErr=1;

	// Failing that, get the primary domain controller
	netErr = NetGetDCName(NULL,NULL,(LPBYTE *)&tPrimaryDC);
	if(netErr == NERR_Success) {
		char temp[256]="", temp2[256]="";
		if(tPrimaryDC) {
			wcsncpy_s(PrimaryDC,_countof(PrimaryDC),tPrimaryDC,_TRUNCATE);
			PDC=PrimaryDC;

			// Get the primary domain
			PBYTE buf = NULL;
			netErr = DsRoleGetPrimaryDomainInformation (NULL,DsRolePrimaryDomainInfoBasic,&buf);
			if (netErr == ERROR_SUCCESS) {
				DSROLE_PRIMARY_DOMAIN_INFO_BASIC * info = (DSROLE_PRIMARY_DOMAIN_INFO_BASIC *) buf;
				WideCharToMultiByte( CP_ACP, 0,info->DomainNameFlat,-1, Domain_cstr, _countof(Domain_cstr), NULL, NULL );
				strncpy_s(temp,_countof(temp),Domain_cstr,_TRUNCATE);
				//strncpy_s(temp,_countof(temp),info->DomainNameFlat,_TRUNCATE);
			} else {
				LogExtMsg(INFORMATION_LOG,"Could not retrieve DC Role info: %d", netErr);
			}
			if (buf) DsRoleFreeMemory(&buf);
			//ExpandEnvironmentStrings("%USERDOMAIN%",temp, _countof(temp));
			WideCharToMultiByte( CP_ACP, 0,PDC,-1, PDC_cstr, _countof(PDC_cstr), NULL, NULL );
			if (!strlen(temp)) strncpy_s(temp,_countof(temp),PDC_cstr,_TRUNCATE);
			_snprintf_s(temp2,_countof(temp2),_TRUNCATE,"SERVER: %s\n",temp);
			if(WEBSERVER_TLS)
				retval = sendTLS(temp2,session_https);
			else
				retval = send(http_socket,temp2,(int)strlen(temp2),0);
		} else {
			if(tPrimaryDC) {
				NetApiBufferFree(tPrimaryDC);
			}
			//char temp[256];
			//PDC=NULL;
			//strncpy_s(temp,_countof(temp),"PDC: LOCAL\n",_TRUNCATE);
			//if(WEBSERVER_TLS)
			//retval = sendTLS(temp,session_https);
			//else
			//retval = send(http_socket,temp,(int)strlen(temp),0);	

			return(0);
		}
	} else {
		if(tPrimaryDC) {
				NetApiBufferFree(tPrimaryDC);
		}
		return(0);
		//char temp[256];
		//
		//PDC=NULL;
		//
		//strncpy_s(temp,_countof(temp),"PDC: LOCAL\n",_TRUNCATE);
		//if(WEBSERVER_TLS)
		//retval = sendTLS(temp,session_https);
		//else
		//retval = send(http_socket,temp,(int)strlen(temp),0);
	}

	if(tPrimaryDC) {
	  NetApiBufferFree(tPrimaryDC);
	}


	NET_API_STATUS nasReturn;
	NET_API_STATUS nasReturn2;
	PNET_DISPLAY_USER p;
	DWORD  dwUsers;
	char szNameBuffer[256]="";
	char szCommentBuffer[256]="";

	char szTextualSid[256];
	DWORD dwBufferLen;

	DWORD i=0;
	DWORD next=0;
	long MaxPwdAge;

	USER_MODALS_INFO_0 *pBuf = NULL;

	if (NetUserModalsGet(PDC, 0, (LPBYTE *)&pBuf) == NERR_Success) {
		LogExtMsg(INFORMATION_LOG,"Maximum password age (d): %d\n", pBuf->usrmod0_max_passwd_age/86400);
		MaxPwdAge=pBuf->usrmod0_max_passwd_age;
	} else {
		LogExtMsg(INFORMATION_LOG,"Could not find MaxPasswordAge");
		MaxPwdAge=-1;
	}
	if (pBuf != NULL) NetApiBufferFree(pBuf);

	do {
		PNET_DISPLAY_USER pNDUBuff=NULL;

		// 1 = Users, 2 = Machines, 3 = groups
		nasReturn = NetQueryDisplayInformation(PDC,1,next,10000,MAX_PREFERRED_LENGTH,&dwUsers,(PVOID *)&pNDUBuff);
		
		if(nasReturn == ERROR_ACCESS_DENIED) {
			char temp[256]="Access Denied. Cannot query domain users while SafedAgent is running with the privileges of the local administrator";
			if(WEBSERVER_TLS)
				retval = sendTLS(temp,session_https);
			else
				retval = send(http_socket,temp,(int)strlen(temp),0);
			if (pNDUBuff) NetApiBufferFree(pNDUBuff);
			break;
        }
		p = pNDUBuff;

		for (i=0; i<dwUsers; i++) {
			USER_INFO_2	*UserInfo=NULL;
			WideCharToMultiByte (CP_ACP,
                           WC_COMPOSITECHECK,
                           p->usri1_name,
                           -1,
                           szNameBuffer,
                           _countof(szNameBuffer)-1,
                           NULL,
                           NULL);
			WideCharToMultiByte (CP_ACP,
                           WC_COMPOSITECHECK,
                           p->usri1_comment,
                           -1,
                           szCommentBuffer,
                           _countof(szCommentBuffer)-1,
                           NULL,
                           NULL);

			if(szNameBuffer) {
				// GET SID HERE

				dwBufferLen=_countof(szTextualSid);

				// Obtain the textual representation of the SID.
				// if we don't have the explicit Domain and PDC info, fallback to best effort
				if (strlen(Domain_cstr) && strlen(PDC_cstr)) {
					GetUserSid(szNameBuffer,szTextualSid,&dwBufferLen,Domain_cstr,PDC_cstr);
				} else {
					GetUserSid(szNameBuffer,szTextualSid,&dwBufferLen);
				}
			}


			// Get rid of tabs in the Description field
			char * t;
			t=szCommentBuffer;
			if(t) {
				while(*t) {
					if(*t == '\t' || *t == '\n' || *t == '\r') { *t=' '; }
					t++;
				}
			}
			snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t%S (%s)\t%s",szNameBuffer,p->usri1_full_name,szCommentBuffer,szTextualSid);
			//if(WEBSERVER_TLS)
			//retval = sendTLS(HTTPBuffer,session_https);
			//else
			//retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);

			//strncpy_s(HTTPBuffer,1,"",_TRUNCATE);
			// Unfortunately, the NetQueryDisplayInformation system call does not tell us the flags!
			// Argh.. ok, get more details on this user.
			// This probably means that user info will slow down lots..
			// Use NetUserGetInfo here.

			nasReturn2=NetUserGetInfo(PDC,p->usri1_name,2,(LPBYTE *)&UserInfo);
			if (nasReturn2 == NERR_Success && UserInfo) {

				if(UserInfo->usri2_flags & UF_ACCOUNTDISABLE) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tACCOUNTDISABLE",_TRUNCATE);
				}
				// This flag doesn't seem to be used by Windows 200 and above, any more
				if(UserInfo->usri2_flags & UF_PASSWD_NOTREQD) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tPASSWD_NOTREQD",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_PASSWD_CANT_CHANGE) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tPASSWD_CANT_CHANGE",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_LOCKOUT) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tLOCKOUT",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_DONT_EXPIRE_PASSWD) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tDONT_EXPIRE_PASSWD",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_INTERDOMAIN_TRUST_ACCOUNT) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tINTERDOMAIN_TRUST_ACCOUNT",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_SERVER_TRUST_ACCOUNT) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tSERVER_TRUST_ACCOUNT",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_WORKSTATION_TRUST_ACCOUNT) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tWORKSTATION_TRUST_ACCOUNT",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_TEMP_DUPLICATE_ACCOUNT) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tTEMP_DUPLICATE_ACCOUNT",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tENCRYPTED_TEXT_PASSWORD_ALLOWED",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_NOT_DELEGATED) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tNOT_DELEGATED",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_SMARTCARD_REQUIRED) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tSMARTCARD_REQUIRED",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_USE_DES_KEY_ONLY) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tUSE_DES_KEY_ONLY",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_DONT_REQUIRE_PREAUTH) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tDONT_REQUIRE_PREAUTH",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_TRUSTED_FOR_DELEGATION) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tTRUSTED_FOR_DELEGATION",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_PASSWORD_EXPIRED) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tPASSWORD_EXPIRED",_TRUNCATE);
				}
				if(UserInfo->usri2_flags & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) {
					strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\tTRUSTED_TO_AUTHENTICATE_FOR_DELEGATION",_TRUNCATE);
				}
				//password age in seconds since last reset:max password age in seconds (const):time when the account will expire in seconds since epoch
				snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t%d:%d:%d:%d\n",HTTPBuffer,UserInfo->usri2_password_age,MaxPwdAge,UserInfo->usri2_acct_expires, UserInfo->usri2_last_logon);
			} else {
				snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t-1:%d:-1:-1\n",HTTPBuffer,MaxPwdAge);
			}
			if(WEBSERVER_TLS)
				retval = sendTLS(HTTPBuffer,session_https);
			else
				retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
			if(UserInfo) NetApiBufferFree(UserInfo);

			next = p->usri1_next_index;
			p++;

		}

		if (pNDUBuff) NetApiBufferFree(pNDUBuff);

	} while(nasReturn == ERROR_MORE_DATA);


	return(1);
}


int ShowLocalGroupMembers(SOCKET http_socket, gnutls_session session_https)
{ 
	int retval;
	char HTTPBuffer[1024]="";
	char TempBuffer[4096]="";

	DWORD dwEntriesRead=0,dwTotalEntries=0,dwReturn=0;
	char szName[255]="";
	char szComment[255]="";
	LogExtMsg(INFORMATION_LOG,"ShowLocalGroupMembers");
	do {
		GROUP_INFO_1	*GroupInfo=NULL,*GISave=NULL;
		dwReturn = NetLocalGroupEnum( NULL, 1, (LPBYTE *)&GroupInfo, MAX_PREFERRED_LENGTH, 
                &dwEntriesRead,	&dwTotalEntries, NULL );
		GISave=GroupInfo;
		switch (dwReturn) {
			case ERROR_MORE_DATA: LogExtMsg(NULL,"ERROR_MORE_DATA"); break;
			case ERROR_ACCESS_DENIED: LogExtMsg(NULL,"ERROR_ACCESS_DENIED"); break;
			case NERR_Success: LogExtMsg(NULL,"NERR_Success"); break;
			case NERR_InvalidComputer: LogExtMsg(NULL,"NERR_InvalidComputer"); break;
			case NERR_BufTooSmall: LogExtMsg(NULL,"NERR_BufTooSmall"); break;
		}
		LogExtMsg(INFORMATION_LOG,"NetLocalGroupEnum: dwEntriesRead (%d) dwTotalEntries (%d) ", dwEntriesRead, dwTotalEntries);
		LogExtMsg(INFORMATION_LOG,"grabbed list of groups, now checking members");

		while ( dwEntriesRead ) {
			// Convert UniCode to ASCII
			WideCharToMultiByte( CP_ACP, 0,GroupInfo->grpi1_name,-1, szName, _countof(szName)-1, NULL, NULL );
			snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t",szName);
			if(WEBSERVER_TLS)
				retval = sendTLS(HTTPBuffer,session_https);
			else
				retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
			WideCharToMultiByte( CP_ACP, 0,GroupInfo->grpi1_comment,-1, szComment, _countof(szComment)-1, NULL, NULL );
			if (!strlen(szComment)) strncpy_s(szComment,_countof(szComment),"-",_TRUNCATE);
			snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t",szComment);
			if(WEBSERVER_TLS)
				retval = sendTLS(HTTPBuffer,session_https);
			else
				retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);

			//This function will grab the group members
			ShowThisLocalGroupMembers(GroupInfo->grpi1_name,http_socket, session_https);
			if(WEBSERVER_TLS)
				retval = sendTLS("\n",session_https);
			else
				retval = send(http_socket,"\n",(int)strlen("\n"),0);
			
			GroupInfo += 1;  // Step to the next one

			dwEntriesRead--;

		}
		if(GISave) NetApiBufferFree(GISave);
	} while(dwReturn == ERROR_MORE_DATA);
	LogExtMsg(INFORMATION_LOG,"finished ShowDomainGroupMembers");

	// Send a newline to finish off.
	if(WEBSERVER_TLS)
		retval = sendTLS("\n",session_https);
	else
		retval = send(http_socket,"\n",(int)strlen("\n"),0);

	return(0);
}

int ShowLicense(SOCKET http_socket, gnutls_session session_https)
{
	int retval;
	char HTTPBuffer[1024]="";
	snprintf_s(HTTPBuffer,_countof(HTTPBuffer), "This program is free software; you can redistribute it and/or modify\n"\
	 "it under the terms of the GNU General Public License as published by\n"\
	 "the Free Software Foundation; either version 2 of the License, or\n"\
	 "(at your option) any later version.\n\n"\
	 "This program is distributed in the hope that it will be useful,\n"\
	 "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"\
	 "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"\
	 "GNU Library General Public License for more details.\n"\
	 "You should have received a copy of the GNU General Public License\n"\
	 "along with this program; if not, write to the Free Software\n"\
	 "Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.\n",_TRUNCATE);
	if(WEBSERVER_TLS)
		retval = sendTLS(HTTPBuffer,session_https);
	else
		retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
	return(0);
}

int GetCustomLogs(SOCKET http_socket, gnutls_session session_https){
	char msg[MAXCUSTOMLOGS*SIZE_OF_EVENTLOG]= "No custom event log have been found in SYSTEM\\CurrentControlSet\\Services\\EventLog!";
	int first = 1;
	char CustomLogNameList[MAXCUSTOMLOGS][SIZE_OF_EVENTLOG];//max 100 Event Logs are supported
	DWORD totcustom = getCustomLogNames(CustomLogNameList);
	for (int i = 0; i < totcustom; i++)
	{
		if(strlen(CustomLogNameList[i]) > 0){
			if(!first){
				strncat_s(msg,MAXCUSTOMLOGS*SIZE_OF_EVENTLOG,"|",_TRUNCATE);
				strncat_s(msg,MAXCUSTOMLOGS*SIZE_OF_EVENTLOG,CustomLogNameList[i],_TRUNCATE);

			}else{
				first=0;
				strncpy_s(msg,MAXCUSTOMLOGS*SIZE_OF_EVENTLOG,CustomLogNameList[i],_TRUNCATE);

			}
		}
	}

	if(WEBSERVER_TLS) 
		sendTLS(msg,session_https);
	else
		send(http_socket,msg,(int)strlen(msg),0);

	return 0;
}
int GetSysAdmin(SOCKET http_socket, gnutls_session session_https){
	char msg[50]= "No system administrator discovery has been done!";
	if(systemAdministrators)
		if(WEBSERVER_TLS) 
			sendTLS(systemAdministrators,session_https);
		else
			send(http_socket,systemAdministrators,(int)strlen(systemAdministrators),0);
	else 
		if(WEBSERVER_TLS) 
			sendTLS(msg,session_https);
		else
			send(http_socket,msg,(int)strlen(msg),0);

	return 0;
}

int ShowDomainGroupMembers(SOCKET http_socket, gnutls_session session_https)
{
	int retval;
	char HTTPBuffer[1024]="";

	LPWSTR tPrimaryDC = NULL;
	WCHAR PrimaryDC[256];
	WCHAR *PDC;
	char PDC_cstr[256]="";
	NET_API_STATUS netErr=1;

	LogExtMsg(INFORMATION_LOG,"ShowDomainGroupMembers");
	// Get the primary domain controller
	netErr = NetGetDCName(NULL,NULL,(LPBYTE *)&tPrimaryDC);
	if(netErr == NERR_Success) {
		char temp[256]="", temp2[256]="";
		if(tPrimaryDC) {
			wcsncpy_s(PrimaryDC,255,tPrimaryDC,_TRUNCATE);
			PDC=PrimaryDC;

			// Get the primary domain
			PBYTE buf = NULL;
			netErr = DsRoleGetPrimaryDomainInformation (NULL,DsRolePrimaryDomainInfoBasic,&buf);
			if (netErr == ERROR_SUCCESS) {
				DSROLE_PRIMARY_DOMAIN_INFO_BASIC * info = (DSROLE_PRIMARY_DOMAIN_INFO_BASIC *) buf;
				WideCharToMultiByte( CP_ACP, 0,info->DomainNameFlat,-1, temp, 255, NULL, NULL );
				//strncpy_s(temp,_countof(temp),info->DomainNameFlat,_TRUNCATE);
			} else {
				LogExtMsg(INFORMATION_LOG,"Could not retrieve DC Role info: %d", netErr);
			}
			if (buf) DsRoleFreeMemory(&buf);
			//ExpandEnvironmentStrings("%USERDOMAIN%",temp, _countof(temp));
			WideCharToMultiByte( CP_ACP, 0,PDC,-1, PDC_cstr, _countof(PDC_cstr), NULL, NULL );
			if (!strlen(temp)) strncpy_s(temp,_countof(temp),PDC_cstr,_TRUNCATE);
			_snprintf_s(temp2,_countof(temp2),_TRUNCATE,"SERVER: %s\n",temp);
			
			if(WEBSERVER_TLS) 
				retval = sendTLS(temp2,session_https);
			else
				retval = send(http_socket,temp2,(int)strlen(temp2),0);
		} else {
			return(0);
		}
	} else {
		if(tPrimaryDC) {
				NetApiBufferFree(tPrimaryDC);
		}
		return(0);
	}

	if(tPrimaryDC) {
	  NetApiBufferFree(tPrimaryDC);
	}


	NET_API_STATUS nasReturn;
	DWORD  dwGroups;
	char szNameBuffer[256]="";
	char szCommentBuffer[256]="";

	DWORD i=0;
	DWORD next=0;

	LogExtMsg(INFORMATION_LOG,"Checking version");
  	LogExtMsg(INFORMATION_LOG,"Version is 5+");
	// Initialise COM object for grabbing AD groups if available.
	CoInitialize(NULL);

	LogExtMsg(INFORMATION_LOG,"Checking for mixed mode");
	if(ADIsMixedMode()) {
		LogExtMsg(INFORMATION_LOG,"domain is mixed mode");
		HRESULT hr = S_OK;
		// Pull back rootDSE and the current user's domain container DN.
		IADs *pObject = NULL;
		IDirectorySearch *pContainerToSearch = NULL;
		LPOLESTR szPath = new OLECHAR[MAX_PATH];
		VARIANT var;
		int iCount = 0;

		hr = ADsOpenObject(L"LDAP://rootDSE",
			NULL,
			NULL,
			ADS_SECURE_AUTHENTICATION, // Use Secure Authentication
			IID_IADs,
			(void**)&pObject);
		
		if (FAILED(hr))	{
			if (pObject) {
				pObject->Release();
			}
			delete [] szPath;
			CoUninitialize();
			return(0);
		}
		
		hr = pObject->Get(L"defaultNamingContext",&var);
		if (SUCCEEDED(hr)) {
			wcscpy_s(szPath,MAX_PATH,L"LDAP://");
			if(wcslen(var.bstrVal) < MAX_PATH) {
				wcscat_s(szPath,MAX_PATH,var.bstrVal);
			} else {
				// Buffer is too small for the domain DN
				if (pObject) { pObject->Release(); }
				delete [] szPath;
				VariantClear(&var);
				CoUninitialize();
				return(0);
			}

			hr = ADsOpenObject(szPath, NULL, NULL,
				ADS_SECURE_AUTHENTICATION, //Use Secure Authentication
				IID_IDirectorySearch, (void**)&pContainerToSearch);
			
			if (SUCCEEDED(hr)) {		
				// Specify subtree search
				ADS_SEARCHPREF_INFO SearchPrefs[2];
				SearchPrefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
				SearchPrefs[0].vValue.dwType = ADSTYPE_INTEGER;
				SearchPrefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
				
				SearchPrefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
				SearchPrefs[1].vValue.dwType = ADSTYPE_INTEGER;
				SearchPrefs[1].vValue.Integer = 1000;

				DWORD dwNumPrefs = 2;
				
				// COL for iterations
				LPOLESTR pszColumn = NULL;    
				ADS_SEARCH_COLUMN col;
				
				// Interface Pointers
				IADs *pObj = NULL;
				IADs * pIADs = NULL;
				
				// Handle used for searching
				ADS_SEARCH_HANDLE hSearch = NULL;
				
				// Set the search preference
				hr = pContainerToSearch->SetSearchPreference(SearchPrefs, dwNumPrefs);
				if (FAILED(hr)) {
					if (pObject) {
						pObject->Release();
					}
					delete [] szPath;
					if (pContainerToSearch) {
						pContainerToSearch->Release();
					}
					VariantClear(&var);
					CoUninitialize();
					return(0);
				}
				
				LPOLESTR pszScanList[] = {L"samaccountname",L"description"};
				
				char cszName[MAX_PATH]="";
				char cszDesc[MAX_PATH]="";
				
				hr = pContainerToSearch->ExecuteSearch(L"(&(objectCategory=group))",
					pszScanList,
					sizeof(pszScanList)/sizeof(LPOLESTR),
					&hSearch);
				
				if (SUCCEEDED(hr)) {
					// Call IDirectorySearch::GetNextRow() to retrieve more data
					hr = pContainerToSearch->GetFirstRow(hSearch);
					if (SUCCEEDED(hr)) {
						while(hr == S_OK) {
							iCount++;
							
							strncpy_s(cszName,_countof(cszName),"",_TRUNCATE);
							strncpy_s(cszDesc,_countof(cszDesc),"-",_TRUNCATE);

							// loop through the array of passed column names,						
							while( pContainerToSearch->GetNextColumnName(hSearch, &pszColumn ) == S_OK ) {
								hr = pContainerToSearch->GetColumn(hSearch, pszColumn, &col);
								if(SUCCEEDED(hr)) {
									// Print the data for the column and free the column
									if (0==wcscmp(L"sAMAccountName", pszColumn)) {
										if(!WideCharToMultiByte(CP_ACP,0,col.pADsValues->CaseIgnoreString,-1,cszName,_countof(cszName)-1,NULL,FALSE)) {
											if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
												strncpy_s(cszName,1,"",_TRUNCATE);
											}
										}
									}
									
									if (0==wcscmp(L"description", pszColumn)) {
										if(!WideCharToMultiByte(CP_ACP,0,col.pADsValues->CaseIgnoreString,-1,cszDesc,_countof(cszDesc)-1,NULL,FALSE)) {
											if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
												strncpy_s(cszDesc,2,"-",_TRUNCATE);
											}
										}
									}
									
									pContainerToSearch->FreeColumn(&col);
								}
								FreeADsMem(pszColumn);
							}

							//snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t%s\t",cszName,cszDesc);
							snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t%s",cszName,cszDesc);
							if(WEBSERVER_TLS) 
								retval = sendTLS(HTTPBuffer,session_https);
							else
								retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);


							//WCHAR szName[MAX_PATH];
							//mbstowcs_s(szName,_countof(szName),cszName,_TRUNCATE);
							
							// ShowThisDomainGroupMembers(szName,PDC,http_socket, session_https);
							if(WEBSERVER_TLS)
								retval = sendTLS("\n",session_https);
							else
								retval = send(http_socket,"\n",(int)strlen("\n"),0);

							
							// Get the next row
							hr = pContainerToSearch->GetNextRow(hSearch);
						}
					}
					// Close the search handle to clean up
					if(hSearch) {
						pContainerToSearch->CloseSearchHandle(hSearch);
					}
				} 
				if (SUCCEEDED(hr) && 0==iCount) {
					hr = S_FALSE;
				}
				
				if (SUCCEEDED(hr)) {
					if (S_FALSE==hr) {
						LogExtMsg(INFORMATION_LOG,"No user object could be found");
					}
				} else if (0x8007203e==hr) {
					LogExtMsg(INFORMATION_LOG,"Could not execute query. An invalid filter was specified.");
				} else {
					LogExtMsg(INFORMATION_LOG,"Query failed to run. HRESULT: %x",hr);
				}
			} else {
				LogExtMsg(INFORMATION_LOG,"Could not execute query. Could not bind to the container.");
			}
		
			if (pContainerToSearch) {
				pContainerToSearch->Release();
			}
			
			VariantClear(&var);
		}
	
	
		if(pObject) {
			pObject->Release();
		}
		if(szPath) {
			delete [] szPath;
		}


		if(WEBSERVER_TLS)
			retval = sendTLS("\n-\n\n",session_https);
		else
			retval = send(http_socket,"\n-\n\n",4,0);


		ShowDomainUserGroupsWin2k(http_socket, session_https, PDC_cstr);

		// We're done, so uninitialise the COM interface
		CoUninitialize();

		return(1);
	} else {
		// We're done, so uninitialise the COM interface
		LogExtMsg(INFORMATION_LOG,"domain is NOT mixed mode");

		CoUninitialize();
		// And fall through to normal mode.
	}


	// If we are not in native mode, fall through to normal mode.

	do {
		PNET_DISPLAY_GROUP pNDUBuff=NULL, p;
		LogExtMsg(INFORMATION_LOG,"Starting native check");
		// 1 = Users, 2 = Machines, 3 = groups
		nasReturn = NetQueryDisplayInformation(PDC,3,next,1000,MAX_PREFERRED_LENGTH,&dwGroups,(PVOID*)&pNDUBuff);
		
		if(nasReturn == ERROR_ACCESS_DENIED) {
			char temp[256]="Access Denied. Cannot query domain groups while SafedAgent is running with the privileges of the local administrator";
			if(WEBSERVER_TLS)
				retval = sendTLS(temp,session_https);
			else
				retval = send(http_socket,temp,(int)strlen(temp),0);

			if(pNDUBuff) NetApiBufferFree (pNDUBuff);
			break;
        }
		p = pNDUBuff;
		for (i=0; i<dwGroups; i++)
		{
			WideCharToMultiByte (CP_ACP,
                           WC_COMPOSITECHECK,
                           p->grpi3_name,
                           -1,
                           szNameBuffer,
                           _countof(szNameBuffer)-1,
                           NULL,
                           NULL);
		
			
			snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t",szNameBuffer);
		
			if(WEBSERVER_TLS)
				retval = sendTLS(HTTPBuffer,session_https);
			else
				retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);


			WideCharToMultiByte (CP_ACP,
                           WC_COMPOSITECHECK,
                           p->grpi3_comment,
                           -1,
                           szCommentBuffer,
                           _countof(szCommentBuffer)-1,
                           NULL,
                           NULL);

			if (!strlen(szCommentBuffer)) strncpy_s(szCommentBuffer,_countof(szCommentBuffer),"-",_TRUNCATE);
			
			snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t",szCommentBuffer);
		
			
			if(WEBSERVER_TLS)
				retval = sendTLS(HTTPBuffer,session_https);
			else
				retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);

			ShowThisDomainGroupMembersNT(p->grpi3_name,PDC,http_socket, session_https);
			
			if(WEBSERVER_TLS)
				retval = sendTLS("\n",session_https);
			else
				retval = send(http_socket,"\n",(int)strlen("\n"),0);
			next = p->grpi3_next_index;
			p++;
		}

		if(pNDUBuff) NetApiBufferFree (pNDUBuff);
	} while(nasReturn == ERROR_MORE_DATA);
	return(1);
}



int ShowThisLocalGroupMembers(WCHAR *Group,SOCKET http_socket, gnutls_session session_https)
{
	DWORD dwEntriesRead=0,dwTotalEntries=0,dwReturn=0;
	char szName[255]="";
	char Buffer[256]="";
	int first=1;
	int retval;

	LogExtMsg(INFORMATION_LOG,"ShowThisLocalGroupMembers");
	do {
	LOCALGROUP_MEMBERS_INFO_3 *Members=NULL,*MSave=NULL;
		dwReturn = NetLocalGroupGetMembers(NULL, Group, 3,
         (PBYTE*) &Members, MAX_PREFERRED_LENGTH,
         &dwEntriesRead,	&dwTotalEntries, NULL );
		MSave=Members;
		LogExtMsg(INFORMATION_LOG,"grabbed list of users, sending data");
		switch (dwReturn) {
			case ERROR_MORE_DATA: LogExtMsg(NULL,"ERROR_MORE_DATA"); break;
			case ERROR_ACCESS_DENIED: LogExtMsg(NULL,"ERROR_ACCESS_DENIED"); break;
			case NERR_Success: LogExtMsg(NULL,"NERR_Success"); break;
			case NERR_InvalidComputer: LogExtMsg(NULL,"NERR_InvalidComputer"); break;
			case ERROR_NO_SUCH_ALIAS: LogExtMsg(NULL,"ERROR_NO_SUCH_ALIAS"); break;
		}

		while ( dwEntriesRead ) {
			// Convert UniCode to ASCII
			WideCharToMultiByte( CP_ACP, 0,Members->lgrmi3_domainandname,-1, szName, 254, NULL, NULL );

			if(!first) {
				snprintf_s(Buffer,256,_TRUNCATE,",%s",szName);
			} else {
				first=0;
				snprintf_s(Buffer,256,_TRUNCATE,"%s",szName);
			}

			
			if(WEBSERVER_TLS)
				retval = sendTLS(Buffer,session_https);
			else
				retval = send(http_socket,Buffer,(int)strlen(Buffer),0);
			

			Members += 1;  // Step to the next one

			dwEntriesRead--;

		}
		if(MSave) NetApiBufferFree(MSave);
	} while(dwReturn == ERROR_MORE_DATA);

	LogExtMsg(INFORMATION_LOG,"finished ShowThisLocalGroupMembers");

	return(0);
}

HRESULT VarToBytes(VARIANT *Variant,LPBYTE *bytes,long *plcb)
{
    HRESULT hr = E_FAIL;
    SAFEARRAY *pArrayVal = NULL;
    CHAR HUGEP *pArray = NULL;

	if(!plcb || !Variant || !Variant->pparray) {
		return(hr);
	}
	int temp = sizeof(Variant);
    // Retrieve the safe array....
    pArrayVal = Variant->parray;
	LogExtMsg(INFORMATION_LOG,"Variant.vt: %d",Variant->vt);
	//if (Variant->vt != 8209) {
	//	LogExtMsg(INFORMATION_LOG,"Unknown Variant type %d.  Time to bail out...",Variant->vt);
	//	return(E_FAIL);
	//}
	
    if (pArrayVal != NULL) {
		ULONG cSize;

		if(!Variant->parray->rgsabound || !pArrayVal->rgsabound) {
			LogExtMsg(INFORMATION_LOG,"WARNING: Variant array is corrupted. I'm not touching it.");
			return(E_FAIL);
		}
		try {
			LogExtMsg(INFORMATION_LOG,"rgsabound is OK: cElements: %il, lLbound: %il", Variant->parray->rgsabound->cElements, Variant->parray->rgsabound->lLbound);
		} catch(...) {
			LogExtMsg(INFORMATION_LOG,"CRASH: cSize grab failed. Some null-pointer weirdness going on here.");
			return(E_FAIL);
		}
		//SAFEARRAYBOUND
		//try {
		//	if(Variant.parray->rgsabound[0] == (SAFEARRAYBOUND)NULL) {
		//		LogExtMsg(INFORMATION_LOG,"WARNING: Variant array is corrupted. I'm not touching it.");
		//		return(E_FAIL);
		//	}
		//} catch(...) {
		//	LogExtMsg(INFORMATION_LOG,"CRASH: rgsabound[0] grab failed. No idea what is going on here.");
		//	return(E_FAIL);
		//}
		//LogExtMsg(INFORMATION_LOG,"rgsabound[0] is OK");

		// try / catch
		try {
			if (!Variant->parray->rgsabound->cElements ) { LogExtMsg(INFORMATION_LOG,"cSize is going to fail"); } 
			cSize = Variant->parray->rgsabound->cElements;
			LogExtMsg(INFORMATION_LOG,"csize(ptr) is OK: %d", cSize);
			if (!pArrayVal->rgsabound[0].cElements ) { LogExtMsg(INFORMATION_LOG,"cSize is going to fail"); } 
			cSize = pArrayVal->rgsabound[0].cElements;
		} catch(...) {
			LogExtMsg(INFORMATION_LOG,"CRASH: cSize grab failed. Some null-pointer weirdness going on here.");
			return(E_FAIL);
		}

		LogExtMsg(INFORMATION_LOG,"csize is OK");
		// Just a small 'what the?' check
		if(cSize > 16384 || cSize <= 0) {
			LogExtMsg(INFORMATION_LOG,"Size: %d is just plain silly. Must be a corruption. Exiting",cSize);
			return(E_FAIL);
		}
        *bytes = (LPBYTE)malloc( cSize );

        if( *bytes == NULL ) return E_FAIL;

        hr = SafeArrayAccessData(pArrayVal, (void HUGEP * FAR *) &pArray);
        if (SUCCEEDED(hr)) {
            // Copy the bytes to the safe array.
		    memcpy( *bytes, pArray, cSize );
		    SafeArrayUnaccessData( pArrayVal );
            *plcb = cSize;
            hr = S_OK;
        } else {
			// Clean up
			free(*bytes);
			return(E_FAIL);
		}
    } else {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}


// Lets go about this VERY differently. It appears that getting a users group membership
// is relatively easy. Lets work backwards from that.
//
int ShowDomainUserGroupsWin2k(SOCKET http_socket, gnutls_session session_https, char *PDC_cstr)
{
	char HTTPBuffer[UGBUFFER]="";
	int HTTPBufferLen=0;
	int trimCN=1;
	
	HRESULT hr = S_OK;

	// Pull back rootDSE and the current user's domain container DN.
	IADs *pObject = NULL;
	IADsUser * pADsUser;
	IDirectorySearch *pContainerToSearch = NULL;
	LPOLESTR szPath = new OLECHAR[MAX_PATH];
	VARIANT var;
	int iCount = 0;
	BOOL FirstUser=1;

	if(!http_socket) {
		return(0);
	}

	LogExtMsg(INFORMATION_LOG,"DGWin2k: Inside ShowDomainUserGroupsWin2k.");
	
	hr = ADsOpenObject(L"LDAP://rootDSE",
		NULL, NULL,
		ADS_SECURE_AUTHENTICATION, // Use Secure Authentication
		IID_IADs,
		(void**)&pObject);
	
	if (FAILED(hr))	{
		if (pObject) {
			pObject->Release();
		}
		delete [] szPath;
		LogExtMsg(INFORMATION_LOG,"DGWin2k: Could not open RootDSE.");
		return(0);
	}

	LogExtMsg(INFORMATION_LOG,"DGWin2k: Grabbed RootDSE.");

	hr = pObject->Get(L"defaultNamingContext",&var);
	if (SUCCEEDED(hr)) {

		LogExtMsg(INFORMATION_LOG,"DGWin2k: Grabbed defaultNamingContext.");

		wcscpy_s(szPath,MAX_PATH,L"LDAP://");
		if(wcslen(var.bstrVal) < MAX_PATH) {
			wcscat_s(szPath,MAX_PATH,var.bstrVal);
		} else {
			// Buffer is too small for the domain DN
			if (pObject) {
				pObject->Release();
			}
			delete [] szPath;
			VariantClear(&var);
			LogExtMsg(INFORMATION_LOG,"DGWin2k: Tiny buffer. Out of here.");
			return(0);
		}
		
		hr = ADsOpenObject(szPath, NULL, NULL,
			ADS_SECURE_AUTHENTICATION, // Use Secure Authentication
			IID_IDirectorySearch, (void**)&pContainerToSearch);
		
		if (SUCCEEDED(hr)) {

			LogExtMsg(INFORMATION_LOG,"DGWin2k: Opened object.");

			// Specify subtree search
			ADS_SEARCHPREF_INFO SearchPrefs[2];
			SearchPrefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
			SearchPrefs[0].vValue.dwType = ADSTYPE_INTEGER;
			SearchPrefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
				
			// Note: By default, MS will only return 1000 entries.
			// The following code forces it to look for more.
			SearchPrefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
			SearchPrefs[1].vValue.dwType = ADSTYPE_INTEGER;
			SearchPrefs[1].vValue.Integer = 1000;

			DWORD dwNumPrefs = 2;
			
			// COL for iterations
			LPOLESTR szADsPath=new OLECHAR[MAX_PATH];

			ADS_SEARCH_COLUMN col;
			
			// Interface Pointers
			IADs *pObj = NULL;
			IADs * pIADs = NULL;
			
			// Handle used for searching
			ADS_SEARCH_HANDLE hSearch = NULL;

			// Set the search preference
			hr = pContainerToSearch->SetSearchPreference(SearchPrefs, dwNumPrefs);
			if (FAILED(hr)) {
				if (pObject) {
					pObject->Release();
				}
				delete [] szADsPath;
				delete [] szPath;
				if (pContainerToSearch) {
					pContainerToSearch->Release();
				}
				VariantClear(&var);
				LogExtMsg(INFORMATION_LOG,"DGWin2k: Could not setsearchpreference.");

				return(0);
			}

			LPOLESTR pszScanList[] = {L"ADsPath"};
			
			hr = pContainerToSearch->ExecuteSearch(L"(&(objectCategory=person)(objectClass=user))",
				pszScanList,
				sizeof(pszScanList)/sizeof(LPOLESTR),
				&hSearch);
			
			if (SUCCEEDED(hr)) {
				// Call IDirectorySearch::GetNextRow() to retrieve more data
				hr = pContainerToSearch->GetFirstRow(hSearch);
				if (SUCCEEDED(hr)) {
					
					while(hr == S_OK) {
						trimCN=1;
						iCount++;

						// No need to loop through the array of passed column names,
						// Since we only asked for one.

						hr = pContainerToSearch->GetColumn(hSearch, L"ADsPath", &col);
						if(SUCCEEDED(hr)) {
							// Print the data for the column and free the column

// DEBUG only - simulate lots of users.
//for(int tempcount=0;tempcount<500;tempcount++) {
// OK.. the memory leak is in here somewhere!!!!!!!

							LogExtMsg(INFORMATION_LOG,"Alloc pADsUser");

							hr = ADsOpenObject(col.pADsValues->CaseIgnoreString,NULL,NULL,
									ADS_SECURE_AUTHENTICATION,
									IID_IADsUser,
									(void **)&pADsUser);

							pContainerToSearch->FreeColumn(&col);

							if(SUCCEEDED(hr)) {
								int firstgroup=1;
								BSTR username;
								VARIANT vTokenGroups;
								VARIANT HUGEP *pVar;
								LPWSTR prop[] = {L"TokenGroups"};
								SAFEARRAY *pArray;
								DWORD SIDCount,lBound;
								PSID pSID;
								DWORD i;
								long cbSID;


								LogExtMsg(INFORMATION_LOG,"Alloc username");
								pADsUser->get_Name(&username);

								// die if username null?
								if(!username) {
									LogExtMsg(INFORMATION_LOG,"DGWin2k: Could not get Name.");
									pADsUser->Release();
									continue;
								}

								snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%S	",username);
								HTTPBufferLen = strlen(HTTPBuffer);

								// Free username here - we don't need it any more.
								LogExtMsg(INFORMATION_LOG,"Free username");
								SysFreeString(username);

								LogExtMsg(INFORMATION_LOG,"Alloc vTokenGroups?");
								// Retreive the token groups array...
								VariantInit(&vTokenGroups);

								hr = ADsBuildVarArrayStr(prop,1,&vTokenGroups);
								if(!SUCCEEDED(hr)) {
									LogExtMsg(INFORMATION_LOG,"DGWin2k: Couldnt buildvararraystr.");
									pADsUser->Release();
									continue;
								}

								hr = pADsUser->GetInfoEx(vTokenGroups, NULL);

								LogExtMsg(INFORMATION_LOG,"Free vTokenGroups");
								VariantClear(&vTokenGroups);
								if(!SUCCEEDED(hr)) {
									LogExtMsg(INFORMATION_LOG,"DGWin2k: Couldnt getinfoex.");
									pADsUser->Release();
									continue;
								}

								LogExtMsg(INFORMATION_LOG,"DGWin2k: Getting tokengroups.");

								LogExtMsg(INFORMATION_LOG,"Alloc vtokengroups again?");
								hr = pADsUser->Get(L"TokenGroups",&vTokenGroups);
								if(!SUCCEEDED(hr)) {
									LogExtMsg(INFORMATION_LOG,"DGWin2k: Could not get tokengroups.");
									pADsUser->Release();
									VariantClear(&vTokenGroups);
									continue;
								}

								// Wander through the TokenGroups with a variant array
								// and loop through the SIDs
								pArray = vTokenGroups.parray;
								SIDCount = pArray->rgsabound->cElements;
								lBound = pArray->rgsabound->lLbound;

								LogExtMsg(INFORMATION_LOG,"Alloc pArray");

								hr = SafeArrayAccessData( pArray, (void HUGEP**)&pVar);
								if(!SUCCEEDED(hr)) {
									LogExtMsg(INFORMATION_LOG,"DGWin2k: Couldn't SafeArrayAccessData.");
									pADsUser->Release();
									VariantClear(&vTokenGroups);
									continue;
								}
								// Grab the sid into pSID (note: allocated by VarToBytes...
								// Don't forget to clear!

								LogExtMsg(INFORMATION_LOG,"DGWin2k: about to loop through sids. lbound is %d nosids is %d",lBound,SIDCount);
								for( i = lBound; i < SIDCount;i++ ) {

									// LogExtMsg(INFORMATION_LOG,"DGWin2k: looping through sids. lbound is %d nosids is %d, i is %d.",lBound,SIDCount,i);
									char szName[513]="";
									char szDomain[513]="";

									// Convert the variant containing the SID into an array
									// of bytes so that we can use lookupaccountsid.
									LogExtMsg(INFORMATION_LOG,"Alloc psid");
									hr = VarToBytes(&pVar[i], (LPBYTE *)&pSID, &cbSID);

									if(!SUCCEEDED(hr)) {
										// Break out of here. Something is seriously corrupted in our pVar variables.
										LogExtMsg(INFORMATION_LOG,"DGWin2k: VarToBytes bugged out. The UserName is %S",username);
										// continue;
										break;
									}

									LogExtMsg(INFORMATION_LOG,"Attempting sid translation");
									// HERE: Translate sid to name.
								    // Some of the MS System calls use by LookupAccountSid are buggy.
									try {
										SID_NAME_USE snu;
										DWORD cbName = 512;
										DWORD cbDomain = 512;
										// LogExtMsg(INFORMATION_LOG,"DGWin2k: Trying lookupaccountsid.");
										LookupAccountSid(NULL, pSID, szName, &cbName, szDomain, &cbDomain, &snu);
									} catch (...) {
										strncpy_s(szName,1,"",_TRUNCATE);
										LogExtMsg(INFORMATION_LOG,"DGWin2k: Lookupaccountsid barfed.");
									}

									int szNameLen = strlen(szName);
									if(szNameLen) {
										if (HTTPBufferLen + szNameLen >= UGBUFFER-2) {
											if (trimCN) {
												
												if(WEBSERVER_TLS)
													sendTLS(&HTTPBuffer[3],session_https);
												else
													send(http_socket,&HTTPBuffer[3],HTTPBufferLen-3,0);
												trimCN=0;
											} else {
												if(WEBSERVER_TLS)
													sendTLS(HTTPBuffer,session_https);
												else
													send(http_socket,HTTPBuffer,HTTPBufferLen,0);
											}
											HTTPBuffer[0]='\0';
											HTTPBufferLen=0;
										}
										if(!firstgroup) {
											strncat_s(HTTPBuffer,_countof(HTTPBuffer),",",_TRUNCATE);
											HTTPBufferLen++;
										}
										strncat_s(HTTPBuffer,_countof(HTTPBuffer),szName,_TRUNCATE);
										HTTPBufferLen+=szNameLen;
										firstgroup=0;
									}

									if(pSID) {
										LogExtMsg(INFORMATION_LOG,"Releasing pSID");
										free(pSID); // VariantArrayToBytes allocates memory using Malloc, must free it
									}

								}

								strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\n",_TRUNCATE);
								HTTPBufferLen++;
								if (trimCN) {
									
									if(WEBSERVER_TLS)
										sendTLS(&HTTPBuffer[3],session_https);
									else
										send(http_socket,&HTTPBuffer[3],HTTPBufferLen-3,0);
									trimCN=0;
								} else {
									
									if(WEBSERVER_TLS)
										sendTLS(HTTPBuffer,session_https);
									else
										send(http_socket,HTTPBuffer,HTTPBufferLen,0);
								}

								// Need to clean up...

								LogExtMsg(INFORMATION_LOG,"Releasing pArray");
								SafeArrayUnaccessData(pArray);

								LogExtMsg(INFORMATION_LOG,"Releasing vTokenGroups");
								VariantClear( &vTokenGroups);


								// Free pADsUser - we don't need it any more.						
								LogExtMsg(INFORMATION_LOG,"Releasing PADSUser");
								if(pADsUser) {	pADsUser->Release(); }
							}
//} // Debug only
						}
						
						// Get the next row
						hr = pContainerToSearch->GetNextRow(hSearch);
					}
				}
				// Close the search handle to clean up
				if(hSearch) {
					pContainerToSearch->CloseSearchHandle(hSearch);
				}
			}
			if(szADsPath) {
				delete [] szADsPath;
			}

			if (SUCCEEDED(hr) && iCount==0) {
				hr = S_FALSE;
			}
			
			if (SUCCEEDED(hr)) {
				if (hr==S_FALSE) {
					LogExtMsg(INFORMATION_LOG,"No user object could be found");
				}
			} else if (hr==0x8007203e) {
				LogExtMsg(INFORMATION_LOG,"Could not execute query. An invalid filter was specified.");
			} else {
				LogExtMsg(INFORMATION_LOG,"Query failed to run. HRESULT: %x",hr);
			}
		} else {
			LogExtMsg(INFORMATION_LOG,"Could not execute query. Could not bind to the container.");
		}

		if (pContainerToSearch) {
			pContainerToSearch->Release();
		}
		VariantClear(&var);
	}

	if(szPath) {
		delete [] szPath;
	}
			
	if(pObject) {
		pObject->Release();
	}

	return(1);
}

// Check for mixed mode..
BOOL ADIsMixedMode()
{
	BOOL rc=0;
	HRESULT hr = E_FAIL;
	VARIANT var;
	
	// This ADSOpenObject is causing a new thread to happen & stick around.
	// Suspect it might be a windows DLL.

	// Pull back rootDSE and the current user's domain container DN.
	IADs *pDomain = NULL;
	LPOLESTR szPath = new OLECHAR[MAX_PATH];
		
	LogExtMsg(INFORMATION_LOG,"ADIsMixedMode");
	hr = ADsOpenObject(L"LDAP://rootDSE",
			NULL,
			NULL,
			ADS_SECURE_AUTHENTICATION, // Use Secure Authentication
			IID_IADs,
			(void**)&pDomain);
		
	if (FAILED(hr))	{
		if (pDomain) {
			pDomain->Release();
		}
		delete [] szPath;
		return(0);
	}
	
	if (pDomain) {
		hr = pDomain->Get(L"defaultNamingContext",&var);
		if (SUCCEEDED(hr)) {
			wcscpy_s(szPath,MAX_PATH,L"LDAP://");
			if(wcslen(var.bstrVal) < MAX_PATH) {
				wcscat_s(szPath,MAX_PATH,var.bstrVal);
			} else {
				// Buffer is too small for the domain DN
				if (pDomain) {
					pDomain->Release();
				}
				delete [] szPath;
				return(0);
			}
			
			if (pDomain) {
				pDomain->Release();
				pDomain=NULL;
			}
			hr = ADsOpenObject(szPath, NULL, NULL,
					ADS_SECURE_AUTHENTICATION, // Use Secure Authentication
					IID_IADs, (void**)&pDomain);
				
			if (SUCCEEDED(hr)) {		
				VariantClear(&var);

				// Get the ntMixedDomain attribute.
				hr = pDomain->Get(_bstr_t("ntMixedDomain"), &var);
				if (SUCCEEDED(hr)) {
			
					// Type should be VT_I4.
					if (var.vt==VT_I4) {			
						// Zero means native mode.
						if (var.lVal == 0) {
							rc=1;
						}
					}
				}
			}

			VariantClear(&var);

			if(pDomain) {
				pDomain->Release();
				pDomain=NULL;
			}
		}
	}
	if(pDomain) {
		pDomain->Release();
	}
	delete [] szPath;
	return rc;
}



int ShowThisDomainGroupMembersNT(WCHAR *Group,WCHAR *PDC, SOCKET http_socket, gnutls_session session_https)
{
	GROUP_USERS_INFO_0* Members,*MSave;
	DWORD dwEntriesRead=0,dwTotalEntries=0,dwReturn=0;
	char szName[255]="";
	char Buffer[256]="";
	int first=1;
	int retval;

	LogExtMsg(INFORMATION_LOG,"ShowThisDomainGroupMembersNT");
	do {
		// NOTE: This function call does not display domain groups of groups in active directory native mode!
		dwReturn = NetGroupGetUsers(PDC, Group, 0,
         (PBYTE*) &Members, MAX_PREFERRED_LENGTH,
         &dwEntriesRead,	&dwTotalEntries, NULL );
		MSave=Members;

		while ( dwEntriesRead ) {
			// Convert UniCode to ASCII
			WideCharToMultiByte( CP_ACP, 0,Members->grui0_name,-1, szName, 254, NULL, NULL );

			if(!first) {
				snprintf_s(Buffer,256,_TRUNCATE,",%s",szName);
			} else {
				first=0;
				snprintf_s(Buffer,256,_TRUNCATE,"%s",szName);
			}
			
			
			if(WEBSERVER_TLS)
				retval = sendTLS(Buffer,session_https);
			else
				retval = send(http_socket,Buffer,(int)strlen(Buffer),0);	

			Members += 1;  // Step to the next one

			dwEntriesRead--;

		}
		if(MSave != NULL) {
			NetApiBufferFree(MSave);
			MSave=NULL;
		}
	} while(dwReturn == ERROR_MORE_DATA);

	return(0);
}








// General instructions:
// $ expr `./base64 logo.gif | wc -c` - `./base64 logo.gif | wc -l` "*" 2 + 1
//   2029
// ./base64 logo.gif | sed 's/^/   "/' | sed 's/$/"  \\/' >out.txt
// 
//  mangle out.txt as appropriate - add the (wc -c) - ((wc -l)*2) + 1 figure to the buffer size.
int ImageClear(char *source, char *dest, int size)
{
	char Gif[329];
	char temp[329];
	int size2;

	strncpy_s(Gif,329,"R0lGODlhDQAOAIQVAAwMDCIiIikpKUJCQk1NTVVVVV9fX2ZmZnd3d4aGhpaWlpmZmaCgpLKy"  \
		"ssDAwMzMzNfX193d3ePj4+rq6vHx8f//////////////////////////////////////////"  \
		"/yH5BAEKAB8ALAAAAAANAA4AAAVx4Cd+RwAIxzgexfJATzMkI3IwkkRRUGMgolnjFYn0EIVP"  \
		"4dZoOJ6OJoIwWDSh0QYjQShcIeBw03BwPIq5HMxxODQiksmOMpFEGonEW1fp0ydbeQ99hH0P"  \
		"eSQKEYUVEgpAImQMEBMQDAgGKiIFA50EKiEAOw==",_TRUNCATE);

	size2=base64decode (temp, Gif);

	memcpy(dest,temp,size2);
	return(size2);
}

int ImageInfo(char *source, char *dest, int size)
{
	char Gif[473];
	char temp[473];
	int size2;

	strncpy_s(Gif,473,"R0lGODlhDQAOAKUjAAwMDBwcHAAzACIiIikpKTMzADMzMzk5OUJCQjNmM1VVVV9fX2ZmMzOZ"  \
   "M3d3d2aZM2aZZoaGhpmZZmbMM2bMZpnMM5nMZrKyspnMmcDAwMzMmZn/Zt3d3cz/Zsz/mefn"  \
   "1urq6vHx8f//zP//////////////////////////////////////////////////////////"  \
   "/////////////////////////////////////////////////////////yH5BAEKAD8ALAAA"  \
   "AAANAA4AAAZ9wJ/wpxgACIrh0LGIXDiZiMKxPEQ+oBDoEzFQf4SEBKPBmCELAjGReEAo8Mmj"  \
   "wTa0H4+JXv5IBAp4ExaDFRV8AgUQExUWG44bjBAFCRCDGx2YG4MSCQwPFpgeHpgdFg8MEQwW"  \
   "oqyiFqg/nqsirKYLQ55jGhYSp0pCCMFsSkEAOw==",_TRUNCATE);

	size2=base64decode (temp, Gif);

	memcpy(dest,temp,size2);
	return(size2);
}

int ImageWarn(char *source, char *dest, int size)
{
	char Gif[473];
	char temp[473];
	int size2;

	strncpy_s(Gif,473,"R0lGODlhDQAOAKUjABwcHCkpKTMzM2YzAEJCQmYzM5kzAJkzM1VVVWZmM2ZmZplmM5lmZnd3"  \
   "d8xmM8xmZoaGhpmZM5mZZpaWlsyZM8yZZv+ZM/+ZZszMZszMmf/MM8zMzP/MZv/Mmd3d3efn"  \
   "1v//Zv//mf/78P//////////////////////////////////////////////////////////"  \
   "/////////////////////////////////////////////////////////yH5BAEKAD8ALAAA"  \
   "AAANAA4AAAZ9wJ/w1wAEBIjhUNFgeDybSQMybBQkos8nKyk0hIdHpUPucCqLw49xcFAoFYzm"  \
   "7TgcCu63Zv6mOAYFFBYWGhwce4MWBgUVh4aPiAsLjY8gII4XCwyNliGelhwUDBILGJ2enhgL"  \
   "Ej8JpaipEQtDCQkRGRkYEhEJSkIJBMG9Q0EAOw==",_TRUNCATE);

	size2=base64decode (temp, Gif);

	memcpy(dest,temp,size2);
	return(size2);
}
int ImagePri(char *source, char *dest, int size)
{
	char Gif[461];
	char temp[461];
	int size2;

	strncpy_s(Gif,461,"R0lGODlhDQAOAKUlAAQEBBwcHDMzM2YzAEJCQmYzM5kzAE1NTZkzM8wzAF9fX2ZmM8wzM2Zm"  \
   "ZplmM5lmZnd3d8xmAMxmM8xmZoaGhv9mM8yZM8yZZq2pkMyZmf+ZM/+ZZsDAwP/MZv/MmdfX"  \
   "1//MzO/Wxufn1v//zP/78P//////////////////////////////////////////////////"  \
   "/////////////////////////////////////////////////////////yH5BAEKAD8ALAAA"  \
   "AAANAA4AAAZ2wJ/w1wgAAofhsEGgcD4cikIxhAgyIJKINMIUKMKBY7LxmC8Xx+DnMEgYkrgl"  \
   "bjCoDYl4ZV+RRBADA3oaG4UafRKBcYUdHYZ9ioVmHo2FEnYIkpMehQ4OFAUXm2aOCBc/D6Ee"  \
   "ISFnnkMPCA5oaQ4LSkIFurpKQQA7",_TRUNCATE);

	size2=base64decode (temp, Gif);

	memcpy(dest,temp,size2);
	return(size2);
}
int ImageCrit(char *source, char *dest, int size)
{
	char Gif[469];
	char temp[469];
	int size2;

	strncpy_s(Gif,469,"R0lGODlhDQAOAKUhAAQEBDMAABwcHGYAACkpKUJCQmYzM01NTZkzM1VVVV9fX8wzM2ZmZswz"  \
   "ZplmM5lmZnd3d8xmM8xmZoaGhv9mZpaWlsyZZv98gMyZmf+ZZv+ZmcDAwP/MmdfX1//MzOfn"  \
   "1vHx8f//////////////////////////////////////////////////////////////////"  \
   "/////////////////////////////////////////////////////////yH5BAEKAD8ALAAA"  \
   "AAANAA4AAAZ8wJ/wxxAABIfhkFGYbDqbiUIxhBAwH5D2UzlMhAaHBIPRkCUPwy+NQDQkkkik"  \
   "bWAjFgu4fEEP3OEUFxQUEXwDAxESgReMgnEDBgiNGpQZjBF1kheUnIwIDxMGZRocpZQWn2sG"  \
   "EhoeHhwaEg4PQ2kPEhYPumpKPwkGwLxCQQA7",_TRUNCATE);

	size2=base64decode (temp, Gif);

	memcpy(dest,temp,size2);
	return(size2);
}



int ImageStatus(char *source, char *dest, int size)
{
	char Gif[1400];
	char temp[1400];
	int size2;

	strncpy_s(Gif,1400,   "R0lGODlhEAAQAIcAAAAAAAQfmgYcmA0alAgfmgYinA4mnQ4qnxMjlxInmhcrmwAupgkqpQA0rgA7"  \
   "pQA9rAA+rAA/rgA1shMzoxMzqQNBrQBBsgVGuQZHugZHuw1AtwtMvQxMvQ1PvxtArB1CqhJGuxNP"  \
   "ux9ItB9JuylNqyhMrCZRrS1VryRQsyVStChRtCtVsitWsitWtDZlvwBDwwBIyw1LxgBH0ARSzg1S"  \
   "wgpQyQBR0gBU2BBRyhVWzxlSyBtcyRtd0QBV4gFZ4B9hzhBg3g9i4SBYxyFczyNdzyRf0yBa2CRh"  \
   "zCNs3C1t1DBo1TNv1j1x1jpw2SRy7C135Sd++Ct/9DNw4DJ97T164T9/801Qp05Rp1VerVlgrmJ0"  \
   "uWR2unh4uHx8ukJvyUNyzU50yUB620x+30x/3kyA31KD3FSD2E2C4E6C4FWR9Vic+WmBwGqCwWGM"  \
   "3G+c3nGZ3nid32qY52+b4G+c4Wyb6mqe8nKd53ed4HOg63Om93mm8Hqq8oePxYmQxYmSxoyVyZin"  \
   "0pin04Kl4oCk5ISn4oir54+x54a09Iy1956+65G495a68pC6+pK+/Je++pTA+qPN+aPM+q7S/7jI"  \
   "577N6bHW/7ba/8PD38XF4cvN5c3P5tHW6tLW6tLc69Pf7tXc7dTd7tTe7dfc7dbg6tvi6/X17/v5"  \
   "7/H09fP29fb38fP0+PX1+vT2+Pf48vv7/f7+/v///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAMAALAALAAAAAAQABAA"  \
   "AAjaAGEJHEiwoME1J1qoKKHFoEBALNw8OrQnDxkPfgoGcgGp0iJKk+zUSTOiD8EVkSQxMsRK1Rs0"  \
   "Z6pQ0CSQjRxLjhDREQRnjBgmUoxgEWhCTSNFeAoNulOmiZIhPBQITAHFiZ44hE6halOESAYaBwSi"  \
   "iNIDCJUwoFqZiXEhQgcDAklM8XFDRo5Qqb5IsACBAwKBW5YEsQEDR6dSXho8qKDBysAPT2a80EHK"  \
   "FJgFDjYQwDTwjwgkNeZ4GpUoBAYGXQrymSAkyY8dR0AI4OIwU5YEBQIMuHLJoe+CAQEAOw==",_TRUNCATE);

	size2=base64decode (temp, Gif);

	memcpy(dest,temp,size2);
	return(size2);
}


int ImageSearch(char *source, char *dest, int size)
{
	char Gif[1400];
	char temp[1400];
	int size2;

	strncpy_s(Gif,1400,    "R0lGODlhEAAQAIcAAAAAACknJjY0Mj89O0NBPkpKSFBQT1ZVVFRXWVxaWF5bWF9eW19gYGNUVGVb"  \
   "V3RZVXhgWmNiYmVjY2ppaGpsbmxranVzcXl4eW92gnV/inuCj3qHl4E4KYc5KpA1J4tSO49RPJVN"  \
   "NLBjHJVeV4htbZd8fKdhW99uEO1qCfFrCoKAf/SONOq0RP/UOv/VPP/bPfLHTfPITPjHX4yLiIyL"  \
   "i4SHko6QmpGPi5aVkpmZn52cnp6en5CcpJifo5mdq5egqJikpqSjo6ClqKanqqqqqqmwtq6xta+x"  \
   "ta+zt7CwsLKysIms15ms1Ze666m+7ZTL/5jH95nM/5nN/5rN/57P/5/P/53T/6LR/6TS/6TY/6jT"  \
   "/6nV/6nX/6rW/6vW/6zX/7LA4rDF8rTI9LfP+bfQ4L7Q7bLX/7XW/7La/7Tb/7Td/7fc/7jb/rvf"  \
   "/7rg/7vg/7/g/8PDw8vLys3IyM/PztXV1cve58Lh/8Pi/8Xl/cfl/8fo/8jm/83n/8vo/8zo/87t"  \
   "/9Pl9NLp/9Pr/9Ts+tjp9djv/9jw/9nw/9ny/9vw/9vz/9v1/9/z//X0y+Ti4uji4ujk5Onk5Orm"  \
   "5uvm5uvr6+3p6eD0/+D3/+L1//Dr6/Dw7/f39/n5+fv7+/39/f///wAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAMAAKAALAAAAAAQABAA"  \
   "AAjGAEGBooMjhw8bFmYIXLhQiQ4wYcQ4YVJDAUOBcnaMOSNI0SA2TTQsuHijzJU3eO7AcZNlyQEi"  \
   "DIOYeYJlixctVaxAwZCA4ZE1VKRImRJlChc1GwgwHOKnDZouW76k2ZMnwwCGKgIB+qNHD58+jMgg"  \
   "YMCQhpFFiQ4ZQoSJEI8Acy5WQFKoUaZLdn4AKWHiIqgJF4QU6UFBAAlHMkL4TSLBQIEIcUasaBED"  \
   "hF+/HlK4gPHh8sUOKF6wgOCZIYcTIhyUZvigAaiAADs="   ,_TRUNCATE);

	size2=base64decode (temp, Gif);

	memcpy(dest,temp,size2);

	return(size2);
}

int ImageCfg(char *source, char *dest, int size)
{
	char Gif[1300];
	char temp[1300];
	int size2;

	strncpy_s(Gif,1300,      "R0lGODlhEAAQAIcAAAAAAEYqImVJOXhILndPMnRTN0FBQEJER0REQ0dISE5OTlFKS1dMS1BQUFBR"  \
   "UVlZWVtcXWRNRGtUSm9dV3FWS3ddVmJhYmVlZWlpaWtsbG1tbmxub21ub3NoaHNrbXxubnZwb3xx"  \
   "bnBwcHNzc3Byen1wcXx8f39/gZJKHZZMGYBNL75WFaJfMK9nJbRoILhwK712Oax9Trl0TN5tFb2d"  \
   "csmVU9+YTtuYUteocuOiXOCyduO1fPe+ev/Cav/NfoCAg4eHiIuDgomJiY+JiY6Pjo6Pk5OFhpeX"  \
   "m56Wl5iZmZ6enpucoKCgoKCjpKamp6anqKepqqmprKusrKytr6qwtrCwsbCxs7e3t7K0uLG3vrm5"  \
   "ubi5u73Awr/Bxdi5lc++tP/TgP3Ql/7bn/3ftv/fvv/hm//mqP/nrcPDw8PGzcfKzMrJy87Ozs3P"  \
   "0c3P1tLS0tHT1tPS19XV1dvb297e3v/zx//83eHj5uXl5ejm6Onp6evr6+3s7O/u7vPz8/f39/v7"  \
   "+/39/f///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAMAAIIALAAAAAAQABAA"  \
   "AAimAAUJFAjkxJElRUwwGcgQTQYucKI8mbIliQiGAjm0uWNlQwIEDR4o0MJwRBM1XdKQsIBRIBsM"  \
   "QqRAyUKFRoGWgn7EWUPkAIgaYHREaKnBDRYDSkK46GEmxpCWEBxcEFiihQ8xBHBeYfjhRZkdAnBi"  \
   "pHDjDA4JYhmq4FHHy4S0Ao3ACGPniwe4ggbkGENGRhC4SFjYmLGCAd4KKVAEcIJXUIcFVQQFBAA7"  ,_TRUNCATE);

	size2=base64decode (temp, Gif);

	memcpy(dest,temp,size2);
	return(size2);
}





int ImageList(char *source, char *dest, int size)
{
	char Gif[1300];
	char temp[1300];
	int size2;

	strncpy_s(Gif,1300,    "R0lGODlhEAAQAIcAAAAAAB8seiUtWSMuYyMwaD1CX1oVFkkjI00yM2I/P0tPaFFSY1hcd3RKSn9M"  \
   "SG1ufxo/mwc1pCQ5tzpJiDxNkQ5J0yhWzjp24khTlllclktXokpWqUlTuktts2dpsGdot2RovGhp"  \
   "tlhnwUZ55COC/ymE/1uDzUyQ+Eyc/06d/1SM81CN/1id/1mc/1yY+1+b/F2c/12g/2KN1Wab82Ke"  \
   "/3+u7HWq/3bC/33B/5YqK5czMp03NphRUZtTUZpvb8cXGdkbHPQNC/oPDf89NNpGPP9ANt1RR/9N"  \
   "Sv9PTY6OjpGRkZWVmpiYmbWWlruYmaCgoKqqqqurq6yrq7CwsLm5vry8vJub0bCw2oDC/4nG/7rg"  \
   "/8utrM+xsc/P1M/P1tfX19rZ2dra2t7e38rK5cvV8dHR6dfe88Ti/8rl/97r/+ba2v/NxP/Rx+Li"  \
   "4+np6e7r6/Pt7fX19ff39/Pz+////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAMAAHQALAAAAAAQABAA"  \
   "AAibAOkIHEhQIAgrGQoqpMNhhpYRDBYS3HDixoUCEp00odOFQocBTBb24LLFgcAlVRbyMMJmDZEE"  \
   "EgXmEFJkSBADMen4AILkyA8EBceE+ODBC50GO3QcmELwiggzc8hooEJHihKFEl6gSXNmRYCYFUrQ"  \
   "sAGDRIQoEi2kaBGDBQoITyRicIElCw4VAmJ2mSCjhgkCSXLSeaBgAZScAQEAOw=="  ,_TRUNCATE);

	size2=base64decode (temp, Gif);

	memcpy(dest,temp,size2);
	return(size2);
}

int ImageSave(char *source, char *dest, int size)
{
	char Gif[1400];
	char temp[1400];
	int size2;

	strncpy_s(Gif,1400,    "R0lGODlhEAAQAIcAAAAAADQzez89ekEoJUkrMEU5O28zD3gwGGUzS0FCWUlNUUlJWE1NWk9PXU5O"  \
   "X1BQXlBQX1FQX1NYUlpYWVJRYFNTcltbdHpaWmNjbGxseB8khSMkhSkqiigpmDA4mzlMukpIgEZF"  \
   "kktInlVSgEFCrFBSpVhVsVtYtVtlvVpvtlNyvnNfq2pnlW5hmnx9mGJgvnJpv3lsvkdhymVmx2hm"  \
   "w2lnx21owmN30ndswHBvz3Rz1H9+1Xl42XWR45BSB6dXG6xrAptbZptoQ4lxcKdzQ6d9VL5+WKJx"  \
   "baNycNJzAcplJ4FwwrOLVuyaAP+vF96zWOWuU+ywevvFAf/dBf/fGP/OK+vOZPPdbPfZbP/wRv/9"  \
   "WP/2YYWFi4yIjoyMjoKPnYeFqYqGoIyTp52dt5uguLiAg6ensLq6u42Dx42Hy4eO1I2Vxo2W05OC"  \
   "1JSQ1ZSb8ISizJquxZe105640Iut85i+4K6Z0KCyxqO0wquwwqS50ai/0Lm+zKCr6KWi8amr96S7"  \
   "/6i8/6m8/6m9/qq//6u+/72x5rK3/7O2/7Sz/ra0/rm3/rq4+by+/5jA85nB/qTC1q3C067I3rbE"  \
   "2rPN36zG/LbP57jD/7rQ5bfT/77e/8CPj8Cngei/jPPyrcDBzcjIyMzM19PT3sDG/8LE/8XG/8fP"  \
   "/8LZ6cHY7cnb78La8M3U/9fZ/9fe/8Pl/8Xl+8rt/9Hg6t3h7dnu+Nnx/9n1/9/3/+Li4ubm5uHm"  \
   "/+/v8unv/+L0+uT0+/f39/H8//n5+fn5+vr6//j8//n+//r8//39/f39/v7//////wAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  \
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAMAAMkALAAAAAAQABAA"  \
   "AAjwAJMJHEiwYLIOJGbQsAEDR4wlK8IU1JCizyhTq1rl2iXMTotkm5Ak26ACjpo/hxA1KsWqmCEE"  \
   "RpQMESCjjhw2fhIpWkSKURkonqIcYPHBEaQ5a9KgcdMmyJMtVIgQGOPhkaQ4eyJRIiPEipYpQAaA"  \
   "SsaBzis9d1DxYXIlixQfBQYG6AHLEqZJRbBUaWJgAsERN1ypOmWmk5MkRyoUBINCEy08Ejj9uJBK"  \
   "zBmCoUpksvVFQZc8sZB94lIwRKVas3j1+kVsmCwMBUG8ATQoUKFAgghdslDQhQgTJ17UyKGDx44E"  \
   "BjMwaPAAQgQKDhZ4GRgQADs="   ,_TRUNCATE);

	size2=base64decode (temp, Gif);

	memcpy(dest,temp,size2);

	return(size2);
}


int ImageArrow(char *source, char *dest, int size)
{
	char Gif[1300];
	char temp[1300];
	int size2;

	strncpy_s(Gif,1300,   "R0lGODlhDwAPAPcAAAQCBPz+5Pz+/AAAAJWYoB7mMAASRQAAAJrjkB3q5wCQEgB8AAA06wDmhxUS"  \
   "1AAAdww4AAAA8AAA/QAAfwA4kAIA5wAAEgAAAADjMgGUiADU1AB3d6DVUOWy5xLUEgB3AHkA/wgG"  \
   "h4IG1HwAdwAgDAAAAAEAAAAAAFYKoAAGgwAFfgAAAKgStOQAgxIAfgACAG4AFAAAAAAAAAAAAMie"  \
   "AeUCABIAAAAAABgBAO4AAJAAAHwAAHAAAAUGAJEGAHwAAP8wEP+AAP9FAP8AAG0KAAUGAJEFAHwA"  \
   "ABUABwoAAIKZAHziAADjAACUABXUAAB3AGBJAANmAADWAAB3ALACAZAGABcFAAAAAHhOMWFvMBV0"  \
   "MAAgIABhJQAgIABmAABpAH5sJABl7AAAEsAAAAATlAAGBAD/1wD/d/+kCP/miP8S1P8Ad/8Q///g"  \
   "///U//93/wAA/wAGhwAG1AAAdwAgQwAAtwAA1AAAdwAKAAAGABUFAAAAAFcSoPMAMAAARQACANgB"  \
   "AuUABhIABQAAAC/sAA7mAIISAHwAANu+BwXfAILUAHx3AEAAAOUGAE8GAAAAAHggAGEAAAEAFQAA"  \
   "AGwKAAAGAAAFAAAAABRXAOXzABIAAAAAADTwAADmAAASAMAAAPiDAPcqABKCAAB8ABgACO4AAJAA"  \
   "oXwAAHAAAAUAAJEAAHwAAP8AAP8AAP8AAP8AAG0ADQUBAJEAAHwAAErnDfYqAICCAHx8AAAUXADn"  \
   "8BUSEgAAAADC/wAq/wCC/wB8/3gAAGEAABUAAAAAAAAMHAEA6AChEgAAAAC+DgA+zwCCSwB8AFf/"  \
   "/Pb/54D/Enz/AAAYW+fo4hISTgAAAHj3MGE+6BWCEgB8ANG4vtzvPtROgncAfKAQqYMZ6H5PEgAA"  \
   "AAwA8QAB/wAA/wAAfwAUnADn6AASEgAAAOAADNwBANQAoXcAAAAWvgA/PgCCggB8fAwBDAAAAAAA"  \
   "oQAAABMAVwYA8/8wAP8AAAHNAACrAAC6AADcAAAAfgAAVQAARwAAACH5BAEAAAIALAAAAAAPAA8A"  \
   "BwhEAAEIGEiwYEEAAg0qFIAw4UKCAAIgfAgxgESHCyNanPhQ40aMBy2K5GjQ40iQDEWqJDnQ5EqM"  \
   "Ll9WVEmTY8yaAm/iDAgAOw==",_TRUNCATE);

	size2=base64decode (temp, Gif);

	memcpy(dest,temp,size2);
	return(size2);
}



int LogoImage(char *source, char *dest, int size)
{
	char LogoGif[15000];  //12920  //2870
	char temp[15000];
	int size2;



  /* strncpy_s(LogoGif,2870,"R0lGODlhwABJANU3AGloaPJmas3MzJuamvvMzfaZm8rLzbCytJ2eofj5+fLy8r6/wdfY2evs7KOl" \
   "qOXl5qqrrtHS00RCQt7f4PmytLe4urSzs11bW4KBgdnZ2cTFx/FZXcmZm8VnaaempnZ0dP3l5v7y" \
   "8/SAg/zZ2vWNj/ilqMA0N+9ARPBNUY+Ojubm5lBOTsxARPNzdvq/wdONj9aztNczOMDAwNlNUe4z" \
   "ODc1NZaYm////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAADcALAAAAADAAEkAAAb/wJtw" \
   "SCwaj8ikcilUTAyVA8RGRRwOGkaDye16v+CweExGJhgLB3XNbtsci0d5Tq/b7+RJxc3vvxl4gYKD" \
   "hFwJBmp+im4OcmINBgcIbQcLDAqFmZp0h5OLn24VCV8MU58QEaObq6xJnaCwjFtMDQexawuYrbus" \
   "E4m3wDYIjkkMnsE2Gqq8zIEJe8jRE8XRbAjTzdl0E8fVwAizRRPebaLa52Eatw4HFQbv8Fffy0IJ" \
   "3W0QC+8M8BW/sugCLklgShGcCMSUKEDzz8+BItDKMaBnJMGEBfeEARLIkUiDjGxQhQvTQANINhGG" \
   "PHCTC4weNxs7Cnxw0oEBXQofvNNw5cA7/4SjzjS0psrWGggjwShY0CamTG0M+hzAlkRBhAon28CZ" \
   "ZuDkghsK2CygKEZBRBtOn/KKyhLnkTMFvy2IYNSNVVx4HvxKq3YVWzYH3FbsSm5RJCpfBRlYk7Rv" \
   "pr9UICQ8EiFr4TWeKhSiKYysY0EfMadU0iDu5UUIPN9JYOvh50KhqQReEuH0LaqZmBp4PYhgldFK" \
   "mH6CM9RNPngaTMtuVbsx7znQkA5U3gbBgi3qHE48wpnNZE2lnt+pbWPsdIMGVEGm9L1Ig5DMGAAX" \
   "T+a9jflmqP8mogDktS7ZodVMe/R5kYAD/zEhHB/KFFFXSIKRtoZqBX5mknNGkGdcY+OwFP9GZBVW" \
   "+IB0tPRhnhFDJQaGLbuFSJ85TBzIB19CrFfeGLbg5uJnClBYxGLVYXiDaRCQYYuQO7rYX5BJ2IeZ" \
   "j0vYkuSURixYBZJW2kBgF5JQ6SVYTCrRjQZzXPEllUCuoaMRTnY2hw2unbnjP/gdkaaAb8YpZ4Ud" \
   "UqEZE3U5wAmce7oYYGpcsEEjGCvpWah4v6x5RFhUCErHSgg8WmACaziaxEpUtDgHeZrSB6oNESKR" \
   "JpRdAJlqqU8BqSITQP5JR3ZbwsqRcK8eIdyiYRhVp64y2TIroFSwyiVixH5mS65GtHaHKZY2q9YB" \
   "1S4rKh1s9GqtNgcMq8Szdyj67VOzfSH/Zbl4VUhCAPAGQMENFMQbAAkCACDAZ8dyIQUe1oQYAA0E" \
   "01DADQUUTEMAA9SQwmfQHqGBrXS0aYOkn52gcAAFDFzwCQJ8sO+e79xxqp8VKqyywqVGAGwYJydb" \
   "4Mo0l/pAxF7EbMO2Hb3Qwc9Av2ACCywMXbQJSJswgwk+A/3zC14mgCSjjPTl8cYrSKA1AADUUMMH" \
   "NXBdw9UFB3BuFxZT8XI2ZBPM8AUSpKC1BBdgUMMAdre98Nld8JEtRzBwIPjgMCgcQww0Bz644DDw" \
   "neiM4tG8suNj9OGAsuhsIHnBG1AuRnE7P0fB5gTP6/mKfnjL0dUoBIBC2bwUIDsIFMhO/4B4Z1Hy" \
   "XAgeH5zwwiHwUjABvYt3pxviPkXBBr5vYLrwBBNP8MHP6QTP9T+dLgYB3IcwAvcgaC9wwUSAULAI" \
   "RJQw/O803F7E1ULorXIAtxNAesEF2D+9Eezf3rDXAAzgCjCgi6557QgABEATBrCCADpQAh/IgBD+" \
   "50AH7ouCXvNAESh4QQDu6wIAlIAEiQBCD6qPYC4YAvtoEDwhaI4GJ0DY8IwAvxvIb2Ug0N/98oc/" \
   "/s0QgxX02gowYcAaINBrCrwB2IL4QBXcAIhB7KAFicDBJ3oQLCWsgQScKAS7AdACNzAfwUgwhNcV" \
   "zHQhOJ8Mo0dD8tnwfgQrgQ5Jx8P9Ff+hf1ZkYgDBWMQjhu0GKtBjBQeQR0FKMYBbHEIVq3iDDEgA" \
   "gBfAhBe9BkYXEgwFQhiByloghNGhcI3tayPB4jc87pmSfQUIgSkJcEIaiGCVOezhHX8IQA8I4Ja3" \
   "XOLdbtBHIyTwBgIIoQW4CBYBZPEDhRwZEqBYg0hO8IqMbOQjvXYBDwSQkENoZfhIQDCNESx4Iuim" \
   "EPD4PjfWkAg6pN4Q0lkEHbbOXq6jpdeUKQQLAJCQReSaPsWGRGACEANHCGY/KYiBARj0oAOoJAWt" \
   "+c9nzjOZRHBkEAFavoKV4AZmpEBGb+BN9IHSfUSo4dVWyb0WnLGdslwnHNm4UFzm8p7/vBTkLwW6" \
   "SyPQVIHMDGASOWjPWkI0mvWsIEWL8MIAaPKb3FzYUWmQwo+KkgakvN8GWqhSO1YVjv6TKSVjqlUF" \
   "0hSbRbhpIZm40ytOsgYZWOQViXBWakaoleGkASeXGtcYjnOGRDUnHMmIUqsKQYcck51gRzpWJg6R" \
   "q3dDqEFnCkBkGkEGv2ypS285QkZmMW7QXGsXEQlJwYhRYaZ7YcE4eVeCOW+VSR3lG90GT4U19arq" \
   "/GtKVSjPZu5Tnx/gYi+LwNh7TtYCxyykLSd7SycyUgHTnGI0MegBibo1rx/Lpsqe50mpRhWqs/Tr" \
   "DdiJztmWNpRAPcJuifBLBWjVpzm9oSZEhUDTAB5yZD31GkWd20y3rNCjYVQZVW8g2s2575yw7avB" \
   "BBzb72b1oUoY7xB+eYMUnNeZ6YUpUBnqXojGtwZDvcGFnZlJe4H0BiKIF1/TB097iSB8QngXvIww" \
   "gng9r8PwevENWhxjI9QLXiPQsD5HmIQU6FO8XHuYEGTwgdve1gO6sICRjQxGJXONx0Lw8T4l6GQA" \
   "ZCAD+8xwPfc5gCAAADs=",_TRUNCATE);*/


   strncpy_s(LogoGif,15000,   "R0lGODlh5AN5AOf/ABkaGBocGRscGhwdGx0fHB4fHR8gHiAhHyEjICIkISMkIiQlIyQmJCUnJCYo"  \
   "JScoJigpJ7cAIrYAKCkqKCkrKLgBIyosKbgCKcIAIsEAKMMAI8EALSstKrcDLsMAKSwtK8IBLsUC"  \
   "Hs0AHC0uLMwAIbkFKdAAF8sAJ80AIs8AHc4AI8sALMQDJM0AKMwALS4vLc4AKaUMK7gGL7sHH8wA"  \
   "M9ABHs4ALroHJdgAEy4wLdYAGsYFGcQEKdABJNkAFNcAGtYAILELINoAFcQEL9kAG9cAIdYAJrEL"  \
   "JroIKtwAFtoAHNgAIs8CKdUALNcAJ8YGH9sAHdYALNgAKNoAI9kAKMYGJdsAI7AMK9IEGDAyL7oJ"  \
   "L7wKINsAKbINIdEEH88DL6gQIuIAGcUHKuEAH90CF+MAGrkKNTEzMOQAG+MAIOEAJrwLJscJGjIz"  \
   "MbIOJ9EFJbsLK7EOLOYAG+QAIeIAJ8cJIMUIMOcAHOUAIuQAJ90DHucAIzM0MtEGKr0NIbEPMcQJ"  \
   "NbMQIscKJtwEJLMQJ9MIGTM1M7sNMdIIH9wEKtAHML0OJ8YLK7wOLMkMGt4GGLMRLdIJJc8IOqgU"  \
   "N7QSKMgNITU3NN4HH8gNJr4QJ9QLGtIKK7QTLr8RIqwWKjY4Nd4IJcgOLL4RLccOMdQMIMoPItMM"  \
   "Jjc5NqwXL7UVKTg5N7UVLskQJ7QVNK0YK78TKMkQLb8TLt8LIK4ZJjk6OLcWKr4UM8kRMrYXLzo7"  \
   "ObYXNMAVLtQQLcoTLsAWNDs9OrcZNcEXL58hNTw+O7kaMeAQLbgbNj0/PN8QMrocLLocMj5APT9A"  \
   "PtcVL0FCQEFDQbsgPkJEQa0mOENFQkRGQ0VHREZIRUdJRkhJR0pLSUpMSktNSkxOS6M3SU9RTlBS"  \
   "T1FTUFNUUlRVU8U1R1VWVFZXVVZYVVdZVlhaV1xeW11fXF9hXmFjYGJkYWVmZGZnZWdoZmlraGps"  \
   "aWttam5wbXJ0cXN1cnd5dnl7eICCf4aIhY2PjJOVkpial6Smo////yH+EUNyZWF0ZWQgd2l0aCBH"  \
   "SU1QACH5BAEKAP8ALPgAHgD0AT0AAAj+AP8JHEiwoMGDCBMqXMiwocOHECNKnEixosWLGDNq3Mix"  \
   "o8ePIEOKHEmypMmTKFOqXMkyIyNMMGPKnEkzJpMTvRS1PNmiBaaeMVXsHEq0qNGjSDlKAuECxRIo"  \
   "UMhAmUK1qtWrWLOmUIGiRYakFEedqKOi0FStKjCB9RhDBaK3cJdMkXLC44ADBAroLUCgr9++BQwQ"  \
   "eLG2sOGkLVggmgK1sePHkCNLboxHhQtAhxe6aTFoEKIUjCfrmJI5IyfQWKFG6shH8IG9sGPDLk27"  \
   "NklgKvAI2d1Yh9zJwCOnToEikgvbBG+4dTwIyu7nvKdKQU4RSejHJqYI5aiXgAHZ4Pf+JqBOvvzE"  \
   "Q0ag6DDhOKv79/CnNtcEBY8Y6rbw4KGc5v2gNFBMZ95D1k222kZ4FZBgeOARUM6AEEZokAZQfIbH"  \
   "VcBdFxxU11EF1SCX7PYIHiAgF8l+Gzq2BAoSMkQJIsJNwcRG9iSYF4PgGYDAPi32WF4mVCGy3xRC"  \
   "DjIFHpdYBQWARL7HoYdQocGhCowxdgmHLNi2yBTNRSbEVFLqcMmVU/mYECVPSbZdRgvciCOO2Zgp"  \
   "J20UTrEEHjpUeOEU/fWWJxRkpgjVU2bh0aWGUKhQQW0VQPmYDrJoxwQmxamgAgv3zVkQJ2lGtuZF"  \
   "7QT2Jo4DGKDpqRO9xqCpF9XBYWP+VcqFSBpoCFGICWYFp8Ouf04FRSE66IdofVO0UJsKvkJ25Qkd"  \
   "oLpQHJ1C9qlFCAg2aniA5eLstgwFVupff2EUCbGhXefbhYhEom4kLTDS07vvoiAvCiqoK4UU+7E3"  \
   "RQrt1ZfGtIahKFyW3CYE7WQATwQBX99diy2rBUdM0I0DNIgRY+gm216JFsnQAmOIyJvGkFYdmFkG"  \
   "eEo2BSMSH8QpwhkpMGrF1zrQcssG5NywbBcpwlh/MDraGRwatbDfW3hIWdVbKdAmwb7DQjHIDTcX"  \
   "JEPUUCUc0QKjEnDAMNcSUHXE3e0c20WMOAfFb41dssQgm2wkxpOA+krkW7TFkUL+rpBN4cbYA10N"  \
   "s0X5qPqmQA9cCzHgpwbmJs8WpU1GVY5dooIUdnAUyWIV3t3ZW0vQtsuRAreXKeAyRPuY1g8tYzaD"  \
   "A3VdAB8hPbgQOfGMtA05D7WTUpwFRfPORSN4/fhsFrWwa7kVjpwCHixvhMQTKGDSiQYaYHICCxks"  \
   "sshDjHTVgqX1LoEI+ejDxXQKKURyAianJ4QKJpXIi+xkRFpK/7zzosJQJy/RXr2MsK4Cso99KGAB"  \
   "C2DyFYv0gn4ssNTm1PcWrrBgCzoJHNYSdZE3CcYAtBPIB/TyutgsDiPR4MMCrOWwAoyAIN05nl4c"  \
   "Eg28LKiFB0iAAQQwDIcgIDz+1gpetUoIGwM4oAHaYkji9pJDIrYwNt4hiPLkciXGpElIJjvKDeqg"  \
   "JEE5Rj8omgsjoJEQJHhxQ0hQCBzu96oNBYpD7IpfQ1zQgieccSoqAEEa/3GIDbKuIdWSYWwmQJB7"  \
   "VAtHebGARgz3xO4c4AwCQUBfiMgQPijAO43ci/EE0wCxLcSDA8mBzAowAEHKhgAIyAI+FGLKTD6M"  \
   "IHODEp8YU4gUpIEOGkAKE5qThpG9MUMYgsqX6hMJSiDEjHeczB4N0ohNIGpMSBKOEaTgoUugAQ2P"  \
   "GBMdIiGKhrgLX8lMkhESwTLBqckiH2RQXthRkDO0Mi+oxAgfbtTKN3lnPDT+o6RC2qSzel4LLwY4"  \
   "AAcUsiq+COQUsnEiFANjiYT405WwieJAWnAWDjVHB8AC1BRcIAaO7YQVAAJUf0JDhjAgqTMo7YzK"  \
   "oMKrtX3PIMhMZmSWCUtqTiUFTxnTr+QCH6zhIRJUU4gG7nZHqgAoBZdYTRxgdE6KcA1HDTsIC4FI"  \
   "gB5WRBV7mWojvXMACDgARwo5wAFKxTCIOi6GB+AdQtT5nX80QDA3ypni4EoAWiDkoWZlWEHkMygN"  \
   "5Uk/a+NKC5hghJ6c4LCGPexhZfIENiCQBUGNCC7aYyfOPSkrjukVkfgFBU3wK2ExleljaDqQcT2l"  \
   "Vyz9DKxCE6g/wSUFwbr+EApeoZDNIVVjKfIQsKaAiRv4kSLxENU7EcIMhTIRnQ7DZELNxkjIHQSh"  \
   "BiCr476jVXo+zk2vOyEM37SwvCLPIHj1bkEKMQU6cChNVzKfc4SwK7adEbVUicQTnrADgjEEE3/F"  \
   "WJKYaiTG5EmzXBoZnhDBU8ASGA+7gKloZ2oQUUyBPVA5mn6j8iXUQiU7S3IUrBp4kFFEIk9c+mVw"  \
   "iBQGNFyJSsD5o0K+OqoDJGSUiHTxRIxrQlFp8obXSkgp73LjvERXQd4hwF0a5rVS0Sw2eFHkQRBJ"  \
   "40weJLyuvFFBFmPeqcCXSJmFS1FTo57zZeK+dEMXjAZhhCagoBKVqAP+mtGcgQy0oAmLmcKf8DDS"  \
   "CLOoIKFdMFRI+w9kiclDbynvFCLRlUiIoA5PqAO9jCAGMVApSaTbj1yMxGeBgLMqIfViL4W1IRU7"  \
   "dGaf7Fo4JnJWxZnwWy1EyCcweTx4fgcBAxjACHaYA1QuiIhSXvKqtGpWwDS0IFDOZK4H4pQqU/Y/"  \
   "VrlEps8YTGLB6EJEU0gmpGbT0RBLjgqhhNGkpJ5eFQJgrkDfBqeEPvJtJQ549u9Z/pQGKWRCGQ3J"  \
   "wLgq2h77EiQQuZmKiM9CQfWZIF0EHFcYUkzqh7Yh1Ez2JESU68HvjHUvFUunw+461tcF+RgO8ac3"  \
   "dP0wG3s3Lw8Ar3f+ETlDgoiCqRqrppz1DExY1UEhGeDK5RhjAvYYCyKM0ClkRrOQueHWMfZmiAbi"  \
   "/KQhcbghN7jE5IZ154JsLjK7MhQTKr0pODACEVIZHEQSwJdVecccCynHJKlqAAhEZASjskAu5MGQ"  \
   "dDQAxrwuuUFI2PXYWAMiDai7bJRckIJ63GsFsMR3CDACC3ir6/BcqHYN8uNVYcTnVNnVanvKZcou"  \
   "gacjprpHOCuchTSijZCJbENUkB3mcejmD/mYZBBxEGRpuNtSkEFEkjHvpi487iTMSwgXssJ6xhMi"  \
   "E9C7bEIOEW7kvfHOJcgwjnzKiDyAnhGV+3aBGN3vJFEhPAZMeJb+8UmJJz9yMJIDy+tD5zd6iM5G"  \
   "ci+ssA0SNvbN86B/jOgZ4vrQDOJoKnjpQ1wghdV3syCuZ3krMxF28FsQcQ18UU8DsA4NAQ7CF1GY"  \
   "tA0QIVfhgQATwQz1dBDHoFAyNoEy9GMcl1DeIRgPQQ0MBx42w0qDFx4bUQHut2At1TZgVEWU0zer"  \
   "UBIUpTLw93ONMX8LwVTlwidTYQoRgWXC4VED8YJnMWgVoYSN4WkFQVbG1YEM0SZA9C0NABGvYUqE"  \
   "NGNgZRAj1CDR9QFb9xrVFRghCEWvVg0Q8QDGZYEKcUiwwxG4EAmWQmCU11NQZ2GRcXQIMQqYkAmY"  \
   "8BlsACOBdjf+KfAZKpABYhA9/1AJ+LODWOODCjEFQpAkUPEWjjFAhdCJnphRGSVMENaHBuGEU6EW"  \
   "FFEJWAOFA/FW/qRwDREO6oR4BfAQuKcXLzQRPzSHBYFj0fdETrQzaVhjGBcRtyh9T3Y4IeEJhHAD"  \
   "jpYu/FMcBVRAAVcvluIoX7JvUIGKCBFzUcEe1wQVdXZZVQIoUiAGvLAkOqgQn8eDUEGJCREVmDgV"  \
   "7vUzkxFogKKNUIFtnOcYZKAD3CgRTKA6T/gQ7tBcOQKLDcEBo0KCDuF9Z0MRWcB8EVkQCRBsvbZ4"  \
   "UEUA8yARNLYQ/lQbcCAGH0MrweGIBRELzyQsQVJedJBSkTf+TK/3GKTBjvHnGPCIEM4xj1VSJWJi"  \
   "KCmFUlRxeVTxkpPBj5PRdBIxk1nzEA1AkeEhVg/lNWLVNQRAAQ95gt8lEQi5lbEzcsmlkWTHDxKh"  \
   "lRV5V8poG0NFg5IxIwdxAp1FjkTyFMMUHEaCcu9nk+4IBTl5EDrwJcwzJHgZHEyyQUhJk/WBehIB"  \
   "GrbHEGaZUGXVNU1Wd1npRBWRBV2JjAIxmWApUX1HKqTmcd8ncl+IHCgABYzZlgdhHZ14WbdiFtYE"  \
   "HIDJlLAiiZLRlwbxl7IEKDowmFAXFeFIm1CgmALBL4hCFX4IEYnYmAqxRKbWQuEFcg0BGERkdl5o"  \
   "SsnYIGD+qUmeOX3aGZqliZbhORG4oAHtIgbwoz1iEEdm0BEq8Ag60CWR4ZYFsQgXxZaNETKL0W92"  \
   "GAnxJQUgEol6OYkQ0ZN00xhb4R5EaUUz12+gg22+2RjECRH4KC0NcQyBwZnbeUoFcAqOiSNUCBEJ"  \
   "KEgHsYt+l1cfpJACQXLgyYvi6aITIQbZYVNWMST0qRGYoDQGchCYcCV/UhV5QgfJWUamyCG2GRm4"  \
   "uVd89Rg/NRIRSgZowHqpuIqA9IAb6jAPl4sKAWPgoQATkQXaBx4H8VTYQhIsKhGjApJpOYzfhQmA"  \
   "eU1ydnm/AgVKmRGYAAUYppqlWDp1QxXspxDKcJrrmBD+7UigD6EevdQ2o0EHKPkREaoerHgQggor"  \
   "BbkQMpOZV2pPqsJ3CPECiQcekOR8ZSOmBtFdsnEXKuoRZxoRacpKa2oQULkXA8ECgBkVnBUaOpAC"  \
   "wcARfrZsj3GjA3EkwiEgEeFgg4oQhXqbELEEhUAHy0ZedJA5IvGoIeMLFDGY1+FpmQqMC1UAC7AQ"  \
   "L1BqUCRk/5A7DNEAkgSRXikQYBMepWKmr+oQrepQj9kXBGWZAjE3l2BT/AJpqIkIxIoRLDBuUDGh"  \
   "/1COyUIkAfsQ5pSXhHqTPQgRp9khncOoEiEDbZaxGbsBk2AQk7pacmGwDGGszGkQ3yAADtMwOrOy"  \
   "LNv+si6LqtgCAAtxjP3EVdiVoTvzkQZxCoIUXam6ECMgAEKWVaUSoisarw0xr2vlRH0BDwkhmt9l"  \
   "B+QyeepxJFLQE4zQaCDQCBugsRnbaI2YtYzACBmACcJKj1GzUX6ZsLCSRQ/BAgL6sHuZpATRCWeh"  \
   "o1UbCxGRCh8WGULqscfpIYPQqAwhBuOmYtLFZBsaZNiChgnBDxR4StYiGLGWXVmVY1IFHkM2HhBB"  \
   "M48DV2x6lg+htAfRBqVUQn0BhwaxavgqEEJCJEIQJqHxCHXJbv0VI5RTjmTAXupHk3VhEHiYiRsT"  \
   "EYMYt8gKse8IEX7wrzoaUpEgARDhKkdpEIn4TGH+YBa8dQMtoAEK5AdbsAUzcAOMSLbh02krhnyr"  \
   "IgA/Bi7s277g4oa+RwChihArCJl1N7mRS2RNtlaaqzPo8BDnYF19QVZG+w+kK69ISxDYYEqAEaK5"  \
   "kBexKn2RMHD8sh+9IhWjuGAhtTxcklmM8ZKVJgJVqx6PkGlSkEsNIYh7Ixk6YAQLgUxY82UFujdo"  \
   "4CgAsojxhgIIuyT6cSWjYBBwMAWXwDc8fFnAcQmdoR9CoAlE/Bgi+w/q8KmSqyAd4QB4tXFPm4DU"  \
   "p0ndGl2MRKKlm4Bmg0kHQIYLsQ1vxcURNQChu65Jm8AE0WQ5S2QcujhpwyF0gCiSN35LGBrLFmf+"  \
   "InuaeXIJiABisJICdaBAiqzIYhBBgCKfkhE6CrFUUiMZMgw+6oG8S6AC27PILMC9blGDmdxXWhMJ"  \
   "acAeviooiyFpbcSnU/C7B5EAiZtQFeO0HCF417J7BzENB5AzGBlRk/uYtXgQv1AxvqjGDNzLpoQX"  \
   "nPuZ44nAz2wQVqyhTKa6/wAMU7C7cinKelaDl3AhAOoYiEB1jNAcwlKhk+celJonQdkZALIQqUB+"  \
   "7WwkdFsQF1Uhl8dTjmInHtJF4nghv0EVUjCk/3B1QUpNvDIa45YxFaICyFAMP3O7TXkQ9FB9yayl"  \
   "HEEBk7kQzsA1wmxPe2EBmKm+pMpxpgRXxhX+pkXkNd/QxrKKpnA8EN9gpZnkGgZhNKN8WSrFxzEC"  \
   "BWgwcC+HEC4wCPyCBiOFKKnsj0s3BaH4GFIBzz7NpxEbEaNgU5Slx1cNFd8cTY/htgCIz+XVN1hD"  \
   "BwIjBd3UDJxDOWEQBl4tEIZ3jHoxah8RwbHBqQhBCxdpVjnzDxHHggkhSV0JTz7Wso7zmHfxAP3g"  \
   "0pr5xtFsEMEHlgaA0QLRCkzgX9/8GPoIg3lSS8FyCSicEC3APvT2GGmgj0pjBHXQj48hpQkxCxkM"  \
   "GZcMEY3Qf5eYIolqZUvwX7AVFRWCAvqHEIHGbV7EL8NkBFfwD8v5GIWgCQFJEBXDuDlixh/+sYVQ"  \
   "y51euhD4EA2oNJXUZQANUA+RJK5uPBDkcElqKCq4R08rGGT3pGMKxcZo2krwvRDhEEicKXHw9AH+"  \
   "gBCMEAn3zNONQZSPsRt5MtAM4QuRwJj6kWlBWHmI0AJpNFTHehCEMG6/DRGH8DGdQruziSEiNhp/"  \
   "NQgEXRDjcAOIoDSyZCe6EgnWityPmjA61GLiIBKT9N4/mxDlgMUJoVYFcXx+nRAHmRdmCBt0bTZy"  \
   "xUIDlRCY6rismsy2SF0NOV08Zp0JAQwnoC79rIkAjhVGgIQMwQj3grvusRhiAAwCMdvusbDMJNBZ"  \
   "EQlgYBE00AL+WTccXHnHJgUuYAwRkQn+MyeUvStLRoAJ6CYQ14gVgwCsAoFXdu0RfKAXpdS4xDcS"  \
   "gwfGZ7wABBxXJ32/XqO+D5CC9Nq4pIa+RIt3SwRQq/LoYhURq3ADmOAWkaDPeZgVcJFAN9AF8FYR"  \
   "q6ABboFTVQHrLRkJGXDrAiEMfxAHxn7sceAGcdANC0EJcXAFyH7sQaARnCAGOnyIVrGgZ0EcLKB5"  \
   "D+EGbmDtTbI0n/EZGoALBiENnhAHnIDsbuDsBvEaQuu+fiGBI8Ew7ntWJVF9P84Q9zABCuAACABr"  \
   "CjWCmIQAAlAO+jCdI9q+oUlX4FLAC0EPC6AAsAZEBZAAFrAMHck4Hv/xEMIOQAYeCMDMTiB/8iif"  \
   "8uRhhmLV8mK1eN0SlQMQACpf8zZ/80hRACgbHg1gyw3hDipNtAXg6Thf9EZ/9CFB0u5aAOHgDC77"  \
   "Gg8wDLws6lDUhUh/9Vif9R750aYGV2oYUAIg8Vo/9mSv9QcgSdtaRHfxa2Xf9m5/9eYwyxv6cKVy"  \
   "3W9/93hv85bwy2HzHQNA9Hkf+ILPOI1Ona5Exwzn84O/+IwvMefwQXRdUD5GlQfgDo1/+ZgfMQrQ"  \
   "AHkXbAOwABbADNyX+aRf+qZ/+qif+qrPLQEBADs=" ,_TRUNCATE);


	size2=base64decode (temp, LogoGif);

	memcpy(dest,temp,size2);
	return(size2);
}

int escape(const char *source, char *dest, int length, const escape_struct * escapes)
{
	if (length==0)
		return 0;
	--length;

	// Iterate over entire string, or until the destination is full
	for (; (*source != '\0') && (length != 0); ++source) {

		// Look for special characters
		const escape_struct * e = escapes;
		for (; e->from != 0; ++e) {
			if (*source == e->from) {
				// Replace special characters if there is room, xor truncate the output
				int l = strlen(e->to);
				if (l <= length) {
					const char * to = e->to;
					for (; *to != '\0'; ++to) {
						*dest = *to;
						++dest;
						--length;
					}
				}
				else
					length = 0;
				break;
			}
		}
		// No special characters found, copy verbatim
		if (e->from == 0) {
			*dest = *source;
			++dest;
			--length;
		}
	}
	// Null terminate
	*dest = '\0';

	return 0;
}

int debracket(char *source, char *dest, int length)
{
	//This routine is simply to replace the HTML metacharacters "<" and ">" with
	// "&lt;" and "&gt;". That's all!

      int count=0;
      char *copyofdest;
      copyofdest=dest;

      if(!source || !dest) return(1);

      while(*source) {
              if(*source == '<') {
                      if(count < length) { *dest='&'; dest++; count++; }
                      if(count < length) { *dest='l'; dest++; count++; }
                      if(count < length) { *dest='t'; dest++; count++; }
                      if(count < length) { *dest=';'; dest++; count++; }
              } else if(*source == '>') {
                      if(count < length) { *dest='&'; dest++; count++; }
                      if(count < length) { *dest='g'; dest++; count++; }
                      if(count < length) { *dest='t'; dest++; count++; }
                      if(count < length) { *dest=';'; dest++; count++; }
              } else {
                      if(count < length) { *dest=*source; dest++; count++;}
              }
              source++;
      }
      *dest='\0';

	  dest=copyofdest;

      return(0);
}

int Display404(SOCKET http_socket, gnutls_session session_https)
{
	char HTTPBuffer[512];
	// Overwrite HTTPBuffer with the header data.
	strncpy_s(HTTPBuffer,_countof(HTTPBuffer), "HTTP/1.0 404 Not Found\r\n" \
						"Server: SafedAgent/1.0\r\n" \
						"MIME-version: 1.0\r\n" \
						"Content-type: text/html\r\n\r\n" \
						"<html><body><center><h2>Page Not Found</h2></center></body></html>",
			_TRUNCATE);

	
	if(WEBSERVER_TLS)
		return(sendTLS(HTTPBuffer,session_https));
	else
		return(send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0));
}

int DisplayTextHeader(SOCKET http_socket, gnutls_session session_https)
{
	char HTTPBuffer[512];
	LogExtMsg(INFORMATION_LOG,"DisplayTextHeader");
	// Overwrite HTTPBuffer with the header data.
	strncpy_s(HTTPBuffer, _countof(HTTPBuffer), "HTTP/1.0 200 OK\r\n" \
						"Server: SafedAgent/1.0\r\n" \
						"MIME-version: 1.0\r\n" \
						"Content-type: text/plain\r\n\r\n",
			_TRUNCATE);
	if(WEBSERVER_TLS)
		return(sendTLS(HTTPBuffer,session_https));
	else
		return(send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0));

}

// Convert sid to text.
BOOL GetUserSid(
    LPSTR szName,            // username
    LPTSTR TextualSid,    // buffer for Textual representation of SID
    LPDWORD lpdwBufferLen, // required/provided TextualSid buffersize
	char *PrimaryDomain,   //Domain to investigate
	char *PDC_cstr        //PDC to lookup domain info
    )
{
	// For LookupAccountName
	PSID pSid = NULL;
	DWORD sid_size=0;
	char * domain;
	DWORD dom_size=0;
	char *pPDC=NULL;

	SID_NAME_USE sid_use;
	int retval=0;
	LogExtMsg(INFORMATION_LOG,"GetUserSid");

	if(!szName || !TextualSid) {
		strncpy_s(TextualSid,*lpdwBufferLen,"Unknown",_TRUNCATE);
		return(0);
	}

	while (1) {
		if(LookupAccountName(pPDC,(LPCSTR)szName,0,&sid_size,0,&dom_size,&sid_use) == 0) {
			if(GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
				strncpy_s(TextualSid,*lpdwBufferLen,"Unknown",_TRUNCATE);
				return(0);
			}
		}

		pSid = (PSID)LocalAlloc( LMEM_FIXED, sid_size);
		if(!pSid) {
			strncpy_s(TextualSid,*lpdwBufferLen,"Unknown",_TRUNCATE);
			return(0);
		}
		domain = (char *)LocalAlloc( LMEM_FIXED, dom_size);
		if(!domain) {
			LocalFree((HLOCAL)pSid);
			strncpy_s(TextualSid,*lpdwBufferLen,"Unknown",_TRUNCATE);
			return(0);
		}

		if(LookupAccountName(pPDC, (LPCSTR)szName, pSid, &sid_size, domain, &dom_size, &sid_use) == 0) {
			LocalFree((HLOCAL)pSid);
			LocalFree((HLOCAL)domain);
			return(0);
		}
		if (PrimaryDomain && PDC_cstr && strcmp(domain,PrimaryDomain) && !pPDC) {
			//looks like we've stumbled on a local account. Repeat using explicit DC
			LocalFree((HLOCAL)pSid);
			LocalFree((HLOCAL)domain);
			pPDC = PDC_cstr;
			continue;
		}

		if(pSid) {
			// Obtain the textual representation of the SID.
			if (!GetTextualSid(
				pSid, // user binary Sid
				TextualSid,      // buffer for TextualSid
				lpdwBufferLen)) {       // size/required buffer
					strncpy_s(TextualSid,*lpdwBufferLen,"Unknown",_TRUNCATE);
			}
		} else {
			strncpy_s(TextualSid,*lpdwBufferLen,"Unknown",_TRUNCATE);
		}
		LocalFree((HLOCAL)pSid);
		LocalFree((HLOCAL)domain);
		break;
	}

	return(1);
}



int DumpRegistry(SOCKET http_socket, gnutls_session session_https, char *source, char * Output, int OutputSize) {

	// Hmm.. maybe present a list of options here:
	// HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS

	char Variable[2048]="", Argument[2048]="";
	char Base[2048]="", SubKey[2048]="";
	char HTTPBuffer[2048]="";
	HKEY BaseKey;
	HKEY FinalKey;

	char *psource=source;

	while((psource=GetNextArgument(psource,Variable,_countof(Variable),Argument,_countof(Argument))) != (char *)NULL) 
	{	
		if (strstr(Variable,"str_Base") != NULL)
		{
			strncpy_s(Base,_countof(Base),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"str_SubKey") != NULL)
		{
			strncpy_s(SubKey,_countof(SubKey),Argument,_TRUNCATE);
		}
	}
	
	if(!(strlen(Base))) {
		strncpy_s(Output,OutputSize,"<ul><li><a href=\"/RegDump?str_Base=HKEY_CLASSES_ROOT\">HKEY_CLASSES_ROOT</a><br><li><a href=\"/RegDump?str_Base=HKEY_CURRENT_CONFIG\">HKEY_CURRENT_CONFIG</a><br><li><a href=\"/RegDump?str_Base=HKEY_CURRENT_USER\">HKEY_CURRENT_USER</a><br><li><a href=\"/RegDump?str_Base=HKEY_LOCAL_MACHINE\">HKEY_LOCAL_MACHINE</a><br><li><a href=\"/RegDump?str_Base=HKEY_USERS\">HKEY_USERS</a><br></ul><p>Note: You can also supply a str_SubKey argument to the URL to restrict your scan to certain registry keys. Backslashes must be escaped. Eg: <a href=\"/RegDump?str_Base=HKEY_LOCAL_MACHINE&str_SubKey=HARDWARE\\\\DESCRIPTION\\\\System\">HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System</a>",_TRUNCATE);
		return(-1);
	}
	
	BaseKey=HKEY_LOCAL_MACHINE;
	if(!strcmp(Base,"HKEY_CLASSES_ROOT")) {
		BaseKey=HKEY_CLASSES_ROOT;
	} else if(!strcmp(Base,"HKEY_CURRENT_CONFIG")) {
		BaseKey=HKEY_CURRENT_CONFIG;
	} else if(!strcmp(Base,"HKEY_CURRENT_USER")) {
		BaseKey=HKEY_CURRENT_USER;
	} else if(!strcmp(Base,"HKEY_LOCAL_MACHINE")) {
		BaseKey=HKEY_LOCAL_MACHINE;
	} else if(!strcmp(Base,"HKEY_USERS")) {
		BaseKey=HKEY_USERS;
	}

	// Try and turn on enhanced privileges, so we can read the security registry keys.
	//EnableSecurityName();

	// HERE: Take registry key from the arguments.
	// NOT SURE What to do with the HKEY_CURRENT_USER thing though......

	LONG result = ::RegOpenKeyEx(BaseKey, // root key
        SubKey,  // key name
        0,   // reserved
        KEY_READ,  // access desired
        &FinalKey);  // result goes here
	
	if(result != ERROR_SUCCESS) {
		switch(result) {
		
			case ERROR_FILE_NOT_FOUND:
				// Basic configuration key missing
				strncpy_s(Output,OutputSize,"<div align=center><font color=\"red\">Sorry - the supplied subkey cannot be found.</font></div>",_TRUNCATE);
				return(-1);
			default:
				return(-1);
		}
	}

	DisplayTextHeader(http_socket, session_https);

	RegDump(FinalKey,Base,SubKey,http_socket, session_https);
	RegCloseKey(FinalKey);
	return(1);
}

// Recursive function
int RegDump(HKEY key, char * rootname, char *path, SOCKET http_socket, gnutls_session session_https)
{
	long result;
	int retval;

	DWORD subkeys;
	DWORD maxsubkeylen;
	DWORD maxvaluenamelen;
	DWORD maxvaluelen;
	DWORD i=0;
	char HTTPBuffer[2048];

	_snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"KEY: %s\\%s\n",rootname,path);
	if(WEBSERVER_TLS)
		retval = sendTLS(HTTPBuffer,session_https);
	else
		retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);


	result=RegQueryInfoKey(key,
		NULL,			// class buffer
		NULL,			// pointer to class buffer size
		NULL,			// reserved
		&subkeys,		// number of subkeys here
		&maxsubkeylen,	// maximum subkey name length
		NULL,			// max class name length
		NULL,			// number of values associated with the key
		&maxvaluenamelen,// maximum value name length
		&maxvaluelen,	// maximum value length
		NULL,			// security descriptor
		NULL);			// last write time

	if(result != ERROR_SUCCESS) {
		return(0);
	}

	// FREE These
	LPTSTR subkeyname = new TCHAR [maxsubkeylen + 1];
	LPTSTR name       = new TCHAR [maxvaluenamelen + 1];
	LPBYTE value      = new BYTE [maxvaluelen + 1];

	BOOL cont=1;
	DWORD namelen = maxvaluenamelen + 1;
	DWORD valuelen = maxvaluelen + 1;
	DWORD type;


	while(cont) {
		namelen = maxvaluenamelen + 1;
		valuelen = maxvaluelen + 1;
		result = RegEnumValue(key,  // base key
			i,   // index
			name, &namelen, // name buffer
			NULL,  // reserved
			&type,  // type
			value,  // value buffer
			&valuelen);  // value count
		if(result == ERROR_NO_MORE_ITEMS) {
			cont=0;
			break;
		}
		if(result != ERROR_SUCCESS) {
			// error
			cont=0;
			break;
		}
		i++;

		char *spos=NULL;
		switch(type) {
			case REG_SZ:
			case REG_MULTI_SZ:
			case REG_EXPAND_SZ:
				_snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"	STRING: %s	",name);
				if(WEBSERVER_TLS)
					retval = sendTLS(HTTPBuffer,session_https);
				else
					retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);

				spos=(char *)value;
				while(*spos) {
					switch(*spos) {
						case '\a':
							
							if(WEBSERVER_TLS)
								{sendTLS(" ",session_https); break;}
							else
								{send(http_socket," ",(int)strlen(" "),0); break;}
						case '\b':
							if(WEBSERVER_TLS)
								{sendTLS(" ",session_https); break;}
							else
								{send(http_socket," ",(int)strlen(" "),0); break;}
						case '\f':
							if(WEBSERVER_TLS)
								{sendTLS(" ",session_https); break;}
							else
								{send(http_socket," ",(int)strlen(" "),0); break;}
						case '\n':
							
							if(WEBSERVER_TLS)
								{sendTLS(" ",session_https); break;}
							else
								{send(http_socket," ",(int)strlen(" "),0); break;}
						case '\r':
							if(WEBSERVER_TLS)
								{sendTLS(" ",session_https); break;}
							else
								{send(http_socket," ",(int)strlen(" "),0); break;}
						case '\t':
							if(WEBSERVER_TLS)
								{sendTLS(" ",session_https); break;}
							else
								{send(http_socket," ",(int)strlen(" "),0); break;}
						case '\v':
							if(WEBSERVER_TLS)
								{sendTLS(" ",session_https); break;}
							else
								{send(http_socket," ",(int)strlen(" "),0); break;}
						//case '\\':
							//if(WEBSERVER_TLS)
							//{sendTLS("\\\\",session_https); break;}
							//else
						//	{send(http_socket,"\\\\",(int)strlen("\\\\"),0); break;}
						default:
							if(WEBSERVER_TLS)
								{sendTLS(spos,session_https); break;}
							else
								{send(http_socket,spos,1,0); break;}
					}
					spos++;
				}
				
				if(WEBSERVER_TLS)
					sendTLS("\n",session_https);
				else
					send(http_socket,"\n",(int)strlen("\n"),0);

				break;
			case REG_DWORD:
				_snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"	DWORD: %s	0x%016x\n",name,*(DWORD *)value);
				
				if(WEBSERVER_TLS)
					retval = sendTLS(HTTPBuffer,session_https);
				else
					retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
				break;
			case REG_BINARY:
				_snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"	BINARY: %s	",name);
				
				if(WEBSERVER_TLS)
					retval = sendTLS(HTTPBuffer,session_https);
				else
					retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
				if(*(DWORD *)value == 0) {
					strncpy_s(HTTPBuffer,_countof(HTTPBuffer),"00000000000000000000000000000000",_TRUNCATE);
				} else {
					_ultoa_s(*(DWORD *)value,HTTPBuffer,_countof(HTTPBuffer),2);
				}
				
				if(WEBSERVER_TLS)
					retval = sendTLS(HTTPBuffer,session_https);
				else
					retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
				
				if(WEBSERVER_TLS)
					retval = sendTLS(HTTPBuffer,session_https);
				else
					retval = send(http_socket,"\n",(int)strlen("\n"),0);
				break;
			default:
				// Assume Hex
				_snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"	OTHER: %s	0x",name);
				
				if(WEBSERVER_TLS)
					retval = sendTLS(HTTPBuffer,session_https);
				else
					retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
				spos=(char *)value;
				int hval=0;
				DWORD vcount=0;
				while(vcount < valuelen) {
					hval=*spos;
					_snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%02x",hval);
					
					if(WEBSERVER_TLS)
						sendTLS(HTTPBuffer,session_https);
					else
						send(http_socket,HTTPBuffer,2,0);
					if(vcount < (valuelen-1)) {
						if(WEBSERVER_TLS)
							sendTLS(" ",session_https);
						else
							send(http_socket," ",1,0);
					}

					spos++;
					vcount++;
				}
				
				if(WEBSERVER_TLS)
					sendTLS("\n",session_https);
				else
					send(http_socket,"\n",(int)strlen("\n"),0);
				break;
		}
	}

	i=0;
	cont=1;
	HKEY subkey;

	// Now enumerate the subkeys
	while(cont) {
		DWORD length = maxsubkeylen + 1;
		result = RegEnumKeyEx(key, i,
			subkeyname,
			&length,
			NULL, // reserved
			NULL, // class name buffer
			NULL, // class name buffer length
			NULL); // file time

		if(result == ERROR_NO_MORE_ITEMS) {
			cont=0;
			break;
		}
		if(result != ERROR_SUCCESS) {
			cont=0;
			break;
		}
		i++;
		
		result = RegOpenKeyEx(key,  // root key
            subkeyname, // key name
            0,  // reserved
            KEY_READ, // access desired
            &subkey); // result goes here
		
		if(result != ERROR_SUCCESS) {
			
			// Should really find out the value of this.
			if(result == 5) {
				// Permission denied
				continue;
			} else {
				cont=0;
				break;
			}
		}

		int tlength=(int)strlen(path) + (int)strlen(subkeyname) + 3;
		LPTSTR subpath = new TCHAR [tlength];
		if(strlen(path)) {
			_snprintf_s(subpath,tlength,_TRUNCATE,"%s\\%s",path,subkeyname);
		} else {
			_snprintf_s(subpath,tlength,_TRUNCATE,"%s",subkeyname);
		}

		// Recurse through
		RegDump(subkey, rootname, subpath, http_socket, session_https);
		
		delete [] subpath;

		RegCloseKey(subkey);
	}
	
	delete [] subkeyname;
    delete [] name;
    delete [] value;
	return(1);

}


int Log_Config(char *source, char *dest, int size)
{
	Reg_Log log_struct;
	int i_log_count= 0;
	DWORD dw_log_error;
	char str_name_metachar_remove[MAX_AUDIT_CONFIG_LINE * 2];
	char str_format_metachar_remove[MAX_AUDIT_CONFIG_LINE * 2];

	FILE *configfile = (FILE *) NULL;

	if (!source || !dest || !size) {
		return(0);
	}

	strcpy_s(log_struct.name, _countof(log_struct.name), "");
	strcpy_s(log_struct.type, _countof(log_struct.type), "");

	strncpy_s(dest,size,
		"<form action=setlog><H2><CENTER>SafedAgent  Log Configuration</H2>",
		_TRUNCATE);

	dw_log_error = Read_Log_Registry(i_log_count,&log_struct);
	if (dw_log_error == 0)
	{
		strncat_s(dest,size,
			"<br>The following log files are being monitored by SafedAgent :<br><br>"
			"<table  width=100% border=1>", _TRUNCATE);

		strncat_s(dest,size,
			"<tr bgcolor=#DEDBD2><center><td width=\"10%\"><b>Action Required</b></td>"
			"<td width=\"15%\"><b>Lines/Event</b></td>"
			"<td width=\"50%\"><b>Log File or Directory</b></td>"
			"<td width=\"20%\"><b>Log File Format</b></td>"
			"</center></tr>", _TRUNCATE);

		while (dw_log_error == 0) {
			if ((i_log_count) == 0)
				strncat_s(dest,size,"<tr bgcolor=#E7E5DD>",_TRUNCATE);
			else
				strncat_s(dest,size,"<tr bgcolor=#DEDBD2>",_TRUNCATE);

			_snprintf_s(dest,size,_TRUNCATE,
				"%s<td><input type=submit name=%d value=Delete>     "
				"<input type=submit name=%d value=Modify></td>"
				"<td>",
				dest,i_log_count,i_log_count);

			// Debracket the strings in here. For HTML display purposes, the HTML metacharacters
			// need to be replaced. This is done with the "debracket" routine.
			// Note that the new strings are allowed to be twice as long as the real strings
			debracket(log_struct.name,
				  str_name_metachar_remove,
				  MAX_AUDIT_CONFIG_LINE * 2);
			debracket(log_struct.format,
				  str_format_metachar_remove,
				  MAX_AUDIT_CONFIG_LINE * 2);

			if (log_struct.multiline == 0) {
				strncat_s(dest,size, "Single", _TRUNCATE);
			} else {
				strncat_s(dest,size, "Multiple", _TRUNCATE);
			}
			strncat_s(dest,size, "</td><td>", _TRUNCATE);

			if (strlen(log_struct.name) == 0) {
				strncat_s(dest,size, "&nbsp", _TRUNCATE);
			} else {
				strncat_s(dest,size, str_name_metachar_remove,
					_TRUNCATE);
			}
			strncat_s(dest,size, "</td><td>", _TRUNCATE);

			if (strlen(log_struct.format) == 0) {
				strncat_s(dest,size, "&nbsp", _TRUNCATE);
			} else {
				strncat_s(dest,size, str_format_metachar_remove,
					_TRUNCATE);
			}
			strncat_s(dest,size, "</td></tr>", _TRUNCATE);

			i_log_count++;
			dw_log_error = Read_Log_Registry(i_log_count,&log_struct);
		}
		strncat_s(dest,size, "</table><br>", _TRUNCATE);
	} else {
		strncat_s(dest,size,
			"<br>There are no current log monitors active.<br><br>",
			_TRUNCATE);
	}

	strncat_s(dest,size, "Select this button to add a new log monitor.  ",
		_TRUNCATE);
	strncat_s(dest,size, "<input type=submit name=0", _TRUNCATE);
	strncat_s(dest,size, " value=Add>", _TRUNCATE);

	return (0);
}

int Log_Display(char *source, char *dest, int size)
{
	Reg_Log log_struct;
	int dw_log_error = 0, dw_log_delete_error = 0, dw_log_write_error = 0;
	char str_logerr[10];
	int i_log_count = 0, i_type = 0, i;
	char *psource = source, Variable[100], Argument[100];
	char str_temp[20], str_temp_log[10];
	int selected=0,log_type_count = 10;		// Don't forget to change this when adding new types

	memset(&log_struct,0,sizeof(Reg_Log));
	// This function will display an existing, or a blank, log
	strncpy_s(dest,size,
		"<form action=changelog name=monitor><h2><center>SafedAgent Log Configuration</h2>",
		_TRUNCATE);

	// Determine whether the log will be modified or deleted
	while ((psource =
		GetNextArgument(psource, Variable, _countof (Variable), Argument,
				_countof (Argument))) != (char *) NULL) {
		if (strstr(Argument, "Delete") != NULL) {
			sscanf_s(Variable, "%20[^?]?%10[^\n]\n", str_temp,_countof(str_temp),
			       str_temp_log,_countof(str_temp_log));
			i_type = 0;
			break;
		}
		if (strstr(Argument, "Modify") != NULL) {
			sscanf_s(Variable, "%20[^?]?%10[^\n]\n", str_temp,_countof(str_temp),
			       str_temp_log,_countof(str_temp_log));
			i_type = 1;
			break;
		}
		if (strstr(Argument, "Add") != NULL) {
			strncpy_s(str_temp_log,_countof (str_temp_log), "-2",_TRUNCATE);
			i_type = 2;
			break;
		}
	}

	// Extract the log number. I have to do this stuff, because atoi returns 0 if it cannot convert the string
	if (strcmp(str_temp_log, "0") == 0)
		i_log_count = -1;
	else
		i_log_count = atoi(str_temp_log);

	// If the log number could not be successfully extracted, return immediately.
	if (i_log_count == 0) {
		strncat_s(dest,size,
			"<br><b>NOTE: It appears the URL is encoded incorrectly.",
			_TRUNCATE);
		return 0;
	}

	if (i_log_count == -1)
		i_log_count = 0;

	// If the log is being modified or added
	if (i_type > 0) {
		if (i_type == 1) {
			dw_log_error = Read_Log_Registry(i_log_count,&log_struct);
		} else {
			// Defaults
			strncpy_s(log_struct.name, _countof(log_struct.name), "",_TRUNCATE);
			strncpy_s(log_struct.type, _countof(log_struct.type), "GenericLog",_TRUNCATE);
			strncpy_s(log_struct.format, _countof(log_struct.format), "",_TRUNCATE);
		}

		// Will display an error if unable to completely read from the config file
		if (dw_log_error > 0) {
			dw_log_error += WEB_READ_LOG_ERROR_CODE;
			_snprintf_s(str_logerr, 10, _TRUNCATE, "%d", dw_log_error);

			strncat_s(dest,size,
				"<br><b>NOTE: Some errors were encountered in reading the configuration file. Default values "
				"may be used.<br> Report error: ",
				_TRUNCATE);
			strncat_s(dest,size, str_logerr, _TRUNCATE);
			strncat_s(dest,size, "</b><br>", _TRUNCATE);
		}

		strncat_s(dest,size,
			"<br>The following parameters of the SafedAgent log inputs may be set:<br><br>"
			"<table  width=100% border=0>", _TRUNCATE);


		_snprintf_s(dest,size, _TRUNCATE, "%s<tr bgcolor=#E7E5DD><td>Multi-Line Format<br></td><td>"
			"<input type=radio name=multiline value=0%s>Single line only"
			"<input type=radio name=multiline value=1%s>Fixed number of lines <input type=text name=log_ml_count size=3 value=%d>"
			"<input type=radio name=multiline value=2%s>Line separating events <input type=text name=str_log_ml_sep size=5 value=%s>"
			"<input type=radio name=multiline value=3%s>Number of bytes <input type=text name=log_ml_block size=5 value=%d>"
			"</td></tr>"
			"<tr bgcolor=#DEDBD2><td>Send Comments:<br><em>By default, lines starting with '#' will be ignored.<br>Enable this option if you wish to collect these lines</em></td><td>"
			"<input type=checkbox name=send_comments%s></td></tr>"
			"<tr bgcolor=#E7E5DD><td>Log File or Directory<br></td><td>"
			"<input type=text name=str_log_name size=50 value=\"%s\"></td></tr>"
			"<tr bgcolor=#DEDBD2><td>Log Name Format:<br />(optional) ",
			dest,
			(!log_struct.multiline?" checked":""),
			(log_struct.multiline==ML_FIXED?" checked":""),(log_struct.multiline==ML_FIXED?log_struct.log_ml_count:0),
			(log_struct.multiline==ML_SEP?" checked":""),log_struct.log_ml_sep,
			(log_struct.multiline==ML_BLOCK?" checked":""),(log_struct.multiline==ML_BLOCK?log_struct.log_ml_count:0),
			(log_struct.send_comments==1?" checked":""),
			log_struct.name);
		strncat_s(dest,size,"<a href=\"javascript:void(0)\" onClick=\"myWindow = window.open('', 'tinyWindow', 'width=350,height=300'); "
					"myWindow.document.write('<html><body><p>A percent sign (%) is used the represent the date format YYMMDD. Wildcards are acceptable.</p>"
					"<p>e.g. log names like ISALOG_20060913_WEB_000.w3c would be represented as ISALOG_20%_WEB_*.w3c).</p>"
					"If this field is not defined, the first matching entry will be used (this is fine in most cases).</body></html>'); "
					"myWindow.document.close();"
					"\">Help</a>", _TRUNCATE);

		_snprintf_s(dest,size, _TRUNCATE,"%s</td><td><input type=text name=str_log_format size=50 value=\"%s\"></td></tr>"
			"</table><br>"
			"<input type=hidden name=lognumber value=%s>"
			"<input type=submit value=\"Change Configuration\">    "
			"<input type=reset value=\"Reset Form\"></form>",dest,log_struct.format, str_temp_log);
	} else {

		dw_log_delete_error = Delete_Log(i_log_count);
		i_log_count++;
		dw_log_error = Read_Log_Registry(i_log_count,&log_struct);
		while (dw_log_error == 0)
		{
			dw_log_write_error = Write_Log_Registry(i_log_count-1,&log_struct);
			dw_log_delete_error = Delete_Log(i_log_count);
			i_log_count++;
			dw_log_error = Read_Log_Registry(i_log_count,&log_struct);
		}

		if (dw_log_delete_error == 0) {
			strncpy(source,"/log", 4);//MM				
			Log_Config(source,dest,size);//MM
		} else
			strncat_s(dest,size,
				"<br>The log monitor was unable to be deleted.",
				_TRUNCATE);
	}

	return (0);
}

int Log_Result(char *source, char *dest, int size)
{
	// All strncpy or strncat functions in this routine have been designed avoid overflows
	Reg_Log log_struct;
	int dw_log_error = 0;
	int i_log = 0, i_log_count = 0;
	char str_log_count[10];
	char *psource = source, Variable[100], Argument[512], CustomLogType[SIZE_OF_LOGNAME];

	memset(&log_struct,0,sizeof(Reg_Log));

	strncpy_s(dest, size, "<form action=setlog><H2><CENTER>SafedAgent Log Configuration</H2>",_TRUNCATE);

	while ((psource =
		GetNextArgument(psource, Variable, _countof (Variable), Argument,
				_countof (Argument))) != (char *) NULL) {

		if (strstr(Variable, "str_log_name") != NULL) {
			strncpy_s(log_struct.name, _countof (log_struct.name), Argument,_TRUNCATE);
		}

		if (strstr(Variable, "str_log_format") != NULL) {
			strncpy_s(log_struct.format, _countof (log_struct.format), Argument,_TRUNCATE);
		}
		
		if (strstr(Variable, "lognumber") != NULL) {
			strncpy_s(str_log_count, _countof (str_log_count), Argument,_TRUNCATE);
		}


		if (strstr(Variable, "send_comments") != NULL) {
			if(strcmp(Argument,"on") == 0) {
				log_struct.send_comments=1;
			} else {
				log_struct.send_comments=0;
			}
		}
		//MULTI
		if (strstr(Variable, "multiline") != NULL) {
			log_struct.multiline=atoi(Argument);
		}
		if (strstr(Variable, "log_ml_count") != NULL && log_struct.multiline == ML_FIXED) {
			log_struct.log_ml_count=atoi(Argument);
		}
		if (strstr(Variable, "log_ml_block") != NULL && log_struct.multiline == ML_BLOCK) {
			log_struct.log_ml_count=atoi(Argument);
		}
		if (strstr(Variable, "str_log_ml_sep") != NULL) {
			strncpy_s(log_struct.log_ml_sep, _countof (log_struct.log_ml_sep), Argument,_TRUNCATE);
		}
	}
	
	strncpy_s(log_struct.type, _countof (log_struct.type), "GenericLog",_TRUNCATE);//Force it to GenericLog for compatibility with old versions
	if (!dw_log_error) {

		i_log = atoi(str_log_count);

		//-2 = "Add a new log monitor"
		if (i_log == -2) {
			dw_log_error = Read_Log_Registry(i_log_count, NULL);
			while (dw_log_error == 0)
			{
				i_log_count++;
				dw_log_error = Read_Log_Registry(i_log_count, NULL);
			}
			i_log = i_log_count;
		}

		dw_log_error = Write_Log_Registry(i_log,&log_struct);

		if (dw_log_error  == 0){
			strncpy(source,"/log", 4);//MM				
			Log_Config(source,dest,size);//MM
		}else
			strncat_s(dest,size, "<br>The log monitor was unable to be modified/added.", _TRUNCATE);
	}

	return (0);
}



int E_Objective_Config(char *source, char *dest, int size)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	E_Reg_Objective reg_objective;
	DWORD dw_objective_error = 0;
	int i_objective_count = 0;
	char str_obj_count[10];
	char str_match_metachar_remove[SIZE_OF_GENERALMATCH*2];


	strncpy_s(dest,size,"<form method=get action=/log/setobjective><H2><CENTER>SafedAgent Filtering Log Objectives Configuration</H2>",_TRUNCATE);
		
	dw_objective_error = E_Read_Objective_Registry(i_objective_count,&reg_objective);
	if (dw_objective_error == 0)
	{
		strncat_s(dest,size,"<br>The following filtering log objectives of the SafedAgent unit are active:<br><br>" \
		"<table  width=100% border=1>",_TRUNCATE);

		strncat_s(dest,size,"<tr bgcolor=#E7E5DD><center><td width=10%><b>Action Required</b></td>" \
			        "<td width=10%><b>User Include/Exclude</b></td><td><b>Search Term</b></td><td><b>Order</b></td></center></tr>",_TRUNCATE);

		while (dw_objective_error == 0)
		{
			_itoa_s(i_objective_count,str_obj_count,10);		
			
			if ((i_objective_count%2) == 0)
				strncat_s(dest,size,"<tr bgcolor=#DEDBD2><td><input type=submit name=",_TRUNCATE);
			else
				strncat_s(dest,size,"<tr bgcolor=#E7E5DD><td><input type=submit name=",_TRUNCATE);

			strncat_s(dest,size,str_obj_count,_TRUNCATE);
			strncat_s(dest,size," value=Delete>     ",_TRUNCATE);

			strncat_s(dest,size,"<input type=submit name=",_TRUNCATE);
			strncat_s(dest,size,str_obj_count,_TRUNCATE);
			strncat_s(dest,size," value=Modify>",_TRUNCATE);
			strncat_s(dest,size,"</td><td>",_TRUNCATE);


			// Debracket the strings in here. For HTML display purposes, the HTML metacharacters
			// need to be replaced. This is done with the "debracket" routine.
			// Note that the new strings are allowed to be twice as long as the real strings

			debracket(reg_objective.str_match,str_match_metachar_remove,SIZE_OF_GENERALMATCH*2);

			if(reg_objective.dw_match_type!=0) {
				strncat_s(dest,size,"Exclude",_TRUNCATE);
			} else {
				strncat_s(dest,size,"Include",_TRUNCATE);
			}
			strncat_s(dest,size,"</td><td>",_TRUNCATE);
			
			if (strlen(reg_objective.str_match) == 0) {
				strncat_s(dest,size,"&nbsp",_TRUNCATE);
			} else {
				strncat_s(dest,size,str_match_metachar_remove,_TRUNCATE);
			}
		
			strncat_s(dest,size,"</td><td>",_TRUNCATE);
			if (i_objective_count != 0) {
				_snprintf_s(dest,size,_TRUNCATE,"%s<div align=center style=\"margin-bottom: 5px; border-left: 2px solid #eeeeee; border-top: 2px solid #eeeeee; border-right: 2px solid #aaaaaa; border-bottom: 2px solid #aaaaaa; background-color: #dddddd\"><a href=\"/log/setobjective?%d=MoveUp\" style=\"font-size: 9px; color: #33aa33; text-decoration: none; display: block;\">&#9650;</a></div>",dest,i_objective_count);
			}

			i_objective_count++;
			dw_objective_error = E_Read_Objective_Registry(i_objective_count,&reg_objective);

			if (dw_objective_error == 0) {
				_snprintf_s(dest,size,_TRUNCATE,"%s<div align=center style=\"margin-bottom: 5px; border-left: 2px solid #eeeeee; border-top: 2px solid #eeeeee; border-right: 2px solid #aaaaaa; border-bottom: 2px solid #aaaaaa; background-color: #dddddd\"><a href=\"/log/setobjective?%d=MoveDown\" style=\"font-size: 9px; color: #33aa33; text-decoration: none; display: block;\">&#9660;</a></div>",dest,i_objective_count-1);
			}
			strncat_s(dest,size,"</td></tr>",_TRUNCATE);
		}
		strncat_s(dest,size,"</table><br>",_TRUNCATE);
	} else {
		strncat_s(dest,size,"<br>There are no current filtering log objectives active.<br><br>",_TRUNCATE);
	}

	strncat_s(dest,size,"Select this button to add a new objective.  ",_TRUNCATE);
	strncat_s(dest,size,"<input type=submit name=0",_TRUNCATE);
	strncat_s(dest,size," value=Add>",_TRUNCATE);

	return(0);
}

int E_Objective_Display(char *source, char *dest, int size)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	E_Reg_Objective reg_objective;
	DWORD dw_objective_error = 0, dw_objective_write_error = 0,dw_objective_delete_error = 0;
;
	char str_objerr[10];
	int i_set=0,i_objective_count = 0,i_type = 0;
	char *psource=source, Variable[100], Argument[100];
	char str_temp[20], str_temp_objective[10];
	

	//This function will display an existing, or a blank, objective
	strncpy_s(dest,size,"<form method=get action=/log/changeobjective><h2><center>SafedAgent Filtering Objective Configuration</h2>",_TRUNCATE);

	//Determine whether the objective will be modified or deleted
	while((psource=GetNextArgument(psource,Variable,_countof(Variable)-1,Argument,_countof(Argument)-1)) != (char *)NULL) 
	{
		if (strstr(Argument,"Add") != NULL) {
			strncpy_s(str_temp_objective,_countof(str_temp_objective),"-2",_TRUNCATE);
			i_type = 2;
			break;
		} else {
			sscanf_s(Variable,"%20[^?]?%10[^\n]\n",str_temp,_countof(str_temp),str_temp_objective,_countof(str_temp_objective));
			if (strstr(Argument,"MoveUp") != NULL) {
				i_type = -2;
			} else if (strstr(Argument,"MoveDown") != NULL) {
				i_type = -1;
			} else if (strstr(Argument,"Delete") != NULL) {
				i_type = 0;
			} else if (strstr(Argument,"Modify") != NULL) {
				i_type = 1;
			} else {
				continue;
			}
			break;
		}
	}

	//Extract the objective number. I have to do this stuff, because atoi returns 0 if it cannot convert the string
	if (strcmp(str_temp_objective,"0") == 0)
		i_objective_count = -1;
	else
		i_objective_count = atoi(str_temp_objective);

	//If the objective number could not be successfully extracted, return immediately.
	if (i_objective_count == 0)
	{
		strncat_s(dest,size,"<br><b>NOTE: It appears the URL is encoded incorrectly.",_TRUNCATE);
		return 0;
	}

	if (i_objective_count == -1)
		i_objective_count = 0;
		
	//If the objective is being modified or added
	if (i_type > 0) {
		if (i_type == 1) {
			dw_objective_error = E_Read_Objective_Registry(i_objective_count,&reg_objective);
		} else {
			strncpy_s(reg_objective.str_match,_countof(reg_objective.str_match),"*",_TRUNCATE);
			strncpy_s(reg_objective.str_match_type,_countof(reg_objective.str_match_type),INCLUDE,_TRUNCATE);
		}

		// Will display an error if unable to completely read from the registry
		if (dw_objective_error > 0) {
			dw_objective_error += WEB_READ_OBJECTIVE_ERROR_CODE;
			_itoa_s(dw_objective_error,str_objerr,10);
	
			_snprintf_s(dest,size,_TRUNCATE,"%s<br><b>NOTE: Some errors were encountered in reading the registry. Default values " \
						"may be used.<br> Report error: %s</b><br>",dest,str_objerr);
		}

		strncat_s(dest,size,"<br>The following parameters of the SafedAgent objective may be set:<br><br>" \
			"<table  width=100% border=0>",_TRUNCATE);

		//Identify the high level event. Note that there is a table within a table in these radio buttons.
		i_set = 0;

		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#E7E5DD><td>General Search Term<br><a href=\"http://en.wikipedia.org/wiki/Regular_expression\"><i>Regular expressions accepted</i></a></td>"
			"<td><input type=text name=str_match size=50 value=\"%s\" onMouseover=\"ddrivetip(\'Use regular expressions like admin[1,2] to filter the log message  \')\" onMouseout=\"hideddrivetip()\"></td></tr>",dest,reg_objective.str_match);

		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#DEDBD2><td>Select the Match Type</td><td>"
			"<input type=radio name=str_match_type value=%s%s>Include    "
			"<input type=radio name=str_match_type value=%s%s>Exclude    </td></tr>",
			dest,INCLUDE, (strstr(reg_objective.str_match_type,INCLUDE)?" checked":""),EXCLUDE,(strstr(reg_objective.str_match_type,EXCLUDE)?" checked":""));

		//Identify the event type to capture. Note that there is a table within a table in these radio buttons.
		i_set = 0;

		//Identify the log type to capture. Note that there is a table within a table in these radio buttons.
		i_set = 0;

		_snprintf_s(dest,size,_TRUNCATE,"%s</table><br>"
			"<input type=hidden name=objnumber value=%s>"
			"<input type=submit value=\"Change Configuration\">    "
			"<input type=reset value=\"Reset Form\"></form>",dest,str_temp_objective);
	} else if (i_type == 0) {
		dw_objective_delete_error = E_Delete_Objective(i_objective_count);
		i_objective_count++;
		dw_objective_error = E_Read_Objective_Registry(i_objective_count,&reg_objective);
		while (dw_objective_error == 0)
		{
			dw_objective_write_error = E_Write_Objective_Registry(i_objective_count-1,&reg_objective);
			dw_objective_delete_error = E_Delete_Objective(i_objective_count);
			i_objective_count++;
			dw_objective_error = E_Read_Objective_Registry(i_objective_count,&reg_objective);
		}
		if (dw_objective_delete_error == 0) {
			strncpy(source,"/log/objective", 14);//MM				
			E_Objective_Config(source,dest,size);//MM
		} else {
			strncat_s(dest,size,"<br>The objective was unable to be deleted.",_TRUNCATE);
			//***REPORT AN ERROR
		}
	} else if (i_type == -1) {
		E_Reg_Objective reg_obj_swap;
		
		dw_objective_error += E_Read_Objective_Registry(i_objective_count,&reg_objective);
		dw_objective_error += E_Read_Objective_Registry(i_objective_count+1,&reg_obj_swap);
		if (dw_objective_error) {
			strncat_s(dest,size,"<br>ERROR: The objective could not be moved (read failure).",_TRUNCATE);
			return(0);
		}
		E_Write_Objective_Registry(i_objective_count+1,&reg_objective);
		E_Write_Objective_Registry(i_objective_count,&reg_obj_swap);
		strncat_s(dest,size,"<br>Swap complete. <a href=\"/objective\">Return to Objectives Configuration</a>.",_TRUNCATE);
	} else if (i_type == -2) {
		E_Reg_Objective reg_obj_swap;
		if (i_objective_count == 0) {
			strncat_s(dest,size,"<br>ERROR: This is the first objective, it cannot be moved up.",_TRUNCATE);
			return(0);
		}
		dw_objective_error += E_Read_Objective_Registry(i_objective_count,&reg_objective);
		dw_objective_error += E_Read_Objective_Registry(i_objective_count-1,&reg_obj_swap);
		if (dw_objective_error) {
			strncat_s(dest,size,"<br>ERROR: The objective could not be moved (read failure).",_TRUNCATE);
			return(0);
		}
		E_Write_Objective_Registry(i_objective_count-1,&reg_objective);
		E_Write_Objective_Registry(i_objective_count,&reg_obj_swap);
		strncat_s(dest,size,"<br>Swap complete. <a href=\"/objective\">Return to Objectives Configuration</a>.",_TRUNCATE);
	}
	
	return(0);
}


int E_Objective_Result(char *source, char *dest, int size)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	E_Reg_Objective reg_objective;
	// DWORD dw_objective_error = -1;
	DWORD dw_objective_error = 0;

	int i_objective_count = 0,i_objective = 0, i_event_type_set = 0, i_event_type_log_set = 0;
	char str_obj_count[10];
	char *psource=source, Variable[100], Argument[100];

	strncpy_s(dest,size,"<form method=get action=/log/setobjective><H2><CENTER>SafedAgent Filtering Log Objectives Configuration</H2>",_TRUNCATE);

	while((psource=GetNextArgument(psource,Variable,_countof(Variable),Argument,_countof(Argument))) != (char *)NULL) 
	{	
		if (strstr(Variable,"str_match_type") != NULL) {
			strncpy_s(reg_objective.str_match_type,_countof(reg_objective.str_match_type),Argument,_TRUNCATE);
			continue;
		}
		if (strstr(Variable,"str_match") != NULL) {
			strncpy_s(reg_objective.str_match,_countof(reg_objective.str_match),Argument,_TRUNCATE);
		}
		if (strstr(Variable,"objnumber") != NULL) {
			strncpy_s(str_obj_count,_countof(str_obj_count),Argument,_TRUNCATE);
		}
	}

	if(!dw_objective_error) {
		i_objective = atoi(str_obj_count);
		
		//-2 = "Add a new objective", hence we must go to the end of the list.
		if (i_objective == -2)
		{
			dw_objective_error = E_Read_Objective_Registry(i_objective_count, NULL);
			while (dw_objective_error == 0)
			{
				i_objective_count++;
				dw_objective_error = E_Read_Objective_Registry(i_objective_count, NULL);
			}
			i_objective = i_objective_count;
		}

		dw_objective_error = E_Write_Objective_Registry(i_objective,&reg_objective);

		if (dw_objective_error  == 0){
			strncpy(source,"/log/objective", 14);//MM				
			E_Objective_Config(source,dest,size);//MM
		}else
			strncat_s(dest,size,"<br>The objective was unable to be modifed/added.",_TRUNCATE);
			//***REPORT AN ERROR
	}

	return(0);
}


int Current_Events(char *source, char *dest, int size)
{
	DWORD dwWaitRes=0;
	MsgCache *myMsg=NULL;
	snprintf_s(dest,size,_TRUNCATE,"<HTML><BODY><H2><CENTER>Current Events</H2></CENTER><P><center><br />"
		"<table border=1 cellspacing=0 cellpadding=2 width=\"99%%\" bgcolor=\"white\">\n"
		"<tr bgcolor=\"#F0F1F5\"><td>&nbsp;</td><td>Date</td><td>System</td><td>Event Count</td><td>EventID</td>"
		"<td>Source</td><td>UserName</td><td>UserType</td><td>ReturnCode</td><td>Strings</td></tr>\n");
	dwWaitRes = WaitForSingleObject(hMutex,2000);
	if(dwWaitRes == WAIT_OBJECT_0) {
		myMsg = MCHead;
		LogExtMsg(DEBUG_LOG,"WebPages: listing events"); 
		for (int i=0; myMsg && myMsg != MCTail && i < 20; myMsg = myMsg->next, i++) {
			if (myMsg->seenflag) {
				if (i%2) snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FEFEFE>", dest);
				else snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#EEEEEE>", dest);
			} else {
				if (i%2) snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#DDFFDD>", dest);
				else snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#CCEECC>", dest);
			}
			char event_text[MAX_EVENT*2] = "";
			escape(myMsg->szTempString, event_text, _countof(event_text) - 3);
			if (strlen(event_text) == _countof(event_text) - 4)
				strcat_s(event_text, _countof(event_text), "...");
			strncat_s(dest,size,"<td>&nbsp;<div style=\"border: 1px solid black; background-color: ",_TRUNCATE);
			switch(myMsg->criticality) {
				case EVENT_CRITICAL:	strncat_s(dest,size,"#FFBBBB",_TRUNCATE); break;
				case EVENT_PRIORITY:	strncat_s(dest,size,"#FFDDBB",_TRUNCATE); break;
				case EVENT_WARNING:		strncat_s(dest,size,"#DEDBD2",_TRUNCATE); break;
				case EVENT_INFORMATION:	strncat_s(dest,size,"#BBFFBB",_TRUNCATE); break;
				default:				strncat_s(dest,size,"#FFFFFF",_TRUNCATE); break;
			}
			strncat_s(dest,size,";height: 20;width: 20\"></div>&nbsp;</td>",_TRUNCATE);
			snprintf_s(dest,size,_TRUNCATE,
				"%s<td>%s</td>"
				"<td>%s</td>"
				"<td>%d</td>"
				"<td>%d <font color=green>(%s)</font></td>"
				"<td>%s</td>"
				"<td>%s</td>"
				"<td>%s</td>",
				dest, myMsg->SubmitTime,
				myMsg->Hostname,
				myMsg->SafedCounter,
				myMsg->ShortEventID, myMsg->szCategoryString,
				myMsg->SourceName,
				myMsg->UserName,
				myMsg->SIDType);
			if (strstr(myMsg->EventLogType, "Fail") || strstr(myMsg->EventLogType, "Error")) {
				if (i%2) snprintf_s(dest,size,_TRUNCATE,"%s<td bgcolor=#FFBBBB>%s</td>", dest, myMsg->EventLogType);
				else snprintf_s(dest,size,_TRUNCATE,"%s<td bgcolor=#EEAAAA>%s</td>", dest, myMsg->EventLogType);
			} else if (strstr(myMsg->EventLogType, "Warn") || strstr(myMsg->EventLogType, "Info")) {
				if (i%2) snprintf_s(dest,size,_TRUNCATE,"%s<td bgcolor=#FFEEBB>%s</td>", dest, myMsg->EventLogType);
				else snprintf_s(dest,size,_TRUNCATE,"%s<td bgcolor=#EEDDAA>%s</td>", dest, myMsg->EventLogType);
			} else {
				if (i%2) snprintf_s(dest,size,_TRUNCATE,"%s<td bgcolor=#BBFFBB>%s</td>", dest, myMsg->EventLogType);
				else snprintf_s(dest,size,_TRUNCATE,"%s<td bgcolor=#AAEEAA>%s</td>", dest, myMsg->EventLogType);
			}
			snprintf_s(dest,size,_TRUNCATE,"%s<td>%s</td></tr>\n", dest, event_text);
			myMsg->seenflag=1;
		}
		ReleaseMutex(hMutex);
	} else {
		LogExtMsg(INFORMATION_LOG,"WebPages: Mutex grab failed.");
		strncat_s(dest,size,"<tr bgcolor=#FEa9a9><td>Failed to grab message pointer</td>",_TRUNCATE);
	}
	strncat_s(dest,size,"</table>",_TRUNCATE);
	snprintf_s(dest,size,_TRUNCATE,"%s</CENTER></BODY></HTML>",dest);
	return(0);
}


/*BOOL isCorrectDate(char * date){
	char* current;
	char next[10];
	int num = 0;
	if(date && (strlen(date)==8)){
		current = date;
		strncpy(next, current, 4);
		next[4] = '\0';
		num = atoi(next);
		if((num < 2010) || (num > 3010) )return FALSE;
		current = current + 4;
		strncpy(next, current, 2);
		next[2] = '\0';
		num = atoi(next);
		if((num < 1) || (num > 12) )return FALSE;
		current = current + 2;
		strncpy(next, current, 2);
		next[2] = '\0';
		num = atoi(next);
		if((num < 1) || (num > 31) )return FALSE;
		return TRUE;
	}else return FALSE;
}*/

int Daily_Events(char *source, char *dest, int size, BOOL at)
{
	FILE * OutputFile=(FILE *)NULL;
	DWORD dwWaitFile=0;
	char filename[1024]="";
	BOOL usefile = FALSE;
	DWORD savedLogs = 0;
	char *psource=source, Variable[100]="", Argument[100]="", number_s[100]="", date_s[10]="";
	int numberFrom = 0;
	int numberTo = 0;
	char* line = (char*)malloc(dwMaxMsgSize*sizeof(char)); 
	if (line)line[0]='\0';
	else {
		LogExtMsg(DEBUG_LOG,"NO MEMORY LEFT!!!");
		return 1;
	}

	if(at){


		while((psource=GetNextArgument(psource,Variable,_countof(Variable)-1,Argument,_countof(Argument)-1)) != (char *)NULL) 
		{	
			if (strstr(Variable,"numberFrom") != NULL) {
				strncpy_s(number_s,_countof(number_s),Argument,_TRUNCATE);
				numberFrom = atoi(number_s) - 1;
			}
			if (strstr(Variable,"numberTo") != NULL) {
				strncpy_s(number_s,_countof(number_s),Argument,_TRUNCATE);
				numberTo = atoi(number_s) - 1;
			}
			if (strstr(Variable,"thedate") != NULL) {
				strncpy_s(date_s,_countof(date_s),Argument,_TRUNCATE);
			}
		}
		if(!((numberFrom == -1) && (numberTo == -1))){
			if((numberFrom == -1) && !(numberTo == -1))numberFrom = numberTo;
			else if(!(numberFrom == -1) && (numberTo == -1))numberTo = numberFrom;
		}


	}
	if(strlen(date_s) >0){
		usefile = GetOutputFile(filename, date_s);
		dwWaitFile = WaitForSingleObject(hMutexFile,500);
		if(dwWaitFile == WAIT_OBJECT_0) {
			fopen_s(&OutputFile,filename,"r");
			if(usefile && OutputFile) {
					savedLogs = GetTotalSavedLogs(OutputFile);
					fclose(OutputFile);
			}
		}
		ReleaseMutex(hMutexFile);		
		snprintf_s(dest,size,_TRUNCATE,"<HTML><BODY><form method=get action=geteventlogat><H2><CENTER>Daily Events for %s</H2></CENTER><P><center><br />\n"
		 "<CENTER>TOTAL Events : %d</CENTER><P><center><br />\n"
		"<table border=1 cellspacing=0 cellpadding=2 width=\"99%%\" bgcolor=\"white\">\n"
		"<tr bgcolor=\"#F0F1F5\"><td align=Center>Event Log</td></tr>\n",date_s, savedLogs);

	}else{
		usefile = GetOutputFile(filename, NULL);
		time_t currenttime;
		struct tm newtime;
		time(&currenttime); 
		localtime_s(&newtime,&currenttime);

		dwWaitFile = WaitForSingleObject(hMutexFile,500);
		if(dwWaitFile == WAIT_OBJECT_0) {
			fopen_s(&OutputFile,filename,"r");
			if(usefile && OutputFile) {
					savedLogs = GetTotalSavedLogs(OutputFile);
					fclose(OutputFile);
			}
		}
		ReleaseMutex(hMutexFile);		
		snprintf_s(dest,size,_TRUNCATE,"<HTML><BODY><form method=get action=geteventlogat><H2><CENTER>Daily Events for %04d%02d%02d</H2></CENTER><P><center><br />\n"
			 "<CENTER>TOTAL Events : %d</CENTER><P><center><br />\n"
			"<table border=1 cellspacing=0 cellpadding=2 width=\"99%%\" bgcolor=\"white\">\n"
			"<tr bgcolor=\"#F0F1F5\"><td align=Center>Event Log</td></tr>\n",newtime.tm_year+1900,newtime.tm_mon+1,newtime.tm_mday,savedLogs);

	}
	if(at){

		if((numberFrom >= 0) && (numberTo >= numberFrom) && (numberTo < savedLogs)){
			dwWaitFile = WaitForSingleObject(hMutexFile,500);
			if(dwWaitFile == WAIT_OBJECT_0) {
				fopen_s(&OutputFile,filename,"r");
				if(usefile && OutputFile) {
					GetSavedLogsAt(OutputFile, line, numberFrom);

					for (int i=numberFrom;  i <= numberTo ; i++) {
						if (i - numberFrom <= 20){
							if (i%2) 
								snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FEFEFE><td>\n%s\n</td></tr>\n",dest,line);
							else 
								snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#EEEEEE><td>\n%s\n</td></tr>\n",dest,line);	
						}
						if(strlen(date_s) <= 0)
							SendToAll(line, (int)strlen(line));

						if(i<=numberTo)GetSavedLogsAt(OutputFile, line, 0);//get next line

					}
					fclose(OutputFile);
				}
			}

			ReleaseMutex(hMutexFile);
		}		
	}

	strncat_s(dest,size,"</table><br><br><table border=1 cellspacing=0 cellpadding=2 width=\"50%%\" bgcolor=\"white\">\n",_TRUNCATE);
	strncat_s(dest,size,"<tr bgcolor=#F0F1F5><td>Insert the Date For Recovery Via HTTP</td><td><input type=text name=thedate size=12 value=\"\" onMouseover=\"ddrivetip(\'When entered the date the recovery of the event logs is only via Http with the max number of recovered event logs of 20. Otherwise the event logs are sent to the syslog server \')\" onMouseout=\"hideddrivetip()\"></td></tr>\n",_TRUNCATE);
	strncat_s(dest,size,"<tr bgcolor=#F0F1F5><td>Insert the From Event Log Number </td><td><input type=text name=numberFrom size=12 value=\"\"></td></tr>\n"
	"<tr bgcolor=#F0F1F5><td>Insert the To Event Log Number </td><td><input type=text name=numberTo size=12 value=\"\"></td></tr>\n"
	"</table>\n",_TRUNCATE);
	strncat_s(dest,size,"<input type=submit name=0 value=Send></CENTER></form></BODY></HTML>",_TRUNCATE);

	if (line) free(line);
	return(0);
}
int substituteEvents(char* obj, int reverse){
	if(!obj || strlen(obj) == 0)return 0;
	char newObj[SIZE_OF_AN_OBJECTIVE]="";
	char events[SIZE_OF_AN_OBJECTIVE]="";
	char* pos = strstr(obj, "\t");
	if(pos){
		pos = pos + 1;
		pos = strstr(pos, "\t");
		if(pos){
			pos = pos + 1;
			pos = strstr(pos, "\t");
			if(pos){
				pos = pos + 1;
				char* pos2 = strstr(pos, "\t");
				if(pos2){
					strncpy(newObj,obj, pos - obj);
					strncpy(events,pos, pos2 - pos);
					if(!reverse){
						if (_stricmp(events,LOGON_LOGOFF_EVENTS) == 0)
						{
							strcat(newObj, LOGONOFF_TOKEN);
						} else if (_stricmp(events,RESTART_EVENTS) == 0) {
							strcat(newObj, REBOOT_TOKEN);
						} else if (_stricmp(events,SECURITY_POLICY_EVENTS) == 0) {
							strcat(newObj, SECPOL_TOKEN);
						} else if (_stricmp(events,USER_GROUP_ADMIN_EVENTS) == 0)	{
							strcat(newObj, MANAGE_TOKEN);
						} else if (_stricmp(events,USER_OF_USER_RIGHTS_EVENTS) == 0) {
							strcat(newObj, USERRIGHTS_TOKEN);
						} else if (_stricmp(events,PROCESS_EVENTS) == 0) {
							strcat(newObj, PROCESS_TOKEN);
						} else if (_stricmp(events,FILE_EVENTS) == 0)	{
							strcat(newObj, FILE_TOKEN);
						} else {
							return 1;
						}
					}else{
						if (_stricmp(events,LOGONOFF_TOKEN ) == 0)
						{
							strcat(newObj, LOGON_LOGOFF_EVENTS);
						} else if (_stricmp(events,REBOOT_TOKEN) == 0) {
							strcat(newObj, RESTART_EVENTS );
						} else if (_stricmp(events,SECPOL_TOKEN) == 0) {
							strcat(newObj, SECURITY_POLICY_EVENTS );
						} else if (_stricmp(events,MANAGE_TOKEN) == 0)	{
							strcat(newObj, USER_GROUP_ADMIN_EVENTS );
						} else if (_stricmp(events,USERRIGHTS_TOKEN) == 0) {
							strcat(newObj, USER_OF_USER_RIGHTS_EVENTS );
						} else if (_stricmp(events, PROCESS_TOKEN) == 0) {
							strcat(newObj,  PROCESS_EVENTS);
						} else if (_stricmp(events,FILE_TOKEN) == 0)	{
							strcat(newObj, FILE_EVENTS );
						} else {
							return 1;
						}					
					}
					strcat(newObj, pos2);
					strcpy(obj,newObj);

				}else return 0;
			}
		}
	}
	return 1;
}

int GetConfig(SOCKET http_socket, gnutls_session session_https, char* fromServer)
{
	int retval;
	char HTTPBuffer[1024 + 50*SIZE_OF_AN_OBJECTIVE]="";
	char strclientname[SIZE_OF_CLIENTNAME]="";
	char strdelim[3]="";
	char str_restrictip[SIZE_OF_RESTRICTIP] = "127.0.0.1";
	char str_password[SIZE_OF_PASSWORD] = "password";
	char str_destination[SIZE_OF_DESTINATION] = "127.0.0.1";
	char str_objective[SIZE_OF_AN_OBJECTIVE]="";
	char str_log[2*SIZE_OF_LOGNAME]="";
	char str_sep[SIZE_OF_SEP]="";
	int linecount = 0;
	DWORD dw_objective_error = 0;
	int i_objective_count = 0;
	DWORD dw_log_error = 0;
	int i_log_count = 0;
	


	if(!MyGetProfileString("Remote","RestrictIP",str_restrictip,SIZE_OF_RESTRICTIP)) {
		strncpy_s(str_restrictip,SIZE_OF_RESTRICTIP,"127.0.0.1",_TRUNCATE);
	}
	if(!MyGetProfileString("Remote","AccessKeySet",str_password,SIZE_OF_PASSWORD)) {
		strncpy_s(str_password,SIZE_OF_PASSWORD,"",_TRUNCATE);
	}
	if(!MyGetProfileString("Config","Clientname",strclientname,SIZE_OF_CLIENTNAME)) {
		strncpy_s(strclientname,1,"",_TRUNCATE);
	} 

	if(!MyGetProfileString("Config","Delimiter",strdelim,3)) {
		strncpy_s(strdelim,1,"",_TRUNCATE);
	} 
	if(!MyGetProfileString("Network","Destination",str_destination,SIZE_OF_DESTINATION)) {
		strncpy_s(str_destination,SIZE_OF_DESTINATION,"127.0.0.1",_TRUNCATE);
	}


	snprintf_s(HTTPBuffer,_countof(HTTPBuffer), 
	"[Config]\n"\
		"\t dAudit=%d\n"\
		"\t dFileAudit=%d\n"\
		"\t dCritAudit=%d\n"\
		"\t dLeaveRetention=%d\n"\
		"\t dFileExport=%d\n"\
		"\t dNumberFiles=%d\n"\
		"\t dNumberLogFiles=%d\n"\
		"\t dLogLevel=%d\n"\
		"\t sClientname=%s\n"\
		"\t sDelimiter=%s\n"\
		"\t dClearTabs=%d\n"\
	"[SysAdmin]\n"\
		"\t dSysAdministrators=%d\n"\
		"\t dTimesADay=%d\n"\
		"\t dVBS=%d\n"\
		"\t dLastSA=%d\n"\
	"[Network]\n"\
		"\t sDestination=%s\n"\
		"\t dDestPort=%d\n"\
		"\t dSocketType=%d\n"\
		"\t dMaxMessageSize=%d\n"\
		"\t dSyslog=%d\n"\
		"\t dSyslogDest=%d\n"\
		"\t dSyslogDynamicCritic=%d\n"\
	"[Remote]\n"\
		"\t dAccessKey=%d\n"\
		"\t sAccessKeySet=%s\n"\
		"\t dTLS=%d\n"\
		"\t dAllow=%d\n"\
		"\t dRestrict=%d\n"\
		"\t sRestrictIP=%s\n"\
		"\t dWebPort=%d\n"\
		"\t dWebPortChange=%d\n",
		MyGetProfileDWORD("Config","Audit",1),
		MyGetProfileDWORD("Config","FileAudit",1),
		MyGetProfileDWORD("Config","CritAudit",1),
		MyGetProfileDWORD("Config","LeaveRetention",0),
		MyGetProfileDWORD("Config","FileExport",0),
		MyGetProfileDWORD("Config","NumberFiles",2),
		MyGetProfileDWORD("Config","NumberLogFiles",1),
		MyGetProfileDWORD("Config","LogLevel",0),
		strclientname,
		strdelim,
		MyGetProfileDWORD("Config","ClearTabs",0),
		MyGetProfileDWORD("SysAdmin","SysAdministrators",0),
		MyGetProfileDWORD("SysAdmin","TimesADay",1),
		MyGetProfileDWORD("SysAdmin","VBS",0),
		MyGetProfileDWORD("SysAdmin","LastSA",0),
		str_destination,
		MyGetProfileDWORD("Network","DestPort",6161),
		MyGetProfileDWORD("Network","SocketType",SOCKETTYPE_UDP),
		MyGetProfileDWORD("Network","MessageSize",2048),
		MyGetProfileDWORD("Network","Syslog",0),
		MyGetProfileDWORD("Network","SyslogDest",13),
		MyGetProfileDWORD("Network","SyslogDynamicCritic",0),
		MyGetProfileDWORD("Remote","AccessKey",0),
		str_password,
		MyGetProfileDWORD("Remote","TLS",0),
		MyGetProfileDWORD("Remote","Allow",0),
		MyGetProfileDWORD("Remote","Restrict",0),
		str_restrictip,
		MyGetProfileDWORD("Remote","WebPort",6161),
		MyGetProfileDWORD("Remote","WebPortChange",0),
		_TRUNCATE);

		dw_objective_error = Read_Objective_Registry_Str(i_objective_count,str_objective);
		if (dw_objective_error == 0)
		{
			substituteEvents(str_objective, 0);
			strncat_s(HTTPBuffer,_countof(HTTPBuffer),"[Objective]\n",_TRUNCATE);
			snprintf_s(HTTPBuffer,_countof(HTTPBuffer),"%s\t %s%d=%s\n",HTTPBuffer,"sObjective",i_objective_count,str_objective,_TRUNCATE);
			while (dw_objective_error == 0)
			{
				i_objective_count++;
				dw_objective_error = Read_Objective_Registry_Str(i_objective_count,str_objective);
				if (dw_objective_error == 0) {
					substituteEvents(str_objective, 0);
					snprintf_s(HTTPBuffer,_countof(HTTPBuffer),"%s\t %s%d=%s\n",HTTPBuffer,"sObjective",i_objective_count,str_objective,_TRUNCATE);				
				}
			}
		} 
		i_objective_count = 0;
		dw_objective_error = E_Read_Objective_Registry_Str(i_objective_count,str_objective);
		if (dw_objective_error == 0)
		{
			strncat_s(HTTPBuffer,_countof(HTTPBuffer),"[EObjective]\n",_TRUNCATE);
			snprintf_s(HTTPBuffer,_countof(HTTPBuffer),"%s\t %s%d=%s\n",HTTPBuffer,"sEObjective",i_objective_count,str_objective,_TRUNCATE);
			while (dw_objective_error == 0)
			{
				i_objective_count++;
				dw_objective_error = E_Read_Objective_Registry_Str(i_objective_count,str_objective);
				if (dw_objective_error == 0) {
					snprintf_s(HTTPBuffer,_countof(HTTPBuffer),"%s\t %s%d=%s\n",HTTPBuffer,"sEObjective",i_objective_count,str_objective,_TRUNCATE);				
				}
			}
		} 

		dw_log_error = Read_Log_Registry_Str(i_log_count,str_log, str_sep, &linecount);
		if (dw_log_error == 0)
		{
			strncat_s(HTTPBuffer,_countof(HTTPBuffer),"[Log]\n",_TRUNCATE);
			snprintf_s(HTTPBuffer,_countof(HTTPBuffer),"%s\t %s%d=%s\n",HTTPBuffer,"sLog",i_log_count,str_log,_TRUNCATE);
			if(strlen(str_sep) > 0){
				snprintf_s(HTTPBuffer,_countof(HTTPBuffer),"%s\t %s%d=%s\n",HTTPBuffer,"sLogMulti",i_log_count,str_sep,_TRUNCATE);			
			}else if(linecount > 0){
					snprintf_s(HTTPBuffer,_countof(HTTPBuffer),"%s\t %s%d=%d\n",HTTPBuffer,"dLogMulti",i_log_count,linecount,_TRUNCATE);									
			}
			while (dw_log_error == 0)
			{
				i_log_count++;
				str_sep[0]='\0';
				linecount = 0;
				dw_log_error = Read_Log_Registry_Str(i_log_count,str_log, str_sep, &linecount);
				if (dw_log_error == 0) {
					snprintf_s(HTTPBuffer,_countof(HTTPBuffer),"%s\t %s%d=%s\n",HTTPBuffer,"sLog",i_log_count,str_log,_TRUNCATE);				
					if(strlen(str_sep) > 0){
						snprintf_s(HTTPBuffer,_countof(HTTPBuffer),"%s\t %s%d=%s\n",HTTPBuffer,"sLogMulti",i_log_count,str_sep,_TRUNCATE);			
					}else if(linecount > 0){
						snprintf_s(HTTPBuffer,_countof(HTTPBuffer),"%s\t %s%d=%d\n",HTTPBuffer,"dLogMulti",i_log_count,linecount,_TRUNCATE);									
					}
				}
			}
		} 
	strncat_s(HTTPBuffer,_countof(HTTPBuffer),"[End]\n",_TRUNCATE);
	
	if(WEBSERVER_TLS)
		retval = sendTLS(HTTPBuffer,session_https);
	else
		retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
	if(fromServer && strlen(fromServer) > 0){
		_snprintf_s(getConfigStatus,_countof(getConfigStatus),_TRUNCATE,"%s %s\n", LGC_MSG, fromServer);
	}else{
		_snprintf_s(getConfigStatus,_countof(getConfigStatus),_TRUNCATE,"");
	}
	return(0);
}

int Config(char *source, char *dest, int size)
{
	snprintf_s(dest,size,_TRUNCATE,"<H2><CENTER>SafedAgent Version %s Set Configuration</H2></CENTER><P><center>",SAFED_VERSION);
	strncat_s(dest,size,"<br>"\
				"<table  width=70% border=0>" \
				"<tbody>"\
				"<tr bgcolor=#E7E5DD><form method=post action=setconfig enctype=\"multipart/form-data\"><td>Select the configuration file: </td>" \
				"<td><input type=file name=cfgname size=25 value=\"\"></td></tr><tr><td></td><td><input type=\"submit\" size=25  value=\"Set\"></td></tr></form><tr><td>",_TRUNCATE);

	return(0);
}

int Certs(char *source, char *dest, int size)
{
	snprintf_s(dest,size,_TRUNCATE,"<H2><CENTER>SafedAgent Version %s Set Certificates</H2></CENTER><P><center>",SAFED_VERSION);
	strncat_s(dest,size,"<br>"\
				"<table  width=70% border=0>" \
				"<tbody>"\
				"<tr bgcolor=#E7E5DD><form method=post action=setca enctype=\"multipart/form-data\"><td>Select the ca file: </td>" \
				"<td><input type=file name=caname size=25 value=\"\"></td></tr><tr><td></td><td><input type=\"submit\" size=25  value=\"Set CA\"></td></tr></form><tr><td>"\
				"<tr bgcolor=#E7E5DD><form method=post action=setcert enctype=\"multipart/form-data\"><td>Select the cert file: </td>" \
				"<td><input type=file name=certname size=25 value=\"\"></td></tr><tr><td></td><td><input type=\"submit\" size=25  value=\"Set CERT\"></td></tr></form><tr><td>"\
				"<tr bgcolor=#E7E5DD><form method=post action=setkey enctype=\"multipart/form-data\"><td>Select the key file: </td>" \
				"<td><input type=file name=keyname size=25 value=\"\"></td></tr><tr><td></td><td><input type=\"submit\" size=25  value=\"Set KEY\"></td></tr></form><tr><td>",_TRUNCATE);

	return(0);
}

int getEndSection(char* pos, char* tag){
	if(!pos || !tag)return(0);
	char* pos2=strstr(pos,tag);
	if(pos2){
		pos[pos2 - pos]='\0';
	} else return (0);
	return(1);
}


int SetConfig(char *source, char *dest, int size, char* fromServer)
{
	char* pos =strstr(source,"\r\n\r\n");
	char buffer[1024 + 50*SIZE_OF_AN_OBJECTIVE]="";
	char tag[80] = "";
	char value[SIZE_OF_AN_OBJECTIVE] = "";
	int len = 0 ;
	char* tmp = buffer;
	int iscorrect = 0;
	iscorrect = getEndSection(pos, "[End]");
	if(!iscorrect){
		strncpy_s(dest,size,"<h2><center>SafedAgent Configuration</h2>Error in received configuration! Values have not been changed.",_TRUNCATE);
		_snprintf_s(setConfigStatus,_countof(setConfigStatus),_TRUNCATE,"");
		return(0);	
	}

	Delete_Reg_Keys();
	if(pos){
		pos = pos + 4;
		if(getSection(pos, buffer, sizeof(buffer), "[Config]")){
			tmp = buffer;
			while(getNextKey(&tmp,tag, sizeof(tag), value, sizeof(value))){
				if(!setRegValue("Config", tag, value))
					LogExtMsg(INFORMATION_LOG,"Errors during Configuration Config %s", tag);
			}
		}else LogExtMsg(INFORMATION_LOG,"Errors during Config Configuration");
		if(getSection(pos, buffer, sizeof(buffer), "[SysAdmin]")){
			tmp = buffer;
			while(getNextKey(&tmp,tag, sizeof(tag), value, sizeof(value))){
				if(!setRegValue("SysAdmin", tag, value))
					LogExtMsg(INFORMATION_LOG,"Errors during Configuration SysAdmin %s", tag);
			}
		}else LogExtMsg(INFORMATION_LOG,"Errors during SysAdmin Configuration");
		if(getSection(pos, buffer, sizeof(buffer), "[Network]")){
			tmp = buffer;
			while(getNextKey(&tmp,tag, sizeof(tag), value, sizeof(value))){
				if(!setRegValue("Network", tag, value))
					LogExtMsg(INFORMATION_LOG,"Errors during Configuration Network %s", tag);
			}
		}else LogExtMsg(INFORMATION_LOG,"Errors during Network Configuration");
		if(getSection(pos, buffer, sizeof(buffer), "[Remote]")){
			tmp = buffer;
			while(getNextKey(&tmp,tag, sizeof(tag), value, sizeof(value))){
				if(!setRegValue("Remote", tag, value))
					LogExtMsg(INFORMATION_LOG,"Errors during Configuration Remote %s", tag);
			}
		}else LogExtMsg(INFORMATION_LOG,"Errors during Remote Configuration");
		if(getSection(pos, buffer, sizeof(buffer), "[Objective]")){
			tmp = buffer;
			while(getNextKey(&tmp,tag, sizeof(tag), value, sizeof(value))){
				substituteEvents(value, 1);
				if(!setRegValue("Objective", tag, value))
					LogExtMsg(INFORMATION_LOG,"Errors during Configuration Objective %s", tag);
			}
		}else LogExtMsg(INFORMATION_LOG,"Errors during Objectives Configuration");
		if(getSection(pos, buffer, sizeof(buffer), "[EObjective]")){
			tmp = buffer;
			while(getNextKey(&tmp,tag, sizeof(tag), value, sizeof(value))){
				if(!setRegValue("EObjective", tag, value))
					LogExtMsg(INFORMATION_LOG,"Errors during Configuration Log Objective %s", tag);
			}
		}else LogExtMsg(INFORMATION_LOG,"Errors during Log Objectives Configuration");
		if(getSection(pos, buffer, sizeof(buffer), "[Log]")){
			tmp = buffer;
			while(getNextKey(&tmp,tag, sizeof(tag), value, sizeof(value))){
				if(!setRegValue("Log", tag, value))
					LogExtMsg(INFORMATION_LOG,"Errors during Configuration Log %s", tag);
			}
		}else LogExtMsg(INFORMATION_LOG,"Errors during Log Configuration");


	}

	
	strncpy_s(dest,size,"<h2><center>SafedAgent Configuration</h2>Values have been changed.",_TRUNCATE);
	if(fromServer && strlen(fromServer) > 0){
		_snprintf_s(setConfigStatus,_countof(setConfigStatus),_TRUNCATE,"%s %s\n", LSC_MSG, fromServer);
		MyWriteProfileString("Status","LastSetTime",fromServer);
	}else{
		_snprintf_s(setConfigStatus,_countof(setConfigStatus),_TRUNCATE,"");
	}
	return(0);
}

int SetCertificate(char *source, char *dest, int size, char* cert)
{
	char* pos =strstr(source,"\r\n\r\n");
	FILE *file = (FILE *)NULL;

	if(!cert || (strlen(cert) == 0)){
		strncpy(dest,"<h2><center>SafedAgent Certificates</h2>Certificates have not been set.",size);
		return(1);
	}

	if(pos){
		pos = pos + 4;
		file = fopen(cert, "w");
		if (file == (FILE *)NULL) {
			LogExtMsg(ERROR_LOG,"Cannot open %s file", cert);
			strncpy(dest,"<h2><center>SafedAgent Certificates</h2>Certificates have not been set.",size);
			return(1);
		}

		fputs(pos, file);
		fflush(file);
		fclose((FILE *)file);
		strncpy(dest,"<h2><center>SafedAgent Certificates</h2>Certificates have been set.",size);

	}
	return(0);


}

