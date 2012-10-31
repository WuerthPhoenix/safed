//
// SNARE - Audit / EventLog analysis and forwarding
// Copyright 2001-2010 InterSect Alliance Pty Ltd
// http://www.intersectalliance.com/
//
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <lm.h>
#include <iads.h>

#include <comdef.h>
#include <activeds.h>

#include <windows.h>
#include <Adshlp.h>
#include <comutil.h>
#include <dsrole.h>
#include <time.h>

#include "WebPages.h"
#include "Version.h"

#include "support.h"
#include "MD5.h"

#include "webserver.h"

extern void DebugMsg(const char* pszFormat, ...);

extern int SNAREDEBUG;
extern HANDLE hMutex,hMutexFile;
extern MsgCache *MCHead, *MCTail;

extern BOOL GetOutputFile(char* filename, char* date);
extern DWORD GetTotalSavedLogs (FILE * fp);
extern void	GetSavedLogsAt (FILE * fp, char* line, int position);
extern void	SendToAll(char *buf, int nSize);

#define snprintf_s _snprintf_s
#define UGBUFFER     10240

// Make sure we return the size, or zero (for strings).
// Note that for the most part, the socket will be ignored
int HandleWebPages(char *HTTPBuffer,char *HTTPOutputBuffer,int size,SOCKET http_socket, HANDLE event)
{
	int returncode=0, refreshflag=0;
	char *ArgPosition;
	char TBuffer[2048]="";
	
	if(SNAREDEBUG >= 5) { DebugMsg("HandleWebPages"); }
	
	if(!HTTPBuffer || !HTTPOutputBuffer) {
		return(0);
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
		
		if(SNAREDEBUG >= 5) { DebugMsg("Processing Request"); }

		ArgPosition=strstr(HTTPBuffer,"?");
		// No arguments passed?
		if(!ArgPosition) {
			// Set argument position to the beginning of the buffer.
			ArgPosition=HTTPBuffer;
		} else {
			ArgPosition++;
		}

		if(!strcmp(HTTPBuffer,"/LocalUsers")) {
			DisplayTextHeader(http_socket);
			ShowLocalUsers(http_socket);
			return(-1);
		} else if(!strcmp(HTTPBuffer,"/DomainUsers")) {
			DisplayTextHeader(http_socket);
			ShowDomainUsers(http_socket);
			return(-1);
		} else if(!strcmp(HTTPBuffer,"/LocalGroupMembers")) {
			DisplayTextHeader(http_socket);
			ShowLocalGroupMembers(http_socket);
			return(-1);
		} else if(!strcmp(HTTPBuffer,"/DomainGroupMembers")) {
			DisplayTextHeader(http_socket);
			ShowDomainGroupMembers(http_socket);
			return(-1);
		} else if(!strncmp(HTTPBuffer,"/RegDump",8)) {
			// DisplayTextHeader(http_socket);
			DumpRegistry(http_socket,ArgPosition,TBuffer,_countof(TBuffer));
			if(!strlen(TBuffer)) {
				return(-1);
			}
		}
		if(!strncmp(HTTPBuffer,"/eventlog",9)) refreshflag=1;
		returncode=DefaultHeader(HTTPBuffer,pBuffer,size, refreshflag);
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
		} else if(!strcmp(HTTPBuffer,"/remote")) {
			returncode+=Remote_Config(ArgPosition,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/setremote",10)) {
			returncode+=Remote_Set(ArgPosition,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/objective",10)) {
			returncode+=Objective_Config(ArgPosition,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/setobjective",13)) {
			returncode+=Objective_Display(HTTPBuffer,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/changeobjective",16)) {
			returncode+=Objective_Result(HTTPBuffer,pBuffer,psize);
		} else if(!strcmp(HTTPBuffer,"/restart")) {
			returncode+=Restart(HTTPBuffer,pBuffer,psize,event);
		} else if(!strncmp(HTTPBuffer,"/restart?",10)) {
			strncpy_s(pBuffer,psize,"Nothing here yet",_TRUNCATE);
		} else if(!strncmp(HTTPBuffer,"/setnetwork",11)) {
			returncode+=Network_Set(HTTPBuffer,pBuffer,psize);
		} else if(!strncmp(HTTPBuffer,"/status",6)) {
			returncode+=Status_Page(ArgPosition,pBuffer,psize);
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
			if(SNAREDEBUG >= 5) { DebugMsg("No page - sending a 404"); }
			Display404(http_socket);
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
int Status_Page(char *source, char *dest, int size)
{
#ifdef _M_X64
	snprintf_s(dest,size,_TRUNCATE,"<HTML><BODY><H2><CENTER>SNARE Version %s Status Page</H2></CENTER><P><center><font color=green>Snare for Windows Vista (AMD64 binary on %d bit arch) is currently active.</font></CENTER></BODY></HTML>",SNARE_VERSION,sizeof(int*)*8);
#elif _M_IA64
	snprintf_s(dest,size,_TRUNCATE,"<HTML><BODY><H2><CENTER>SNARE Version %s Status Page</H2></CENTER><P><center><font color=green>Snare for Windows Vista (IA64 binary on %d bit arch) is currently active.</font></CENTER></BODY></HTML>",SNARE_VERSION,sizeof(int*)*8);
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

	snprintf_s(dest,size,_TRUNCATE,"<HTML><BODY><H2><CENTER>SNARE Version %s Status Page</H2></CENTER><P><center><font color=green>Snare for Windows (X86 binary on %d bit arch) is currently active.</font></CENTER></BODY></HTML>",SNARE_VERSION,(f64?64:32));
#endif
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
	char *str_protocol[] = {"UDP", "TCP"};
	UINT i,i_SyslogFacility,i_SyslogPriority;
		
	dw_config_error = Read_Config_Registry(&config_struct);
	dw_network_error = Read_Network_Registry(&network_struct);

	// This function will display the form used to set the audit configuration
	// The result of the form will be sent to "network_set"
	strncpy_s(dest,size,"<form method=get action=setnetwork><h2><center>SNARE Network Configuration</h2>",_TRUNCATE);

	// Will display an error if unable to completely read from the registry
	if ((dw_network_error > 0) || (dw_config_error > 0)) {
		dw_network_error += WEB_READ_NETWORK_ERROR_CODE;
		dw_config_error += WEB_READ_CONFIG_ERROR_CODE;

		_snprintf_s(dest,size,_TRUNCATE,"%s<br><b>NOTE: Some errors were encountered in reading the registry. Default values " \
					"may be used.<br> Report error: %d.%d</b><br>",dest,dw_network_error,dw_config_error);
	}

	strncat_s(dest,size,"<br>The following network configuration parameters of the SNARE unit is set to the following values:<br><br>" \
				"<table  width=70% border=0>" \
				"<tr bgcolor=#FFFFCC><td>Override detected DNS Name with: </td>" \
				"<td><input type=text name=str_ClientName size=25 value=\"",_TRUNCATE);
	
	strncat_s(dest,size,config_struct.str_ClientName,_TRUNCATE);
	strncat_s(dest,size,"\"></td></tr>",_TRUNCATE);


	// Here: Two alternatives: Allow a user-supplied comma-separated list, or
	// alternatively, add a new element for each new system?
	strncat_s(dest,size,"<tr bgcolor=#FFFFBB><td>Destination Snare Server address </td><td><input type=text name=str_Destination size=25 value=\"",_TRUNCATE);
	strncat_s(dest,size,network_struct.str_Destination,_TRUNCATE);
	strncat_s(dest,size,"\"></td></tr>",_TRUNCATE);

	_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFCC><td>Destination Port</td><td><input type=text name=dw_DestPort size=8 value=\"%d\" onMouseover=\"ddrivetip(\'514 is the default rsyslog port  \')\" onMouseout=\"hideddrivetip()\"></td></tr>",dest,network_struct.dw_DestPort);


	strncat_s(dest,size,"<tr bgcolor=#E7E5DD><td>Protocol Type</td><td><select name=dw_SocketType>",_TRUNCATE);
	for (i = SOCKETTYPE_UDP; i <= SOCKETTYPE_TCP; i++)
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
		"%s<tr bgcolor=#FFFFCC><td>Perform a scan of ALL objectives, and display the maximum criticality?</td><td><input type=checkbox name=dw_CritAudit%s></td></tr>"
		"<tr bgcolor=#FFFFBB><td>Allow SNARE to automatically set audit configuration?</td><td><input type=checkbox name=dw_Audit%s></td></tr>"
		"<tr bgcolor=#FFFFCC><td>Allow SNARE to automatically set file audit configuration?</td><td><input type=checkbox name=dw_FileAudit%s></td></tr><tr bgcolor=#FFFFFF><td><br></td></tr>"
		"<tr bgcolor=#FFFFBB><td>Export Snare Log data to a file?</td><td><input type=checkbox name=dw_FileExport%s></td></tr><tr bgcolor=#FFFFFF><td><br></td></tr>"
		"<tr bgcolor=#DEDBD2><td>Number of Safed Log files</td><td><input type=text size=5  name=dw_NumberFiles value=\"%d\"></td></tr><tr bgcolor=#FFFFFF><td><br></td><td><br></td></tr>",
		dest,
		(config_struct.dw_CritAudit != 0?" checked":""),
		(config_struct.dw_Audit != 0?" checked":""),
		(config_struct.dw_FileAudit != 0?" checked":""),
		(config_struct.dw_FileExport != 0?" checked":""),
		config_struct.dw_NumberFiles);

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
	strncat_s(dest,size,"<tr bgcolor=#FFFFBB><td>Enable SYSLOG Header?</td><td><input type=checkbox name=dw_Syslog",_TRUNCATE);
	if (network_struct.dw_Syslog != 0) {
		strncat_s(dest,size," checked",_TRUNCATE);
	}
	strncat_s(dest,size,"></td></tr>",_TRUNCATE);

	strncat_s(dest,size,"<tr bgcolor=#FFFFCC><td>SYSLOG Facility </td><td><select name=SyslogFacility>",_TRUNCATE);
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

	strncat_s(dest,size,"<tr bgcolor=#FFFFBB><td>SYSLOG Priority </td><td><select name=SyslogPriority>",_TRUNCATE);
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
				 "<input type=submit value=\"Change Configuration\">    " \
				 "<input type=reset value=\"Reset Form\"></form>",_TRUNCATE);
	
	return(0);
}

int Network_Set(char *source, char *dest, int size)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	char *psource=source;
	char Variable[100]="", cache_size[100]="", web_port[100]="", number_files[100]="", syslog_fac[100]="", protocol[10] = "", syslog_pri[100]="";
	char Argument[100]="";
	char *str_facility[] = {"Kernel","User","Mail","Daemon","Auth","Syslog","Lpr","News","UUCP","Cron","Authpriv","Ftp","Local0","Local1","Local2","Local3","Local4","Local5","Local6","Local7"};
	char *str_priority[] = {"Emergency","Alert","Critical","Error","Warning","Notice","Information","Debug"};
	char *str_protocol[] = {"UDP", "TCP"};
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
	strncpy_s(dest,size,"<h2><center>SNARE Network Configuration</h2>",_TRUNCATE);

	// Note that all the possible variables do NOT have to be in the URL. The ones that are selected
	// via a checkbox will not be listed if the checkbox has been deselected.
	// Checking is limited to ensuring the Detsination port in the range 1-65535.
	// The variable associated with the checkbox (dw_Syslog) must be
	// exactly "on" or it will be defaulted to "off".

	network_struct.dw_DestPort = -1;
	network_struct.dw_SocketType=SOCKETTYPE_UDP;	// UDP
	network_struct.dw_Syslog = 0;
	config_struct.dw_Audit = 0;
	config_struct.dw_FileAudit = 0;
	config_struct.dw_FileExport = 0;
	config_struct.dw_NumberFiles = 0;

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
	}else{
		network_struct.dw_SocketType = SOCKETTYPE_UDP;
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
	strncpy_s(dest,size,"\n<form method=get action=setremote><h2><center>SNARE Remote Control Configuration</h2>",_TRUNCATE);

	// Will display an error if unable to completely read from the registry
	if (dw_remote_error > 0)
	{
		dw_remote_error += WEB_READ_REMOTE_ERROR_CODE;
		
		_snprintf_s(dest,size,_TRUNCATE,"%s<br><b>NOTE: Some errors were encountered in reading the registry. Default values " \
					"may be used.<br> Report error: %d</b><br>\n",dest,dw_remote_error);
	}
	strncat_s(dest,size,"<br>The following remote control configuration parameters of the SNARE unit is set to the following values:<br><br>" \
		"<table  width=70% border=0>",_TRUNCATE);

	strncat_s(dest,size,"<tr bgcolor=#FFFFBB><td>Restrict remote control of SNARE agent to certain hosts </td><td><input type=checkbox name=dw_Restrict",_TRUNCATE);

	if (remote_struct.dw_Restrict != 0)
		strncat_s(dest,size," checked",_TRUNCATE);
	strncat_s(dest,size,"></td></tr>\n",_TRUNCATE);

	strncat_s(dest,size,"<tr bgcolor=#FFFFCC><td>IP Address allowed to remote control SNARE </td><td><input type=text name=str_RestrictIP size=12 value=\"",_TRUNCATE);
	strncat_s(dest,size,remote_struct.str_RestrictIP,_TRUNCATE);
	strncat_s(dest,size,"\"></td></tr>\n",_TRUNCATE);
	
	_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFBB><td>Require a password for remote control? </td><td><input type=checkbox name=dw_Password%s></td></tr>\n",dest,(remote_struct.dw_Password != 0?" checked":""));

	_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFCC><td>Password to allow remote control of SNARE </td><td><input type=password name=str_Password size=12 value=\"%s\"></td></tr>\n",dest,remote_struct.str_Password);

	strncat_s(dest,size,"<tr bgcolor=#FFFFBB><td>Change Web Server default (6161) port </td><td><input type=checkbox name=dw_PortChange",_TRUNCATE);

	if (remote_struct.dw_WebPortChange != 0)
		strncat_s(dest,size," checked",_TRUNCATE);
	strncat_s(dest,size,"></td></tr>\n",_TRUNCATE);

	_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFCC><td>Web Server Port </td><td><input type=text name=dw_WebPort size=8 value=\"%d\"></td></tr>\n",dest,remote_struct.dw_WebPort);

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
	strncpy_s(dest,size,"<h2><center>SNARE Remote Control Configuration</h2>",_TRUNCATE);

	// Note that all the possible variables do NOT have to be in the URL. The ones that are selected
	// via a checkbox will not be listed if the checkbox has been deselected.
	// Also be aware that there may not be any arguments for this objective. If a sysadmin does not want
	// remote control, then there will be no arguments.
	// Hence: Checking is limited to Webport in the range 1-65535 only if portchange is "on"
	// The three variable associated with the checkboxes (dw_Allow, dw_Restrict, and dw_PortChange) must be
	// exactly "on" or they will be defaulted to "off".
	// str_RestrictIP can be anything it wants to be, so long as it is within size bounds.

	// Configure the defaults.
	remote_struct.dw_WebPort = -1;
	remote_struct.dw_Password = 0;
	remote_struct.dw_Restrict = 0;
	remote_struct.dw_WebPortChange = 0;

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


	strncpy_s(dest,size,"<form method=get action=setobjective><H2><CENTER>SNARE Filtering Objectives Configuration</H2>",_TRUNCATE);
		
	dw_objective_error = Read_Objective_Registry(i_objective_count,&reg_objective);
	if (dw_objective_error == 0)
	{
		strncat_s(dest,size,"<br>The following filtering objectives of the SNARE unit are active:<br><br>" \
		"<table  width=100% border=1>",_TRUNCATE);

		strncat_s(dest,size,"<tr bgcolor=#FFFFBB><center><td><b>Action Required</b></td><td><b>Criticality</b></td>" \
			        "<td><b>Event ID Include/Exclude</b></td><td><b>Event ID Match</b></td><td><b>User Include/Exclude</b></td><td><b>User Match</b></td><td><b>General Match Include/Exclude</b></td><td><b>General Match</b>" \
					"</td><td><b>Return</b></td><td><b>Event Src</b></td><td><b>Order</b></td></center></tr>",_TRUNCATE);

		while (dw_objective_error == 0)
		{
			if ((i_objective_count%2) == 0)
				strncat_s(dest,size,"<tr bgcolor=#FFFFCC>",_TRUNCATE);
			else
				strncat_s(dest,size,"<tr bgcolor=#FFFFBB>",_TRUNCATE);

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

			strncat_s(dest,size,"</td><td>",_TRUNCATE);
			if (i_objective_count != 0) {
				_snprintf_s(dest,size,_TRUNCATE,"%s<div align=center style=\"margin-bottom: 5px; border-left: 2px solid #eeeeee; border-top: 2px solid #eeeeee; border-right: 2px solid #aaaaaa; border-bottom: 2px solid #aaaaaa; background-color: #dddddd\"><a href=\"/setobjective?%d=MoveUp\" style=\"font-size: 9px; color: #33aa33; text-decoration: none; display: block;\">&#9650;</a></div>",dest,i_objective_count);
			}

			i_objective_count++;
			dw_objective_error = Read_Objective_Registry(i_objective_count,&reg_objective);

			if (dw_objective_error == 0) {
				_snprintf_s(dest,size,_TRUNCATE,"%s<div align=center style=\"margin-bottom: 5px; border-left: 2px solid #eeeeee; border-top: 2px solid #eeeeee; border-right: 2px solid #aaaaaa; border-bottom: 2px solid #aaaaaa; background-color: #dddddd\"><a href=\"/setobjective?%d=MoveDown\" style=\"font-size: 9px; color: #33aa33; text-decoration: none; display: block;\">&#9660;</a></div>",dest,i_objective_count-1);
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


int Objective_Display(char *source, char *dest, int size)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	Reg_Objective reg_objective;
	DWORD dw_objective_error = 0, dw_objective_write_error = 0,dw_objective_delete_error = 0;
	int i_objective_count = 0,i_type = 0;
	char *psource=source, Variable[100], Argument[100];
	char str_temp[20], str_temp_objective[10];
	

	//This function will display an existing, or a blank, objective
	strncpy_s(dest,size,"<form method=get action=changeobjective><h2><center>SNARE Filtering Objective Configuration</h2>",_TRUNCATE);

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
			strncpy_s(reg_objective.str_general_match,_countof(reg_objective.str_general_match),"*",_TRUNCATE);
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

		strncat_s(dest,size,"<br>The following parameters of the SNARE objective may be set:<br><br>" \
			"<table  width=100% border=0>",_TRUNCATE);

		//Identify the high level event. Note that there is a table within a table in these radio buttons.
		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFBB><td>Identify the high level event</td><td><div id=\"hilvl\"><table  width=100%% border=0>"
			"<tr><td><input type=radio name=str_eventid_match value=%s%s>Logon or Logoff  </td>"
			    "<td><input type=radio name=str_eventid_match value=%s%s>Account Administration  </td></tr>"
			"<tr><td><input type=radio name=str_eventid_match value=%s%s>Access a file or directory  </td>"
			    "<td><input type=radio name=str_eventid_match value=%s%s>Change the security policy  </td></tr>"
			"<tr><td><input type=radio name=str_eventid_match value=%s%s>Start or stop a process  </td>"
			    "<td><input type=radio name=str_eventid_match value=%s%s>Restart, shutdown and system  </td></tr>"
			"<tr><td><input type=radio name=str_eventid_match value=%s%s>Use of user rights  </td>"
			    "<td>&nbsp;</td>",
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
			strstr(reg_objective.str_eventid_match,USERRIGHTS_TOKEN))
		{
			reg_objective.str_eventid_match[0]='\0';
			strncat_s(dest,size,"</tr><tr><td colspan=2><input type=radio name=str_eventid_match id=\"anyevt\" value=Any_Event onMouseover=\"ddrivetip(\'You can filter events through the Event ID Search Term field   \')\" onMouseout=\"hideddrivetip()\">Any event(s) </td></tr></table></div></td></tr>",_TRUNCATE);
		} else {
			strncat_s(dest,size,"</tr><tr><td colspan=2><input type=radio name=str_eventid_match id=\"anyevt\" value=Any_Event checked>Any event(s) </td></tr></table></div></td></tr>",_TRUNCATE);
		}
	
		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFCC><td>Select the Event ID Match Type</td><td>"
			"<input type=radio name=str_event_match_type value=%s%s>Include    "
			"<input type=radio name=str_event_match_type value=%s%s>Exclude    </td></tr>",
			dest,
			INCLUDE, (strstr(reg_objective.str_event_match_type,INCLUDE) != NULL?" checked":""),
			EXCLUDE, (strstr(reg_objective.str_event_match_type,EXCLUDE) != NULL?" checked":"")
		);

		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFCC><td>Event ID Search Term<br><i>Optional, Comma separated: only used by the 'Any Event' setting above</i></td>"
				"<td><input type=text name=str_eventid_text size=50 value=\"%s\" onMouseover=\"ddrivetip(\'By example 512,513 - Restart and shutdown system \')\" onMouseout=\"hideddrivetip()\"></td></tr>",
			dest,
			reg_objective.str_eventid_match
		);

		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFCC><td>Select the General Search Type</td><td>"
			"<input type=radio name=str_general_match_type value=%s%s>Include    "
			"<input type=radio name=str_general_match_type value=%s%s>Exclude    </td></tr>",
			dest,
			INCLUDE, (strstr(reg_objective.str_general_match_type,INCLUDE) != NULL?" checked":""),
			EXCLUDE, (strstr(reg_objective.str_general_match_type,EXCLUDE) != NULL?" checked":"")
		);

		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFBB><td>General Search Term<br><i>Regular expressions accepted</i></td>"
				"<td><input type=text name=str_general_match size=50 value=\"%s\" onMouseover=\"ddrivetip(\'Use regular expressions like admin[1,2] to filter the event record payload  \')\" onMouseout=\"hideddrivetip()\"></td></tr>",
			dest,
			reg_objective.str_general_match
		);

		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFCC><td>Select the User Match Type</td><td>"
			"<input type=radio name=str_user_match_type value=%s%s>Include    "
			"<input type=radio name=str_user_match_type value=%s%s>Exclude    </td></tr>",
			dest,
			INCLUDE,(strstr(reg_objective.str_user_match_type,INCLUDE) != NULL?" checked":""),
			EXCLUDE,(strstr(reg_objective.str_user_match_type,EXCLUDE) != NULL?" checked":"")
		);

		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFCC><td>User Search Term<br><i>User Names, comma separated. Wilcards accepted</i></td>"
			"<td><input type=text name=str_user_match size=50 value=\"%s\" onMouseover=\"ddrivetip(\'Use wildcards amin1,admini* to filter the event by User Name  \')\" onMouseout=\"hideddrivetip()\"></td></tr>",dest,reg_objective.str_user_match);

		//Identify the event type to capture. Note that there is a table within a table in these radio buttons.
		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFBB><td>Identify the event types to be captured</td><td><table  width=100%% border=0>"
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
			"%s<tr bgcolor=#FFFFCC><td>Identify the event logs <br>(ignored if any objective other <br>than 'Any event(s)' is selected):</td><td><table  width=100%% border=0>"
			"<tr><td><input type=checkbox name=str_eventlog_type_seclog onClick=\"document.getElementById('anyevt').checked=true;toggleDisabledGroup(document.getElementById('hilvl'));document.getElementById('succ').disabled=false;document.getElementById('fail').disabled=false;\" value=%s%s>Security  </td>"
			    "<td><input type=checkbox name=str_eventlog_type_syslog value=%s%s>System  </td></tr>"
			"<tr><td><input type=checkbox name=str_eventlog_type_applog value=%s%s>Application  </td>"
			    "<td><input type=checkbox name=str_eventlog_type_dirlog value=%s%s>Directory Service  </td></tr>"
			"<tr><td><input type=checkbox name=str_eventlog_type_dnslog value=%s%s>DNS Server  </td>"
			    "<td><input type=checkbox name=str_eventlog_type_replog value=%s%s>File Replication  </td></tr>",
			dest,
			SECLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,SECLOG_TOKEN) != NULL?" checked":""),
			SYSLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,SYSLOG_TOKEN) != NULL?" checked":""),
			APPLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,APPLOG_TOKEN) != NULL?" checked":""),
			DIRLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,DIRLOG_TOKEN) != NULL?" checked":""),
			DNSLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,DNSLOG_TOKEN) != NULL?" checked":""),
			REPLOG_TOKEN,(strstr(reg_objective.str_eventlog_type,REPLOG_TOKEN) != NULL?" checked":"")
		);
		if (strstr(reg_objective.str_eventlog_type,SECLOG_TOKEN) == NULL) {
			strncat_s(dest,size,"<script type=\"text/javascript\">toggleDisabledGroup(document.getElementById('hilvl'));</script>",_TRUNCATE);
		}

		strncat_s(dest,size,"</table></td></tr>",_TRUNCATE);

		//Determine the criticality level
		_snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FFFFBB><td>Select the Alert Level</td><td>"

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
			strncpy(source,"/objective", 10);//MM				
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
		strncat_s(dest,size,"<br>Swap complete. <a href=\"/objective\">Return to Objectives Configuration</a>.",_TRUNCATE);
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
		strncat_s(dest,size,"<br>Swap complete. <a href=\"/objective\">Return to Objectives Configuration</a>.",_TRUNCATE);
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

	strncpy_s(dest,size,"<form method=get action=setobjective><H2><CENTER>SNARE Filtering Objectives Configuration</H2>",_TRUNCATE);

	strncpy_s(reg_objective.str_event_type,_countof(reg_objective.str_event_type),"",_TRUNCATE);
	strncpy_s(reg_objective.str_eventlog_type,_countof(reg_objective.str_eventlog_type),"",_TRUNCATE);

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
			strncpy(source,"/objective", 10);//MM				
			Objective_Config(source,dest,size);//MM
		}else
			strncat_s(dest,size,"<br>The objective was unable to be modifed/added.",_TRUNCATE);
			//***REPORT AN ERROR
	}

	return(0);
}


int DefaultHeader(char *source, char *dest, int size, int refreshflag)
{
	//All strncpy or strncat functions in this routine have been designed avoid overflows
	strncpy_s(dest,size,"<HTML><head>" \
	"<title>InterSect Alliance - Information Technology Security</title>" \
	"<meta name=\"TITLE\" content=\"InterSect Alliance - Information Technology Security\">" \
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
		"document.write('<div id=\"dhtmltooltip\"></div>')\n"
		"document.write('<img id=\"dhtmlpointer\" src=\"arrow.gif\">')\n" 
		"var ie=document.all\n"
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
	"<body text=black bgcolor=white link=#000066 vlink=#000044 alink=#000055>" \
	"<table border=0 cellspacing=0 cellpadding=0 columns=3 width=100%>" \
	"<tbody>" \
    "<tr>" \
    "<td height=70><img src=/intersect.gif alt=\"InterSect\" width=205 height=70 hspace=20 vspace=0 border=0 align=Right>" \
    "</td>" \
    "<td height=70 width=1% bgcolor=#eeeeee><br></td>" \
	"<td height=70 width=1% bgcolor=#dddddd><br></td>" \
	"<td height=70 width=1% bgcolor=#cccccc><br></td>" \
	"<td height=70 width=1% bgcolor=#ccbbbb><br></td>" \
	"<td height=70 width=1% bgcolor=#ccaaaa><br></td>" \
	"<td height=70 width=1% bgcolor=#cc9999><br></td>" \
	"<td height=70 width=1% bgcolor=#cc8888><br></td>" \
	"<td height=70 width=1% bgcolor=#cc7777><br></td>" \
	"<td height=70 width=1% bgcolor=#cc6666><br></td>" \
	"<td height=70 width=1% bgcolor=#cc5555><br></td>" \
	"<td height=70 width=1% bgcolor=#cc4444><br></td>" \
	"<td height=70 width=1% bgcolor=#cc3333><br></td>" \
	"<td height=70 width=1% bgcolor=#cc2222><br></td>" \
	"<td height=70 width=1% bgcolor=#cc1111><br></td>" \
	"<td height=70 width=86% bgcolor=#cc0000><div align=right><center><h1>SNARE for Windows&nbsp;</h1></center></div></td>" \
    "</tr>" \
    "</tbody>" \
	"</table>" \
	"<table border=0 cellspacing=0 cellpadding=0 columns=1 width=100%>" \
    "<tr><td height=3 border=0 bgcolor=white width=100%></td></tr>" \
    "<tr><td height=3 border=0 bgcolor=black width=100%></td></tr>" \
    "<tr><td height=2 border=0 bgcolor=#AAAAAA width=100%></td></tr>" \
    "<tr><td height=2 border=0 bgcolor=white width=100%></td></tr>" \
	"</table>" \
	"<table border=0 cellspacing=0 cellpadding=5 columns=2 width=100% height=100%>" \
	"<tbody>" \
    "<tr>" \
      "<td valign=Top width=20% bgcolor=#cc0000>" \
      "<div align=Center><font color=#ffffff>" \
      "<br>" \
      "<font face=\"Helvetica,Arial,sans-serif\" size=-1><B>" \
      "<br><A HREF=\"/eventlog\" style=\"color:FFFFFF;text-decoration:none\">Latest Events</A><br>" \
      "<br><A HREF=\"/dailylog\" style=\"color:FFFFFF;text-decoration:none\">Daily Events</A><br>" \
      "<br><A HREF=\"/network\" style=\"color:FFFFFF;text-decoration:none\">Network Configuration</A><br>" \
      "<br><A HREF=\"/remote\" style=\"color:FFFFFF;text-decoration:none\">Remote Control Configuration</A><br>" \
      "<br><A HREF=\"/objective\" style=\"color:FFFFFF;text-decoration:none\">Objectives Configuration</A><br>" \
      "<br><A HREF=\"/status\" style=\"color:FFFFFF;text-decoration:none\">View Audit Service Status</A><br>" \
	  "<br><A HREF=\"/restart\" style=\"color:FFFFFF;text-decoration:none\">Apply the Latest Audit Configuration</A><br>" \
	  "</div>" \
	  "<br><font size=-2><A HREF=\"/LocalUsers\" style=\"color:FFFFFF;text-decoration:none\" target=\"SnareData\">Local Users</A></font>" \
	  "<br><font size=-2><A HREF=\"/DomainUsers\" style=\"color:FFFFFF;text-decoration:none\" target=\"SnareData\">Domain Users</A></font>" \
	  "<br><font size=-2><A HREF=\"/LocalGroupMembers\" style=\"color:FFFFFF;text-decoration:none\" target=\"SnareData\">Local Group Members</A></font>" \
	  "<br><font size=-2><A HREF=\"/DomainGroupMembers\" style=\"color:FFFFFF;text-decoration:none\" target=\"SnareData\">Domain Group Members</A></font>" \
	  "<br><font size=-2><A HREF=\"/RegDump\" style=\"color:FFFFFF;text-decoration:none\" target=\"SnareData\">Registry Dump</A></font><br>" \
      "</b></font>" \
      "<br>" \
      
    "</td>" \
    "<td width=100% valign=Top>" \
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
		"</td>" \
		"</tr>" \
		"</tbody>" \
		"</table>" \
		"</body><center>" \
		"<BR><BR><FONT SIZE=-1 face=helvetica>(c) <A HREF=\"http://www.intersectalliance.com\">Intersect Alliance</A> Pty Ltd 1999-2010. " \
		"This site is powered by <A HREF=\"http://www.intersectalliance.com/projects/\">SNARE for Windows.</A></FONT>" \
		"</center></html>",_TRUNCATE);

	return(0);
}

int Restart(char *source, char *dest, int size, HANDLE event)
{
	// All strncpy or strncat functions in this routine have been designed avoid overflows
	strncpy_s(dest,size,"<HTML><BODY><H2><CENTER>Reapply the Latest Configuration</H2><P>Snare Objectives have been reapplied to the running system.</CENTER></BODY></HTML>",_TRUNCATE);

	// Notify the main thread that we want to reapply config changes
		SetEvent(event);
	//Kill off CollectionThread to help things along.
		//SetEvent(m_hCollectEvent);

    return(0);
}



int ShowLocalUsers(SOCKET http_socket)
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
		if (SNAREDEBUG >= 6) DebugMsg("Maximum password age (d): %d\n", pModBuf->usrmod0_max_passwd_age/86400);
		MaxPwdAge=pModBuf->usrmod0_max_passwd_age;
	} else {
		if (SNAREDEBUG >= 6) DebugMsg("Could not find MaxPasswordAge");
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
			retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
			
			i = p->usri1_next_index;
			p++;  // Step to the next one

			dwEntriesRead--;

		}
		if(pBuf) NetApiBufferFree(pBuf);
	} while(dwReturn == ERROR_MORE_DATA);

	// Send a newline to finish off.
	retval = send(http_socket,"\n",(int)strlen("\n"),0);
	return(0);
}

int ShowDomainUsers(SOCKET http_socket)
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
				if (SNAREDEBUG >= 6) DebugMsg("Could not retrieve DC Role info: %d", netErr);
			}
			if (buf) DsRoleFreeMemory(&buf);
			//ExpandEnvironmentStrings("%USERDOMAIN%",temp, _countof(temp));
			WideCharToMultiByte( CP_ACP, 0,PDC,-1, PDC_cstr, _countof(PDC_cstr), NULL, NULL );
			if (!strlen(temp)) strncpy_s(temp,_countof(temp),PDC_cstr,_TRUNCATE);
			_snprintf_s(temp2,_countof(temp2),_TRUNCATE,"SERVER: %s\n",temp);
			retval = send(http_socket,temp2,(int)strlen(temp2),0);
		} else {
			if(tPrimaryDC) {
				NetApiBufferFree(tPrimaryDC);
			}
			//char temp[256];
			//PDC=NULL;
			//strncpy_s(temp,_countof(temp),"PDC: LOCAL\n",_TRUNCATE);
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
		if (SNAREDEBUG >= 6) DebugMsg("Maximum password age (d): %d\n", pBuf->usrmod0_max_passwd_age/86400);
		MaxPwdAge=pBuf->usrmod0_max_passwd_age;
	} else {
		if (SNAREDEBUG >= 6) DebugMsg("Could not find MaxPasswordAge");
		MaxPwdAge=-1;
	}
	if (pBuf != NULL) NetApiBufferFree(pBuf);

	do {
		PNET_DISPLAY_USER pNDUBuff=NULL;

		// 1 = Users, 2 = Machines, 3 = groups
		nasReturn = NetQueryDisplayInformation(PDC,1,next,10000,MAX_PREFERRED_LENGTH,&dwUsers,(PVOID *)&pNDUBuff);
		
		if(nasReturn == ERROR_ACCESS_DENIED) {
			char temp[256]="Access Denied. Cannot query domain users while SNARE is running with the privileges of the local administrator";
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
		
			retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);

			if(UserInfo) NetApiBufferFree(UserInfo);

			next = p->usri1_next_index;
			p++;

		}

		if (pNDUBuff) NetApiBufferFree(pNDUBuff);

	} while(nasReturn == ERROR_MORE_DATA);


	return(1);
}


int ShowLocalGroupMembers(SOCKET http_socket)
{
	int retval;
	char HTTPBuffer[1024]="";
	char TempBuffer[4096]="";

	DWORD dwEntriesRead=0,dwTotalEntries=0,dwReturn=0;
	char szName[255]="";
	char szComment[255]="";

	if (SNAREDEBUG >= 5) DebugMsg("ShowLocalGroupMembers");
	do {
		GROUP_INFO_1	*GroupInfo=NULL,*GISave=NULL;
		dwReturn = NetLocalGroupEnum( NULL, 1, (LPBYTE *)&GroupInfo, MAX_PREFERRED_LENGTH, 
                &dwEntriesRead,	&dwTotalEntries, NULL );
		GISave=GroupInfo;
		switch (dwReturn) {
			case ERROR_MORE_DATA: DebugMsg("ERROR_MORE_DATA"); break;
			case ERROR_ACCESS_DENIED: DebugMsg("ERROR_ACCESS_DENIED"); break;
			case NERR_Success: DebugMsg("NERR_Success"); break;
			case NERR_InvalidComputer: DebugMsg("NERR_InvalidComputer"); break;
			case NERR_BufTooSmall: DebugMsg("NERR_BufTooSmall"); break;
		}
		if (SNAREDEBUG >= 5) DebugMsg("NetLocalGroupEnum: dwEntriesRead (%d) dwTotalEntries (%d) ", dwEntriesRead, dwTotalEntries);
		if (SNAREDEBUG >= 5) DebugMsg("grabbed list of groups, now checking members");

		while ( dwEntriesRead ) {
			// Convert UniCode to ASCII
			WideCharToMultiByte( CP_ACP, 0,GroupInfo->grpi1_name,-1, szName, _countof(szName)-1, NULL, NULL );
			snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t",szName);
			retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
			
			WideCharToMultiByte( CP_ACP, 0,GroupInfo->grpi1_comment,-1, szComment, _countof(szComment)-1, NULL, NULL );
			if (!strlen(szComment)) strncpy_s(szComment,_countof(szComment),"-",_TRUNCATE);
			snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%s\t",szComment);
			retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);

			//This function will grab the group members
			ShowThisLocalGroupMembers(GroupInfo->grpi1_name,http_socket);
			retval = send(http_socket,"\n",(int)strlen("\n"),0);
			
			GroupInfo += 1;  // Step to the next one

			dwEntriesRead--;

		}
		if(GISave) NetApiBufferFree(GISave);
	} while(dwReturn == ERROR_MORE_DATA);
	if (SNAREDEBUG >= 5) DebugMsg("finished ShowDomainGroupMembers");

	// Send a newline to finish off.
	retval = send(http_socket,"\n",(int)strlen("\n"),0);

	return(0);
}


int ShowDomainGroupMembers(SOCKET http_socket)
{
	int retval;
	char HTTPBuffer[1024]="";

	LPWSTR tPrimaryDC = NULL;
	WCHAR PrimaryDC[256];
	WCHAR *PDC;
	char PDC_cstr[256]="";
	NET_API_STATUS netErr=1;

	if (SNAREDEBUG >= 5) DebugMsg("ShowDomainGroupMembers");
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
				if (SNAREDEBUG >= 6) DebugMsg("Could not retrieve DC Role info: %d", netErr);
			}
			if (buf) DsRoleFreeMemory(&buf);
			//ExpandEnvironmentStrings("%USERDOMAIN%",temp, _countof(temp));
			WideCharToMultiByte( CP_ACP, 0,PDC,-1, PDC_cstr, _countof(PDC_cstr), NULL, NULL );
			if (!strlen(temp)) strncpy_s(temp,_countof(temp),PDC_cstr,_TRUNCATE);
			_snprintf_s(temp2,_countof(temp2),_TRUNCATE,"SERVER: %s\n",temp);
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

	if (SNAREDEBUG >= 5) DebugMsg("Checking version");
	if (SNAREDEBUG >= 5) DebugMsg("Version is 5+");
	// Initialise COM object for grabbing AD groups if available.
	CoInitialize(NULL);

	if (SNAREDEBUG >= 5) DebugMsg("Checking for mixed mode");
	if(ADIsMixedMode()) {
		if (SNAREDEBUG >= 5) DebugMsg("domain is mixed mode");
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
							retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
							
							//WCHAR szName[MAX_PATH];
							//mbstowcs_s(szName,_countof(szName),cszName,_TRUNCATE);
							
							// ShowThisDomainGroupMembers(szName,PDC,http_socket);
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
						if(SNAREDEBUG >= 6) DebugMsg("No user object could be found");
					}
				} else if (0x8007203e==hr) {
					if(SNAREDEBUG >= 6) DebugMsg("Could not execute query. An invalid filter was specified.");
				} else {
					if(SNAREDEBUG >= 6) DebugMsg("Query failed to run. HRESULT: %x",hr);
				}
			} else {
				if(SNAREDEBUG >= 6) DebugMsg("Could not execute query. Could not bind to the container.");
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


			retval = send(http_socket,"\n-\n\n",4,0);

			ShowDomainUserGroupsWin2k(http_socket,PDC_cstr);

		// We're done, so uninitialise the COM interface
		CoUninitialize();

		return(1);
	} else {
		// We're done, so uninitialise the COM interface
		if (SNAREDEBUG >= 5) DebugMsg("domain is NOT mixed mode");

		CoUninitialize();
		// And fall through to normal mode.
	}

	// If we are not in native mode, fall through to normal mode.

	do {
		PNET_DISPLAY_GROUP pNDUBuff=NULL, p;
		if (SNAREDEBUG >= 5) DebugMsg("Starting native check");
		// 1 = Users, 2 = Machines, 3 = groups
		nasReturn = NetQueryDisplayInformation(PDC,3,next,1000,MAX_PREFERRED_LENGTH,&dwGroups,(PVOID*)&pNDUBuff);
		
		if(nasReturn == ERROR_ACCESS_DENIED) {
			char temp[256]="Access Denied. Cannot query domain groups while SNARE is running with the privileges of the local administrator";
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
		
			retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);

			ShowThisDomainGroupMembersNT(p->grpi3_name,PDC,http_socket);
			retval = send(http_socket,"\n",(int)strlen("\n"),0);
			next = p->grpi3_next_index;
			p++;
		}

		if(pNDUBuff) NetApiBufferFree (pNDUBuff);
	} while(nasReturn == ERROR_MORE_DATA);
	return(1);
}


int ShowThisLocalGroupMembers(WCHAR *Group,SOCKET http_socket)
{
	DWORD dwEntriesRead=0,dwTotalEntries=0,dwReturn=0;
	char szName[255]="";
	char Buffer[256]="";
	int first=1;
	int retval;

	if (SNAREDEBUG >= 5) DebugMsg("ShowThisLocalGroupMembers");
	do {
		LOCALGROUP_MEMBERS_INFO_3 *Members=NULL,*MSave=NULL;
		dwReturn = NetLocalGroupGetMembers(NULL, Group, 3,
         (PBYTE*) &Members, MAX_PREFERRED_LENGTH,
         &dwEntriesRead,	&dwTotalEntries, NULL );
		MSave=Members;
		if (SNAREDEBUG >= 5) DebugMsg("grabbed list of users, sending data");
		switch (dwReturn) {
			case ERROR_MORE_DATA: DebugMsg("ERROR_MORE_DATA"); break;
			case ERROR_ACCESS_DENIED: DebugMsg("ERROR_ACCESS_DENIED"); break;
			case NERR_Success: DebugMsg("NERR_Success"); break;
			case NERR_InvalidComputer: DebugMsg("NERR_InvalidComputer"); break;
			case ERROR_NO_SUCH_ALIAS: DebugMsg("ERROR_NO_SUCH_ALIAS"); break;
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

			retval = send(http_socket,Buffer,(int)strlen(Buffer),0);			

			Members += 1;  // Step to the next one

			dwEntriesRead--;

		}
		if(MSave) NetApiBufferFree(MSave);
	} while(dwReturn == ERROR_MORE_DATA);

	if (SNAREDEBUG >= 5) DebugMsg("finished ShowThisLocalGroupMembers");

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
	if (SNAREDEBUG >= 6) DebugMsg("Variant.vt: %d",Variant->vt);
	//if (Variant->vt != 8209) {
	//	if (SNAREDEBUG >= 6) DebugMsg("Unknown Variant type %d.  Time to bail out...",Variant->vt);
	//	return(E_FAIL);
	//}
	
    if (pArrayVal != NULL) {
		ULONG cSize;

		if(!Variant->parray->rgsabound || !pArrayVal->rgsabound) {
			if(SNAREDEBUG >= 6) { DebugMsg("WARNING: Variant array is corrupted. I'm not touching it."); }
			return(E_FAIL);
		}
		try {
			if(SNAREDEBUG >= 6) { DebugMsg("rgsabound is OK: cElements: %il, lLbound: %il", Variant->parray->rgsabound->cElements, Variant->parray->rgsabound->lLbound); }
		} catch(...) {
			if(SNAREDEBUG >= 6) { DebugMsg("CRASH: cSize grab failed. Some null-pointer weirdness going on here."); }
			return(E_FAIL);
		}
		//SAFEARRAYBOUND
		//try {
		//	if(Variant.parray->rgsabound[0] == (SAFEARRAYBOUND)NULL) {
		//		if(SNAREDEBUG >= 6) { DebugMsg("WARNING: Variant array is corrupted. I'm not touching it."); }
		//		return(E_FAIL);
		//	}
		//} catch(...) {
		//	if(SNAREDEBUG >= 6) { DebugMsg("CRASH: rgsabound[0] grab failed. No idea what is going on here."); }
		//	return(E_FAIL);
		//}
		//if(SNAREDEBUG >= 6) { DebugMsg("rgsabound[0] is OK"); }

		// try / catch
		try {
			if (!Variant->parray->rgsabound->cElements && SNAREDEBUG >= 6) { DebugMsg("cSize is going to fail"); } 
			cSize = Variant->parray->rgsabound->cElements;
			if(SNAREDEBUG >= 6) { DebugMsg("csize(ptr) is OK: %d", cSize); }
			if (!pArrayVal->rgsabound[0].cElements && SNAREDEBUG >= 6) { DebugMsg("cSize is going to fail"); } 
			cSize = pArrayVal->rgsabound[0].cElements;
		} catch(...) {
			if(SNAREDEBUG >= 6) { DebugMsg("CRASH: cSize grab failed. Some null-pointer weirdness going on here."); }
			return(E_FAIL);
		}

		if(SNAREDEBUG >= 6) { DebugMsg("csize is OK"); }
		// Just a small 'what the?' check
		if(cSize > 16384 || cSize <= 0) {
			if(SNAREDEBUG >= 6) { DebugMsg("Size: %d is just plain silly. Must be a corruption. Exiting",cSize); }
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
int ShowDomainUserGroupsWin2k(SOCKET http_socket, char *PDC_cstr)
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

	if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Inside ShowDomainUserGroupsWin2k."); }
	
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
		if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Could not open RootDSE."); }
		return(0);
	}

	if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Grabbed RootDSE."); }

	hr = pObject->Get(L"defaultNamingContext",&var);
	if (SUCCEEDED(hr)) {

		if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Grabbed defaultNamingContext."); }

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
			if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Tiny buffer. Out of here."); }
			return(0);
		}
		
		hr = ADsOpenObject(szPath, NULL, NULL,
			ADS_SECURE_AUTHENTICATION, // Use Secure Authentication
			IID_IDirectorySearch, (void**)&pContainerToSearch);
		
		if (SUCCEEDED(hr)) {

			if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Opened object."); }

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
				if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Could not setsearchpreference."); }

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

							if(SNAREDEBUG >= 6) { DebugMsg("Alloc pADsUser"); }

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


								if(SNAREDEBUG >= 6) { DebugMsg("Alloc username"); }
								pADsUser->get_Name(&username);

								// die if username null?
								if(!username) {
									if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Could not get Name."); }
									pADsUser->Release();
									continue;
								}

								snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%S	",username);
								HTTPBufferLen = strlen(HTTPBuffer);

								// Free username here - we don't need it any more.
								if(SNAREDEBUG >= 6) { DebugMsg("Free username"); }
								SysFreeString(username);

								if(SNAREDEBUG >= 6) { DebugMsg("Alloc vTokenGroups?"); }
								// Retreive the token groups array...
								VariantInit(&vTokenGroups);

								hr = ADsBuildVarArrayStr(prop,1,&vTokenGroups);
								if(!SUCCEEDED(hr)) {
									if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Couldnt buildvararraystr."); }
									pADsUser->Release();
									continue;
								}

								hr = pADsUser->GetInfoEx(vTokenGroups, NULL);

								if(SNAREDEBUG >= 6) { DebugMsg("Free vTokenGroups"); }
								VariantClear(&vTokenGroups);
								if(!SUCCEEDED(hr)) {
									if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Couldnt getinfoex."); }
									pADsUser->Release();
									continue;
								}

								if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Getting tokengroups."); }

								if(SNAREDEBUG >= 6) { DebugMsg("Alloc vtokengroups again?"); }
								hr = pADsUser->Get(L"TokenGroups",&vTokenGroups);
								if(!SUCCEEDED(hr)) {
									if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Could not get tokengroups."); }
									pADsUser->Release();
									VariantClear(&vTokenGroups);
									continue;
								}

								// Wander through the TokenGroups with a variant array
								// and loop through the SIDs
								pArray = vTokenGroups.parray;
								SIDCount = pArray->rgsabound->cElements;
								lBound = pArray->rgsabound->lLbound;

								if(SNAREDEBUG >= 6) { DebugMsg("Alloc pArray"); }

								hr = SafeArrayAccessData( pArray, (void HUGEP**)&pVar);
								if(!SUCCEEDED(hr)) {
									if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Couldn't SafeArrayAccessData."); }
									pADsUser->Release();
									VariantClear(&vTokenGroups);
									continue;
								}
								// Grab the sid into pSID (note: allocated by VarToBytes...
								// Don't forget to clear!

								if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: about to loop through sids. lbound is %d nosids is %d",lBound,SIDCount); }
								for( i = lBound; i < SIDCount;i++ ) {

									// if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: looping through sids. lbound is %d nosids is %d, i is %d.",lBound,SIDCount,i); }
								char szName[513]="";
								char szDomain[513]="";

									// Convert the variant containing the SID into an array
									// of bytes so that we can use lookupaccountsid.
									if(SNAREDEBUG >= 6) { DebugMsg("Alloc psid"); }
									hr = VarToBytes(&pVar[i], (LPBYTE *)&pSID, &cbSID);

									if(!SUCCEEDED(hr)) {
										// Break out of here. Something is seriously corrupted in our pVar variables.
										if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: VarToBytes bugged out. The UserName is %S",username); }
										// continue;
										break;
									}

									if(SNAREDEBUG >= 6) { DebugMsg("Attempting sid translation"); }
									// HERE: Translate sid to name.
								    // Some of the MS System calls use by LookupAccountSid are buggy.
									try {
										SID_NAME_USE snu;
										DWORD cbName = 512;
										DWORD cbDomain = 512;
										// if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Trying lookupaccountsid."); }
										LookupAccountSid(NULL, pSID, szName, &cbName, szDomain, &cbDomain, &snu);
									} catch (...) {
										strncpy_s(szName,1,"",_TRUNCATE);
										if(SNAREDEBUG >= 6) { DebugMsg("DGWin2k: Lookupaccountsid barfed."); }
									}

									int szNameLen = strlen(szName);
									if(szNameLen) {
										if (HTTPBufferLen + szNameLen >= UGBUFFER-2) {
											if (trimCN) {
												send(http_socket,&HTTPBuffer[3],HTTPBufferLen-3,0);
												trimCN=0;
											} else {
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
										if(SNAREDEBUG >= 6) { DebugMsg("Releasing pSID"); }
										free(pSID); // VariantArrayToBytes allocates memory using Malloc, must free it
									}

								}

								strncat_s(HTTPBuffer,_countof(HTTPBuffer),"\n",_TRUNCATE);
								HTTPBufferLen++;
								if (trimCN) {
									send(http_socket,&HTTPBuffer[3],HTTPBufferLen-3,0);
									trimCN=0;
								} else {
									send(http_socket,HTTPBuffer,HTTPBufferLen,0);
								}

								// Need to clean up...

								if(SNAREDEBUG >= 6) { DebugMsg("Releasing pArray"); }
								SafeArrayUnaccessData(pArray);

								if(SNAREDEBUG >= 6) { DebugMsg("Releasing vTokenGroups"); }
								VariantClear( &vTokenGroups);


								// Free pADsUser - we don't need it any more.						
								if(SNAREDEBUG >= 6) { DebugMsg("Releasing PADSUser"); }
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
					if(SNAREDEBUG >= 6) DebugMsg("No user object could be found");
				}
			} else if (hr==0x8007203e) {
				if(SNAREDEBUG >= 6) DebugMsg("Could not execute query. An invalid filter was specified.");
			} else {
				if(SNAREDEBUG >= 6) DebugMsg("Query failed to run. HRESULT: %x",hr);
			}
		} else {
			if(SNAREDEBUG >= 6) DebugMsg("Could not execute query. Could not bind to the container.");
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
		
	if (SNAREDEBUG >= 5) DebugMsg("ADIsMixedMode");
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



int ShowThisDomainGroupMembersNT(WCHAR *Group,WCHAR *PDC, SOCKET http_socket)
{
	GROUP_USERS_INFO_0* Members,*MSave;
	DWORD dwEntriesRead=0,dwTotalEntries=0,dwReturn=0;
	char szName[255]="";
	char Buffer[256]="";
	int first=1;
	int retval;

	if (SNAREDEBUG >= 5)DebugMsg("ShowThisDomainGroupMembersNT");
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
// $ expr `./base64 intersect.gif | wc -c` - `./base64 intersect.gif | wc -l` "*" 2 + 1
//   2029
// ./base64 intersect.gif | sed 's/^/   "/' | sed 's/.$/"  \\/' >out.txt
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


   strncpy_s(LogoGif,15000,   "R0lGODlhzAE8AOf/AB0hIyIgIyAhHyQgHyAiICMhJCUhICUhIB8jJSEjICMiJSIkISUjJigmKScp"  \
   "JiooKykrKSwqLS0rLyktLy4sMMsAGswAGywuK8sAIM0AHMwAIc0AIs8AHc8AI84AKS4vNy8wLs4B"  \
   "LjIwMy8zNTIzMS80NjIzOzY0N9AHNTg2OjU5Ozc4QMkQJzs5PDc7PTk6QsoSLT07Pzo+QD89QcsV"  \
   "ND8/SMwYNcsYOkJAQ80ZMM4aNs0bO0FFR80cQUZER8ghOUtJTcolQcwmPMwnQssnR09NUU1OVlFP"  \
   "U84rSc0rTlJQVFNRVVRSVsoxSMkxTsszT8o0VVhWWs01Ucw2Vsc5VVtZXVlaYsk7UMk7Vss9V8w+"  \
   "WMs+XWBeYl5faM1AWslDWGNhZcpFX2NkbWZkaMtHZsxIYcdKYGhmamZncMpNYslNaMtPacpPbshS"  \
   "ZGtsdcdTaW9tcW1ud8pVbG9wecpWcXJwdHFye8habcdacs5adclcdHR1fstedXZ3gMpffMdhdnp4"  \
   "fHl6g8plf3t8hYB+gn5/iMhqgMpqe8psgshsiIGCi8Zvg4OEjYeFichyi8pyhoeHkcd2h4iJkoqL"  \
   "lMl5j4aOlcV8kIqOnY2Ol4iQmMh/kst/jpCQmsqBlMiBmsaDlMSEm8iFl5SUnseGnZKWpcWJmMmI"  \
   "n8WLn8OOmpmao8mNnJ6Zp8iOosePqZefp56eqMaTpZ+fqZygsMaVrMmVp6Giq8KYrcWYqMiXrsaZ"  \
   "qcKcqqSlrsibq8absaOntsWduMqdraeossOgs8ehr6qqtMOiu6erusikuKquva2ut8Snucemv8Op"  \
   "wMaqu62xwbCxusKsvLOwwbC0xMqtv7O0vseuxcWwv7i1xrO3xsWyx7e3wbS4yMizw8O1w8e0ycG2"  \
   "ycW3xcO4zLi8y8i5x729x8a6zsC8zrq+zcO8yLzA0MW+ysK/0MDBy8TA0b7C0cXB07/D08fD1cHF"  \
   "1cTFz8XE3MjE1sLG1sXG0MnF18PH173J18bH0cDJ0cTI2MfI0sjJ0yH+EUNyZWF0ZWQgd2l0aCBH"  \
   "SU1QACwAAAAAzAE8AAAI/gDtCRxIsKDBgwgTKrSHT+C+fPY0mVlDcU2aReX2wQqz5k1FPNYEyltI"  \
   "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"  \
   "+ZQYNQnZjh2jgAAAOw==" ,_TRUNCATE);


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

int Display404(SOCKET http_socket)
{
	char HTTPBuffer[512];
	// Overwrite HTTPBuffer with the header data.
	strncpy_s(HTTPBuffer,_countof(HTTPBuffer), "HTTP/1.0 404 Not Found\r\n" \
						"Server: SNARE/1.0\r\n" \
						"MIME-version: 1.0\r\n" \
						"Content-type: text/html\r\n\r\n" \
						"<html><body><center><h2>Page Not Found</h2></center></body></html>",
			_TRUNCATE);

	return(send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0));
}

int DisplayTextHeader(SOCKET http_socket)
{
	char HTTPBuffer[512];
	if(SNAREDEBUG >= 5) { DebugMsg("DisplayTextHeader"); }
	// Overwrite HTTPBuffer with the header data.
	strncpy_s(HTTPBuffer, _countof(HTTPBuffer), "HTTP/1.0 200 OK\r\n" \
						"Server: SNARE/1.0\r\n" \
						"MIME-version: 1.0\r\n" \
						"Content-type: text/plain\r\n\r\n",
			_TRUNCATE);
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
	if (SNAREDEBUG >=5) DebugMsg("GetUserSid");

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



int DumpRegistry(SOCKET http_socket, char *source, char * Output, int OutputSize) {

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

	DisplayTextHeader(http_socket);

	RegDump(FinalKey,Base,SubKey,http_socket);
	RegCloseKey(FinalKey);
	return(1);
}

// Recursive function
int RegDump(HKEY key, char * rootname, char *path, SOCKET http_socket)
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
				retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
				spos=(char *)value;
				while(*spos) {
					switch(*spos) {
						case '\a':
							send(http_socket," ",(int)strlen(" "),0); break;
						case '\b':
							send(http_socket," ",(int)strlen(" "),0); break;
						case '\f':
							send(http_socket," ",(int)strlen(" "),0); break;
						case '\n':
							send(http_socket," ",(int)strlen(" "),0); break;
						case '\r':
							send(http_socket," ",(int)strlen(" "),0); break;
						case '\t':
							send(http_socket," ",(int)strlen(" "),0); break;
						case '\v':
							send(http_socket," ",(int)strlen(" "),0); break;
						//case '\\':
						//	send(http_socket,"\\\\",(int)strlen("\\\\"),0); break;
						default:
							send(http_socket,spos,1,0); break;
					}
					spos++;
				}
				send(http_socket,"\n",(int)strlen("\n"),0);

				break;
			case REG_DWORD:
				_snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"	DWORD: %s	0x%016x\n",name,*(DWORD *)value);
				retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
				break;
			case REG_BINARY:
				_snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"	BINARY: %s	",name);
				retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
				if(*(DWORD *)value == 0) {
					strncpy_s(HTTPBuffer,_countof(HTTPBuffer),"00000000000000000000000000000000",_TRUNCATE);
				} else {
					_ultoa_s(*(DWORD *)value,HTTPBuffer,_countof(HTTPBuffer),2);
				}
				retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
				retval = send(http_socket,"\n",(int)strlen("\n"),0);
				break;
			default:
				// Assume Hex
				_snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"	OTHER: %s	0x",name);
				retval = send(http_socket,HTTPBuffer,(int)strlen(HTTPBuffer),0);
				spos=(char *)value;
				int hval=0;
				DWORD vcount=0;
				while(vcount < valuelen) {
					hval=*spos;
					_snprintf_s(HTTPBuffer,_countof(HTTPBuffer),_TRUNCATE,"%02x",hval);
					send(http_socket,HTTPBuffer,2,0);
					if(vcount < (valuelen-1)) {
						send(http_socket," ",1,0);
					}

					spos++;
					vcount++;
				}
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
		RegDump(subkey, rootname, subpath, http_socket);
		
		delete [] subpath;

		RegCloseKey(subkey);
	}
	
	delete [] subkeyname;
    delete [] name;
    delete [] value;
	return(1);

}

int Current_Events(char *source, char *dest, int size)
{
	DWORD dwWaitRes=0;
	MsgCache *myMsg=NULL;
	snprintf_s(dest,size,_TRUNCATE,"<HTML><BODY><H2><CENTER>Current Events</H2></CENTER><P><center><br />"
		"<table border=1 cellspacing=0 cellpadding=2 width=\"99%%\" bgcolor=\"white\">\n"
		"<tr bgcolor=\"#ffffcc\"><td>&nbsp;</td><td>Date</td><td>System</td><td>Event Count</td><td>EventID</td>"
		"<td>Source</td><td>UserName</td><td>UserType</td><td>ReturnCode</td><td>Strings</td></tr>\n");
	dwWaitRes = WaitForSingleObject(hMutex,2000);
	if(dwWaitRes == WAIT_OBJECT_0) {
		myMsg = MCHead;
		if(SNAREDEBUG >= 9) { DebugMsg("WebPages: listing events"); }
		for (int i=0; myMsg && myMsg != MCTail && i < 20; myMsg = myMsg->next, i++) {
			if (myMsg->seenflag) {
				if (i%2) snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#FEFEFE>", dest);
				else snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#EEEEEE>", dest);
			} else {
				if (i%2) snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#DDFFDD>", dest);
				else snprintf_s(dest,size,_TRUNCATE,"%s<tr bgcolor=#CCEECC>", dest);
			}
			char event_text[1024] = "";
			escape(myMsg->szTempString, event_text, _countof(event_text) - 3);
			if (strlen(event_text) == _countof(event_text) - 4)
				strcat_s(event_text, _countof(event_text), "...");
			strncat_s(dest,size,"<td>&nbsp;<div style=\"border: 1px solid black; background-color: ",_TRUNCATE);
			switch(myMsg->criticality) {
				case EVENT_CRITICAL:	strncat_s(dest,size,"#FFBBBB",_TRUNCATE); break;
				case EVENT_PRIORITY:	strncat_s(dest,size,"#FFDDBB",_TRUNCATE); break;
				case EVENT_WARNING:		strncat_s(dest,size,"#FFFFBB",_TRUNCATE); break;
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
				myMsg->SnareCounter,
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
		if(SNAREDEBUG >= 5) { DebugMsg("WebPages: Mutex grab failed."); }
		strncat_s(dest,size,"<tr bgcolor=#FEa9a9><td>Failed to grab message pointer</td>",_TRUNCATE);
	}
	strncat_s(dest,size,"</table>",_TRUNCATE);
	snprintf_s(dest,size,_TRUNCATE,"%s</CENTER></BODY></HTML>",dest);
	return(0);
}

int Daily_Events(char *source, char *dest, int size, BOOL at)
{
	FILE * OutputFile=(FILE *)NULL;
	DWORD dwWaitFile=0;
	char filename[1024]="";
	BOOL usefile = FALSE;
	DWORD savedLogs = 0;
	char line[MAX_OUTPUT_STRING];
	char *psource=source, Variable[100]="", Argument[100]="", number_s[100]="", date_s[10]="";
	int numberFrom = 0;
	int numberTo = 0;

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


	return(0);
}

