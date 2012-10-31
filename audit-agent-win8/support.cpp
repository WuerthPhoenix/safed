//#include "stdafx.h"   //Only required for the SNARE GUI
// Let us access the win2k+ apis if required
#define _WIN32_WINNT 0x500
#include <windows.h>
#include <winsvc.h>
#include <aclapi.h>
#include <stdio.h>
#include <process.h>
#include <time.h>

#include "support.h"
#include "LogUtils.h"
#include "RegKeyUtilities.h"


//Note that these functions are self contained, since they will need to be shared
//with the "web server".

//NOTE: Retrun value of 0 = SUCCESS
//		Return value of 1 to 4 = Higher End Registry Read/Write Failure
//		Return value > 4 = Lower End Registry Read/Write Failure
//Also, return values are in binary.

int Read_SysAdmin_Registry(Reg_SysAdmin *pRegistry_struct)
{
	int i_return_val = 0;
	DWORD dw_SysAdminEnable = 0;
	DWORD dw_TimesADay = 1;
	DWORD dw_ForceSysAdmin = 0;
	DWORD dw_VBS = 0;
	DWORD dw_LastSA = 0;

	dw_SysAdminEnable=MyGetProfileDWORD("SysAdmin","SysAdministrators",0);
	dw_TimesADay=MyGetProfileDWORD("SysAdmin","TimesADay",1);
	dw_ForceSysAdmin=MyGetProfileDWORD("SysAdmin","ForceSysAdmin",0);
	dw_VBS=MyGetProfileDWORD("SysAdmin","VBS",0);
	dw_LastSA=MyGetProfileDWORD("SysAdmin","LastSA",0);

	pRegistry_struct->dw_SysAdminEnable = dw_SysAdminEnable;
	pRegistry_struct->dw_TimesADay = dw_TimesADay;
	pRegistry_struct->dw_ForceSysAdmin = dw_ForceSysAdmin;
	pRegistry_struct->dw_VBS = dw_VBS;
	pRegistry_struct->dw_LastSA = dw_LastSA;

	return i_return_val;
}


int Read_Config_Registry(Reg_Config *pRegistry_struct)
{
	char strclientname[SIZE_OF_CLIENTNAME]="";
	char OutputFilePath[SIZE_OF_FILENAME]="";
	char strdelim[3]="";
	int i_return_val = 0;
	DWORD dw_Audit = 1;
	DWORD dw_FileAudit = 1;
	DWORD dw_FileExport = 1;
	DWORD dw_NumberFiles = 0;
	DWORD dw_NumberLogFiles = 0;
	DWORD dw_LogLevel = 1;
	DWORD dw_CritAudit = 1;


	//Defaults to NULL if no hostname found, or key is out of bounds.
	if(!MyGetProfileString("Config","Clientname",strclientname,SIZE_OF_CLIENTNAME)) {
		strncpy_s(pRegistry_struct->str_ClientName,1,"",_TRUNCATE);
		i_return_val += 1;
	} else {
		strncpy_s(pRegistry_struct->str_ClientName,SIZE_OF_CLIENTNAME,strclientname,_TRUNCATE);
	}

	if(!MyGetProfileString("Config","OutputFilePath",OutputFilePath,SIZE_OF_FILENAME)) {
		strncpy_s(pRegistry_struct->str_FileName,1,"",_TRUNCATE);
	} else {
		strncpy_s(pRegistry_struct->str_FileName,SIZE_OF_FILENAME,OutputFilePath,_TRUNCATE);
	}

	if(!MyGetProfileString("Config","Delimiter",strdelim,3)) {
		strncpy_s(pRegistry_struct->str_Delimiter,1,"",_TRUNCATE);
	} else {
		strncpy_s(pRegistry_struct->str_Delimiter,3,strdelim,_TRUNCATE);
	}

	dw_Audit=MyGetProfileDWORD("Config","Audit",1);
	dw_FileAudit=MyGetProfileDWORD("Config","FileAudit",1);
	dw_FileExport=MyGetProfileDWORD("Config","FileExport",0);
	dw_NumberFiles=MyGetProfileDWORD("Config","NumberFiles",2);
	dw_NumberLogFiles=MyGetProfileDWORD("Config","NumberLogFiles",1);
	dw_LogLevel=MyGetProfileDWORD("Config","LogLevel",0);
	dw_CritAudit=MyGetProfileDWORD("Config","CritAudit",0);

	pRegistry_struct->dw_Audit = dw_Audit;
	pRegistry_struct->dw_FileAudit = dw_FileAudit;
	pRegistry_struct->dw_FileExport = dw_FileExport;
	pRegistry_struct->dw_NumberFiles = dw_NumberFiles;
	pRegistry_struct->dw_NumberLogFiles = dw_NumberLogFiles;
	pRegistry_struct->dw_LogLevel = dw_LogLevel;
	pRegistry_struct->dw_CritAudit = dw_CritAudit;

	return i_return_val;
}


int E_Read_Objective_Registry_Str(int i_objective_number, char *str_objective)
{
	HKEY hKey;
	DWORD  dw_objective_bytes = SIZE_OF_AN_OBJECTIVE, dwRegType;
	char objective_buffer[SIZE_OF_AN_OBJECTIVE]="";
	//char str_objective[SIZE_OF_AN_OBJECTIVE]="";
	int o_return_val = 0,i_event_type,i_type = 0,i_event_type_log = 0;
	char str_objective_to_read[20] = ""; 
	char str_temp_pri[4]="",str_temp_evt_type[4]="",str_temp_log_type[4]="",str_temp_eventids[SIZE_OF_EVENTIDMATCH]="";
	char str_temp_usr[SIZE_OF_USERMATCH]="",str_temp_general[SIZE_OF_GENERALMATCH+2]="";
  	char str_temp_event_match_type[SIZE_OF_EVENT_MATCH_TYPE]="";
  	char str_temp_user_match_type[SIZE_OF_USER_MATCH_TYPE]="";
	long error_type=0;

	_snprintf_s(str_objective_to_read,_countof(str_objective_to_read),_TRUNCATE,"EObjective%d",i_objective_number);

	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, E_OBJECTIVE_KEY_NAME, 0, KEY_READ,&hKey ) 
		== ERROR_SUCCESS )	{
		error_type = RegQueryValueEx(hKey, str_objective_to_read, NULL, &dwRegType, 
		     (LPBYTE) objective_buffer, &dw_objective_bytes );
	  if ( error_type == ERROR_SUCCESS ) {
			// Reject any str_objective that is longer than 1056 chars
		  if ((dwRegType == REG_SZ) & (dw_objective_bytes <= SIZE_OF_AN_OBJECTIVE)) {
				strncpy_s( str_objective,dw_objective_bytes,objective_buffer,_TRUNCATE);
		  } else {
				// reject the str_objective and return immediately
			    RegCloseKey(hKey);
				return (o_return_val + 1);
		  }
	  } else {
		  // Retain this error value as 4, since the error control in the other routines
		  // look for errors in the range 1 to 3.
		  RegCloseKey(hKey);
		  return (o_return_val + 4);
	  }

	  // Close the registry key when done
	  RegCloseKey(hKey);
	  
    } else {
	   return (o_return_val + 2);
	}
	return (o_return_val);
}


int Read_Objective_Registry_Str(int i_objective_number, char *str_objective)
{
	HKEY hKey;
	DWORD  dw_objective_bytes = SIZE_OF_AN_OBJECTIVE, dwRegType;
	char objective_buffer[SIZE_OF_AN_OBJECTIVE]="";
	//char str_objective[SIZE_OF_AN_OBJECTIVE]="";
	int o_return_val = 0,i_event_type,i_type = 0,i_event_type_log = 0;
	char str_objective_to_read[20] = ""; 
	char str_temp_pri[4]="",str_temp_evt_type[4]="",str_temp_log_type[4]="",str_temp_eventids[SIZE_OF_EVENTIDMATCH]="";
	char str_temp_usr[SIZE_OF_USERMATCH]="",str_temp_general[SIZE_OF_GENERALMATCH+2]="";
  	char str_temp_event_match_type[SIZE_OF_EVENT_MATCH_TYPE]="";
  	char str_temp_user_match_type[SIZE_OF_USER_MATCH_TYPE]="";
	long error_type=0;

	_snprintf_s(str_objective_to_read,_countof(str_objective_to_read),_TRUNCATE,"Objective%d",i_objective_number);

	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, OBJECTIVE_KEY_NAME, 0, KEY_READ,&hKey ) 
		== ERROR_SUCCESS )	{
		error_type = RegQueryValueEx(hKey, str_objective_to_read, NULL, &dwRegType, 
		     (LPBYTE) objective_buffer, &dw_objective_bytes );
	  if ( error_type == ERROR_SUCCESS ) {
			// Reject any str_objective that is longer than 1056 chars
		  if ((dwRegType == REG_SZ) & (dw_objective_bytes <= SIZE_OF_AN_OBJECTIVE)) {
				strncpy_s( str_objective,dw_objective_bytes,objective_buffer,_TRUNCATE);
		  } else {
				// reject the str_objective and return immediately
			    RegCloseKey(hKey);
				return (o_return_val + 1);
		  }
	  } else {
		  // Retain this error value as 4, since the error control in the other routines
		  // look for errors in the range 1 to 3.
		  RegCloseKey(hKey);
		  return (o_return_val + 4);
	  }

	  // Close the registry key when done
	  RegCloseKey(hKey);
	  
    } else {
	   return (o_return_val + 2);
	}
	return (o_return_val);
}


int Read_Log_Registry_Str(int i_log_number, char *str_log, char *str_sep, int * linecount)
{
	HKEY hKey;
	DWORD  dw_log_bytes = SIZE_OF_LOGNAME, dwRegType;
	char log_buffer[SIZE_OF_LOGNAME]="";
	int o_return_val = 0,multiline=0;
	char str_log_to_read[20] = "";
	long error_type=0;
	char *pos, *pos2, *pos3;

	_snprintf_s(str_log_to_read,_countof(str_log_to_read),_TRUNCATE,"Log%d",i_log_number);

	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, LOG_KEY_NAME, 0, KEY_READ,&hKey ) == ERROR_SUCCESS )	{
		error_type = RegQueryValueEx(hKey, str_log_to_read, NULL, &dwRegType, (LPBYTE) log_buffer, &dw_log_bytes );
		if ( error_type == ERROR_SUCCESS ) {
			// Reject any str_log that is longer than 512 chars
			if ((dwRegType == REG_SZ) & (dw_log_bytes <= SIZE_OF_LOGNAME)) {
				strncpy_s( str_log,dw_log_bytes,log_buffer,_TRUNCATE);
			} else {
				// reject the str_log and return immediately
				return (o_return_val + 1);
			}
		} else {
			// Retain this error value as 4, since the error control in the other routines
			// look for errors in the range 1 to 3.
			return (o_return_val + 4);
		}

		//MULTI
		//check for multiple line configuration
		dw_log_bytes = SIZE_OF_LOGNAME;
		_snprintf_s(str_log_to_read,_countof(str_log_to_read),_TRUNCATE,"LogMulti%d",i_log_number);
		error_type = RegQueryValueEx(hKey, str_log_to_read, NULL, &dwRegType, (LPBYTE) log_buffer, &dw_log_bytes );
		if ( error_type == ERROR_SUCCESS ) {
			//the existance of this setting enables the multiline config
			// Reject any str_log that is longer than 512 chars
			if (dwRegType == REG_DWORD) {
					multiline=ML_FIXED;
					*linecount=MyGetProfileDWORD("Log",str_log_to_read,1);
					if (*linecount <= 1) {
						multiline=0;
						*linecount=0;
						LogExtMsg(WARNING_LOG,"Multiline config error, falling back to normal mode");
					}
			} else if ((dwRegType == REG_SZ) & (dw_log_bytes <= SIZE_OF_SEP)) {
				multiline=ML_SEP;
				if (dw_log_bytes) strncpy_s( str_sep,dw_log_bytes,log_buffer,_TRUNCATE);
			} else {
				multiline=0;
				LogExtMsg(WARNING_LOG,"Multiline config outside expected parameter, falling back to normal mode");
			}
		} else {
			LogExtMsg(WARNING_LOG,"Failed to read multiline config, falling back to normal mode");
		}

		// Close the registry key when done
		RegCloseKey(hKey);
	  
	} else {
	   return (o_return_val + 2);
	}


	return(o_return_val);
}

int Read_Log_Registry(int i_log_number, Reg_Log *pRegistry_struct)
{
	HKEY hKey;
	DWORD  dw_log_bytes = SIZE_OF_LOGNAME, dwRegType;
	char log_buffer[SIZE_OF_LOGNAME]="";
	char str_log[SIZE_OF_LOGNAME]="";
	char str_sep[SIZE_OF_SEP]="";
	int o_return_val = 0,multiline=0,linecount=0;
	char str_log_to_read[20] = "";
	long error_type=0;
	char *pos, *pos2, *pos3;

	_snprintf_s(str_log_to_read,_countof(str_log_to_read),_TRUNCATE,"Log%d",i_log_number);

	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, LOG_KEY_NAME, 0, KEY_READ,&hKey ) == ERROR_SUCCESS )	{
		error_type = RegQueryValueEx(hKey, str_log_to_read, NULL, &dwRegType, (LPBYTE) log_buffer, &dw_log_bytes );
		if ( error_type == ERROR_SUCCESS ) {
			// Reject any str_log that is longer than 512 chars
			if ((dwRegType == REG_SZ) & (dw_log_bytes <= SIZE_OF_LOGNAME)) {
				strncpy_s( str_log,dw_log_bytes,log_buffer,_TRUNCATE);
			} else {
				// reject the str_log and return immediately
				return (o_return_val + 1);
			}
		} else {
			// Retain this error value as 4, since the error control in the other routines
			// look for errors in the range 1 to 3.
			return (o_return_val + 4);
		}
		//MULTI
		//check for multiple line configuration
		dw_log_bytes = SIZE_OF_LOGNAME;
		_snprintf_s(str_log_to_read,_countof(str_log_to_read),_TRUNCATE,"LogMulti%d",i_log_number);
		error_type = RegQueryValueEx(hKey, str_log_to_read, NULL, &dwRegType, (LPBYTE) log_buffer, &dw_log_bytes );
		if ( error_type == ERROR_SUCCESS ) {
			//the existance of this setting enables the multiline config
			// Reject any str_log that is longer than 512 chars
			if (dwRegType == REG_DWORD) {
					multiline=ML_FIXED;
					linecount=MyGetProfileDWORD("Log",str_log_to_read,1);
					if (linecount <= 1) {
						multiline=0;
						linecount=0;
						LogExtMsg(WARNING_LOG,"Multiline config error, falling back to normal mode");
					}
			} else if ((dwRegType == REG_SZ) & (dw_log_bytes <= SIZE_OF_SEP)) {
				char * pos = strstr(log_buffer, "$BYTES");
				if (pos) {
					multiline=ML_BLOCK;
					*pos='\0';
					linecount = atoi(log_buffer);
					if (linecount <= 1) {
						multiline=0;
						linecount=0;
						LogExtMsg(WARNING_LOG,"Multiline config error, falling back to normal mode");
					}
				}else{
					multiline=ML_SEP;
					if (dw_log_bytes) strncpy_s( str_sep,dw_log_bytes,log_buffer,_TRUNCATE);
				}
			} else {
				multiline=0;
				LogExtMsg(WARNING_LOG,"Multiline config outside expected parameter, falling back to normal mode");
			}
		} else {
			LogExtMsg(WARNING_LOG,"Failed to read multiline config, falling back to normal mode");
		}

		// Close the registry key when done
		RegCloseKey(hKey);
	  
	} else {
	   return (o_return_val + 2);
	}

	if (!pRegistry_struct) return(0);
	pRegistry_struct->send_comments=0;
	// Valid formats: logname, logtype|logname, logtype|logname|logformat, logtype|logname|logformat|sendcomment
	pos = strstr(str_log, "|");
	if (!pos) {
		//assume the default Epilog	format
		strncpy_s(pRegistry_struct->type, SIZE_OF_LOGNAME, "GenericLog",_TRUNCATE);
		// Record the name and open the file for reading
		strncpy_s(pRegistry_struct->name, SIZE_OF_LOGNAME, str_log,_TRUNCATE);
		//Set the format to NULL
		strncpy_s(pRegistry_struct->format, SIZE_OF_LOGNAME, "",_TRUNCATE);
	} else {
		pos2 = str_log;
		pos3 = pos + 1;
		*pos='\0';
		strncpy_s(pRegistry_struct->type, SIZE_OF_LOGNAME, pos2,_TRUNCATE);
		pos = strstr(pos3, "|");
		if (!pos) {
			// Record the name and open the file for reading
			strncpy_s(pRegistry_struct->name, SIZE_OF_LOGNAME, pos3,_TRUNCATE);
			//Set the format to NULL
			strncpy_s(pRegistry_struct->format, SIZE_OF_LOGNAME, "",_TRUNCATE);
		} else {
			pos2 = pos + 1;
			*pos='\0';
			// Record the name and open the file for reading
			strncpy_s(pRegistry_struct->name, SIZE_OF_LOGNAME, pos3,_TRUNCATE);
			// check for the send_comments flag
			pos = strstr(pos2, "|");		
			if (pos) {
				pos3 = pos + 1;
				*pos='\0';
				if (!strcmp(pos3,"1")) {
					pRegistry_struct->send_comments=1;
				}
			}
			strncpy_s(pRegistry_struct->format, SIZE_OF_LOGNAME, pos2,_TRUNCATE);
		}
	}
	pRegistry_struct->multiline=multiline;
	pRegistry_struct->log_ml_count=linecount;
	strncpy_s(pRegistry_struct->log_ml_sep, SIZE_OF_SEP, str_sep,_TRUNCATE);

	return(o_return_val);
}





int Read_Objective_Registry(int i_objective_number, Reg_Objective *pRegistry_struct)
{
	HKEY hKey;
	DWORD  dw_objective_bytes = SIZE_OF_AN_OBJECTIVE, dwRegType;
	char objective_buffer[SIZE_OF_AN_OBJECTIVE]="";
	char str_objective[SIZE_OF_AN_OBJECTIVE]="";
	int o_return_val = 0,i_event_type,i_type = 0,i_event_type_log = 0;
	char str_objective_to_read[20] = ""; 
	char str_temp_pri[4]="",str_temp_evt_type[4]="",str_temp_log_type[SIZE_OF_EVENTLOG]="",str_temp_log_type_custom[SIZE_OF_EVENTLOG]="",str_temp_eventids[SIZE_OF_EVENTIDMATCH]="";
	char str_temp_usr[SIZE_OF_USERMATCH]="",str_temp_general[SIZE_OF_GENERALMATCH+2]="";
	char str_temp_general_match_type[SIZE_OF_GENERAL_MATCH_TYPE]="";
  	char str_temp_event_match_type[SIZE_OF_EVENT_MATCH_TYPE]="";
  	char str_temp_user_match_type[SIZE_OF_USER_MATCH_TYPE]="";
	long error_type=0;

	_snprintf_s(str_objective_to_read,_countof(str_objective_to_read),_TRUNCATE,"Objective%d",i_objective_number);

	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, OBJECTIVE_KEY_NAME, 0, KEY_READ,&hKey ) 
		== ERROR_SUCCESS )	{
		error_type = RegQueryValueEx(hKey, str_objective_to_read, NULL, &dwRegType, 
		     (LPBYTE) objective_buffer, &dw_objective_bytes );
	  if ( error_type == ERROR_SUCCESS ) {
			// Reject any str_objective that is longer than 1056 chars
		  if ((dwRegType == REG_SZ) & (dw_objective_bytes <= SIZE_OF_AN_OBJECTIVE)) {
				strncpy_s( str_objective,dw_objective_bytes,objective_buffer,_TRUNCATE);
		  } else {
				// reject the str_objective and return immediately
			    RegCloseKey(hKey);
				return (o_return_val + 1);
		  }
	  } else {
		  // Retain this error value as 4, since the error control in the other routines
		  // look for errors in the range 1 to 3.
		  RegCloseKey(hKey);
		  return (o_return_val + 4);
	  }

	  // Close the registry key when done
	  RegCloseKey(hKey);
	  
    } else {
	   return (o_return_val + 2);
	}
	


	// NOTE: This line is TAB delimited.
	// Note str_general_temp is 514 bytes to allow for the two wildcard characters
	//sscanf_s(str_objective,"%4[^\t]\t%4[^\t]\t%4[^\t]\t%256[^\t]\t%514[^\t]\t%4[^\t]\t%256[^\t]\t%4[^\t]\t%4[^\n]\n",str_temp_pri,_countof(str_temp_pri),str_temp_evt_type,_countof(str_temp_evt_type),str_temp_log_type,_countof(str_temp_log_type),str_temp_eventids,_countof(str_temp_eventids),str_temp_general,_countof(str_temp_general),str_temp_user_match_type,_countof(str_temp_user_match_type),str_temp_usr,_countof(str_temp_usr),str_temp_event_match_type,_countof(str_temp_event_match_type),str_temp_general_match_type,_countof(str_temp_general_match_type));
	sscanf_s(str_objective,"%4[^\t]\t%4[^\t]\t%35[^\t]\t%256[^\t]\t%514[^\t]\t%4[^\t]\t%256[^\t]\t%4[^\t]\t%4[^\n]\n",str_temp_pri,_countof(str_temp_pri),str_temp_evt_type,_countof(str_temp_evt_type),str_temp_log_type,_countof(str_temp_log_type),str_temp_eventids,_countof(str_temp_eventids),str_temp_general,_countof(str_temp_general),str_temp_user_match_type,_countof(str_temp_user_match_type),str_temp_usr,_countof(str_temp_usr),str_temp_event_match_type,_countof(str_temp_event_match_type),str_temp_general_match_type,_countof(str_temp_general_match_type));
	//retrieve custom event log
	char* pos =strstr(str_temp_log_type,"#");
	if(pos){
		if((pos - str_temp_log_type) < strlen(str_temp_log_type)){
			char* tmp = pos + 1;
			char* pos2 =strstr(tmp,"#");
			if(pos2){
				tmp[pos2 - tmp]= '\0';
				strncpy_s(str_temp_log_type_custom,SIZE_OF_EVENTLOG - 4,tmp,_TRUNCATE);
			}
		}
		if((pos - str_temp_log_type) < 4)
			str_temp_log_type[pos - str_temp_log_type]='\0';
		else
			str_temp_log_type[4]='\0';

	}

	strncpy_s(pRegistry_struct->str_eventlog_type_custom,SIZE_OF_EVENTLOG,"",_TRUNCATE);

	// Copy all the values to the struct

	// If the str_objective doesn't contain a valid criticality, assume it is 'clear'
	if (_stricmp(str_temp_pri,"4") == 0) {
		strncpy_s(pRegistry_struct->str_critic,SIZE_OF_CRITICALITY,CRITICAL_TOKEN,_TRUNCATE);
	} else if (_stricmp(str_temp_pri,"3") == 0) {
		strncpy_s(pRegistry_struct->str_critic,SIZE_OF_CRITICALITY,PRIORITY_TOKEN,_TRUNCATE);
	} else if (_stricmp(str_temp_pri,"2") == 0) {
		strncpy_s(pRegistry_struct->str_critic,SIZE_OF_CRITICALITY,WARNING_TOKEN,_TRUNCATE);
	} else if (_stricmp(str_temp_pri,"1") == 0) {
		strncpy_s(pRegistry_struct->str_critic,SIZE_OF_CRITICALITY,INFORMATION_TOKEN,_TRUNCATE);
	} else {
		strncpy_s(pRegistry_struct->str_critic,SIZE_OF_CRITICALITY,CLEAR_TOKEN,_TRUNCATE);
	}


	//If the str_objective doesn't contain a valid event match type, assume it is "0"
	if (_stricmp(str_temp_event_match_type,"1") == 0) {
		strncpy_s(pRegistry_struct->str_event_match_type,SIZE_OF_EVENT_MATCH_TYPE,EXCLUDE,_TRUNCATE);
		pRegistry_struct->dw_event_match_type = 1;
	} else {
		strncpy_s(pRegistry_struct->str_event_match_type,SIZE_OF_EVENT_MATCH_TYPE,INCLUDE,_TRUNCATE);
		pRegistry_struct->dw_event_match_type = 0;
	}

	//If the str_objective doesn't contain a valid general match type, assume it is "0"
	if (_stricmp(str_temp_general_match_type,"1") == 0) {
		strncpy_s(pRegistry_struct->str_general_match_type,SIZE_OF_GENERAL_MATCH_TYPE,EXCLUDE,_TRUNCATE);
		pRegistry_struct->dw_general_match_type = 1;
	} else {
		strncpy_s(pRegistry_struct->str_general_match_type,SIZE_OF_GENERAL_MATCH_TYPE,INCLUDE,_TRUNCATE);
		pRegistry_struct->dw_general_match_type = 0;
	}

	//If the str_objective doesn't contain a valid user match type, assume it is "0"
	if (_stricmp(str_temp_user_match_type,"1") == 0) {
		strncpy_s(pRegistry_struct->str_user_match_type,SIZE_OF_USER_MATCH_TYPE,EXCLUDE,_TRUNCATE);
		pRegistry_struct->dw_user_match_type = 1;
	} else {
		strncpy_s(pRegistry_struct->str_user_match_type,SIZE_OF_USER_MATCH_TYPE,INCLUDE,_TRUNCATE);
		pRegistry_struct->dw_user_match_type = 0;
	}


	//If it doesn't return with a value we can use, reject the str_objective
	i_event_type = atoi(str_temp_evt_type);
	pRegistry_struct->dw_event_type = i_event_type;
	if (i_event_type != 0) {
		if (i_event_type & TYPE_SUCCESS) {
			strncpy_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,SUCCESS_TOKEN,_TRUNCATE);
			i_type = 1;
		}
		if (i_event_type & TYPE_FAILURE)
		{
			if (i_type)	{
				strncat_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,",",_TRUNCATE);
				strncat_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,FAILURE_TOKEN,_TRUNCATE);
			} else {
				strncpy_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,FAILURE_TOKEN,_TRUNCATE);
			}

			i_type = 1;
		}
		if (i_event_type & TYPE_INFO) {
			if (i_type)
			{
				strncat_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,",",_TRUNCATE);
				strncat_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,INFO_TOKEN,_TRUNCATE);
			} else {
				strncpy_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,INFO_TOKEN,_TRUNCATE);
			}
			i_type = 1;
		}
		if (i_event_type & TYPE_WARN)
		{
			if (i_type)
			{
				strncat_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,",",_TRUNCATE);
				strncat_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,WARN_TOKEN,_TRUNCATE);
			} else {
				strncpy_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,WARN_TOKEN,_TRUNCATE);
			}
			i_type = 1;
		}
		if (i_event_type & TYPE_ERROR) {
			if (i_type) {
				strncat_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,",",_TRUNCATE);
				strncat_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,ERROR_TOKEN,_TRUNCATE);
			} else {
				strncpy_s(pRegistry_struct->str_event_type,SIZE_OF_EVENTLOG,ERROR_TOKEN,_TRUNCATE);
			}

			i_type = 1;
		}
		if (i_type == 0) {
			return (o_return_val + 8);
		}
	} else {
		return (o_return_val + 16);
	}


	i_type = 0;

	i_event_type_log = atoi(str_temp_log_type);
	pRegistry_struct->dw_eventlog_type = i_event_type_log;
	if (i_event_type_log != 0)
	{
		if (i_event_type_log & LOG_CUS) {
			strncpy_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,CUSLOG_TOKEN,_TRUNCATE);
			strncpy_s(pRegistry_struct->str_eventlog_type_custom,SIZE_OF_EVENTLOG,str_temp_log_type_custom,_TRUNCATE);
			i_type = 1;
		}
		if (i_event_type_log & LOG_SEC) {
			if (i_type) {
				strncat_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,",",_TRUNCATE);
				strncat_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,SECLOG_TOKEN,_TRUNCATE);
			} else {
				strncpy_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,SECLOG_TOKEN,_TRUNCATE);
			}

			i_type = 1;
		}
		if (i_event_type_log & LOG_SYS) {
			if (i_type) {
				strncat_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,",",_TRUNCATE);
				strncat_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,SYSLOG_TOKEN,_TRUNCATE);
			} else {
				strncpy_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,SYSLOG_TOKEN,_TRUNCATE);
			}

			i_type = 1;
		}
		if (i_event_type_log & LOG_APP) {
			if (i_type) {
				strncat_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,",",_TRUNCATE);
				strncat_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,APPLOG_TOKEN,_TRUNCATE);
			} else {
				strncpy_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,APPLOG_TOKEN,_TRUNCATE);
			}

			i_type = 1;
		}
		if (i_event_type_log & LOG_DIR) {
			if (i_type) {
				strncat_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,",",_TRUNCATE);
				strncat_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,DIRLOG_TOKEN,_TRUNCATE);
			} else {
				strncpy_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,DIRLOG_TOKEN,_TRUNCATE);
			}

			i_type = 1;
		}
		if (i_event_type_log & LOG_DNS) {
			if (i_type) {
				strncat_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,",",_TRUNCATE);
				strncat_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,DNSLOG_TOKEN,_TRUNCATE);
			} else {
				strncpy_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,DNSLOG_TOKEN,_TRUNCATE);
			}

			i_type = 1;
		}
		if (i_event_type_log & LOG_REP) {
			if (i_type) {
				strncat_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,",",_TRUNCATE);
				strncat_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,REPLOG_TOKEN,_TRUNCATE);
			} else {
				strncpy_s(pRegistry_struct->str_eventlog_type,SIZE_OF_EVENTLOG,REPLOG_TOKEN,_TRUNCATE);
			}

			i_type = 1;
		}

		if (i_type == 0) {
			return (o_return_val + 32);
		}
	} else {
		return (o_return_val + 64);
	}

	//if the event id search term is greater than 256 chars, reject the str_objective
	if (strlen(str_temp_eventids) < 257) {
		strncpy_s(pRegistry_struct->str_unformatted_eventid_match,SIZE_OF_EVENTIDMATCH,str_temp_eventids,_TRUNCATE);
		if (_stricmp(str_temp_eventids,LOGON_LOGOFF_EVENTS) == 0)
		{
			strncpy_s(pRegistry_struct->str_eventid_match,SIZE_OF_EVENTIDMATCH,LOGONOFF_TOKEN,_TRUNCATE);
		} else if (_stricmp(str_temp_eventids,RESTART_EVENTS) == 0) {
			strncpy_s(pRegistry_struct->str_eventid_match,SIZE_OF_EVENTIDMATCH,REBOOT_TOKEN,_TRUNCATE);
		} else if (_stricmp(str_temp_eventids,SECURITY_POLICY_EVENTS) == 0) {
			strncpy_s(pRegistry_struct->str_eventid_match,SIZE_OF_EVENTIDMATCH,SECPOL_TOKEN,_TRUNCATE);
		} else if (_stricmp(str_temp_eventids,USER_GROUP_ADMIN_EVENTS) == 0)	{
			strncpy_s(pRegistry_struct->str_eventid_match,SIZE_OF_EVENTIDMATCH,MANAGE_TOKEN,_TRUNCATE);
		} else if (_stricmp(str_temp_eventids,USER_OF_USER_RIGHTS_EVENTS) == 0) {
			strncpy_s(pRegistry_struct->str_eventid_match,SIZE_OF_EVENTIDMATCH,USERRIGHTS_TOKEN,_TRUNCATE);
		} else if (_stricmp(str_temp_eventids,PROCESS_EVENTS) == 0) {
			strncpy_s(pRegistry_struct->str_eventid_match,SIZE_OF_EVENTIDMATCH,PROCESS_TOKEN,_TRUNCATE);
		} else if (_stricmp(str_temp_eventids,FILE_EVENTS) == 0)	{
			strncpy_s(pRegistry_struct->str_eventid_match,SIZE_OF_EVENTIDMATCH,FILE_TOKEN,_TRUNCATE);
		} else  if (_stricmp(str_temp_eventids,FILTERING_EVENTS) == 0)	{
			strncpy_s(pRegistry_struct->str_eventid_match,SIZE_OF_EVENTIDMATCH,FILTERING_TOKEN,_TRUNCATE);
		} else {
			strncpy_s(pRegistry_struct->str_eventid_match,SIZE_OF_EVENTIDMATCH,str_temp_eventids,_TRUNCATE);
		}
	} else {
		return (o_return_val + 128);
	}

	// if the user search term is greater than 256 chars, reject the str_objective
	if (_countof(str_temp_usr) < 257) {
		strncpy_s(pRegistry_struct->str_user_match,SIZE_OF_USERMATCH,str_temp_usr,_TRUNCATE);
	} else {
		return (o_return_val + 256);
	}

	// Remove the wildcard characters from the generla match temp string
	remove_wildcard_start_and_end(str_temp_general,pRegistry_struct->str_general_match,SIZE_OF_GENERALMATCH);

	// if the general search term is greater than 512 chars, reject the str_objective
	// Note that the statements below won't do much since the struct var should have been
	// throttled by the function to remove the wildcard chars
	// if (_countof(pRegistry_struct->str_general_match) < 513)
	//  strncpy_s(pRegistry_struct->str_general_match,SIZE_OF_GENERALMATCH,str_temp_general,_TRUNCATE);
	// else
	//  return (i_return_val += 512);

	return(o_return_val);
}

int Read_Network_Registry(Reg_Network *pRegistry_struct)
{
	char str_destination[SIZE_OF_DESTINATION] = "127.0.0.1";
	DWORD dw_DestPort = 6161;
	DWORD dw_SocketType = SOCKETTYPE_UDP; // UDP
	DWORD dw_MaxMsgSize = MAXMSGSIZE;
	DWORD dw_Syslog = 1, dw_Syslog_buffer = 1, dw_DynamicCritic = 0;
	DWORD dw_Syslog_Dest = 13, dw_Syslog_Dest_buffer = 13;
	int i_return_val = 0;
  

	if(!MyGetProfileString("Network","Destination",str_destination,SIZE_OF_DESTINATION)) {
		strncpy_s(str_destination,SIZE_OF_DESTINATION,"127.0.0.1",_TRUNCATE);
		i_return_val += 1;
	}

	dw_Syslog_Dest=MyGetProfileDWORD("Network","SyslogDest",13);
	dw_Syslog=MyGetProfileDWORD("Network","Syslog",0);
	dw_DestPort=MyGetProfileDWORD("Network","DestPort",6161);
	dw_SocketType=MyGetProfileDWORD("Network","SocketType",SOCKETTYPE_UDP);
	dw_MaxMsgSize=MyGetProfileDWORD("Network","MaxMessageSize",MAXMSGSIZE);
	dw_DynamicCritic=MyGetProfileDWORD("Network","SyslogDynamicCritic",0);
	
	if(dw_DestPort > 65535 || dw_DestPort < 1) {
		dw_DestPort = 6161;
		i_return_val += 4;
	}

	// Write the values to the struct
	strncpy_s( pRegistry_struct->str_Destination,SIZE_OF_DESTINATION,str_destination,_TRUNCATE);
	pRegistry_struct->dw_SocketType = dw_SocketType;
	pRegistry_struct->dw_SyslogDest = dw_Syslog_Dest;
	pRegistry_struct->dw_DynamicCritic = dw_DynamicCritic;
	pRegistry_struct->dw_MaxMsgSize = dw_MaxMsgSize;
	pRegistry_struct->dw_Syslog = dw_Syslog;
	pRegistry_struct->dw_DestPort = dw_DestPort;
	return i_return_val;
}

int Read_Remote_Registry(Reg_Remote *pRegistry_struct)
{
	char str_restrictip[SIZE_OF_RESTRICTIP] = "127.0.0.1";
	char str_password[SIZE_OF_PASSWORD] = "password";
	DWORD dw_webport = 6161, dw_webport_buffer = 6161;
	DWORD dw_allow = 0, dw_allow_buffer = 0, dw_password = 0, dw_tls = 0;
	DWORD dw_restrict = 0, dw_restrict_buffer = 0;
	DWORD dw_webportchange = 0, dw_webportchange_buffer = 0;
	int i_return_val = 0;
    
	if(!MyGetProfileString("Remote","RestrictIP",str_restrictip,SIZE_OF_RESTRICTIP)) {
		strncpy_s(str_restrictip,SIZE_OF_RESTRICTIP,"127.0.0.1",_TRUNCATE);
		i_return_val += 1;
	}

	dw_allow=MyGetProfileDWORD("Remote","Allow",0);
	dw_password=MyGetProfileDWORD("Remote","AccessKey",0);
	dw_webport=MyGetProfileDWORD("Remote","WebPort",6161);
	
	if(dw_webport > 65535 || dw_webport < 1) {
		dw_webport = 6161;
		i_return_val += 2;
	}
	
	dw_restrict=MyGetProfileDWORD("Remote","Restrict",1);
	dw_webportchange=MyGetProfileDWORD("Remote","WebPortChange",0);
	dw_tls=MyGetProfileDWORD("Remote","TLS",0);

	if(!MyGetProfileString("Remote","AccessKeySet",str_password,SIZE_OF_PASSWORD)) {
		strncpy_s(str_password,SIZE_OF_PASSWORD,"",_TRUNCATE);
		i_return_val += 4;
	}

	   
   // Copy all the values into the structure
   strncpy_s( pRegistry_struct->str_Password,SIZE_OF_PASSWORD,str_password,_TRUNCATE);
   strncpy_s( pRegistry_struct->str_RestrictIP,SIZE_OF_RESTRICTIP,str_restrictip,_TRUNCATE);
   pRegistry_struct->dw_Restrict = dw_restrict;
   pRegistry_struct->dw_WebPortChange = dw_webportchange;
   pRegistry_struct->dw_Allow = dw_allow;
   pRegistry_struct->dw_TLS = dw_tls;
   pRegistry_struct->dw_WebPort = dw_webport;
   pRegistry_struct->dw_Password = dw_password;

   // Return the error code
   return i_return_val;
}




int Write_SysAdmin_Registry(Reg_SysAdmin *pRegistry_struct)
{
	HKEY hKey;
	DWORD dwDisp, dwBytesReturned = 100; 
	int i_return_val = 0;
    
	// Open the registry key for ALL access. 
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, SYS_ADMIN_KEY_NAME, 0, KEY_ALL_ACCESS,&hKey ) 
		!= ERROR_SUCCESS )
	{
		// The registry key does not exist and was thus unable to be opened.
		// Try and create it.
		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, SYS_ADMIN_KEY_NAME,0,REG_NONE,
					       REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,
						   NULL,&hKey,&dwDisp) != ERROR_SUCCESS) {
			// The registry key was unable to be created. Return.
			i_return_val += 2;
			return i_return_val;
		}
	}
		


	
	if ((pRegistry_struct->dw_SysAdminEnable < 0) | (pRegistry_struct->dw_SysAdminEnable > 1))
		pRegistry_struct->dw_SysAdminEnable = 0;
	if ( RegSetValueEx(hKey, "SysAdministrators",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_SysAdminEnable,
			  sizeof(pRegistry_struct->dw_SysAdminEnable))
			  != ERROR_SUCCESS )
		i_return_val += 4;

	if (pRegistry_struct->dw_TimesADay < 0)
		pRegistry_struct->dw_TimesADay = 1;
	if ( RegSetValueEx(hKey, "TimesADay",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_TimesADay,
			  sizeof(pRegistry_struct->dw_TimesADay))
			  != ERROR_SUCCESS ) 
		i_return_val += 8;

	if ((pRegistry_struct->dw_ForceSysAdmin < 0) | (pRegistry_struct->dw_ForceSysAdmin > 1))
		pRegistry_struct->dw_ForceSysAdmin = 0;
	if(pRegistry_struct->dw_ForceSysAdmin)
		if ( RegSetValueEx(hKey, "ForceSysAdmin",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_ForceSysAdmin,
			  sizeof(pRegistry_struct->dw_ForceSysAdmin))
			  != ERROR_SUCCESS )
		i_return_val += 16;

	if ((pRegistry_struct->dw_VBS < 0) | (pRegistry_struct->dw_VBS > 1))
		pRegistry_struct->dw_VBS = 0;
	if ( RegSetValueEx(hKey, "VBS",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_VBS,
			  sizeof(pRegistry_struct->dw_VBS))
			  != ERROR_SUCCESS )
		i_return_val += 32;

	if ((pRegistry_struct->dw_LastSA < 0) | (pRegistry_struct->dw_LastSA > 1))
		pRegistry_struct->dw_LastSA = 0;
	if ( RegSetValueEx(hKey, "LastSA",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_LastSA,
			  sizeof(pRegistry_struct->dw_LastSA))
			  != ERROR_SUCCESS )
		i_return_val += 64;
	

	
	//Close the registry key when done
	RegCloseKey(hKey);

	return i_return_val;
}



int Write_Config_Registry(Reg_Config *pRegistry_struct)
{
	HKEY hKey;
	DWORD dwDisp, dwBytesReturned = 100; 
	int i_return_val = 0;
	char str_clientnamebuffer[SIZE_OF_CLIENTNAME]="";
    
	// Open the registry key for ALL access. 
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, CONFIG_KEY_NAME, 0, KEY_ALL_ACCESS,&hKey ) 
		!= ERROR_SUCCESS )
	{
		// The registry key does not exist and was thus unable to be opened.
		// Try and create it.
		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, CONFIG_KEY_NAME,0,REG_NONE,
					       REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,
						   NULL,&hKey,&dwDisp) != ERROR_SUCCESS) {
			// The registry key was unable to be created. Return.
			i_return_val += 2;
			return i_return_val;
		}
	}
		
	// Now attempt to set the registry values

	// No error checking required on this Reg Value
	strncpy_s(str_clientnamebuffer,SIZE_OF_CLIENTNAME,pRegistry_struct->str_ClientName,_TRUNCATE);
	if ( RegSetValueEx(hKey, "Clientname",0,REG_SZ,
			  (CONST BYTE *) str_clientnamebuffer,(DWORD)strlen(str_clientnamebuffer)) 
			  != ERROR_SUCCESS ) {
		i_return_val += 4;
	}
				
	// If Audit is out of bounds, then it becomes 1
	if ((pRegistry_struct->dw_Audit < 0) | (pRegistry_struct->dw_Audit > 1)) {
		pRegistry_struct->dw_Audit = 1;
	}
	if ( RegSetValueEx(hKey, "Audit",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_Audit,
			  sizeof(pRegistry_struct->dw_Audit))
			  != ERROR_SUCCESS ) {
		i_return_val += 8;
	}

	// If FileAudit is out of bounds, then it becomes 1
	if ((pRegistry_struct->dw_FileAudit < 0) | (pRegistry_struct->dw_FileAudit > 1))
		pRegistry_struct->dw_FileAudit = 1;
	if ( RegSetValueEx(hKey, "FileAudit",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_FileAudit,
			  sizeof(pRegistry_struct->dw_FileAudit))
			  != ERROR_SUCCESS )
		i_return_val += 16;

	//If FileExport is out of bounds, then it becomes 0
	if ((pRegistry_struct->dw_FileExport < 0) | (pRegistry_struct->dw_FileExport > 1))
		pRegistry_struct->dw_FileExport = 0;
	if ( RegSetValueEx(hKey, "FileExport",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_FileExport,
			  sizeof(pRegistry_struct->dw_FileExport))
			  != ERROR_SUCCESS )
		i_return_val += 16;

	if (pRegistry_struct->dw_NumberFiles < 0)
		pRegistry_struct->dw_NumberFiles = 2;
	if ( RegSetValueEx(hKey, "NumberFiles",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_NumberFiles,
			  sizeof(pRegistry_struct->dw_NumberFiles))
			  != ERROR_SUCCESS ) 
		i_return_val += 16;

	if (pRegistry_struct->dw_NumberLogFiles < 1)
		pRegistry_struct->dw_NumberLogFiles = 1;
	if ( RegSetValueEx(hKey, "NumberLogFiles",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_NumberLogFiles,
			  sizeof(pRegistry_struct->dw_NumberLogFiles))
			  != ERROR_SUCCESS ) 
		i_return_val += 128;

	if (pRegistry_struct->dw_LogLevel < 0)
		pRegistry_struct->dw_LogLevel = 0;
	if ( RegSetValueEx(hKey, "LogLevel",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_LogLevel,
			  sizeof(pRegistry_struct->dw_LogLevel))
			  != ERROR_SUCCESS ) 
		i_return_val += 256;

	
	//If CritAudit is out of bounds, then it becomes 0
	if ((pRegistry_struct->dw_CritAudit < 0) | (pRegistry_struct->dw_CritAudit > 1))
		pRegistry_struct->dw_CritAudit = 0;
	if ( RegSetValueEx(hKey, "CritAudit",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_CritAudit,
			  sizeof(pRegistry_struct->dw_CritAudit))
			  != ERROR_SUCCESS )
		i_return_val += 32;


	
	//Close the registry key when done
	RegCloseKey(hKey);

	return i_return_val;
}

int Write_Network_Registry(Reg_Network *pRegistry_struct)
{
	HKEY hKey;
	DWORD dwDisp, dwBytesReturned = 100; 
	int i_return_val = 0;
	char str_destination[SIZE_OF_DESTINATION]="";
    
	// Open the registry key for ALL access. 
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_KEY_NAME, 0, KEY_ALL_ACCESS,&hKey ) 
		!= ERROR_SUCCESS )
	{
		// The registry key does not exist and was thus unable to be opened.
		// Try and create it.
		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, NETWORK_KEY_NAME,0,REG_NONE,
					       REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,
						   NULL,&hKey,&dwDisp) != ERROR_SUCCESS)
		{
		//The registry key was unable to be created. Return.
			i_return_val ++;
			return i_return_val;
		}
	}
		
	// Now attempt to set the registry values

	// No error checking required on this Reg Value
	strncpy_s(str_destination,SIZE_OF_DESTINATION,pRegistry_struct->str_Destination,_TRUNCATE);
	if ( RegSetValueEx(hKey, "Destination",0,REG_SZ,
			  (CONST BYTE *) str_destination,(DWORD)strlen(str_destination)) 
			  != ERROR_SUCCESS ) {
		i_return_val ++;
	}
		
	// If DestPort is out of bounds, then it becomes 6161
	if ((pRegistry_struct->dw_DestPort < 1) | (pRegistry_struct->dw_DestPort > 65535)) {
		pRegistry_struct->dw_DestPort = 6161;
	}

	if ( RegSetValueEx(hKey, "DestPort",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_DestPort,
			  sizeof(pRegistry_struct->dw_DestPort))
			  != ERROR_SUCCESS ) {
		i_return_val ++;
	}

	if ( RegSetValueEx(hKey, "SocketType",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_SocketType,
			  sizeof(pRegistry_struct->dw_DestPort))
			  != ERROR_SUCCESS ) {
		i_return_val ++;
	}

	if (pRegistry_struct->dw_MaxMsgSize < 0) {
		pRegistry_struct->dw_MaxMsgSize = 2048;
	}
	if ( RegSetValueEx(hKey, "MaxMessageSize",0,REG_DWORD,
		(CONST BYTE *) &pRegistry_struct->dw_MaxMsgSize,
			  sizeof(pRegistry_struct->dw_MaxMsgSize))
			  != ERROR_SUCCESS ) 
		i_return_val ++;

	// If Syslog is out of bounds, then it becomes 1
	if ((pRegistry_struct->dw_Syslog < 0) | (pRegistry_struct->dw_Syslog > 1)) {
		pRegistry_struct->dw_Syslog = 1;
	}
	if ( RegSetValueEx(hKey, "Syslog",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_Syslog,
			  sizeof(pRegistry_struct->dw_Syslog))
			  != ERROR_SUCCESS ) {
		i_return_val ++;
	}

	// No error checking for the Syslog catgeory and criticality
	if ( RegSetValueEx(hKey, "SyslogDest",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_SyslogDest,
			  sizeof(pRegistry_struct->dw_SyslogDest))
			  != ERROR_SUCCESS ) {
		i_return_val ++;
	}

	if ( RegSetValueEx(hKey, "SyslogDynamicCritic",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_DynamicCritic,
			  sizeof(pRegistry_struct->dw_DynamicCritic))
			  != ERROR_SUCCESS ) {
		i_return_val ++;
	}


	// Close the registry key when done
	RegCloseKey(hKey);

	return i_return_val;
}


int Write_Remote_Registry(Reg_Remote *pRegistry_struct)
{
	HKEY hKey;
	DWORD dwDisp, dwBytesReturned = 100; 
	int i_return_val = 0;
	char str_restrictip[SIZE_OF_RESTRICTIP]="";
	char str_password[SIZE_OF_PASSWORD]="";
    
	//Open the registry key for ALL access. 
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, REMOTE_KEY_NAME, 0, KEY_ALL_ACCESS,&hKey ) 
		!= ERROR_SUCCESS )
	{
		//The registry key does not exist and was thus unable to be opened.
		//Try and create it.
		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, REMOTE_KEY_NAME,0,REG_NONE,
					       REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,
						   NULL,&hKey,&dwDisp) != ERROR_SUCCESS)
		{
			//The registry key was unable to be created. Return.
			i_return_val += 2;
			return i_return_val;
		}
	}
		
	//Now attempt to set the registry values

	//No error checking required on this Reg Value
	strncpy_s(str_restrictip,SIZE_OF_RESTRICTIP,pRegistry_struct->str_RestrictIP,_TRUNCATE);
	if ( RegSetValueEx(hKey, "RestrictIP",0,REG_SZ,
			  (CONST BYTE *) str_restrictip,(DWORD)strlen(str_restrictip)) 
			  != ERROR_SUCCESS ) {
		i_return_val += 4;
	}
		
	//If WebPort is out of bounds, then it becomes 6161
	if ((pRegistry_struct->dw_WebPort < 1) | (pRegistry_struct->dw_WebPort > 65535)) {
		pRegistry_struct->dw_WebPort = 6161;
	}

	if ( RegSetValueEx(hKey, "WebPort",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_WebPort,
			  sizeof(pRegistry_struct->dw_WebPort))
			  != ERROR_SUCCESS ) {
		i_return_val += 8;
	}

	//If Allow is out of bounds, then it becomes 0, the default
	if ((pRegistry_struct->dw_Allow < 0) | (pRegistry_struct->dw_Allow > 1)) {
		pRegistry_struct->dw_Allow = 0;
	}

	if ( RegSetValueEx(hKey, "Allow",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_Allow,
			  sizeof(pRegistry_struct->dw_Allow))
			  != ERROR_SUCCESS ) {
		i_return_val += 16;
	}

	//If Password is out of bounds, then it becomes 0, the default
	if ((pRegistry_struct->dw_Password < 0) | (pRegistry_struct->dw_Password > 1)) {
		pRegistry_struct->dw_Password = 0;
	}

	if ( RegSetValueEx(hKey, "AccessKey",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_Password,
			  sizeof(pRegistry_struct->dw_Password))
			  != ERROR_SUCCESS ) {
		i_return_val += 256;
	}


	//If Restrict is out of bounds, then it becomes 0, the default
	if ((pRegistry_struct->dw_Restrict < 0) | (pRegistry_struct->dw_Restrict > 1)) {
		pRegistry_struct->dw_Restrict = 0;
	}

	if ( RegSetValueEx(hKey, "Restrict",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_Restrict,
			  sizeof(pRegistry_struct->dw_Restrict))
			  != ERROR_SUCCESS )
		i_return_val += 32;

	//If WebPortChange is out of bounds, then it becomes 0, the default
	if ((pRegistry_struct->dw_WebPortChange < 0) | (pRegistry_struct->dw_WebPortChange > 1))
		pRegistry_struct->dw_WebPortChange = 0;

	if ( RegSetValueEx(hKey, "WebPortChange",0,REG_DWORD,
			  (CONST BYTE *) &pRegistry_struct->dw_WebPortChange,
			  sizeof(pRegistry_struct->dw_WebPortChange))
			  != ERROR_SUCCESS )
		i_return_val += 64;
		
	//No error checking required on this Reg Value
	strncpy_s(str_password,SIZE_OF_PASSWORD,pRegistry_struct->str_Password,_TRUNCATE);
	if ( RegSetValueEx(hKey, "AccessKeySet",0,REG_SZ,
			  (CONST BYTE *) str_password,(DWORD)strlen(str_password)) 
			  != ERROR_SUCCESS )
		i_return_val += 128;

	if ( RegSetValueEx(hKey, "TLS",0,REG_DWORD,
		  (CONST BYTE *) &pRegistry_struct->dw_TLS,
		  sizeof(pRegistry_struct->dw_TLS))
		  != ERROR_SUCCESS )
	i_return_val += 512;

	//Close the registry key when done
	RegCloseKey(hKey);

	return i_return_val;
}


int Write_Objective_Registry(int i_objective_number, Reg_Objective *pRegistry_struct)
{
	HKEY hKey;
	DWORD dwDisp, dwBytesReturned = 100,i_AlertType = 0,i_EventType = 0;
	DWORD i_EventLogType = 0;
	int i_return_val = 0;
	char str_UserMatch[SIZE_OF_USERMATCH]="", str_EventIDMatch[SIZE_OF_EVENTIDMATCH]="";
	char str_GeneralMatch[SIZE_OF_GENERALMATCH],str_Alert[2] = "1";
	char str_event_log[SIZE_OF_EVENTLOG]="",str_event_log_custom[SIZE_OF_EVENTLOG]="",str_event_type[SIZE_OF_EVENTLOG]="";
	char str_objective[SIZE_OF_AN_OBJECTIVE] = "";
	char str_objective_to_read[20] = "Objective"; 
	char str_user_match_type[SIZE_OF_USER_MATCH_TYPE];
	char str_event_match_type[SIZE_OF_EVENT_MATCH_TYPE];
	char str_general_match_type[SIZE_OF_GENERAL_MATCH_TYPE];
	char str_GeneralMatchPlusTwo[SIZE_OF_GENERALMATCH+2];
	int custom=0;


	_snprintf_s(str_objective_to_read,_countof(str_objective_to_read),_TRUNCATE,"Objective%d",i_objective_number);

	//Attempt to set the registry values
		if (_stricmp(pRegistry_struct->str_critic,CRITICAL_TOKEN) == 0)
			strncpy_s(str_Alert,_countof(str_Alert),"4",_TRUNCATE);
		else if (_stricmp(pRegistry_struct->str_critic,PRIORITY_TOKEN) == 0)
			strncpy_s(str_Alert,_countof(str_Alert),"3",_TRUNCATE);
		else if (_stricmp(pRegistry_struct->str_critic,WARNING_TOKEN) == 0)
			strncpy_s(str_Alert,_countof(str_Alert),"2",_TRUNCATE);
		else if (_stricmp(pRegistry_struct->str_critic,INFORMATION_TOKEN) == 0)
			strncpy_s(str_Alert,_countof(str_Alert),"1",_TRUNCATE);
		else 
			strncpy_s(str_Alert,_countof(str_Alert),"0",_TRUNCATE);

		if (strstr(pRegistry_struct->str_event_type,SUCCESS_TOKEN) != NULL)
			i_EventType += TYPE_SUCCESS;
		if (strstr(pRegistry_struct->str_event_type,FAILURE_TOKEN) != NULL)
			i_EventType += TYPE_FAILURE;
		if (strstr(pRegistry_struct->str_event_type,INFO_TOKEN) != NULL)
			i_EventType += TYPE_INFO;
		if (strstr(pRegistry_struct->str_event_type,WARN_TOKEN) != NULL)
			i_EventType += TYPE_WARN;
		if (strstr(pRegistry_struct->str_event_type,ERROR_TOKEN) != NULL)
			i_EventType += TYPE_ERROR;
		_itoa_s(i_EventType,str_event_type,10);

		if (strstr(pRegistry_struct->str_eventlog_type,CUSLOG_TOKEN) != NULL){
			i_EventLogType += LOG_CUS;		
			strncpy_s(str_event_log_custom,_countof(str_event_log_custom),"#",_TRUNCATE);
			strncat_s(str_event_log_custom,_countof(str_event_log_custom),pRegistry_struct->str_eventlog_type_custom,_TRUNCATE);
			strncat_s(str_event_log_custom,_countof(str_event_log_custom),"#",_TRUNCATE);
		}
		if (strstr(pRegistry_struct->str_eventlog_type,SECLOG_TOKEN) != NULL)
			i_EventLogType += LOG_SEC;
		if (strstr(pRegistry_struct->str_eventlog_type,SYSLOG_TOKEN) != NULL)
			i_EventLogType += LOG_SYS;
		if (strstr(pRegistry_struct->str_eventlog_type,APPLOG_TOKEN) != NULL)
			i_EventLogType += LOG_APP;
		if (strstr(pRegistry_struct->str_eventlog_type,DIRLOG_TOKEN) != NULL)
			i_EventLogType += LOG_DIR;
		if (strstr(pRegistry_struct->str_eventlog_type,DNSLOG_TOKEN) != NULL)
			i_EventLogType += LOG_DNS;
		if (strstr(pRegistry_struct->str_eventlog_type,REPLOG_TOKEN) != NULL)
			i_EventLogType += LOG_REP;
		_itoa_s(i_EventLogType,str_event_log,10);

		if (strstr(pRegistry_struct->str_user_match_type,EXCLUDE) != NULL)
			strncpy_s(str_user_match_type,SIZE_OF_USER_MATCH_TYPE,"1",_TRUNCATE);
		else
			strncpy_s(str_user_match_type,SIZE_OF_USER_MATCH_TYPE,"0",_TRUNCATE);

		if (strstr(pRegistry_struct->str_event_match_type,EXCLUDE) != NULL)
			strncpy_s(str_event_match_type,SIZE_OF_EVENT_MATCH_TYPE,"1",_TRUNCATE);
		else
			strncpy_s(str_event_match_type,SIZE_OF_EVENT_MATCH_TYPE,"0",_TRUNCATE);

		if (strstr(pRegistry_struct->str_general_match_type,EXCLUDE) != NULL)
			strncpy_s(str_general_match_type,SIZE_OF_GENERAL_MATCH_TYPE,"1",_TRUNCATE);
		else
			strncpy_s(str_general_match_type,SIZE_OF_GENERAL_MATCH_TYPE,"0",_TRUNCATE);


		if (_stricmp(pRegistry_struct->str_eventid_match,LOGONOFF_TOKEN) == 0)
			strncpy_s(str_EventIDMatch,SIZE_OF_EVENTIDMATCH,LOGON_LOGOFF_EVENTS,_TRUNCATE);
		else if (_stricmp(pRegistry_struct->str_eventid_match,FILE_TOKEN) == 0)
			strncpy_s(str_EventIDMatch,SIZE_OF_EVENTIDMATCH,FILE_EVENTS,_TRUNCATE);
		else if (_stricmp(pRegistry_struct->str_eventid_match,FILTERING_TOKEN) == 0)
			strncpy_s(str_EventIDMatch,SIZE_OF_EVENTIDMATCH,FILTERING_EVENTS,_TRUNCATE);
		else if (_stricmp(pRegistry_struct->str_eventid_match,PROCESS_TOKEN) == 0)
			strncpy_s(str_EventIDMatch,SIZE_OF_EVENTIDMATCH,PROCESS_EVENTS,_TRUNCATE);
		else if (_stricmp(pRegistry_struct->str_eventid_match,USERRIGHTS_TOKEN) == 0)
			strncpy_s(str_EventIDMatch,SIZE_OF_EVENTIDMATCH,USER_OF_USER_RIGHTS_EVENTS,_TRUNCATE);
		else if (_stricmp(pRegistry_struct->str_eventid_match,MANAGE_TOKEN) == 0)
			strncpy_s(str_EventIDMatch,SIZE_OF_EVENTIDMATCH,USER_GROUP_ADMIN_EVENTS,_TRUNCATE);
		else if (_stricmp(pRegistry_struct->str_eventid_match,SECPOL_TOKEN) == 0)
			strncpy_s(str_EventIDMatch,SIZE_OF_EVENTIDMATCH,SECURITY_POLICY_EVENTS,_TRUNCATE);
		else if (_stricmp(pRegistry_struct->str_eventid_match,REBOOT_TOKEN) == 0)
			strncpy_s(str_EventIDMatch,SIZE_OF_EVENTIDMATCH,RESTART_EVENTS,_TRUNCATE);
		else {
			if(strlen(pRegistry_struct->str_eventid_match) == 0) {
				strncpy_s(str_EventIDMatch,SIZE_OF_EVENTIDMATCH,"*",_TRUNCATE);
			} else {
				// Need to make sure the length is limited
				strncpy_s(str_EventIDMatch,SIZE_OF_EVENTIDMATCH,pRegistry_struct->str_eventid_match,_TRUNCATE);
			}
			
		}
		

		//Need to make sure the length is limited
		strncpy_s(str_UserMatch,SIZE_OF_USERMATCH,pRegistry_struct->str_user_match,_TRUNCATE);

		//Need to make sure the length is limited
		strncpy_s(str_GeneralMatch,SIZE_OF_GENERALMATCH,pRegistry_struct->str_general_match,_TRUNCATE);

		//This is to add a "*" character to the start and end of the general string
		add_wildcard_start_and_end(str_GeneralMatch,str_GeneralMatchPlusTwo,SIZE_OF_GENERALMATCH+2);
		
		//form the str_objective
		strncpy_s(str_objective,_countof(str_objective),str_Alert,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),OBJECTIVE_DELIMITER,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),str_event_type,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),OBJECTIVE_DELIMITER,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),str_event_log,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),str_event_log_custom,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),OBJECTIVE_DELIMITER,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),str_EventIDMatch,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),OBJECTIVE_DELIMITER,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),str_GeneralMatchPlusTwo,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),OBJECTIVE_DELIMITER,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),str_user_match_type,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),OBJECTIVE_DELIMITER,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),str_UserMatch,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),OBJECTIVE_DELIMITER,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),str_event_match_type,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),OBJECTIVE_DELIMITER,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),str_general_match_type,_TRUNCATE);

	//Open the registry key for ALL access. 
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, OBJECTIVE_KEY_NAME, 0, KEY_ALL_ACCESS,&hKey ) 
		!= ERROR_SUCCESS )
	{
		//The registry key does not exist and was thus unable to be opened.
		//Try and create it.
		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, OBJECTIVE_KEY_NAME,0,REG_NONE,
					       REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,
						   NULL,&hKey,&dwDisp) != ERROR_SUCCESS)
		{
		//The registry key was unable to be created. Return.
			i_return_val += 2;
			return i_return_val;
		}
	}

	//No error checking required on this Reg Value
	//strncpy_s(str_buffer,_countof(str_buffer),pRegistry_struct->str_RestrictIP,_TRUNCATE);
	
	if ( RegSetValueEx(hKey, str_objective_to_read,0,REG_SZ,
			  (CONST BYTE *) str_objective,(DWORD)strlen(str_objective)) 
			  != ERROR_SUCCESS )
		i_return_val += 4;
		

	//Close the registry key when done
	RegCloseKey(hKey);

	return i_return_val;
}


int Recreate_Objective_Key()
{
	HKEY hKey;
	DWORD dwDisp; 
	int i_return_val = 0;
    
	//Delete the "Objective" Registry Key 
	if ( RegDeleteKey(HKEY_LOCAL_MACHINE, OBJECTIVE_KEY_NAME) != ERROR_SUCCESS )
	{
		//The registry key could not be deleted
		i_return_val += 1;
	}
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, OBJECTIVE_KEY_NAME,0,REG_NONE,
					       REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,
						   NULL,&hKey,&dwDisp) != ERROR_SUCCESS)
	{
		//The registry key was unable to be created. Return.
		i_return_val += 2;
	}
		

	//Close the registry key when done
	RegCloseKey(hKey);

	return i_return_val;
}


int Delete_Objective(int i_objective_number)
{
	HKEY hKey;
	int i_return_val = 0;
	char str_objective_to_delete[20] = "Objective"; 
    
	_snprintf_s(str_objective_to_delete,_countof(str_objective_to_delete),_TRUNCATE,"Objective%d",i_objective_number);

	//Open the registry key for ALL access. 
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, OBJECTIVE_KEY_NAME, 0, KEY_ALL_ACCESS,&hKey ) != ERROR_SUCCESS )
			return i_return_val += 1;

	if ( RegDeleteValue(hKey, str_objective_to_delete) != ERROR_SUCCESS )
		i_return_val += 2;
		
	//Close the registry key when done
	RegCloseKey(hKey);

	return i_return_val;
}




int add_wildcard_start_and_end(char *source, char *dest, int length)
{
	//This routine is simply to add the wildcard "*" to the start and
	//end of a string

      int count=0;
      char *copyofdest;
      copyofdest=dest;

      if(!source || !dest) 
		  return(1);
	  else
	  {	
		  if(count < length)
		  {
			  *dest='*';
			  dest++;
			  count++;
		  }
	  }


      while(*source) 
	  {
		if(count < length)
		{ 
			*dest=*source; 
			dest++; 
			count++; 
		}
		source++;
	  }

      if((count+2) < length)
	  {
		  *dest='*';
		  dest++;
		  *dest='\0';
	  }


	  dest=copyofdest;

      return(0);
}

int remove_wildcard_start_and_end(char *source, char *dest, int length)
{
	//This routine is simply to remove the wildcard "*" to the start and
	//end of a string

      int count=0;
      char *copyofdest;
      copyofdest=dest;

      if(!source || !dest) 
		  return(1);

	  if (*source == '*')
	  {
		  source++;
		  if(count < length)
		  {
			  *dest = *source;
			  dest++;
			  count++;
			  source++;
		  }
	  }

	  while(*source)
	  {
		  if(count < length)
		  {
			  *dest = *source;
			  dest++;
			  count++;
		  }
		  source++;
	  }

	  source--;
	  dest--;
	  count--;
	  if (*source == '*')
	  {
		  if(count < length)
		  {
			  *dest = '\0';
			  dest++;
			  count++;
		  }
	  }



	  dest=copyofdest;

      return(0);
}

// return 0 for failure
// return 1 for file
// return 2 for directory
int validate_file_or_directory(char *filename)
{
	if(!filename)				return(FALSE);
	if(strlen(filename) < 3)	return(FALSE); // Must be at least "C:\"
	if(!((filename[0] >= 'a' && filename[0] <= 'z') || (filename[0] >= 'A' && filename[0] <= 'Z'))) {
		return(FALSE);
	}
	if(filename[1] != ':')		return(FALSE);
	if(filename[2] != '\\')		return(FALSE);

	// Ok, anything else is fair game.
	DWORD Attributes;
	Attributes=GetFileAttributes(filename);
	if(Attributes == 0xFFFFFFFF) {
		// File or directory does not exist
		return(FALSE);
	}
	if(Attributes & FILE_ATTRIBUTE_DIRECTORY) {
		return(2);
	}

	return(1);
}


// Don't set audit on c:\winnt\system32\msaudite.dll
// Win2k+: No need to walk - just set recursive on encountered directories.
void WalkPathAndSet(char *dir, PSECURITY_DESCRIPTOR NewSD)
// void WalkPathAndSet(char *dir, PACL NewSD)
{
	char path[MAX_PATH];
	
	WIN32_FIND_DATA fd;
	// first the files
	HANDLE hFind;
	BOOL more;
	BOOL set=1;
	int returncode=0;
	
	// MAKE SURE that we don't set audit on msaudite.dll
	// if(is msaudite.dll as last path element
	if(strlen(dir) > 12) {
		if(!_stricmp("msaudite.dll",&dir[strlen(dir)-strlen("msaudite.dll")])) {
			char tempdir[256];
			ExpandEnvironmentStrings("%SystemRoot%\\system32\\msaudite.dll",tempdir,256);
			if(!_stricmp(dir,tempdir)) {
				// Dont set attributes
				set=0;
			}
		}
	}
	
	if(set)
	{
		returncode=SetFileSecurity(dir,SACL_SECURITY_INFORMATION|SE_SACL_AUTO_INHERIT_REQ|SE_SACL_AUTO_INHERITED,NewSD);
		// returncode=SetNamedSecurityInfo(dir,SE_FILE_OBJECT,SACL_SECURITY_INFORMATION,NULL,NULL,NULL,NewSD);
	}
	
	hFind = FindFirstFile(dir,&fd);
	if(hFind == INVALID_HANDLE_VALUE) {
		return;
	}
	FindClose(hFind);
	if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
		return;
	}
		
	_snprintf_s(path,MAX_PATH,_TRUNCATE,"%s\\*",dir);

	// Set for the current path.
	
	hFind = FindFirstFile(path,&fd);
	more = (hFind!=INVALID_HANDLE_VALUE);

	while(more) {
		_snprintf_s(path,MAX_PATH,_TRUNCATE,"%s\\%s",dir,fd.cFileName);
		
		if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			// Ignore . and .., but not files called ".a" (for example)
			if(fd.cFileName[0]!='.' && (strlen(fd.cFileName) == 1 || (fd.cFileName[1] !='.' && strlen(fd.cFileName) == 2))) {
				// Was this &NewSD?
				WalkPathAndSet(path,NewSD);
			}
		} else {
			// MAKE SURE that we don't set audit on msaudite.dll
			// if(is msaudite.dll as last path element
			set=1;
			if(strlen(path) > 12) {
				if(!_stricmp("msaudite.dll",&path[strlen(path)-strlen("msaudite.dll")])) {
					char tempdir[256];
					ExpandEnvironmentStrings("%SystemRoot%\\system32\\msaudite.dll",tempdir,256);
					if(!_stricmp(path,tempdir)) {
						// Dont set attributes
						set=0;
					}
				}
			}
			if(set) {
				returncode=SetFileSecurity(path,SACL_SECURITY_INFORMATION|SE_SACL_AUTO_INHERIT_REQ|SE_SACL_AUTO_INHERITED,NewSD);
				// returncode=SetNamedSecurityInfo(path,SE_FILE_OBJECT,SACL_SECURITY_INFORMATION,NULL,NULL,NULL,NewSD);
			}
		}
		more=FindNextFile(hFind,&fd);
	}
	FindClose(hFind);
}


BOOL EnableSecurityName() {

   // A process that tries to read or write a SACL needs
   // to have and enable the SE_SECURITY_NAME privilege.
   
   LUID   SecurityNameValue;
   HANDLE hToken;
   TOKEN_PRIVILEGES tp;

   if (!OpenProcessToken(GetCurrentProcess(),
         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
      return FALSE;
   }

   if (!LookupPrivilegeValue(NULL, SE_SECURITY_NAME,
         &SecurityNameValue)) {
	  CloseHandle(hToken);
      return FALSE;
   }

   tp.PrivilegeCount = 1;
   tp.Privileges[0].Luid = SecurityNameValue;
   tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

   if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp),
         NULL, NULL)) {
	  CloseHandle(hToken);
      return FALSE;
   }
   CloseHandle(hToken);
   return TRUE;
}


BOOL AddEveryoneAceToFileSacl(char * strFileName,
      DWORD dwAccessMask) {

   BOOL  bReturn   = FALSE;
   PSID  psidWorld = NULL;
   PACL  pNewACL   = NULL;
   DWORD dwNewACLSize;

   SID_IDENTIFIER_AUTHORITY authWorld = SECURITY_WORLD_SID_AUTHORITY;

   __try {

      // Build the "Everyone" SID
      if (!AllocateAndInitializeSid(&authWorld, 1, SECURITY_WORLD_RID,
            0, 0, 0, 0, 0, 0, 0, &psidWorld)) {
         __leave;
      }

      // Compute size needed for the new ACL
      dwNewACLSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) 
            + GetLengthSid(psidWorld) - sizeof(DWORD);
 
      // Allocate memory for new ACL
      pNewACL = (PACL) HeapAlloc(GetProcessHeap(), 0, dwNewACLSize);
      if (!pNewACL) {
         __leave;
      }

      // Initialize the new ACL
      if (!InitializeAcl(pNewACL, dwNewACLSize, ACL_REVISION2)) {
         __leave;
      }
 
		int returncode;

		// WIN2k PRO and Above

		// Add the audit ACE to the new SACL
		if (!AddAuditAccessAceEx(pNewACL, ACL_REVISION2,
			CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | FAILED_ACCESS_ACE_FLAG | SUCCESSFUL_ACCESS_ACE_FLAG,
			dwAccessMask, psidWorld, TRUE /* Audit Success */,
				TRUE /* Audit Failure */)) {
			__leave;
		}
		returncode=SetNamedSecurityInfo(strFileName,SE_FILE_OBJECT,SACL_SECURITY_INFORMATION,NULL,NULL,NULL,pNewACL);
		
		// WAS: INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE | FAILED_ACCESS_ACE_FLAG | INHERITED_ACE | OBJECT_INHERIT_ACE | SUCCESSFUL_ACCESS_ACE_FLAG,
      bReturn = TRUE;
   }

   __finally
   {
      // Free the allocated SID.
      if (psidWorld) FreeSid(psidWorld);

      // Free the memory allocated for the new ACL.
      if (pNewACL) HeapFree(GetProcessHeap(), 0, pNewACL);
   }

   return bReturn;
}

// Convert sid to text.
BOOL GetTextualSid(
    PSID pSid,            // binary SID
    LPTSTR TextualSid,    // buffer for Textual representation of SID
    LPDWORD lpdwBufferLen // required/provided TextualSid buffersize
    )
{
    PSID_IDENTIFIER_AUTHORITY psia;
    DWORD dwSubAuthorities;
    DWORD dwSidRev=SID_REVISION;
    DWORD dwCounter;
    DWORD dwSidSize;

    // Validate the binary SID.

    if(!IsValidSid(pSid)) return FALSE;

    // Get the identifier authority value from the SID.

    psia = GetSidIdentifierAuthority(pSid);

    // Get the number of subauthorities in the SID.

    dwSubAuthorities = *GetSidSubAuthorityCount(pSid);

    // Compute the buffer length.
    // S-SID_REVISION- + IdentifierAuthority- + subauthorities- + NULL

    dwSidSize=(15 + 12 + (12 * dwSubAuthorities) + 1) * sizeof(TCHAR);

    // Check input buffer length.
    // If too small, indicate the proper size and set last error.

    if (*lpdwBufferLen < dwSidSize)
    {
        *lpdwBufferLen = dwSidSize;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    // Add 'S' prefix and revision number to the string.

    dwSidSize=wsprintf(TextualSid, TEXT("S-%lu-"), dwSidRev );

    // Add SID identifier authority to the string.

    if ( (psia->Value[0] != 0) || (psia->Value[1] != 0) )
    {
        dwSidSize+=wsprintf(TextualSid + lstrlen(TextualSid),
                    TEXT("0x%02hx%02hx%02hx%02hx%02hx%02hx"),
                    (USHORT)psia->Value[0],
                    (USHORT)psia->Value[1],
                    (USHORT)psia->Value[2],
                    (USHORT)psia->Value[3],
                    (USHORT)psia->Value[4],
                    (USHORT)psia->Value[5]);
    }
    else
    {
        dwSidSize+=wsprintf(TextualSid + lstrlen(TextualSid),
                    TEXT("%lu"),
                    (ULONG)(psia->Value[5]      )   +
                    (ULONG)(psia->Value[4] <<  8)   +
                    (ULONG)(psia->Value[3] << 16)   +
                    (ULONG)(psia->Value[2] << 24)   );
    }

    // Add SID subauthorities to the string.
    //
    for (dwCounter=0 ; dwCounter < dwSubAuthorities ; dwCounter++)
    {
        dwSidSize+=wsprintf(TextualSid + dwSidSize, TEXT("-%lu"),
                    *GetSidSubAuthority(pSid, dwCounter) );
    }

    return TRUE;
}




int getSection(char* pos, char* buffer, int size, char* tag){
	char* pos3;
	int len = 0 ;
	if(!pos || !buffer || !tag)return(0);
	char* pos2=strstr(pos,tag);
	if(pos2){
		pos2 = pos2 + strlen(tag);
		while((*pos2 == '\r')||(*pos2 == '\n')){
			pos2 = pos2 + 1 ;
		}
		pos3=strstr(pos2,"\n[");
		if(pos3){
			len = (int)(pos3 - pos2 + 1);
		}else {
			len = strlen(pos2);
		}

		if(len >= size)len = size -1;
		strncpy(buffer,pos2,len);
		buffer[len] = '\0';
	} else return (0);

	return(1);
}

int getNextKey(char** position, char* tag, int size1, char* value, int size2){

	int len = 0 ;
	char* pos = *position;
	if(!pos || !tag  || !value)return(0);
	while((*pos == '\t')||(*pos == ' ')){
		pos = pos + 1 ;
	}
	char* pos2=strstr(pos,"=");
	if(pos2){
		len = (int)(pos2 -pos);
		if(len >= size1)len = size1 -1;
		strncpy(tag, pos, len);
		tag[len] = '\0';
		pos = pos2 + 1 ;
	}else return (0);
	
	pos2=strstr(pos,"\n");
	if(pos2){
		if(*pos2 == '\r')pos2 = pos2 - 1;
		len = (int)(pos2 -pos);
		if(len >= size2)len = size2 -1;
		strncpy(value, pos, len);
		value[len] = '\0';
		pos = pos2 + 1;
		if(*pos2 == '\n')pos2 = pos2 - 1;
	}else return (0);
	*position = pos;
	return (1);
}

BOOL setRegValue(char* tag, char* tag2, char* value){
	if(tag2[0] == 'd'){
		tag2++;
		return MyWriteProfileDWORD(tag,tag2,atoi(value));
	}else if(tag2[0] == 's'){
		tag2++;
		return MyWriteProfileString(tag,tag2,value);
	}else return FALSE;
}

int Delete_Reg_Keys()
{
	int i_return_val = 0;
    
	if ( RegDeleteKey(HKEY_LOCAL_MACHINE, CONFIG_KEY_NAME) != ERROR_SUCCESS )
	{
		//The registry key could not be deleted
		i_return_val += 1;
	}

	if ( RegDeleteKey(HKEY_LOCAL_MACHINE, NETWORK_KEY_NAME) != ERROR_SUCCESS )
	{
		//The registry key could not be deleted
		i_return_val += 2;
	}
	if ( RegDeleteKey(HKEY_LOCAL_MACHINE, REMOTE_KEY_NAME) != ERROR_SUCCESS )
	{
		//The registry key could not be deleted
		i_return_val += 3;
	}
	if ( RegDeleteKey(HKEY_LOCAL_MACHINE, OBJECTIVE_KEY_NAME) != ERROR_SUCCESS )
	{
		//The registry key could not be deleted
		i_return_val += 4;
	}
	if ( RegDeleteKey(HKEY_LOCAL_MACHINE, E_OBJECTIVE_KEY_NAME) != ERROR_SUCCESS )
	{
		//The registry key could not be deleted
		i_return_val += 5;
	}
	if ( RegDeleteKey(HKEY_LOCAL_MACHINE, LOG_KEY_NAME) != ERROR_SUCCESS )
	{
		//The registry key could not be deleted
		i_return_val += 6;
	}
	if ( RegDeleteKey(HKEY_LOCAL_MACHINE, SYS_ADMIN_KEY_NAME) != ERROR_SUCCESS )
	{
		//The registry key could not be deleted
		i_return_val += 7;
	}

	return i_return_val;
}


int GetLine(FILE * fp, char * dest, int max, int block)
{
	char c;
	int i=0,len=0,allspace=1;
	while((c=fgetc(fp))!='\n' && (c != '\0' || block) && !feof(fp)) {
		if (c=='\r' || c=='\0') {
			len++;
			continue;
		}
		if (i < max) dest[i] = c;
		else break;
		if (allspace && c!=' ') allspace=0;
		i++; len++;
		if(block && len == max) break;
	}

	if (i!=max) {
		if (c == '\n') len++;
		dest[i]='\n';
		dest[i+1]='\0';
	} else {
		if(block){
			dest[max]='\n';
			dest[max + 1]='\0';
		}else{
			len++;
			if (c == '\n' ) dest[max]='\n';
			else dest[max]='\0';
		}
	}
	if (allspace && (feof(fp) || i>=max)) return 0;
	else return len;
}


int Delete_Log(int i_log_number)
{
	HKEY hKey;
	int i_return_val = 0;
	char str_log_to_delete[20] = ""; 
    
	_snprintf_s(str_log_to_delete,_countof(str_log_to_delete),_TRUNCATE,"Log%d",i_log_number);

	//Open the registry key for ALL access. 
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, LOG_KEY_NAME, 0, KEY_ALL_ACCESS,&hKey ) != ERROR_SUCCESS )
			return i_return_val += 1;

	if ( RegDeleteValue(hKey, str_log_to_delete) != ERROR_SUCCESS )
		i_return_val += 2;

	//MULTI
	_snprintf_s(str_log_to_delete,_countof(str_log_to_delete),_TRUNCATE,"LogMulti%d",i_log_number);

	//Open the registry key for ALL access. 
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, LOG_KEY_NAME, 0, KEY_ALL_ACCESS,&hKey ) != ERROR_SUCCESS )
			return i_return_val += 1;

	RegDeleteValue(hKey, str_log_to_delete);

	//Close the registry key when done
	RegCloseKey(hKey);

	return i_return_val;
}

int Write_Log_Registry(int i_log_number, Reg_Log *pRegistry_struct)
{
	HKEY hKey;
	DWORD dwDisp, dwBytesReturned = 100,i_AlertType = 0,i_EventType = 0;
	DWORD i_EventLogType = 0;
	int i_return_val = 0;
	char str_event_log[SIZE_OF_EVENTLOG]="",str_event_type[SIZE_OF_EVENTLOG]="";
	char str_log[SIZE_OF_LOGNAME] = "";
	char str_log_to_read[20]=""; 

	_snprintf_s(str_log_to_read,_countof(str_log_to_read),_TRUNCATE,"Log%d",i_log_number);

	//form the str_log
	_snprintf_s(str_log,_countof(str_log),_TRUNCATE,"%s|%s|%s|%d",pRegistry_struct->type,pRegistry_struct->name,pRegistry_struct->format,pRegistry_struct->send_comments);

	//Open the registry key for ALL access. 
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, LOG_KEY_NAME, 0, KEY_ALL_ACCESS,&hKey ) != ERROR_SUCCESS ) {
		//The registry key does not exist and was thus unable to be opened.
		//Try and create it.
		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, LOG_KEY_NAME,0,REG_NONE,
					       REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,
						   NULL,&hKey,&dwDisp) != ERROR_SUCCESS)
		{
		//The registry key was unable to be created. Return.
			i_return_val += 2;
			return i_return_val;
		}
	}

	//No error checking required on this Reg Value
	
	if ( RegSetValueEx(hKey, str_log_to_read,0,REG_SZ,(CONST BYTE *) str_log,(DWORD)strlen(str_log)) != ERROR_SUCCESS )
		i_return_val += 4;

	//MULTI
	//if there is a multi setting, write it as well.

	if (pRegistry_struct->multiline) {
		_snprintf_s(str_log_to_read,_countof(str_log_to_read),_TRUNCATE,"LogMulti%d",i_log_number);
		if (pRegistry_struct->multiline == ML_FIXED) {
			if ( RegSetValueEx(hKey, str_log_to_read,0,REG_DWORD,(CONST BYTE *) &pRegistry_struct->log_ml_count,sizeof(pRegistry_struct->log_ml_count)) != ERROR_SUCCESS )
				i_return_val += 8;
		} else if (pRegistry_struct->multiline == ML_SEP) {
			if ( RegSetValueEx(hKey, str_log_to_read,0,REG_SZ,(CONST BYTE *) pRegistry_struct->log_ml_sep,(DWORD)strlen(pRegistry_struct->log_ml_sep)) != ERROR_SUCCESS )
				i_return_val += 8;
		} else if (pRegistry_struct->multiline == ML_BLOCK) {
			_snprintf_s(pRegistry_struct->log_ml_sep, SIZE_OF_SEP, _TRUNCATE, "%d$BYTES", pRegistry_struct->log_ml_count);
			if ( RegSetValueEx(hKey, str_log_to_read,0,REG_SZ,(CONST BYTE *) pRegistry_struct->log_ml_sep,(DWORD)strlen(pRegistry_struct->log_ml_sep)) != ERROR_SUCCESS )
				i_return_val += 8;
		} else {
				i_return_val += 8;
		}
	} else {
		_snprintf_s(str_log_to_read,_countof(str_log_to_read),_TRUNCATE,"LogMulti%d",i_log_number);
		RegDeleteValue(hKey, str_log_to_read);
	}
		

	//Close the registry key when done
	RegCloseKey(hKey);

	return i_return_val;
}

int E_Write_Objective_Registry(int i_objective_number, E_Reg_Objective *pRegistry_struct)
{
	HKEY hKey;
	DWORD dwDisp, dwBytesReturned = 100,i_AlertType = 0,i_EventType = 0;
	DWORD i_EventLogType = 0;
	int i_return_val = 0;
	char str_GeneralMatch[SIZE_OF_GENERALMATCH];
	char str_event_log[SIZE_OF_EVENTLOG]="",str_event_type[SIZE_OF_EVENTLOG]="";
	char str_objective[SIZE_OF_AN_OBJECTIVE] = "";
	char str_objective_to_read[20] = "EObjective",str_temp[10]=""; 
	char str_match_type[SIZE_OF_MATCH_TYPE];
	char str_GeneralMatchPlusTwo[SIZE_OF_GENERALMATCH+2];

	_itoa_s(i_objective_number,str_temp,10);
	strncat_s(str_objective_to_read,_countof(str_objective_to_read),str_temp,_TRUNCATE);


		if (strstr(pRegistry_struct->str_match_type,EXCLUDE) != NULL)
			strncpy_s(str_match_type,SIZE_OF_MATCH_TYPE,"1",_TRUNCATE);
		else
			strncpy_s(str_match_type,SIZE_OF_MATCH_TYPE,"0",_TRUNCATE);

		//Need to make sure the length is limited
		strncpy_s(str_GeneralMatch,SIZE_OF_GENERALMATCH,pRegistry_struct->str_match,_TRUNCATE);

		//This is to add a "*" character to the start and end of the general string
		add_wildcard_start_and_end(str_GeneralMatch,str_GeneralMatchPlusTwo,SIZE_OF_GENERALMATCH+2);
		
		//form the str_objective
		strncat_s(str_objective,_countof(str_objective),str_GeneralMatchPlusTwo,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),OBJECTIVE_DELIMITER,_TRUNCATE);
		strncat_s(str_objective,_countof(str_objective),str_match_type,_TRUNCATE);
		

	//Open the registry key for ALL access. 
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, E_OBJECTIVE_KEY_NAME, 0, KEY_ALL_ACCESS,&hKey ) 
		!= ERROR_SUCCESS )
	{
		//The registry key does not exist and was thus unable to be opened.
		//Try and create it.
		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, E_OBJECTIVE_KEY_NAME,0,REG_NONE,
					       REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,
						   NULL,&hKey,&dwDisp) != ERROR_SUCCESS)
		{
		//The registry key was unable to be created. Return.
			i_return_val += 2;
			return i_return_val;
		}
	}

	//No error checking required on this Reg Value
	//strncpy_s(str_buffer,1024,pRegistry_struct->str_RestrictIP,_TRUNCATE);
	
	if ( RegSetValueEx(hKey, str_objective_to_read,0,REG_SZ,
			  (CONST BYTE *) str_objective,(DWORD)strlen(str_objective)) 
			  != ERROR_SUCCESS )
		i_return_val += 4;
		

	//Close the registry key when done
	RegCloseKey(hKey);

	return i_return_val;
}

int E_Read_Objective_Registry(int i_objective_number, E_Reg_Objective *pRegistry_struct)
{
	HKEY hKey;
	DWORD  dw_objective_bytes = SIZE_OF_AN_OBJECTIVE, dwRegType;
	char objective_buffer[SIZE_OF_AN_OBJECTIVE]="";
	char str_objective[SIZE_OF_AN_OBJECTIVE]="";
	int o_return_val = 0,i_type = 0,i_event_type_log = 0;
	char str_objective_to_read[20] = "",str_temp[5]=""; 
	char str_temp_general[SIZE_OF_GENERALMATCH+2]="";
  	char str_temp_match_type[SIZE_OF_MATCH_TYPE]="";
	long error_type=0;

	//_itoa_s_s(i_objective_number,str_temp,10);
	//strncat(str_objective_to_read,_countof(str_temp),str_temp,_TRUNCATE);
	_snprintf_s(str_objective_to_read,_countof(str_objective_to_read),_TRUNCATE,"EObjective%d",i_objective_number);

	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, E_OBJECTIVE_KEY_NAME, 0, KEY_READ,&hKey ) 
		== ERROR_SUCCESS )	{
		error_type = RegQueryValueEx(hKey, str_objective_to_read, NULL, &dwRegType, 
		     (LPBYTE) objective_buffer, &dw_objective_bytes );
	  if ( error_type == ERROR_SUCCESS ) {
			// Reject any str_objective that is longer than 1056 chars
		  if ((dwRegType == REG_SZ) & (dw_objective_bytes <= SIZE_OF_AN_OBJECTIVE)) {
				strncpy_s( str_objective,dw_objective_bytes,objective_buffer,_TRUNCATE);
		  } else {
				// reject the str_objective and return immediately
				return (o_return_val + 1);
		  }
	  } else {
		  // Retain this error value as 4, since the error control in the other routines
		  // look for errors in the range 1 to 3.
		  return (o_return_val + 4);
	  }

	  // Close the registry key when done
	  RegCloseKey(hKey);
	  
    } else {
	   return (o_return_val + 2);
	}
	
	if (!pRegistry_struct) return(0);

	// NOTE: This line is TAB delimited.
	// Note str_general_temp is 514 bytes to allow for the two wildcard characters
	sscanf_s(str_objective,"%514[^\t]\t%4[^\n]\n",str_temp_general,_countof(str_temp_general),str_temp_match_type,_countof(str_temp_match_type));

	
	// Copy all the values to the struct

	//If the str_objective doesn't contain a valid match type, assume it is "0"
	if (_stricmp(str_temp_match_type,"1") == 0) {
		strncpy_s(pRegistry_struct->str_match_type,SIZE_OF_MATCH_TYPE,EXCLUDE,_TRUNCATE);
		pRegistry_struct->dw_match_type = 1;
	} else {
		strncpy_s(pRegistry_struct->str_match_type,SIZE_OF_MATCH_TYPE,INCLUDE,_TRUNCATE);
		pRegistry_struct->dw_match_type = 0;
	}

	i_type = 0;


	// Remove the wildcard characters from the generla match temp string
	remove_wildcard_start_and_end(str_temp_general,pRegistry_struct->str_match,SIZE_OF_GENERALMATCH);

	// if the general search term is greater than 512 chars, reject the str_objective
	// Note that the statements below won't do much since the struct var should have been
	// throttled by the function to remove the wildcard chars
	// if (_countof(pRegistry_struct->str_match) < 513)
	//  strncpy_s(pRegistry_struct->str_match,SIZE_OF_GENERALMATCH,str_temp_general,_TRUNCATE);
	// else
	//  return (i_return_val += 512);

	return(o_return_val);
}


int E_Delete_Objective(int i_objective_number)
{
	HKEY hKey;
	int i_return_val = 0;
	char str_objective_to_delete[20] = "EObjective",str_temp[10]=""; 
    
	_itoa_s(i_objective_number,str_temp,10);
	strncat_s(str_objective_to_delete,_countof(str_objective_to_delete),str_temp,_TRUNCATE);

	//Open the registry key for ALL access. 
	if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, E_OBJECTIVE_KEY_NAME, 0, KEY_ALL_ACCESS,&hKey ) != ERROR_SUCCESS )
			return i_return_val += 1;

	if ( RegDeleteValue(hKey, str_objective_to_delete) != ERROR_SUCCESS )
		i_return_val += 2;
		
	//Close the registry key when done
	RegCloseKey(hKey);

	return i_return_val;
}


void syslogdate(char *sdate, struct tm *cdate)
{
	char Month[4];
	char Date[3];
	char Hour[3];
	char Min[3];
	char Sec[3];

	if(!sdate || !cdate) return;

	switch (cdate->tm_mon) {
		case 0: strncpy_s(Month,_countof(Month),"Jan",_TRUNCATE); break;
		case 1: strncpy_s(Month,_countof(Month),"Feb",_TRUNCATE); break;
		case 2: strncpy_s(Month,_countof(Month),"Mar",_TRUNCATE); break;
		case 3: strncpy_s(Month,_countof(Month),"Apr",_TRUNCATE); break;
		case 4: strncpy_s(Month,_countof(Month),"May",_TRUNCATE); break;
		case 5: strncpy_s(Month,_countof(Month),"Jun",_TRUNCATE); break;
		case 6: strncpy_s(Month,_countof(Month),"Jul",_TRUNCATE); break;
		case 7: strncpy_s(Month,_countof(Month),"Aug",_TRUNCATE); break;
		case 8: strncpy_s(Month,_countof(Month),"Sep",_TRUNCATE); break;
		case 9: strncpy_s(Month,_countof(Month),"Oct",_TRUNCATE); break;
		case 10: strncpy_s(Month,_countof(Month),"Nov",_TRUNCATE); break;
		default: strncpy_s(Month,_countof(Month),"Dec",_TRUNCATE); break;
	}

	if(cdate->tm_mday<10) {
		_snprintf_s(Date,3,_TRUNCATE," %d\0",cdate->tm_mday);
	} else {
		_snprintf_s(Date,3,_TRUNCATE,"%d\0",cdate->tm_mday);
	}

	if(cdate->tm_hour<10) {
		_snprintf_s(Hour,3,_TRUNCATE,"0%d\0",cdate->tm_hour);
	} else {
		_snprintf_s(Hour,3,_TRUNCATE,"%d\0",cdate->tm_hour);
	}

	if(cdate->tm_min<10) {
		_snprintf_s(Min,3,_TRUNCATE,"0%d\0",cdate->tm_min);
	} else {
		_snprintf_s(Min,3,_TRUNCATE,"%d\0",cdate->tm_min);
	}

	if(cdate->tm_sec<10) {
		_snprintf_s(Sec,3,_TRUNCATE,"0%d\0",cdate->tm_sec);
	} else {
		_snprintf_s(Sec,3,_TRUNCATE,"%d\0",cdate->tm_sec);
	}

	_snprintf_s(sdate,16,_TRUNCATE,"%s %s %s:%s:%s\0",Month,Date,Hour,Min,Sec);
}
