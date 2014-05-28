#ifndef _SUPPORT_H_
#define _SUPPORT_H_

#define CONFIG_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\Config\\"
#define NETWORK_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\Network\\"
#define REMOTE_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\Remote\\"
#define OBJECTIVE_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\Objective\\"
#define SYS_ADMIN_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\SysAdmin\\"
#define E_OBJECTIVE_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\EObjective\\"
#define LOG_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\Log\\"

#define LOGON_LOGOFF_EVENTS "4624,4625,4626,4627,4628,4629,4630,4631,4632,4633,4634,4635,4636,4637,4638,4639,4640,4641,4642,4643,4647,4648,4768,4769,4770,4771,4772,4773,4774,4776,4777,4778,4779,4800,4801,4802,4803"
#define RESTART_EVENTS "4608,4609"
#define SECURITY_POLICY_EVENTS "4612,4613,4704,4705,4706,4707,4708,4709,4710,4711,4712,4713,4714,4716,4719,4739"
#define USER_GROUP_ADMIN_EVENTS "4720,4721,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4736,4737,4738,4739,4740,4741,4742,4743,4744,4745,4746,4747,4748,4749,4750,4751,4752,4753,4754,4755,4756,4757,4758,4759,4760,4761,4762,4763,4764,4765,4766,4767"
#define USER_OF_USER_RIGHTS_EVENTS "4672,4673,4674,4704,4705"
#define PROCESS_EVENTS "4688,4689,4690,4691"
#define FILE_EVENTS "4656,4657,4658,4659,4660,4661,4662,4663,4690,4691"
#define FILTERING_EVENTS "5152,5153,5154,5155,5156,5157,5158,5159,5447"
#define USB_EVENTS "18,19,20"

// Audit all events
#define AUDIT_ALL -99

#define IS_PRIVILEGE_USE(n)             (n==4672||n==4673||n==4674||n==4604||n==4605||n==AUDIT_ALL)
#define IS_PROCESS_TRACKING(n)          (n==4688||n==4689||n==4690||n==4691||n==AUDIT_ALL)
#define IS_SYSTEM_EVENTS(n)             (n==4608||n==4609||n==4610||n==4611||n==4612||n==4613||n==4614||n==AUDIT_ALL)
#define IS_LOGON_EVENTS(n)              (n==4624||n==4625||n==4626||n==4627||n==4628||n==4629||n==4630||n==4631||n==4632||n==4633||n==4634||n==4635||n==4636||n==4637||n==4638||n==4639||n==4640||n==4641||n==4642||n==4643||n==4778||n==4777||n==AUDIT_ALL)
#define IS_ACCOUNT_LOGON_EVENTS(n)      (n==4768||n==4769||n==4770||n==4771||n==4772||n==4773||n==4774||n==4776||n==4777||n==4778||n==4779||n==AUDIT_ALL)
#define IS_ACCOUNT_MANAGEMENT_EVENTS(n) (n==4720||n==4721||n==4722||n==4723||n==4724||n==4725||n==4726||n==4727||n==4728||n==4729||n==4730||n==4731||n==4732||n==4733||n==4734||n==4735||n==4736||n==4737||n==4738||n==4738||n==4740||n==4741||n==4742||n==4743||n==4744||n==4745||n==4746||n==4747||n==4748||n==4749||n==4750||n==4751||n==4752||n==4753||n==4754||n==4755||n==4756||n==4757||n==4758||n==4759||n==4760||n==4761||n==4762||n==4763||n==4764||n==4765||n==4766||n==4767||n==AUDIT_ALL)
#define IS_OBJECT_ACCESS(n)             (n==4656||n==4657||n==4658||n==4659||n==4660||n==4661||n==4662||n==4663||n==AUDIT_ALL)
#define IS_FILTERING_EVENTS(n)			(n==5152||n==5153||n==5154||n==5155||n==5156||n==5157||n==5158||n==5159||n==5447||n==AUDIT_ALL)
#define IS_POLICY_CHANGE(n)             (n==4704||n==4705||n==4706||n==4706||n==4708||n==4709||n==4710||n==4711||n==4712||n==4713||n==4714||n==4715||n==4716||n==4864||n==AUDIT_ALL)
#define IS_DIRECTORY_SERVICE_ACCESS(n)  (n==4661||n==AUDIT_ALL)
#define IS_USB_EVENTS(n)				(n==18||n==19||n==20||n==AUDIT_ALL)

#define LOGONOFF_TOKEN "Logon_Logoff"
#define FILE_TOKEN "File_Events"
#define PROCESS_TOKEN "Process_Events"
#define FILTERING_TOKEN "Filtering_Events"
#define USERRIGHTS_TOKEN "User_Right_Events"
#define MANAGE_TOKEN "User_Group_Management_Events"
#define SECPOL_TOKEN "Security_Policy_Events"
#define REBOOT_TOKEN "Reboot_Events"
#define USB_TOKEN "USB_Audit_Events"

#define CRITICAL_TOKEN "Critical"
#define PRIORITY_TOKEN "Priority"
#define WARNING_TOKEN "Warning"
#define INFORMATION_TOKEN "Information"
#define CLEAR_TOKEN "Clear"

#define EVENT_CRITICAL		4
#define EVENT_PRIORITY		3
#define EVENT_WARNING		2
#define EVENT_INFORMATION	1 
#define EVENT_CLEAR			0

#define SUCCESS_TOKEN "Success"
#define FAILURE_TOKEN "Failure"
#define INFO_TOKEN "Info"
#define WARN_TOKEN "Warn"
#define ERROR_TOKEN "Error"

#define SECLOG_TOKEN "Sec"
#define CUSLOG_TOKEN "Cus"
#define SYSLOG_TOKEN "Sys"
#define APPLOG_TOKEN "App"
#define DIRLOG_TOKEN "Dir"
#define DNSLOG_TOKEN "DNS"
#define REPLOG_TOKEN "Rep"

#define TYPE_SUCCESS 16
#define TYPE_FAILURE 8
#define TYPE_ERROR 4
#define TYPE_INFO 2
#define TYPE_WARN 1

#define LOG_CUS 64
#define LOG_SEC 32
#define LOG_SYS 16
#define LOG_APP 8
#define LOG_DIR 4
#define LOG_DNS 2
#define LOG_REP 1

#define EXCLUDE "Exclude"
#define INCLUDE "Include"

#define ML_FIXED				 1
#define ML_SEP					 2
#define ML_BLOCK				 3

#define SIZE_OF_RESTRICTIP		 2048
#define SIZE_OF_PASSWORD		 256
#define SIZE_OF_USERMATCH		 256
#define SIZE_OF_GENERALMATCH	 512
#define SIZE_OF_EVENTLOG		 35
#define SIZE_OF_CRITICALITY		 12
#define SIZE_OF_EVENTIDMATCH	 256
#define SIZE_OF_AN_OBJECTIVE	 1056
#define SIZE_OF_LOGNAME			 512
#define SIZE_OF_CLIENTNAME		 100
#define SIZE_OF_DESTINATION		 2048
#define SIZE_OF_USER_MATCH_TYPE	 10
#define SIZE_OF_EVENT_MATCH_TYPE 10
#define SIZE_OF_GENERAL_MATCH_TYPE 10
#define SIZE_OF_FILENAME		 1024
#define SIZE_OF_AUDITPOL_ARG	 64
#define SIZE_OF_MATCH_TYPE		 10
#define SIZE_OF_SEP				 32

#define OBJECTIVE_DELIMITER		 "\t"

//These are definitions for the length of event record fields
//#define MAX_ENC_STRING			  12288
#define MAX_ENC_STRING			  6100
#define FIELD_SOURCE_NAME		  100
#define	FIELD_SIDTYPE			  100
#define FIELD_EVENTLOGTYPE	      50
#define FIELD_EXPANDEDSTRING	  1024
#define FIELD_DATASTRING		  1024
#define FIELD_COMPUTERNAME		  256
#define FIELD_USERNAME		      256
#define FIELD_CATEGORYSTRING      256
#define FIELD_DATETIME		      100
#define FIELD_CRITICALITY		  2
#define FIELD_SYSTEM			  256
#define FIELD_NULL			      256
#define FIELD_EVENTID			  10

#define READ_CONFIG_ERROR_CODE			210000
#define READ_NETWORK_ERROR_CODE			230000
#define READ_REMOTE_ERROR_CODE			260000
#define READ_OBJECTIVE_ERROR_CODE		310000
#define WRITE_CONFIG_ERROR_CODE			330000
#define WRITE_NETWORK_ERROR_CODE		370000
#define WRITE_REMOTE_ERROR_CODE			410000
#define WRITE_OBJECTIVE_ERROR_CODE		440000
#define RESTART_SERVICE_ERROR_CODE		480000
#define WEB_READ_CONFIG_ERROR_CODE		510000
#define WEB_READ_SYSADMIN_ERROR_CODE	540000
#define WEB_READ_NETWORK_ERROR_CODE		530000
#define WEB_READ_REMOTE_ERROR_CODE		580000
#define WEB_READ_OBJECTIVE_ERROR_CODE	610000
#define WEB_WRITE_CONFIG_ERROR_CODE		660000
#define WEB_WRITE_NETWORK_ERROR_CODE	720000
#define WEB_WRITE_REMOTE_ERROR_CODE		770000
#define WEB_WRITE_OBJECTIVE_ERROR_CODE	850000
#define WEB_RESTART_SERVICE_ERROR_CODE	890000
#define WEB_READ_LOG_ERROR_CODE			630000;

#define SIZE_EVENTREAD 1024

#define WEB_CACHE_SIZE 50
#define MAX_EVENT 8192
#define MAX_TYPE 64
#define MAX_AUDIT_CONFIG_LINE	8192

#define SOCKETTYPE_UDP 0
#define SOCKETTYPE_TCP 1
#define SOCKETTYPE_TCP_TLS 2


#define MAXMSGSIZE		2048
#define MAX_STRING 1024

// Web reset flags
#define BASIC_WEB_RESET 1
#define FULL_WEB_RESET  2

// The following structure has been defined to cater for the 'config' registry settings
struct  Reg_Config
{
	char	str_Delimiter[3];
	char	str_ClientName[SIZE_OF_CLIENTNAME];
	char	str_FileName[SIZE_OF_FILENAME];
	DWORD	dw_Audit;
	DWORD	dw_FileAudit;
	DWORD	dw_FileExport;
	DWORD	dw_NumberFiles;
	DWORD	dw_NumberLogFiles;
	DWORD	dw_LogLevel;
	DWORD	dw_CritAudit;
	DWORD	dw_EnableUSB;
};

struct  Reg_SysAdmin
{
	DWORD	dw_SysAdminEnable;
	DWORD	dw_TimesADay;
	DWORD	dw_ForceSysAdmin;
	DWORD	dw_VBS;
	DWORD	dw_LastSA;

};

struct Reg_Network
{
	char	str_Destination[SIZE_OF_DESTINATION];
	DWORD	dw_SyslogDest;
	DWORD	dw_DynamicCritic;
	DWORD	dw_MaxMsgSize;
	DWORD	dw_Syslog;
	DWORD	dw_DestPort;
	DWORD	dw_SocketType;
};

struct Reg_Remote
{
	DWORD	dw_Allow;
	DWORD	dw_WebPort;
	DWORD	dw_WebPortChange;
	DWORD	dw_Restrict;
	DWORD	dw_TLS;
	char	str_RestrictIP[SIZE_OF_RESTRICTIP];
	DWORD	dw_Password;
	char	str_Password[SIZE_OF_PASSWORD];
};

struct E_Reg_Objective
{
	char	str_match[SIZE_OF_GENERALMATCH];
	char	str_match_type[SIZE_OF_MATCH_TYPE];
	// The DWORD is ONLY to support READ operations for Leigh's code
	DWORD	dw_match_type;
};

struct Reg_Objective
{
	char	str_critic[SIZE_OF_CRITICALITY];
	char	str_event_type[SIZE_OF_EVENTLOG];
	char	str_eventlog_type[SIZE_OF_EVENTLOG];
	char	str_eventlog_type_custom[SIZE_OF_EVENTLOG];
	char	str_eventid_match[SIZE_OF_EVENTIDMATCH];
	char	str_user_match[SIZE_OF_USERMATCH];
	char	str_general_match[SIZE_OF_GENERALMATCH];
	char	str_user_match_type[SIZE_OF_USER_MATCH_TYPE];
	char	str_event_match_type[SIZE_OF_EVENT_MATCH_TYPE];
	char	str_general_match_type[SIZE_OF_GENERAL_MATCH_TYPE];
	// These four DWORDS and the STRING are ONLY to support READ operations for Leigh's code
	DWORD	dw_event_type;			
	DWORD	dw_eventlog_type;
	DWORD	dw_user_match_type;
	DWORD	dw_event_match_type;
	DWORD	dw_general_match_type;
	char	str_unformatted_eventid_match[SIZE_OF_EVENTIDMATCH];
};


struct _msgcache {
	char Hostname[100];
	int criticality;
	DWORD SafedCounter;
	TCHAR SubmitTime[26];
	DWORD ShortEventID;
	DWORD EventLogLevel;
	UINT64 EventLogKeyword; 
	TCHAR SourceName[100];
	TCHAR EventLogSourceName[100];
	TCHAR UserName[256];
	TCHAR SIDType[100];
	TCHAR EventLogType[60];
	TCHAR szCategoryString[256];
	char DataString[MAX_EVENT];
	char szTempString[MAX_EVENT];
	DWORD EventLogCounter;
	int seenflag;
	wchar_t	Bookmark[SIZE_EVENTREAD];
	struct _msgcache *next;
	struct _msgcache *prev;
};

typedef struct _msgcache MsgCache;


// Linked List
struct _e_msgcache {
	char* msg;//DMM 4096 = no page faults
	// Log type
	char type[MAX_TYPE];
	int msglen;
	struct _e_msgcache *next;
	int cached;
	int counter;
};

typedef struct _e_msgcache E_MsgCache;


struct Reg_Log {
	int multiline;
	int log_ml_count;
	int send_comments;
	char log_ml_sep[SIZE_OF_SEP];
	char name[SIZE_OF_LOGNAME];
	char type[SIZE_OF_LOGNAME];
	char format[SIZE_OF_LOGNAME];
};


int Read_Config_Registry(Reg_Config *);
int Read_SysAdmin_Registry(Reg_SysAdmin *);
int Read_Objective_Registry(int, Reg_Objective *);
int E_Read_Objective_Registry(int i_objective_number, E_Reg_Objective *pRegistry_struct);
int Read_Objective_Registry_Str(int , char *);
int E_Read_Objective_Registry_Str(int , char *);
int Read_Network_Registry(Reg_Network *);
int Read_Remote_Registry(Reg_Remote *);
int Read_Log_Registry(int, Reg_Log *);
int Read_Log_Registry_Str(int i_log_number, char *str_log, char *str_sep, int * linecount);
int Write_Config_Registry(Reg_Config *);
int Write_SysAdmin_Registry(Reg_SysAdmin *);
int Write_Network_Registry(Reg_Network *);
int Write_Remote_Registry(Reg_Remote *);
int Write_Objective_Registry(int, Reg_Objective *);
int E_Write_Objective_Registry(int i_objective_number, E_Reg_Objective *pRegistry_struct);
int Write_Log_Registry(int, Reg_Log *);
int Recreate_Objective_Key();
int Delete_Objective(int);
int E_Delete_Objective(int i_objective_number);
int Delete_Reg_Keys();
int add_wildcard_start_and_end(char *,char *,int);
int remove_wildcard_start_and_end(char *,char *,int);
int	validate_file_or_directory(char *filename);
void WalkPathAndSet(char *dir, PSECURITY_DESCRIPTOR NewSD);
BOOL EnableSecurityName();
BOOL AddEveryoneAceToFileSacl(char * strFileName, DWORD dwAccessMask);
int GetLine(FILE * fp, char * dest, int max, int block);

int Delete_Log(int);

int getSection(char*, char*, int , char*);
int getNextKey(char** , char* , int, char* , int);
BOOL setRegValue(char* , char* , char* );



BOOL	GetTextualSid(PSID pSid,LPTSTR TextualSid,LPDWORD lpdwBufferLen);
void syslogdate(char *sdate, struct tm *cdate);


#endif // _SUPPORT_H_
