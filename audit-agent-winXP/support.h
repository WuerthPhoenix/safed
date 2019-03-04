#ifndef _SUPPORT_H_
#define _SUPPORT_H_


#define CONFIG_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\Config\\"
#define NETWORK_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\Network\\"
#define REMOTE_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\Remote\\"
#define OBJECTIVE_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\Objective\\"
#define SYS_ADMIN_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\SysAdmin\\"
#define E_OBJECTIVE_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\EObjective\\"
#define LOG_KEY_NAME "SOFTWARE\\Wuerth Phoenix\\AuditService\\Log\\"

#define LOGON_LOGOFF_EVENTS "528,529,530,531,532,533,534,535,536,537,538,539,540,541,542,543,544,545,546,547,551,552,672,673,674,675,676,677,678,680,681,682,683"
#define RESTART_EVENTS "512,513"
#define SECURITY_POLICY_EVENTS "516,517,608,609,610,611,612,613,614,615,616,617,618,620,643"
#define USER_GROUP_ADMIN_EVENTS "624,625,626,627,628,629,630,631,632,633,634,635,636,637,638,639,640,641,642,643,644,645,646,647,648,649,650,651,652,653,654,655,656,657,658,659,660,661,662,663,664,665,666,667,668,669,670,671"
#define USER_OF_USER_RIGHTS_EVENTS "576,577,578,608,609"
#define PROCESS_EVENTS "592,593,594,595"
#define FILE_EVENTS "560,561,562,563,564,565,566,567,594,595"
#define USB_EVENTS "134,135"

// Audit all events
#define AUDIT_ALL -99

#define IS_PRIVILEGE_USE(n)             (n==576||n==577||n==578||n==AUDIT_ALL)
#define IS_PROCESS_TRACKING(n)          (n==592||n==593||n==594||n==595||n==AUDIT_ALL)
#define IS_SYSTEM_EVENTS(n)             (n==512||n==513||n==514||n==515||n==516||n==517||n==518||n==AUDIT_ALL)
#define IS_LOGON_EVENTS(n)              (n==528||n==529||n==530||n==531||n==532||n==533||n==534||n==535||n==536||n==537||n==538||n==539||n==540||n==541||n==542||n==543||n==544||n==545||n==546||n==547||n==682||n==683||n==AUDIT_ALL)
#define IS_ACCOUNT_LOGON_EVENTS(n)      (n==672||n==673||n==674||n==675||n==676||n==677||n==678||n==680||n==681||n==682||n==683||n==AUDIT_ALL)
#define IS_ACCOUNT_MANAGEMENT_EVENTS(n) (n==624||n==625||n==626||n==627||n==628||n==629||n==630||n==631||n==632||n==633||n==634||n==635||n==636||n==637||n==638||n==639||n==640||n==641||n==642||n==643||n==644||n==645||n==646||n==647||n==648||n==649||n==650||n==651||n==652||n==653||n==654||n==655||n==656||n==657||n==658||n==659||n==660||n==661||n==662||n==663||n==664||n==665||n==666||n==667||n==668||n==669||n==670||n==671||n==AUDIT_ALL)
#define IS_OBJECT_ACCESS(n)             (n==560||n==561||n==562||n==563||n==564||n==565||n==566||n==567||n==AUDIT_ALL)
#define IS_POLICY_CHANGE(n)             (n==608||n==609||n==610||n==611||n==612||n==613||n==614||n==615||n==616||n==617||n==618||n==619||n==620||n==768||n==AUDIT_ALL)
#define IS_DIRECTORY_SERVICE_ACCESS(n)  (n==565||n==AUDIT_ALL)
#define IS_USB_EVENTS(n)				(n==134||n==135||n==AUDIT_ALL)

#define LOGONOFF_TOKEN "Logon_Logoff"
#define FILE_TOKEN "File_Events"
#define PROCESS_TOKEN "Process_Events"
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

#define USB_ARRIVAL	134
#define USB_REMOVAL	135

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
	TCHAR SourceName[100];
	TCHAR UserName[256];
	TCHAR SIDType[100];
	TCHAR EventLogType[60];
	TCHAR szCategoryString[256];
	char DataString[MAX_EVENT];
	char szTempString[MAX_EVENT];
	DWORD EventLogCounter;
	int seenflag;
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

struct _usbcache {
	DWORD ShortEventID;
	TCHAR SubmitTime[26];
	char szTempString[MAX_EVENT];
	struct _usbcache *next;
};

typedef struct _usbcache USBCache;

#endif // _SUPPORT_H_


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
BOOL IsNT5plus();
int GetLine(FILE * fp, char * dest, int max, int block);

int Delete_Log(int);

int getSection(char*, char*, int , char*);
int getNextKey(char** , char* , int, char* , int);
BOOL setRegValue(char* , char* , char* );


BOOL	GetTextualSid(PSID pSid,LPTSTR TextualSid,LPDWORD lpdwBufferLen);

void syslogdate(char *sdate, struct tm *cdate);
