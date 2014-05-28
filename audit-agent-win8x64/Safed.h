/*
FILE: Safed.h
*/

#include <sstream>
#include "NTService.h"
#include <WinEvt.h>
#include <Dbt.h>
#include <process.h>
#include <ntsecapi.h>
#include <regex.h>



//#define MAX_ENC_STRING 12288
#define MAX_ENC_STRING 6100
#define MAX_USERNAME	512
#define MSG_COUNT_SAVE_POS 100

#define LOG_TYPE_SECURITY 0
#define LOG_TYPE_SYSTEM 1
#define LOG_TYPE_APPLICATION 2
#define LOG_TYPE_DS 3
#define LOG_TYPE_DNS 4
#define LOG_TYPE_FRS 5
#define MAX_LOG_TYPE 5

//Object Access SubCategories
#define OBJACCESS_FILE_SYS			0	//File System
#define OBJACCESS_REG				1	//Registry
#define OBJACCESS_KERN_OBJ			2	//Kernel Object
#define OBJACCESS_SAM				3	//SAM
#define OBJACCESS_CERT_SRV			4	//Certification Services
#define OBJACCESS_APP_GEN			5	//Application Generated
#define OBJACCESS_HANDLE_MANIP		6	//Handle Manipulation
#define OBJACCESS_FILE_SHARE		7	//File Share
#define OBJACCESS_FP_PACKET_DROP	8	//Filtering Platform Packet Drop
#define OBJACCESS_FP_CONNECTION		9	//Filtering Platform Connection
#define OBJACCESS_OTHER				10	//Other Object Access Events

struct _node
{
	int event_bottom;				// The start of the event list
	int event_top;					// The end of the event list
	int criticality;				// How critical is this particular node
	int excludeflag;				// Include or exclude users?
	int excludematchflag;			// Include or exclude general match?
	int excludeidflag;				// Include or exclude event IDs?
	int eventlogtype;				// binary Warning / Information / Success / Failure / Error
	int sourcename;					// binary Security / Application / Active Directory etc
	char username[SIZE_OF_USERMATCH];	// Remember, this will be a wildcard match.
	BOOL muserflag;					// Are there multiple users?
	char match[SIZE_OF_GENERALMATCH];
	char sysadmin[SIZE_OF_GENERALMATCH + 7];// in case of sys admin discovery contains "'" separated admins + N/A
	regex_t regexpCompiled;
	int regexpError;	
	struct _node *next;
};

typedef struct _node Node;



class CSafedService : public CNTService
{
public:
	CSafedService();
	virtual BOOL OnInit();
    virtual void Run();
    virtual BOOL OnUserControl(DWORD dwOpcode);
	void OnShutdown();
	void OnStop();
	void OnSignal();

    void SaveStatus();

// 	int SNAREDEBUG;

private:
	HANDLE *m_hEventList; // just the web server left. +  1 Safed thread
};

// Function Prototypes.
void	syslogdate				(char *, struct tm *);

int		wildmatch				(char *, char *, int);
int		wildmatchi				(char *, char *, int);
char	*stristr				(const char *, const char *);
BOOL	IsSimpleWildMatch		(char *);
void	ExtractSimpleWildMatch	(char *,char *,int);
void	splitstrings			(char *, int, char *, int);

DWORD WINAPI EventSubCallBack(EVT_SUBSCRIBE_NOTIFY_ACTION Action, PVOID Context, EVT_HANDLE Event);
BOOL	CheckLogExists			(TCHAR *LogName, int LeaveRetention);
char *	GetParameterMsg			(char *message, char *tmp);
void	GetFQDN					(char *string,int length);

int		ReadObjectives();
void	AddToList				(int eventbottom, int eventtop, char *username, char *match, int criticality, int excludematchflag, int excludeidflag,
								 int excludeflag, int muserflag, int eventlogtype, int sourcename, int objectivecount);

static Node * FastCheckObjective	(int eventnumber, int etype, int stype);
int	CheckObjective				(Node * Match, int eventnumber, char *username, char *match, char* matched);
// Node *	CheckObjective			(int eventnumber, char *username, char *match, int etype, int stype);
void	ResetCurrentNode		(void);
void	DestroyList				(void);
void	freeMatchLists			(void);
char *  string_split			(char divider,char *string,char *destination,int destlength);


// BOOL	ClearAllAuditCategories	(void);
void	ClearAuditFlags			(void);
int		SetAuditFlag			(POLICY_AUDIT_EVENT_TYPE AuditCategory, DWORD SuccessFailure);
int		SetObjectAuditFlag		(int ObjectSubCategory, GUID SubCatID, char *SubCatName, DWORD SuccessFailure);
BOOL	ApplyAudit				(void);
BOOL	TurnOnEvent				(DWORD EventID,DWORD SuccessFailure);

int		SetAuditEvent			(LSA_HANDLE PolicyHandle, POLICY_AUDIT_EVENT_TYPE EventType,
									 POLICY_AUDIT_EVENT_OPTIONS EventOption);
int		SetAuditMode			(LSA_HANDLE PolicyHandle, BOOL bEnable);

void	GetHostname				(char * Hostname,int size);
void	GetSyslog				(DWORD * dwSyslog);
void	GetSyslogDynamic		(DWORD * dwSyslogDynamic);
void	GetSyslogHeader			(DWORD * dwSyslogHeader);
void	GetWEBSERVER_ACTIVE		(DWORD * WEBSERVER_ACTIVE);
void	GetHANDLER_ACTIVE		(DWORD * HANDLER_ACTIVE);
void	GetWEBSERVER_TLS		(DWORD * WEBSERVER_TLS);
void	GetPortNumber			(DWORD * dwPortNumber);
void	GetSysAdminEnable		(DWORD * dwSAE);
void	GetTimesADay			(int * dwTAD);
void	GetNextTimeDiscovery	(DWORD * dwNT);
void	GetForceSysAdmin		(DWORD * dwFSA);
DWORD	GetVBS					();
void	GetChecksum				(BOOL * ActivateChecksum);
void	GetLeaveRetention		(BOOL * LeaveRetention);
void	GetCrit					(DWORD * dwCrit);
void	GetDestination			(char * lpszDestination,int size);
void	GetDelim				(char * DELIM,int size);
void	GetPassword				(char * lpszPassword,int size);
void	GetSentIndex			(char * sfile,int size, int *sindex);
void	SetSentIndex			(char * sfile,int sindex);
void	GetIPAddress			(char * lpszIPAddress,int size);
void	GetClearTabs			(DWORD * ClearTabs);
void	GetNumberFiles			(DWORD * dwNumberFiles);
void	GetMaxMsgSize			();
DWORD	GetTotalSavedLogs		(FILE * fp);
void	GetSavedLogsAt			(FILE * fp, char* line, int position);
BOOL	resetSafedCounter		(struct tm* newtime);
BOOL	changeCacheFileName		(struct tm newtime);

BOOL ImportMySessionBlob(HCRYPTPROV *hProv,LPBYTE pbKeyMaterial,DWORD dwKeyMaterial,HCRYPTKEY *hSessionKey);

int		StartWebThread(HANDLE event);
void	HandleWebThread(HANDLE event);

int		StartCollectThread(HANDLE event);
void CollectionThread(HANDLE event);


typedef struct _tagEVENTID
{
	TCHAR lpszMachineName[_MAX_PATH + 1];
	TCHAR lpszEventName[_MAX_PATH + 1];
	DWORD dwEventId;
	HWND  hwndDlg;
} EVENTID, *LPEVENTID;

// thread structure
typedef struct
{
	SOCKET hSocket;
	BOOL bTerminate;
} ThreadStruct;

typedef struct
{
	GUID SubCatGuid;
	char SubCatName[128];
	ULONG Flags;
} AuditSubCat;
