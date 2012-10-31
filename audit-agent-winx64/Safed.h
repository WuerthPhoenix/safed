/*
FILE: Safed.h
*/


#include <Dbt.h>
#include <process.h>
#include <ntsecapi.h>
#include <regex.h>
#include "NTService.h"



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
	char sysadmin[SIZE_OF_GENERALMATCH + 7];// in case of sys admin discovery contains "'" separated admins + SYSTEM
	regex_t regexpCompiled;
	int regexpError;	
	struct _node *next;
};

typedef struct _node Node;

// Store a linked list of our target destinations.


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
	HANDLE *m_hEventList; // minimum 8 elements, 6 standard event logs, 1 web event 1 Safed thread
	HANDLE *m_hRestartEventList; // 1 web event 1 Safed thread

	HANDLE *hEventLog;
};

// Function Prototypes.
int		RunServer				();
SOCKET	StartServer				(UINT, char *);
BOOL	WINAPI ClientThread		(LPVOID);

void	syslogdate				(char *, struct tm *);

int		wildmatch				(char *, char *);
void	splitstrings			(char *, int, char *, int);

BOOL	GetCategoryString		(PEVENTLOGRECORD pELR, char *Trigger, char *Source, char *StringBuffer, DWORD length);
BOOL	GetEventLogType			(TCHAR *sz, unsigned short uEventType, DWORD length);
BOOL	GetSIDType				(SID_NAME_USE _SidNameUse, TCHAR *szSIDType, DWORD length);
BOOL	ExpandStrings			(PEVENTLOGRECORD pELR, char *Trigger, char *StringBuffer, DWORD length);
BOOL	GetDataString			(PEVENTLOGRECORD pELR, char *StringBuffer, DWORD length);
void	GetArgs					(const EVENTLOGRECORD *pELR, char **Args);
BOOL	GetEventUserName		(EVENTLOGRECORD *pELR, char * lpszUser, int length, SID_NAME_USE *snu);

BOOL	CheckLogExists			(TCHAR *LogName, int LeaveRetention);
char *	GetParameterMsg			(char *message, char *tmp);
void	GetFQDN					(char *string,int length);

int		ReadObjectives();
void	AddToList				(int eventbottom, int eventtop, char *username, char *match, int criticality,int excludematchflag, int excludeidflag,
								 int excludeflag, int muserflag, int eventlogtype, int sourcename, int objectivecount);

static Node * FastCheckObjective	(int eventnumber, int etype, int stype);
int	CheckObjective				(Node * Match, int eventnumber, char *username, char *match, char* matchedstr);
// Node *	CheckObjective			(int eventnumber, char *username, char *match, int etype, int stype);
void	ResetCurrentNode		(void);
void	DestroyList				(void);
void	freeMatchLists			(void);
char *  string_split			(char divider,char *string,char *destination,int destlength);

void	ClearAuditFlags			(void);
int		SetAuditFlag			(POLICY_AUDIT_EVENT_TYPE AuditCategory, DWORD SuccessFailure);
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
void	check_usb_enabled		();
BOOL	resetSafedCounter		(struct tm* newtime);
BOOL	changeCacheFileName		(struct tm newtime);
BOOL	ImportMySessionBlob(HCRYPTPROV *hProv,LPBYTE pbKeyMaterial,DWORD dwKeyMaterial,HCRYPTKEY *hSessionKey);

int		StartWebThread(HANDLE event);
void	HandleWebThread(HANDLE event);

void	DEBUGDumpEventLog(DWORD EventTriggered,DWORD dwBytesRead,PEVENTLOGRECORD pELR);

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
