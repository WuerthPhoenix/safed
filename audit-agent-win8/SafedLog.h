#include "support.h"
#define MAX_SEP 32


#define ENT_HTML_QUOTE_NONE        0
#define ENT_HTML_QUOTE_SINGLE    1
#define ENT_HTML_QUOTE_DOUBLE    2
#define ENT_COMPAT        ENT_HTML_QUOTE_DOUBLE
#define ENT_QUOTES        (ENT_HTML_QUOTE_DOUBLE | ENT_HTML_QUOTE_SINGLE)
#define ENT_NOQUOTES    ENT_HTML_QUOTE_NONE
#define MAX_LINE_GRAB 10
#define DEFAULT_CACHE 320000
#define DIR_NEW_FILE 2

struct _e_node
{
	int excludematchflag;				// Include or exclude search term matches?
	char match[SIZE_OF_GENERALMATCH];
	regex_t regexpCompiled;
	int regexpError;
	struct _e_node *next;
};

typedef struct _e_node E_Node;


struct _log_node
{
	// firstly, is this actually a directory that we are just
	// watching for the latest file:
	int dir;
	int dir_check;
	char dir_name[SIZE_OF_LOGNAME];
	// If it is a directory, we can also record the desired format
	char format[SIZE_OF_LOGNAME];

	// File name
	char name[SIZE_OF_LOGNAME];
	char old_name[SIZE_OF_LOGNAME]; //since there is no indode, we need other ways of tracking files

	/* File stream on which the file is open; -1 if it's not open. */
	FILE *fs;

	// partial msg storage
	char pmsg[MAX_EVENT];

	//MULTI LINE EVENTS
	//flag specifying a multiline format event
	int multiline;
	//event separator if not fixed length events
	char separator[MAX_SEP];
	//number of lines if fixed length
	int linecount;
	//counter of current lines stored in buffer
	int lines;
	

	// Log type
	char type[MAX_TYPE];

	/* Attributes of the file the last time we checked. */
	__int64 old_size;
	__int64 size;
	time_t mtime;
	_dev_t dev;
	_ino_t ino;
	unsigned short mode;
	
	// a flag used to identify when there are still more entries to grab.
	int still_more;
	// a flag specifying if commented lines (those starting with #) should be sent
	int send_comments;

	// When did the last error occur (zero means no error)
	time_t last_error;

	struct _log_node *next;
};

typedef struct _log_node LogNode;


//htmlspecialchars
static const struct { 
    unsigned short charcode; 
    char *entity; 
    int entitylen; 
    int flags; 
}basic_entities[]={ 
    {'&', "&amp;", 5,0}, 
    {'"', "&quot;",6,ENT_HTML_QUOTE_DOUBLE}, 
    {'\'',"&#039;",6,ENT_HTML_QUOTE_SINGLE}, 
    {'<', "&lt;",    4,0}, 
    {'>', "&gt;",    4,0}, 
    {0,NULL,0,0} 
}; 

int StartSafedEThread(HANDLE event);
void RunSafedE(HANDLE event);
int E_CheckObjective(char *searchterm);
int E_ReadObjectives();
void E_AddToList(char *match, int excludematchflag);
void E_DestroyList(void);
int ReadLogs();
int AddLogWatch(Reg_Log *rl);
int file_has_changed (LogNode *f, int fd);
int FindDirFile(LogNode *f);
int htmlspecialchars(char *src,char **ret,int type);
int CloseSafedE();
char *	getdate					(char *date, BOOL ytday = false);
BOOL isNotClosed();