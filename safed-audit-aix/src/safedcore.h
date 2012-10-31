#ifndef _SAFEDCORE_H
#define _SAFEDCORE_H
/**********************************************************
 * SAFED for UNIX (Linux, Solaris, HP-UX)
 * Author: Wuerth-Phoenix s.r.l.,
 * made starting from:
 * Snare for AIX header file
 *
 * Author: InterSect Alliance Pty Ltd
 *
 * Copyright 2001-2010 InterSect Alliance Pty Ltd
 *
 * Last Modified: 7/12/2004
 *
 * Available under the terms of the GNU Public Licence.
 * - See www.gnu.org
 *
 **********************************************************
 *
 * History:
 *       7/11/2004  Initial working version
 *
 **********************************************************/

#define PIDFILE "/var/run/safedaudit.pid"

#define LOGGING_DEFAULT 0
#define LOGGING_ERROR 1
#define LOGGING_NORMAL 2
#define LOGGING_DEBUG 3
#define LOGGING_LEVELS 4
// Linked List
struct _node
{
	// int event_number;	// The event number this is supposed to match
	char event_name[MAX_EVENTNAME];	// The event number this is supposed to match
	int criticality;	// How critical is this particular node
	int returncode;		// return code required.
	int excludeflag;	// Include or exclude users?
	int excludematchflag;	// Include or exclude the match?
	char username[MAX_USERREG];	// Remember, this will be a regular expression.
	regex_t usernameRE;
	char path[MAX_PATH];	// NOTE: this could match either path or destpath
	regex_t pathRE;
	char options[MAX_OPTIONS];	// Options associated with a audit type (eg: O_RDONLY|O_CREAT)
	regex_t optionsRE;
	struct _node *next;
};

typedef struct _node Node;




void	pipe_signal();		/* Routine to handle SIGPIPEs */
void	kill_signal();		/* Routine to handle SIGTERMs */
void	usr1_signal();

int		turn_event_on(int);
int		turn_event_off(int);
int		setclass(unsigned int);
int		read_config_file(int);
char *	gethostident(char *string, char *host,int length);
char *	getconfstring(char *string, char *file,int length);

int		setsignals(sigset_t *signalset);
int flush_audit_events(void);

void	trim(char *string);
void	trimallwhitespace(char *string);
int		IsListEmpty(void);

int audit_off(void);
int iscomment(char *);
int isheader(char *);
int getheader(char *);
int splitobjective(char *,char *,char *,char *,int *,int *,int *);
int getLogLevel(char *);
int regmatch(const char *, const char *);
int regmatchi(const char *, const char *);
int sendevent(char *,int);
void syslogdate(char *, struct tm *);
int issyslog(char *);
int get_syslog_dest(char *);



Node *	AddToList(char *eventname, char *username, char *path, int criticality, char *options, int excludeflag, int excludematchflag, int returncode);
char *	getfqdn(char * FQDN);

Node *	CheckObjective(char *username,char *searchterm, char *eventname, char *options, int returncode);
char *	FormatDelimiters(char *eventbuffer);
int		GetAIXDetails(char *logbuffer, char *username, char *searchterm, char *eventname, char *options);
int GetElement(char *source, int count, char *dest, int buffersize);
Node *GetCurrentItem(void);

char *FindToken(char *,char *);

void DestroyList(void);

int open_audit_output(char *);


void DebugMsg(int level, const char *,...);

#endif //_SAFEDCORE_H
