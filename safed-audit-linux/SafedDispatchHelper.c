#define _GNU_SOURCE

#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <locale.h>
#include "libaudit.h"

#define DEFAULT_NODES 4096
#define NEW_REC_TIMEOUT 2
#define PIDFILE "/var/run/safedaudit.pid"

struct safed_hdr {
	uint32_t type;
	uint32_t size;
	uint32_t serial;
	uint32_t datetime;
};

struct _node {
	void * line;
	struct safed_hdr hdr;
	short int watch;
	struct _node *next;
	struct _node *prev;
};

typedef struct _node Node;

// Local data
static volatile int signaled = 0;
static int pipe_fd;
static const char *pgm = "SafedDispatchHelper";
Node * phead=NULL;
Node * ptail=NULL;
Node * pcurrent=NULL;
Node * head=NULL;
Node * tail=NULL;
Node * current=NULL;
int PrimaryNodeCounter=0;
int SecondaryNodeCounter=0;
int NODECOUNT = DEFAULT_NODES;
pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER; 
pthread_mutex_t	data_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  list_data_available = PTHREAD_COND_INITIALIZER;
int ChildPID=0;

// Local functions
int merge_records(Node *dest, Node *src);
void line2data(char *s, struct safed_hdr *hdr);
void SafedDispatcher(int *);

// SIGTERM handler
static void term_handler( int sig )
{
	signaled = 1;
	if (ChildPID > 0) kill(ChildPID,SIGTERM);
}

void writepid(int pid) {
	FILE *pidfile;
	if ((pidfile = fopen(PIDFILE,"w"))) {
		fprintf(pidfile,"%d\n",pid);
		fclose(pidfile);
	} else {
		syslog(LOG_ERR, "... unable to open for writing the safed audit pid file");
	}
}

/*
 * main is started by auditd. See dispatcher in auditd.conf
 */
int main(int argc, char *argv[])
{
	struct sigaction sa;
	int PREV_ERROR=0,rc;
	int daemon2dispatch[2];	// Pipe from daemon to SafedDispatcher
	char exepath[1024];
	char exename[64];
	void* data;
	struct iovec vec_hdr[1],vec_data[1];
	struct audit_dispatcher_header a_hdr;

	setlocale (LC_ALL, "");
	openlog(pgm, LOG_PID, LOG_DAEMON);
	//syslog(LOG_NOTICE, "starting...");

#ifndef DEBUG
	// Make sure we are root
	if (getuid() != 0) {
		syslog(LOG_ERR, "You must be root to run this program.");
		return 4;
	}
#endif
	// register sighandlers
	sa.sa_flags = 0 ;
	sa.sa_handler = term_handler;
	sigemptyset( &sa.sa_mask ) ;
	sigaction( SIGTERM, &sa, NULL );
	sa.sa_handler = term_handler;
	sigemptyset( &sa.sa_mask ) ;
	sigaction( SIGCHLD, &sa, NULL );
	sa.sa_handler = SIG_IGN;
	sigaction( SIGHUP, &sa, NULL );
	(void)chdir("/");

	// change over to pipe_fd
	pipe_fd = dup(0);
	close(0);
	open("/dev/null", O_RDONLY);
	fcntl(pipe_fd, F_SETFD, FD_CLOEXEC);

	strncpy(exepath,"/usr/sbin/SafedDispatcher",sizeof(exepath));
	strncpy(exename,"SafedDispatcher",sizeof(exename));

        if (pipe(daemon2dispatch) == -1) {
                syslog(LOG_NOTICE,"Cannot open pipe for audit information");
                exit(1);
        }

	ChildPID=fork();
	if(ChildPID == -1) {
		syslog(LOG_NOTICE,"Cannot fork to execute the SafedDispatcher process");
		exit(3);
	} else if(ChildPID == 0) {
		// Child process
		if (dup2(daemon2dispatch[0], STDIN_FILENO) ==-1) {
                	syslog(LOG_NOTICE,"Could not reroute stdin for SafedDispatcher");
                        exit(4);
		}
		// Close unused files.
		close(daemon2dispatch[0]);
                close(daemon2dispatch[1]);

		execlp(exepath,exename,"-",(char *)0);
		syslog(LOG_NOTICE,"Could not execute the SafedDispatcher process");
		exit(5);
	}
	//parent
	writepid(ChildPID);
	close(daemon2dispatch[0]);
	pthread_t thread[1]; 

	// This is required to make sure the dispatcher can keep up with auditd
	// and prevent any dispatch errors
	nice(-1);

	pthread_create(&thread[0], NULL, (void *)SafedDispatcher, &daemon2dispatch[1]);

	// allocate data structure
	data = malloc(MAX_AUDIT_MESSAGE_LENGTH);
	if (data == NULL) {
		syslog(LOG_ERR, "Cannot allocate buffer");
		return 1;
	}

	//clear the memory
	memset(data, 0, MAX_AUDIT_MESSAGE_LENGTH);
	memset(&a_hdr, 0, sizeof(struct audit_dispatcher_header));

	/* Get header first. it is fixed size */
	vec_hdr[0].iov_base = (void*)&a_hdr;
	vec_hdr[0].iov_len = sizeof(struct audit_dispatcher_header);

	// Next payload, but we need to set the size according to the header
	vec_data[0].iov_base = data;


	do {
		struct timeval tv;
		fd_set fd;
		Node *new_rec=NULL;

		rc=0;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&fd);
		FD_SET(pipe_fd, &fd);

		// this will return -1 as soon as auditd exits
		rc = select(pipe_fd+1, &fd, NULL, NULL, &tv);
		if (rc == 0) continue;
		else if (rc == -1) break;

		//Grab the header
		rc = readv(pipe_fd, vec_hdr, 1);
		if (rc == 0 || rc == -1) {
			syslog(LOG_ERR, "rc == %d(%s). Exitting", rc, strerror(errno));
			break;
		}
		if (a_hdr.size > MAX_AUDIT_MESSAGE_LENGTH) {
			// Error, attempt to resync
			if (PREV_ERROR) {
				PREV_ERROR=0;
				lseek(pipe_fd,0,SEEK_END);
			} else {
				char garbage[MAX_AUDIT_MESSAGE_LENGTH];
				read(pipe_fd,garbage,MAX_AUDIT_MESSAGE_LENGTH);
				PREV_ERROR=1;
			}
			continue;
		}
		//Using the size defined in the header, grab the data section
		vec_data[0].iov_len = a_hdr.size; 
		rc = readv(pipe_fd, vec_data, 1);
		if (rc == 0 || rc == -1) {
			syslog(LOG_ERR, "rc2 == %d(%s). Exitting", rc, strerror(errno));
			break;
		}

		//Ignore CONFIG_CHANGE records
		if (a_hdr.type == 1305 || a_hdr.type == 1308) continue;
//if (a_hdr.type != 1300 && a_hdr.type != 1302 && a_hdr.type != 1307 && a_hdr.type != 1308 && a_hdr.type != 1301) {
//	syslog(LOG_NOTICE,"TYPE: %d:%s", a_hdr.type,(char *)data);
	//syslog(LOG_NOTICE,"TYPE: %d", a_hdr.type);
//}
		//Create the record and add it to the list (if there is room)
		if(PrimaryNodeCounter >= NODECOUNT * 2) {
			//sleep to see if we can clear some space
			sleep(2);
			if(PrimaryNodeCounter >= NODECOUNT * 2) {
				syslog(LOG_ERR,"* * * * * * * Memory top-stop hit - primary nodecounter is %d, max is %d.",PrimaryNodeCounter,NODECOUNT);
				continue;
			}
		}

		new_rec=(Node *)malloc(sizeof(Node));
		//memset(new_rec, 0, sizeof(Node));
		if (new_rec != NULL) {
			//memcpy(&new_rec->a_hdr,&a_hdr,sizeof(a_hdr));
			new_rec->hdr.size = a_hdr.size;
			new_rec->hdr.type = a_hdr.type;
			new_rec->line=malloc(MAX_AUDIT_MESSAGE_LENGTH);
			strncpy(new_rec->line,(char *)data,a_hdr.size);
			new_rec->next= NULL;
			new_rec->prev= NULL;
			pthread_mutex_lock(&list_mutex);
			if (ptail) {
				ptail->next = new_rec;
				new_rec->prev = tail;
				ptail = new_rec;
			} else {
				ptail = phead = new_rec;
			}
			PrimaryNodeCounter++;
			pthread_mutex_unlock(&list_mutex);
			pthread_cond_signal(&list_data_available);
		} else {
			syslog(LOG_ERR,"* * * * * * * Cannot allocate RAM for new event, event lost.");
			// Drop this event and sleep for a few seconds.
			sleep(5);
		}

	} while(!signaled);
	unlink(PIDFILE);
	return 0;
}

// Given a line from auditd, it will return the serial number (and date) or zero on error
void line2data(char *s, struct safed_hdr *hdr)
{
	char *ptr;

	if (strlen(s) < 20) return;
	errno = 0;
	ptr = strchr(s, '(');
	if (ptr) {
		hdr->datetime = strtoul(ptr+1, NULL, 10);
	}
	ptr = strchr(s+17, ':');
	if (ptr) {
		hdr->serial = strtoul(ptr+1, NULL, 10);
		if (errno) hdr->serial = 0;
	} else {
		hdr->serial = 0;
	}
}

// Given two Nodes, it will remove the audit(...) section from the source record
// and add it to the destination. It will also modify the headers accordingly
int merge_records(Node *dest,Node *src)
{
	char *ptr=NULL;
	char newstring[MAX_AUDIT_MESSAGE_LENGTH];
	int skip=0;

	if (strlen((char *)src->line) < 20) return 0;
	ptr = (char *)src->line;
	while (ptr) {
		skip++;
		if (*ptr == ' ') break;
		else ptr++;
	}
	if (!ptr) return 0;
	ptr++;
	src->hdr.size -= skip;
	snprintf(newstring,MAX_AUDIT_MESSAGE_LENGTH,"%.*s %.*s",dest->hdr.size, (char *)dest->line, src->hdr.size, ptr);
	strncpy(dest->line,newstring,MAX_AUDIT_MESSAGE_LENGTH);
	dest->hdr.size = dest->hdr.size + src->hdr.size + 1;
	if (dest->hdr.size > MAX_AUDIT_MESSAGE_LENGTH) dest->hdr.size = MAX_AUDIT_MESSAGE_LENGTH;
	return 1;
}

// Spawned as a pthread, this function is used to pass the complete messages onto SafedDispatcher
void SafedDispatcher(int *WRITEPOINTER) {
	Node * mycurrent;
	int continueloop=1, wait=0;
	int length,leftover=0;
	struct timespec timeout;
	time_t now;
	int headersize = sizeof(struct safed_hdr);

	pthread_mutex_lock(&data_mutex);
	while(continueloop && !signaled) {
		// Waiting for head to be valid
		time(&now);
		// Run this thread every second, or when signaled.
		timeout.tv_sec = now + 1;
		timeout.tv_nsec = 0;
		pthread_cond_timedwait(&list_data_available,&data_mutex,&timeout);
		wait++;
		// Ok, check for more data
//#############################################
		mycurrent = phead;
		while(mycurrent && !signaled) {
			wait=0;
			int match=0;
			line2data((char *)mycurrent->line,&mycurrent->hdr);
			if (mycurrent->hdr.serial == 0) {
				syslog(LOG_ERR,"BAD SERIAL, skipping [%.*s]", mycurrent->hdr.size, (char *)mycurrent->line);
				pthread_mutex_lock(&list_mutex);
				phead = mycurrent->next;
				if (phead) phead->prev = NULL;
				free(mycurrent->line);
				free(mycurrent);
				if (!phead) ptail = NULL;
				mycurrent = phead;
				pthread_mutex_unlock(&list_mutex);
				continue;
			}
			mycurrent->watch = 0;
			//syslog(LOG_NOTICE, "Node created, now processing");
			current=tail;
			while (current != NULL) {
				//syslog(LOG_NOTICE,"serial compare %lu", current->hdr.serial);
				if (current->hdr.serial == mycurrent->hdr.serial) {
					//matching records, just add the lines together
					match++;
					//NB.AUDIT_FS_WATCH       1301     * Deprecated
					if ( (!(current->hdr.type == 1301 && current->watch)) && merge_records(current,mycurrent)) {
						if (current->hdr.type == 1301) current->watch=1;
						pthread_mutex_lock(&list_mutex);
						phead = mycurrent->next;
						if (phead) phead->prev = NULL;
						free(mycurrent->line);
						free(mycurrent);
						PrimaryNodeCounter--;
						if (!phead) ptail = NULL;
						mycurrent = phead;
						pthread_mutex_unlock(&list_mutex);
					} else {
						if (mycurrent) {
							pthread_mutex_lock(&list_mutex);
							phead = mycurrent->next;
							if (phead) phead->prev = NULL;
							free(mycurrent->line);
							free(mycurrent);
							PrimaryNodeCounter--;
							if (!phead) ptail = NULL;
							mycurrent = phead;
							pthread_mutex_unlock(&list_mutex);
						}
					}
					break;
				}
				current = current->prev;
			}
			if (!match) {
				//if no merge move the node from the first to the second list; SecondaryNodeCounter++; PrimaryNodeCounter--; stop when added 100 new nodes (completed lines)
				//syslog(LOG_NOTICE, "no match, adding new record");
				if(SecondaryNodeCounter >= NODECOUNT) {
					syslog(LOG_ERR,"* * * * * * * Memory top-stop hit - secondary nodecounter is %d, max is %d.",SecondaryNodeCounter,NODECOUNT);
					// For the moment, just log, and sleep for a few seconds.
					sleep(5);
					continue;
				}

				if(!mycurrent->hdr.size) {
					//No data, drop the record and continue straight away
					syslog(LOG_ERR,"ERROR: No Data");
					pthread_mutex_lock(&list_mutex);
					phead = mycurrent->next;
					if (phead) phead->prev = NULL;
					free(mycurrent->line);
					free(mycurrent);
					PrimaryNodeCounter--;
					if (!phead) ptail = NULL;
					mycurrent = phead;
					pthread_mutex_unlock(&list_mutex);
					continue;
				}

				pthread_mutex_lock(&list_mutex);
				phead = mycurrent->next;
				if (phead) phead->prev = NULL;
				PrimaryNodeCounter--;
				if (!phead) {
					ptail = NULL;
				}
				pthread_mutex_unlock(&list_mutex);

				SecondaryNodeCounter++;
				if(tail) {
					mycurrent->prev = tail;
					tail->next=mycurrent;
				}
				tail=mycurrent;
				tail->next=NULL;
				if(!head) {
					head=tail;
				}

				mycurrent = phead;
			}
			if (SecondaryNodeCounter > leftover + 100) break;
		}
//#############################################
		//try send lines from the second list exept the last line which could be not completed;filter filterkey=safedignore; leftover = number of sending failed  lines
		mycurrent=head;
		while(mycurrent && !signaled) {
			struct iovec vec[2];
			int i,newstart=0;
			char *newline=NULL;

			// all but the last record should be complete
			// unless we've been waiting
			if (mycurrent == tail && wait < 2) break;
			wait=0;

			// check if we should ignore this event
			if (strstr((char *)mycurrent->line,"filterkey=safedignore") == NULL) {
				//strip newlines
				for (i=0;i<mycurrent->hdr.size;i++) {
					//look for the first space signalling the header
					if (!newstart && ((char *)mycurrent->line)[i] == ' ') {
						newstart=1;
						newline=&((char *)mycurrent->line)[i];
						mycurrent->hdr.size -= i;
					}
					//replace all CR/NL with a space
					if (((char *)mycurrent->line)[i] == '\n' || ((char *)mycurrent->line)[i] == '\r') {
						((char *)mycurrent->line)[i] = ' ';
					}
				}

				vec[0].iov_base = (void*)&mycurrent->hdr;
				vec[0].iov_len = headersize;

				// Next payload 
				vec[1].iov_base = newline;
				vec[1].iov_len = mycurrent->hdr.size; 

				length=writev(*WRITEPOINTER,vec,2);
			} else {
				//ignore the event and just free it
				//syslog(LOG_NOTICE,"Rejecting message");
				length = 1;
			}
			if(length == -1) {
				// Oh dear - write error. Check that WRITEPOINTER is still ok
				if (!WRITEPOINTER) {
					syslog(LOG_ERR,"PTHREAD: * * * * * * * Write error %d in SafedDispatcher. WRITEPOINTER has failed, restarting.",errno);
					execlp("/etc/init.d/auditd","auditd","restart","&",(char *)0);
				} else {
					//Sleep and try again
					syslog(LOG_ERR,"PTHREAD: * * * * * * * Write error %d in SafedDispatcher thread within helper. Continuing after a 5 second delay.",errno);
					sleep(5);
					break;
				}
			} else if(length == 0) {
				syslog(LOG_ERR,"PTHREAD: * * * * * * * Write failure - 0 bytes sent. Continuing after a 5 second delay.");
				sleep(5);
				break;
			} else {
				// Just in case the variable has gone away
				if(!mycurrent) {
					syslog(LOG_NOTICE,"PTHREAD: Bad continue");
					continue;
				}
				pthread_mutex_lock(&list_mutex);
				head=mycurrent->next;
				if (head) head->prev=NULL;
				free(mycurrent->line);
				free(mycurrent);
				SecondaryNodeCounter--;
				pthread_mutex_unlock(&list_mutex);
				mycurrent=head;
				if(!mycurrent) {
					tail=NULL;
				}
			}
		}
		leftover=SecondaryNodeCounter;
//#############################################
	}
	//syslog(LOG_ERR,"Leaving dispatch loop");
}
