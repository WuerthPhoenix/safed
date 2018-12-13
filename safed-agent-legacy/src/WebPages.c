#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

//TODO: rimuovere questa dipendenza
#include "safed.h"

#include "Configuration.h"
#include "Misc.h"
#include "webserver.h"
#include "WebPages.h"
#include "WebPagesAudit.h"
#include "webutilities.h"
#include "MessageFile.h"
#include "Configuration.h"
#ifdef TLSPROTOCOL
	#include "SafedTLS.h"
#endif

#define VERSION "1.9.1"


extern void trim(char *);
extern int isheader(char *);
extern int iscomment(char *);
extern int getheader(char *);
extern char *getconfstring(char *string, char *file, int length);
extern int regmatchInsensitive(const char *, const char *);
extern int getport(char *string);


extern char USER_CONFIG_FILENAME[MAX_AUDIT_CONFIG_LINE];

extern HostNode host;
extern char lastSetTime[25];
extern char initStatus[100];
extern int remoteControlHttps;
char setConfigStatus[80] = "";
char getConfigStatus[80] = "";
char lastConnectionStatus[80] = "";



#define LSC_MSG "Last set of configuration from NetEye server"
#define LGC_MSG "Last get of configuration from NetEye server"
#define LCS_MSG "Last connection from NetEye server"
regex_t logPattern;

// forward declarations -- just to avoid compilation warnings
int ArrowImage(char *source, char *dest, int size);
int CfgImage(char *source, char *dest, int size);
int getLogFileToKeep(char *string);
int getLogLevel(char *string);
int isLogFileToKeep(char *string);
int ListImage(char *source, char *dest, int size);
int Log_Config(char *source, char *dest, int size);
int Log_Display(char *source, char *dest, int size);
int Log_Result(char *source, char *dest, int size);
int LogoImage(char *source, char *dest, int size);
int SafedLog_Page(char *source, char *dest, int size);
int SaveImage(char *source, char *dest, int size);
int SearchImage(char *source, char *dest, int size);
int StatusImage(char *source, char *dest, int size);


// Make sure we return the size, or zero (for strings).
#ifdef TLSPROTOCOL
int HandleWebPages(char *HTTPBuffer, char *HTTPOutputBuffer, int size, int http_listen_socket, int http_message_socket, gnutls_session_t session_https, char* fromServer)
#else
int HandleWebPages(char *HTTPBuffer, char *HTTPOutputBuffer, int size, int http_listen_socket, int http_message_socket, char* fromServer)
#endif
{
	int returncode = 0;
	char *ArgPosition;

	if(fromServer && strlen(fromServer) > 0){
		snprintf(lastConnectionStatus,sizeof(lastConnectionStatus),"%s %s\n", LCS_MSG, fromServer);
	}else{
		lastConnectionStatus[0]='\0';
	}

	// Stuff without the header/footer
	if (!strcmp(HTTPBuffer, "/logo.gif")) {
		return (LogoImage(HTTPBuffer, HTTPOutputBuffer, size));
	} else if (!strcmp(HTTPBuffer, "/cfg.gif")) {
		return (CfgImage(HTTPBuffer, HTTPOutputBuffer, size));
	} else if (!strcmp(HTTPBuffer, "/search.gif")) {
		return (SearchImage(HTTPBuffer, HTTPOutputBuffer, size));
	}else if (!strcmp(HTTPBuffer, "/list.gif")) {
		return (ListImage(HTTPBuffer, HTTPOutputBuffer, size));
	}else if (!strcmp(HTTPBuffer, "/status.gif")) {
		return (StatusImage(HTTPBuffer, HTTPOutputBuffer, size));
	}else if (!strcmp(HTTPBuffer, "/arrow.gif")) {
		return (ArrowImage(HTTPBuffer, HTTPOutputBuffer, size));
	}else if (!strcmp(HTTPBuffer, "/save.gif")) {
		return (SaveImage(HTTPBuffer, HTTPOutputBuffer, size));
	} else {
		char *pBuffer = HTTPOutputBuffer;
		int length = 0;
		int psize = 0;

		ArgPosition = strstr(HTTPBuffer, "?");
		// No arguments passed?
		if (!ArgPosition) {
			// Set argument position to the beginning of the buffer.
			ArgPosition = HTTPBuffer;
		} else {
			ArgPosition++;
		}
        if(!strcmp(HTTPBuffer,"/GetConfig")) {
#ifdef TLSPROTOCOL
                GetConfig(http_message_socket, session_https, fromServer);
#else
                GetConfig(http_message_socket, fromServer);
#endif
                return(-1);
        }



		returncode = DefaultHeader(HTTPBuffer, pBuffer, size);
		length = strlen(HTTPOutputBuffer);

		pBuffer += length;
		psize = size - length;
		if (psize < 0) {
			psize = 0;
		}

		if (!strncmp(HTTPBuffer, "/License", 8)) {
			return(ShowLicense(HTTPOutputBuffer, size));
		}
		// Web pages
		if (!strcmp(HTTPBuffer, "/network")) {
			returncode += Network_Config(ArgPosition, pBuffer, psize);
		} else if (!strcmp(HTTPBuffer, "/remote")) {
			returncode += Remote_Config(ArgPosition, pBuffer, psize);
		} else if (!strncmp(HTTPBuffer, "/setremote", 10)) {
			returncode += Remote_Set(ArgPosition, pBuffer, psize);
		}
#if defined(__sun) || defined(_AIX) || defined(__linux__)
		else if (!strncmp(HTTPBuffer, "/safed/objective", 16)) {
			returncode += Audit_Objective_Config(ArgPosition, pBuffer, psize);
		} else if (!strncmp(HTTPBuffer, "/safed/setobjective", 19)) {
			returncode += Audit_Objective_Display(HTTPBuffer, pBuffer, psize);
		} else if (!strncmp(HTTPBuffer, "/safed/changeobjective", 22)) {
			returncode += Audit_Objective_Result(ArgPosition, pBuffer, psize);
		}
#endif
#if defined(__linux__)
		else if (!strncmp(HTTPBuffer, "/safed/watch", 12)) {
			returncode += Watch_Config(ArgPosition, pBuffer, psize);
		} else if (!strncmp(HTTPBuffer, "/safed/setwatch", 14)) {
			returncode += Watch_Display(HTTPBuffer, pBuffer, psize);
		} else if (!strncmp(HTTPBuffer, "/safed/changewatch", 18)) {
			returncode += Watch_Result(HTTPBuffer, pBuffer, psize);
		}
#endif
		else if (!strncmp(HTTPBuffer, "/log/objective", 14)) {
			returncode += Objective_Config(ArgPosition, pBuffer, psize);
		} else if (!strncmp(HTTPBuffer, "/log/setobjective", 17)) {
			returncode += Objective_Display(HTTPBuffer, pBuffer, psize);
		} else if (!strncmp(HTTPBuffer, "/log/changeobjective", 20)) {
			returncode += Objective_Result(HTTPBuffer, pBuffer, psize);
		} else if (!strncmp(HTTPBuffer, "/log", 4)) {
			returncode += Log_Config(ArgPosition, pBuffer, psize);
		} else if (!strncmp(HTTPBuffer, "/setlog", 7)) {
			returncode += Log_Display(HTTPBuffer, pBuffer, psize);
		} else if (!strncmp(HTTPBuffer, "/changelog", 10)) {
			returncode += Log_Result(HTTPBuffer, pBuffer, psize);
		} else if (!strcmp(HTTPBuffer, "/restart")) {
			returncode += Restart(HTTPBuffer, pBuffer, psize, http_listen_socket, http_message_socket);
		} else if (!strncmp(HTTPBuffer, "/setnetwork", 11)) {
			returncode += Network_Set(HTTPBuffer, pBuffer, psize);
		} else if(!strcmp(HTTPBuffer,"/config")) {
			returncode+=Config(ArgPosition,pBuffer,psize);
		}
#ifdef TLSPROTOCOL
		else if(!strcmp(HTTPBuffer,"/certs")) {
			returncode+=Certs(ArgPosition,pBuffer,psize);
		}
#endif
		else if(!strncmp(HTTPBuffer,"/setconfig",10)) {
			returncode+=SetConfig(ArgPosition,pBuffer,psize, fromServer);
		}
#ifdef TLSPROTOCOL
		else if(!strncmp(HTTPBuffer,"/setca",6)) {
			returncode+=SetCertificate(ArgPosition,pBuffer,psize,getCAFILE());
		} else if(!strncmp(HTTPBuffer,"/setcert",8)) {
			returncode+=SetCertificate(ArgPosition,pBuffer,psize,getCERT_FILE());
		} else if(!strncmp(HTTPBuffer,"/setkey",7)) {
			returncode+=SetCertificate(ArgPosition,pBuffer,psize, getKEY_FILE());
		}
#endif
		else if (!strncmp(HTTPBuffer, "/status", 7)) {
			returncode += Status_Page(ArgPosition, pBuffer, psize);
		} else if(!strncmp(HTTPBuffer,"/safedlog",9)) {
			returncode+=SafedLog_Page(ArgPosition,pBuffer,psize);
		}  else if(!strncmp(HTTPBuffer,"/dailylog",9)) {
		        returncode += Daily_Events(ArgPosition,pBuffer,psize,0);
		}else if(!strncmp(HTTPBuffer,"/geteventlogat",14)) {
	       		 returncode += Daily_Events(ArgPosition,pBuffer,psize,1);
	        }else {
            		returncode += Daily_Events(ArgPosition,pBuffer,psize,0);
                }


		pBuffer = HTTPOutputBuffer;
		length = strlen(HTTPOutputBuffer);
		pBuffer += length;
		psize = size - length;
		if (psize < 0) {
			psize = 0;
		}

		returncode += DefaultFooter(HTTPBuffer, pBuffer, psize);

	}

	return (returncode);
}



int safedlogfilter(const struct dirent *entry) {
	static int firstTime = 1;
	if (firstTime) {
		firstTime = 0;
		regcomp(&logPattern, "^safed.log.?[0-9]*", REG_EXTENDED | REG_NOSUB);
	}
	return (regexec(&logPattern, entry->d_name, (size_t) 0, NULL, 0) == 0);
}

void getFullFileNames(char* filename){
	char filetmp[260];
	strcpy(filetmp,filename);
	filename[0]='\0';
	sprintf(filename,"%s//%s",LOGFILE_DIR,filetmp);
}


char** getAllLogFileNames(int* number) {

	struct dirent **namelist;
	int n = 0;
	int i = 0;
	char* filename = NULL;
	char **list = NULL;

	n = scandir(LOGFILE_DIR, &namelist, safedlogfilter, alphasort);

	if (n < 0){
		perror("scandir\n");
	}else {
		list = (char **)malloc(n*sizeof(char*));
		while(i < n) {
			if(list){
				filename = malloc(strlen(namelist[i]->d_name) + 1);
				if(filename){
					strcpy(filename,namelist[i]->d_name);
					list[i] = filename;

				}
			}
			free(namelist[i]);
			i++;
			*number=i;
		}
		free(namelist);
	}
	if(!list){
			*number=0;
	}

	return list;
}


// This page will be usefull for debug information
int SafedLog_Page(char *source, char *dest, int size)
{

	char filename[260];
	char *psource=source, Variable[100]="", Argument[100]="", number_s[100]="", file_s[255]="", fileO_s[255]="";
	int numberorig = 0;
	int number = 0;
	int numberFrom = 0;
	int numberTo = 0;
	int total = 0;
	int MAX = 80;
	int MAXLINE = 200;
	int next = -1;
	char line[LOGBUFSIZE];
	int usefile = 0;
	FILE *file = (FILE *)NULL;
	int nLogs = 0;

	int numberoffiles=0;
	struct stat stats;


	char** filelist = getAllLogFileNames(&numberoffiles);
	int cnt = 0;
	while((psource=getNextArgument(psource,Variable,sizeof(Variable)-1,Argument,sizeof(Argument)-1)) != (char *)NULL)
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
			strncpy(number_s,Argument,sizeof(number_s));
			number = atoi(number_s);
		}
		if (strstr(Variable,"numberO") != NULL) {
			strncpy(number_s,Argument,sizeof(number_s));
			numberorig = atoi(number_s);
		}
		if (strstr(Variable,"numberFrom") != NULL) {
			strncpy(number_s,Argument,sizeof(number_s));
			numberFrom = atoi(number_s);
		}
		if (strstr(Variable,"numberTo") != NULL) {
			strncpy(number_s,Argument,sizeof(number_s));
			numberTo = atoi(number_s);
		}

		if (strstr(Variable,"thefile") != NULL) {
			strncpy(file_s,Argument,sizeof(file_s));
		}
		if (strstr(Variable,"thefileO") != NULL) {
			strncpy(fileO_s,Argument,sizeof(fileO_s));
		}
	}

	if((number < 1) || (number > MAX)){
		number = MAX;
	}
	if(numberFrom < 1) numberFrom = 1;
	if(numberTo < numberFrom) numberTo = numberFrom;


	if(strlen(file_s) == 0){
		if(numberoffiles > 0){
			snprintf(file_s,sizeof(file_s),"%s",LOGFILE_NAME);
			usefile = 1;
		}
	}else{
		for(cnt = 0; cnt < numberoffiles; cnt++){
			if(!strcmp(filelist[cnt],file_s)){
				usefile = 1;
				break;
			}
		}
	}
	strcpy(filename,file_s);


	sprintf(dest,"<HTML><BODY><form method=get action=/safedlog><H2><CENTER>Logs for %s",file_s);
	if (usefile) {
		getFullFileNames(filename);
		if (!stat(filename, &stats)){
			sprintf(dest,"%s %d bytes",dest,(int) stats.st_size);
		}
		file = fopen(filename,"r");
		if(file) {
				nLogs = getTotalSavedLogs(file);
				fclose(file);
		}

	}
	sprintf(dest,"%s</CENTER></H2><BR/><br/><CENTER><textarea rows=\"30\" cols=\"100\" readonly=\"readonly\" style=\"background-color: rgb(231,231,231)\">\n",dest);
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

	//sprintf(dest,"<HTML><BODY><form method=get action=/safedlog><H2><CENTER>Logs for %s</CENTER></H2><BR/><br/><CENTER><textarea rows=\"%d\" cols=\"100\" readonly=\"readonly\" style=\"background-color: rgb(231,231,231)\">\n",file_s,number);


	if (usefile) {
		file = fopen(filename,"r");
		if(file){
			getSavedLogAt(file, line, numberFrom);//place it to numberFrom line
			if(strlen(line)){
				if(strlen(line) > MAXLINE){
					line[MAXLINE -2] = '\n';
					line[MAXLINE -1] = '\0';
				}
				sprintf(dest,"%s%s",dest,line);
				total++;
				int i= 0;
				for (i=(numberFrom+1);  i < numberTo ; i++) {
					getSavedLogAt(file, line, 0);// give the next line
					if(strlen(line)){
						if(strlen(line) > MAXLINE){
							line[MAXLINE -2] = '\n';
							line[MAXLINE -1] = '\0';
						}
						sprintf(dest,"%s%s",dest,line);
						total++;
					}else break;
				}
			}
			fclose(file);
		}
	}


	if((total < number) && (next || (numberFrom == 0))){
		numberTo = numberTo - number + total;
	}

	//printf("============ %d  %d  %d  %s  %s  %s\n",number, numberFrom, numberTo, file_s, fileO_s, filename);
	//limit is set to 80 lines due to tls limits of 16384 bytes!!!
	sprintf(dest,"%s</textarea></CENTER><CENTER><BR/>Shown lines from %d to %d <br/><br/><input type=hidden name=thefileO size=\"8\" value=\"%s\"/><input type=hidden name=numberO size=\"2\" value=\"%d\"/><input type=text name=numberW size=\"3\" value=\"%d\"/> lines per page (max 80 allowed) for <select name=thefile></CENTER>\n",dest, (numberFrom + 1), (numberFrom + total), fileO_s, numberorig, number);
	for(cnt = 0; cnt < numberoffiles; cnt++){
		if(filelist[cnt]){
			sprintf(dest,"%s<option",dest);
			if (!strcmp(file_s,filelist[cnt])) {

				sprintf(dest,"%s selected>",dest);
			} else {
				sprintf(dest,"%s>",dest);
			}
			sprintf(dest,"%s%s",dest,filelist[cnt]);
			free(filelist[cnt]);
		}
	}

	sprintf(dest,"%s</select><input type=hidden name=numberFrom size=12 value=\"%d\"/><input type=hidden name=numberTo size=12 value=\"%d\"/></CENTER>\n",dest, (numberFrom + 1), numberTo + 1);
	sprintf(dest,"%s<br/><CENTER><input type=submit name=btnPrevious value=\"Previous\"/><input type=submit name=btnNext value=\"Next\"/><input type=submit name=btnLast value=\"Last\"/></CENTER></form>",dest );


	if(filelist)free(filelist);

	return(0);
}


int Status_Page(char *source, char *dest, int size)
{
	if (source && dest && size) {
		if(strlen(setConfigStatus) == 0){
			if(strlen(lastSetTime) > 0){
					snprintf(setConfigStatus,sizeof(setConfigStatus),"%s %s\n", LSC_MSG, lastSetTime);
			}
		}

		struct stat buf;
		char socketStatus[600] = "";
		time_t ctime;
		time(&ctime);
		struct tm *ntime = localtime(&ctime);;
		char thedate[25] = "";
		snprintf(thedate,sizeof(thedate),"[%04d/%02d/%02d - %02d:%02d:%02d]",ntime->tm_year+1900,ntime->tm_mon+1,ntime->tm_mday,ntime->tm_hour,ntime->tm_min,ntime->tm_sec);
		char color[6]="green";
		if(!stat(SOCKETSTATUSFILE, &buf)){
			snprintf(socketStatus,sizeof(socketStatus),"The connection %s to %s is up! %s\n",host.protocolName, host.desthost, thedate);
		}
		else{
			snprintf(socketStatus,sizeof(socketStatus),"The connection %s to %s is down! %s\n", host.protocolName, host.desthost, thedate);
			strcpy(color,"red");
		}

		snprintf(dest,size,"<H1><CENTER>Welcome to SafedAgent for UNIX version %s</H1><P>Please select from the menu on the left.</CENTER><p>\n"
									   "<center>Status: <font color=green>SafedAgent for UNIX currently running.</font></center><p>\n"
									   "<center><b><font color=%s size=-1>%s</font></b></center><p>\n"
						   "<center><b><font color=red size=-1>%s</font></b></center><p>\n"
			                           "<center><font size=-1>%s</font></center><p>\n"
			                           "<center><font size=-1>%s</font></center><p>\n"
			                           "<center><font size=-1>%s</font></center>"
									   ,VERSION,color,socketStatus,initStatus,lastConnectionStatus,setConfigStatus,getConfigStatus);

	}
	return (0);
}



int Network_Config(char *source, char *dest, int size) {
	struct Reg_Config config_struct;
	struct Reg_Host host_struct;
	int dw_config_error;
	char str_DestPort[10];
	char str_WaitTime[25];
	char str_NumberOfFiles[25];
	char str_NumberOfLogFiles[25];
	char str_MaxMsgSize[25];

	char str_net_count[10];
	char str_conferr[10], str_neterr[10];
	int SyslogPriority, SyslogFacility;
#ifdef TLSPROTOCOL
	char *str_protocol[] = {"udp", "tcp", "tls"};
#else
	char *str_protocol[] = {"udp", "tcp"};
#endif
	char *str_facility[] = {"Kernel", "User", "Mail", "Daemon", "Auth", "Syslog", "Lpr", "News", "UUCP", "Cron", "Authpriv", "Ftp", "Local0", "Local1", "Local2", "Local3", "Local4", "Local5", "Local6", "Local7"};
	char *str_priority[] = {"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Information", "Debug"};
	char *str_log[] = {"NONE", "ERROR", "WARNING","INFORMATION", "DEBUG"};
	int i;
	int i_network_count= 1;

	FILE *configfile = (FILE *) NULL;

	if (!source || !dest || !size) {
		return(0);
	}

	strcpy(config_struct.str_ClientName, "");
	config_struct.dw_NumberOfFiles = MAXDAYSINCACHE;
	config_struct.dw_NumberOfLogFiles = LOG_FILE_TO_KEEP;
	config_struct.dw_LogLevel = DEFAULT_LOG_LEVEL;
	config_struct.dw_waitTime = TIMEOUT;
	config_struct.dw_MaxMsgSize = MAXMSGSIZE;
	config_struct.dw_SetAudit = 0;
	strcpy(host_struct.str_NetworkDestination, "");
	host_struct.dw_DestPort = 0;
	host_struct.str_Protocol[0] = '\0';


	dw_config_error = Read_Config_From_File(&config_struct);

	// This function will display the form used to set the audit configuration
	// The result of the form will be sent to "network_set"
	strncpy(dest,
		"<form action=/setnetwork><h1><center>SafedAgent Configuration</h1>",
		size);

	// Will display an error if unable to completely read from the registry
	if (dw_config_error > 0) {
		dw_config_error += WEB_READ_CONFIG_ERROR_CODE;
		snprintf(str_conferr, 10, "%d", dw_config_error);

		strncat(dest,
			"<br><b>NOTE: Some errors were encountered in reading the file. Default values "
			"may be used.<br> Report error: ", size - strlen(dest));
		strncat(dest, str_neterr, size - strlen(dest));
		strncat(dest, ".", size - strlen(dest));
		strncat(dest, str_conferr, size - strlen(dest));
		strncat(dest, "</b><br>", size - strlen(dest));
	}

	strncat(dest,
		"<br>The following network configuration parameters of the SafedAgent unit are set to the following values (blank entries are not used):<br><br>\n"
		"<table  width=70% border=0>"
		"<tr bgcolor=#DEDBD2><td>Override detected DNS Name with:</td><td><input type=text name=str_ClientName size=25 value=\"",
		size - strlen(dest));

	strncat(dest, config_struct.str_ClientName, size - strlen(dest));
	strncat(dest, "\"></td></tr>", size - strlen(dest));

	configfile = Find_First(CONFIG_OUTPUT);
	if (configfile) {
		Get_Next_Network(configfile, &host_struct);
		snprintf(str_net_count, 10, "%d", i_network_count);
		strncat(dest,
			"<tr bgcolor=#DEDBD2><td colspan=2><strong>Destination</strong></td></tr>", size - strlen(dest));
		strncat(dest,
			"<tr bgcolor=#E7E5DD><td>Destination Server address </td><td><input type=text name=str_NetworkDestination size=25 value=\"",
			size - strlen(dest));
		strncat(dest, host_struct.str_NetworkDestination,
			size - strlen(dest));
		strncat(dest, "\"></td></tr>", size - strlen(dest));

		strncat(dest,
			"<tr bgcolor=#DEDBD2><td>Destination Port (514 to enable syslog)</td><td><input type=text name=dw_DestPort size=8 value=\"",
			size - strlen(dest));
		if (host_struct.dw_DestPort) {
			snprintf(str_DestPort, 10, "%d", host_struct.dw_DestPort);
		} else {
			str_DestPort[0] = '\0';
		}

		strncat(dest, str_DestPort, size - strlen(dest));
		strncat(dest, "\" onMouseover=\"ddrivetip(\'514 is the default rsyslog port  \')\" onMouseout=\"hideddrivetip()\"></td></tr>", size - strlen(dest));
		//strncat(dest, "<tr bgcolor=#888888><td>Protocol </td><td><input type=checkbox name=str_Protocol disabled> Available in supported version</td></tr>", size - strlen(dest));
		strncat(dest, "<tr bgcolor=#E7E5DD><td>Protocol </td><td><select name=str_Protocol>", size - strlen(dest));
#ifdef TLSPROTOCOL
		for (i = 0; i < 3; i++) {
#else
		for (i = 0; i < 2; i++) {
#endif
			strncat(dest, "<option", size - strlen(dest));
			if (!strcmp(str_protocol[i],host_struct.str_Protocol))
				strncat(dest, " selected>", size - strlen(dest));
			else
				strncat(dest, ">", size - strlen(dest));
			strncat(dest, str_protocol[i], size - strlen(dest));
		}
		strncat(dest, "</select></td></tr>", size - strlen(dest));

		i_network_count++;
		Close_File(configfile);
	} else {
		strncat(dest,
			"<tr bgcolor=#DEDBD2><td colspan=2>ERROR</td></tr>",
			size - strlen(dest));
	}


	//Number of Cache files
	strncat(dest,
		"<tr bgcolor=#E7E5DD><td>Number of Cache files </td><td><input type=text name=dw_NumberOfFiles size=10 value=\"",
		size - strlen(dest));
	snprintf(str_NumberOfFiles, 10, "%d", config_struct.dw_NumberOfFiles);
	strncat(dest, str_NumberOfFiles, size - strlen(dest));
	strncat(dest, "\" onMouseover=\"ddrivetip(\' Number of days with cached data. The default is 2 \')\" onMouseout=\"hideddrivetip()\"></td></tr>", size - strlen(dest));

	strncat(dest,"<tr bgcolor=#FFFFFF><td><br/></td><td><br/></td></tr>",size - strlen(dest));

	//Number of Log files
	strncat(dest,
		"<tr bgcolor=#E7E5DD><td>Number of Safed Log files </td><td><input type=text name=dw_NumberOfLogFiles size=10 value=\"",
		size - strlen(dest));
	snprintf(str_NumberOfLogFiles, 10, "%d", config_struct.dw_NumberOfLogFiles);
	strncat(dest, str_NumberOfLogFiles, size - strlen(dest));
	strncat(dest, "\" onMouseover=\"ddrivetip(\' Number of logs. The default is 4 \')\" onMouseout=\"hideddrivetip()\"></td></tr>", size - strlen(dest));

	//LogLevel
	strncat(dest,"<tr bgcolor=#E7E5DD><td>Log level </td><td><select name=dw_LogLevel>",	size - strlen(dest));
	for (i = 0; i < 5; i++) {
		strncat(dest, "<option", size - strlen(dest));
		if (i == config_struct.dw_LogLevel)
			strncat(dest, " selected>", size - strlen(dest));
		else
			strncat(dest, ">", size - strlen(dest));
		strncat(dest, str_log[i], size - strlen(dest));
	}
	strncat(dest, "</select></td></tr>", size - strlen(dest));

	strncat(dest,"<tr bgcolor=#FFFFFF><td><br/></td><td><br/></td></tr>",size - strlen(dest));

	//Wait Time
	strncat(dest,
		"<tr bgcolor=#DEDBD2><td>Wait Time </td><td><input type=text name=dw_WaitTime size=10 value=\"",
		size - strlen(dest));
	snprintf(str_WaitTime, 10, "%d", config_struct.dw_waitTime);
	strncat(dest, str_WaitTime, size - strlen(dest));
	strncat(dest, "\" onMouseover=\"ddrivetip(\' Time, in nanoseconds, to wait between reads \')\" onMouseout=\"hideddrivetip()\"></td></tr>", size - strlen(dest));

	//Max Message Size
	strncat(dest,
		"<tr bgcolor=#E7E5DD><td>Max Message Size </td><td><input type=text name=dw_MaxMsgSize size=10 value=\"",
		size - strlen(dest));
	snprintf(str_MaxMsgSize, 10, "%d", config_struct.dw_MaxMsgSize);
	strncat(dest, str_MaxMsgSize, size - strlen(dest));
	strncat(dest, "\" onMouseover=\"ddrivetip(\' Max Message Size in characters \')\" onMouseout=\"hideddrivetip()\"></td></tr>", size - strlen(dest));

	strncat(dest,"<tr bgcolor=#FFFFFF><td><br/></td><td><br/></td></tr>",size - strlen(dest));
#if defined(__linux__)
	strncat(dest,
		"<tr bgcolor=#E7E5DD><td>Allow SafedAgent to automatically set audit configuration? </td><td><input type=checkbox name=dw_SetAudit",
		size - strlen(dest));

	// Need to convert this next section to YES or NO
	if (config_struct.dw_SetAudit != 0)
		strncat(dest, " checked", size - strlen(dest));
	strncat(dest, "></td></tr>", size - strlen(dest));

	strncat(dest,"<tr bgcolor=#FFFFFF><td><br/></td><td><br/></td></tr>",size - strlen(dest));
#endif

	SyslogPriority = config_struct.dw_Syslog & 7;
	SyslogFacility = config_struct.dw_Syslog >> 3;
	if (SyslogFacility > 11) {
		SyslogFacility -= 4;
	}



	strncat(dest, "<tr bgcolor=#DEDBD2><td>SYSLOG Facility (optional) </td><td><select name=SyslogFacility>", size - strlen(dest));
	for (i = 0; i < 19; i++) {
		strncat(dest, "<option", size - strlen(dest));
		if (i == SyslogFacility)
			strncat(dest, " selected>", size - strlen(dest));
		else
			strncat(dest, ">", size - strlen(dest));
		strncat(dest, str_facility[i], size - strlen(dest));
	}
	strncat(dest, "</select></td></tr>", size - strlen(dest));

	strncat(dest, "<tr bgcolor=#E7E5DD><td>SYSLOG Priority (optional) </td><td><select name=SyslogPriority>", size - strlen(dest));
	for (i = 0; i < 8; i++) {
		strncat(dest, "<option", size - strlen(dest));
		if (i == SyslogPriority)
			strncat(dest, " selected>", size - strlen(dest));
		else
			strncat(dest, ">", size - strlen(dest));
		strncat(dest, str_priority[i], size - strlen(dest));
	}
	strncat(dest, "</select></td></tr>", size - strlen(dest));

	strncat(dest, "</table><br>", size - strlen(dest));
	strncat(dest, "<input type=submit value=\"Change Configuration\">    ",
		size - strlen(dest));
	strncat(dest, "<input type=reset value=\"Reset Form\"></form>",
		size - strlen(dest));

	return (0);
}

int Network_Set(char *source, char *dest, int size)
{
	char *psource = source;
	char Variable[100], web_port[100], syslog_fac[100], syslog_pri[100], numberOfFiles[100], numberOfLogFiles[100], logLevel[100], wait_time[100], max_msg_size[100];
	char Argument[100];
	struct Reg_Config config_struct;
	struct Reg_Host * RHead=NULL;
	struct Reg_Host * RCurrent=NULL;
	struct Reg_Host * RTail=NULL;
	int dw_error_config = 0, i = 0;
	char *str_facility[] = {"Kernel", "User", "Mail", "Daemon", "Auth", "Syslog", "Lpr", "News", "UUCP", "Cron", "Authpriv", "Ftp", "Local0", "Local1", "Local2", "Local3", "Local4", "Local5", "Local6", "Local7"};
	char *str_priority[] = {"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Information", "Debug"};
	char *str_log[] = {"NONE", "ERROR", "WARNING","INFORMATION", "DEBUG"};
	int dw_SyslogClass = 0;
	int dw_error_port=0;

	// This function will display that the remote audit configurations have been changed, or there have been errors
	strncpy(dest, "<h1><center>SafedAgent Configuration</h1>", size);

	// Note that all the possible variables do NOT have to be in the URL. The ones that are selected
	// via a checkbox will not be listed if the checkbox has been deselected.
	// Checking is limited to ensuring the Detsination port in the range 1-65535.
	// The variable associated with the checkbox (dw_Syslog) must be
	// exactly "on" or it will be defaulted to "off".
	// str_Destination,str_Delimiter_Text,str_ClientName can be anything it wants to be, so long
	// as it is within size bounds.

	strncpy(config_struct.str_ClientName, "",
		sizeof (config_struct.str_ClientName));
	strncpy(web_port, "", sizeof (web_port));
	strncpy(wait_time, "", sizeof (wait_time));
	strncpy(max_msg_size, "", sizeof (max_msg_size));
	strncpy(numberOfFiles, "", sizeof (numberOfFiles));
	strncpy(numberOfLogFiles, "", sizeof (numberOfLogFiles));
	strncpy(logLevel, "", sizeof (logLevel));

	while ((psource =
		getNextArgument(psource, Variable, sizeof (Variable), Argument,
				sizeof (Argument))) != (char *) NULL) {

		if (strstr(Variable, "str_ClientName") != NULL) {
			strncpy(config_struct.str_ClientName, Argument,
				sizeof (config_struct.str_ClientName));
		}

		if (strstr(Variable, "dw_NumberOfFiles") != NULL) {
			strncpy(numberOfFiles, Argument,
				sizeof (numberOfFiles));
			config_struct.dw_NumberOfFiles = atoi(numberOfFiles);
		}
		if (strstr(Variable, "dw_NumberOfLogFiles") != NULL) {
			strncpy(numberOfLogFiles, Argument,
				sizeof (numberOfLogFiles));
			config_struct.dw_NumberOfLogFiles = atoi(numberOfLogFiles);
		}
		if (strstr(Variable, "dw_LogLevel") != NULL) {
			strncpy(logLevel, Argument,
				sizeof (logLevel));
		}
		if (strstr(Variable, "dw_WaitTime") != NULL) {
			strncpy(wait_time, Argument,
				sizeof (wait_time));
			config_struct.dw_waitTime = atoi(wait_time);
		}
		if (strstr(Variable, "dw_MaxMsgSize") != NULL) {
			strncpy(max_msg_size, Argument,
				sizeof (max_msg_size));
			config_struct.dw_MaxMsgSize = atoi(max_msg_size);
		}
		if (strstr(Variable, "dw_SetAudit") != NULL) {
			if (strcmp(Argument, "on") == 0)
				config_struct.dw_SetAudit = 1;
			else
				config_struct.dw_SetAudit = 0;
		}


		if (strstr(Variable, "str_NetworkDestination") != NULL) {
			RCurrent = (struct Reg_Host *)malloc(sizeof(struct Reg_Host));
			RCurrent->next=NULL;
			RCurrent->dw_DestPort = 0;
			RCurrent->str_Protocol[0] = '\0';
			if (RCurrent) {
				strncpy(RCurrent->str_NetworkDestination, Argument,
					sizeof (RCurrent->str_NetworkDestination));
			}
		}

		if (strstr(Variable, "dw_DestPort") != NULL) {
			strncpy(web_port, Argument, sizeof (web_port));
			if (RCurrent) {
				RCurrent->dw_DestPort = atoi(web_port);
			}
			if (strcmp(RCurrent->str_NetworkDestination, "") != 0) {
				if (RTail) {
					RTail->next=RCurrent;
					RTail=RCurrent;
				}
				if (!RHead) {
					RHead=RCurrent;
					RTail=RCurrent;
				}
			}
		}

		if (strstr(Variable, "str_Protocol") != NULL) {
			if (RCurrent) {
				strncpy(RCurrent->str_Protocol,Argument, SIZE_OF_PROTOCOL);
			}
		}

		if (strstr(Variable, "SyslogPriority") != NULL) {
			strncpy(syslog_pri, Argument, sizeof(syslog_pri));
		}
		if (strstr(Variable, "SyslogFacility") != NULL) {
			strncpy(syslog_fac, Argument, sizeof(syslog_fac));
		}
	}

	for (i = 0; i < 5; i++) {
		if (strstr(logLevel, str_log[i]) != NULL)
			config_struct.dw_LogLevel = i;
	}
	//for now it is limited to 3
	if(config_struct.dw_LogLevel > 3)
		config_struct.dw_LogLevel = 3;


	for (i = 0; i < 8; i++) {
		if (strstr(syslog_pri, str_priority[i]) != NULL)
			config_struct.dw_Syslog = i;
	}
	for (i = 0; i < 19; i++) {
		if (strstr(syslog_fac, str_facility[i]) != NULL)
			dw_SyslogClass = i;
	}
	if (dw_SyslogClass > 11) {
		dw_SyslogClass = dw_SyslogClass + 4;
	}
	config_struct.dw_Syslog = config_struct.dw_Syslog | (dw_SyslogClass << 3);

	// Check that all the port numbers are valid
	RCurrent = RHead;
	while (RCurrent) {
		if (strlen(RCurrent->str_NetworkDestination)
		    && ((RCurrent->dw_DestPort < 1)
		    || (RCurrent->dw_DestPort > 65535))) {
			strncat(dest,
				"The Destination Port value must be between 1 and 65535. Use the 'back' button to change the value.",
				size - strlen(dest));
			dw_error_port++;
			break;
		}
		RCurrent = RCurrent->next;
	}
	if (!dw_error_port) {
		void *rampointer = (void *) NULL;
		char *position;
		char inputbuffer[MAX_AUDIT_CONFIG_LINE];
		int headertype = 0;
		FILE *configfile;

		rampointer = Load_Config_File();

		if (!rampointer) {
			dw_error_config = 1;
		} else {
			int size = 0;
			int wroteconfig = 0;
			int wrotelog = 0;
			int skip = 0;

			position = (char *) rampointer;

			configfile = current_config("w");
			if (!configfile) {
				dw_error_config = 1;
				strncat(dest,
					"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
					size - strlen(dest));
				Clear_Config_File(rampointer);
				return (0);
			}

			while ((size =
				Grab_RAMConfig_Line(position, inputbuffer,
						    MAX_AUDIT_CONFIG_LINE))) {
				trim(inputbuffer);

				// Is this line a header?
				if (isheader(inputbuffer) || skip) {
					// Jump over any lines in the headers that we're writing out.
					if (!isheader(inputbuffer)) {
						position += size;
						continue;
					}
					fprintf(configfile, "%s\n",
						inputbuffer);

					headertype = getheader(inputbuffer);
					if (headertype == CONFIG_HOSTID) {
						wroteconfig += 1;
						// WRITE OUT NEW hostid here.
						if (strlen
						    (config_struct.
						     str_ClientName)) {
							fprintf(configfile,
								"	name=%s\n",
								config_struct.
								str_ClientName);
						}
						skip = 1;
					} else if (headertype == CONFIG_LOG) {
						wrotelog += 1;
						if (config_struct.dw_NumberOfLogFiles && (config_struct.dw_NumberOfLogFiles!=LOG_FILE_TO_KEEP)) {
							fprintf(configfile,
								"	logFileToKeep=%d\n", config_struct.dw_NumberOfLogFiles);
						}

						if (config_struct.dw_LogLevel && (config_struct.dw_LogLevel!=DEFAULT_LOG_LEVEL)) {
							fprintf(configfile,
								"	logLevel=%d\n", config_struct.dw_LogLevel);
						}
						skip = 1;
					}else if (headertype == CONFIG_OUTPUT) {
						wroteconfig += 2;
						RCurrent = RHead;
						while (RCurrent) {
							fprintf(configfile,
								"	network=%s:%d:%s\n",
								RCurrent->
								str_NetworkDestination,
								RCurrent->
								dw_DestPort,
								RCurrent->
								str_Protocol);
							RCurrent=RCurrent->next;
						}
						if (config_struct.dw_Syslog) {
							fprintf(configfile,
								"	syslog=%d\n", config_struct.dw_Syslog);
						}
						if (config_struct.dw_NumberOfFiles && (config_struct.dw_NumberOfFiles!=MAXDAYSINCACHE)) {
							fprintf(configfile,
								"	days=%d\n", config_struct.dw_NumberOfFiles);
						}
						if (config_struct.dw_waitTime && (config_struct.dw_waitTime!=TIMEOUT)) {
							fprintf(configfile,
								"	waittime=%d\n", config_struct.dw_waitTime);
						}
						if (config_struct.dw_MaxMsgSize && (config_struct.dw_MaxMsgSize!=MAXMSGSIZE)) {
							fprintf(configfile,
								"	maxmsgsize=%d\n", config_struct.dw_MaxMsgSize);
						}
#if defined(__linux__)
						fprintf(configfile,	"	set_audit=%d\n", config_struct.dw_SetAudit);
#endif
						//fprintf(configfile, "\n");
						skip = 1;
					} else {
						skip = 0;
					}
				} else {

					// Print this line to file.
					if (iscomment(inputbuffer)
					    || !strlen(inputbuffer)) {
						fprintf(configfile, "%s\n",
							inputbuffer);
					} else {
						fprintf(configfile, "	%s\n",
							inputbuffer);
					}
				}
				position += size;
			}

			if (!wroteconfig || wroteconfig == 2) {
				if (strlen(config_struct.str_ClientName)) {
					fprintf(configfile,
						"\n[HostID]\n	name=%s\n",
						config_struct.str_ClientName);
				}
			}
			if (!wroteconfig || wroteconfig == 1) {
				fprintf(configfile, "\n[Output]\n");
				RCurrent = RHead;
				while (RCurrent) {
					fprintf(configfile,
						"	network=%s:%d:%s\n",
						RCurrent->
						str_NetworkDestination,
						RCurrent->
						dw_DestPort,
						RCurrent->
						str_Protocol);
					RCurrent=RCurrent->next;
				}

				if (config_struct.dw_NumberOfFiles && (config_struct.dw_NumberOfFiles!=MAXDAYSINCACHE)) {
					fprintf(configfile,
						"	days=%d\n", config_struct.dw_NumberOfFiles);
				}

				if (config_struct.dw_waitTime && (config_struct.dw_waitTime!=TIMEOUT)) {
					fprintf(configfile,
						"	waittime=%d\n", config_struct.dw_waitTime);
				}
				if (config_struct.dw_MaxMsgSize && (config_struct.dw_MaxMsgSize!=MAXMSGSIZE)) {
					fprintf(configfile,
						"	maxmsgsize=%d\n", config_struct.dw_MaxMsgSize);
				}
				fprintf(configfile, "\n");
			}
			if (!wrotelog) {
				fprintf(configfile, "\n[Log]\n");

				if (config_struct.dw_NumberOfLogFiles && (config_struct.dw_NumberOfLogFiles!=LOG_FILE_TO_KEEP)) {
					fprintf(configfile,
						"	logFileToKeep=%d\n", config_struct.dw_NumberOfLogFiles);
				}
				if (config_struct.dw_LogLevel && (config_struct.dw_LogLevel!=DEFAULT_LOG_LEVEL)) {
					fprintf(configfile,
						"	logLevel=%d\n", config_struct.dw_LogLevel);
				}
			}
			if (fclose(configfile)) {
				dw_error_config = 1;
				strncat(dest,
					"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?",
					size - strlen(dest));
				Clear_Config_File(rampointer);
				return (0);
			}

			Clear_Config_File(rampointer);
		}

		if (dw_error_config != 0) {
			strncat(dest, "Values have NOT been changed.",
				size - strlen(dest));
		} else {
			strncat(dest, "Values have been changed.",
				size - strlen(dest));
		}
	}

	return (0);

}


int Remote_Config(char *source, char *dest, int size)
{
	struct Reg_Remote remote_struct;
	int dw_remote_error;
	char str_WebPort[10];
	char str_remerr[10];

	if (!source || !dest || !size) {
		return(0);
	}

	dw_remote_error = Read_Remote_From_File(&remote_struct);

	// This function will display the form used to set the remote audit configuration
	strncpy(dest,
		"<form action=/setremote><h1><center>SafedAgent Remote Control Configuration</h1>",
		size);

	// Will display an error if unable to completely read from the registry
	if (dw_remote_error > 0) {
		dw_remote_error += WEB_READ_REMOTE_ERROR_CODE;
		// itoa(dw_remote_error,str_remerr,10);
		snprintf(str_remerr, 10, "%d", dw_remote_error);

		strncat(dest,
			"<br><b>NOTE: Some errors were encountered in reading the registry. Default values "
			"may be used.<br> Report error: ", size - strlen(dest));
		strncat(dest, str_remerr, size - strlen(dest));
		strncat(dest, "</b><br>", size - strlen(dest));
	}
	strncat(dest,
		"<br>The following remote control configuration parameters of the SafedAgent unit is set to the following values:<br><br>"
		"<table  width=70% border=0>"
		"<tr bgcolor=#DEDBD2><td>Allow remote control of SafedAgent</td><td><input type=checkbox name=dw_Allow",
		size - strlen(dest));

	// Need to convert this next section to YES or NO
	if (remote_struct.dw_Allow != 0) {
		strncat(dest, " checked", size - strlen(dest));
	}

	strncat(dest, "></td></tr><tr bgcolor=#FFFFFF><td><br></td><td><br></td></tr>",
		size - strlen(dest));
	strncat(dest,
		"<tr bgcolor=#E7E5DD><td>Restrict remote control of SafedAgent to certain host </td><td><input type=checkbox name=dw_Restrict",
		size - strlen(dest));

	// Need to convert this next section to YES or NO
	if (remote_struct.dw_Restrict != 0)
		strncat(dest, " checked", size - strlen(dest));
	strncat(dest, "></td></tr>", size - strlen(dest));

	strncat(dest,
		"<tr bgcolor=#DEDBD2><td>IP Addresses allowed to remote control SafedAgent <br><i>(max 10 hosts ; separated) </i></td><td><input type=text name=str_RestrictIP size=12 value=\"",
		size - strlen(dest));
	strncat(dest, remote_struct.str_RestrictIP, size - strlen(dest));
	strncat(dest, "\"></td></tr>", size - strlen(dest));

	strncat(dest,
		"<tr bgcolor=#E7E5DD><td>Require a password for remote control? </td><td><input type=checkbox name=dw_Password",
		size - strlen(dest));

	// Need to convert this next section to YES or NO
	if (remote_struct.dw_Password != 0)
		strncat(dest, " checked", size - strlen(dest));
	strncat(dest, "></td></tr>", size - strlen(dest));

	strncat(dest,
		"<tr bgcolor=#DEDBD2><td>Password to allow remote control of SafedAgent </td><td><input type=password name=str_Password size=12 value=\"",
		size - strlen(dest));
	strncat(dest, remote_struct.str_Password, size - strlen(dest));
	strncat(dest, "\"><input type=hidden name=str_OldPassword value=\"", size - strlen(dest));
	strncat(dest, remote_struct.str_Password, size - strlen(dest));
	strncat(dest, "\"></td></tr>", size - strlen(dest));

	strncat(dest,
		"<tr bgcolor=#DEDBD2><td>Web Server Port </td><td><input type=text name=dw_WebPort size=8 value=\"",
		size - strlen(dest));
	snprintf(str_WebPort, 10, "%d", remote_struct.dw_WebPort);
	strncat(dest, str_WebPort, size - strlen(dest));
	strncat(dest, "\"></td></tr>", size - strlen(dest));
#ifdef TLSPROTOCOL
	strncat(dest,
		"<tr bgcolor=#E7E5DD><td>HTTPS protocol</td><td><input type=checkbox name=dw_TLS",
		size - strlen(dest));

	// Need to convert this next section to YES or NO
	if (remote_struct.dw_TLS != 0)
		strncat(dest, " checked", size - strlen(dest));
	strncat(dest, "></td></tr>", size - strlen(dest));
#endif
	strncat(dest, "</table><br>", size - strlen(dest));
	strncat(dest, "<input type=submit value=\"Change Configuration\">    ",
		size - strlen(dest));
	strncat(dest, "<input type=reset value=\"Reset Form\"></form>",
		size - strlen(dest));

	return (0);
}

int Remote_Set(char *source, char *dest, int size)
{
	char *psource = source;
	char Variable[100], web_port[100];
	char Argument[100];
	char OldPassword[100] = "";
	struct Reg_Remote remote_struct;
	int dw_error = 0;

	dw_error = Read_Remote_From_File(&remote_struct);

	// This function will display that the remote audit configurations have been changed, or there have been errors
	strncpy(dest, "<h1><center>SafedAgent Remote Control Configuration</h1>",
		size);

	// Note that all the possible variables do NOT have to be in the URL. The ones that are selected
	// via a checkbox will not be listed if the checkbox has been deselected.
	// Also be aware that there may not be any arguments for this objective. If a sysadmin does not want
	// remote control, then there will be no arguments.
	// Hence: Checking is limited to Webport in the range 1-65535 only if portchange is "on"
	// The three variable associated with the checkboxes (dw_Allow, dw_Restrict, and dw_PortChange) must be
	// exactly "on" or they will be defaulted to "off".
	// str_RestrictIP can be anything it wants to be, so long as it is within size bounds.

	remote_struct.dw_WebPort = -1;
	remote_struct.dw_Allow = 0;
	remote_struct.dw_TLS = 0;
	remote_struct.dw_Password = 0;
	remote_struct.dw_Restrict = 0;

	while ((psource =
		getNextArgument(psource, Variable, sizeof (Variable), Argument,
				sizeof (Argument))) != (char *) NULL) {

		if (strstr(Variable, "dw_WebPort") != NULL) {
			strncpy(web_port, Argument, sizeof (web_port));
		}
		if (strstr(Variable, "str_RestrictIP") != NULL) {
			strncpy(remote_struct.str_RestrictIP, Argument,
				sizeof (remote_struct.str_RestrictIP));
		}
		if (strstr(Variable, "str_Password") != NULL) {
			if (strcmp(Argument, remote_struct.str_Password) != 0) {
				strncpy(remote_struct.str_Password, Argument, sizeof(remote_struct.str_Password));

			}
		}

		if (strstr(Variable, "str_OldPassword") != NULL) {
			strncpy(OldPassword, Argument, sizeof(OldPassword));
		}
		if (strstr(Variable, "dw_Allow") != NULL) {
			if (strcmp(Argument, "on") == 0)
				remote_struct.dw_Allow = 1;
			else
				remote_struct.dw_Allow = 0;
		}
		if (strstr(Variable, "dw_TLS") != NULL) {
			if (strcmp(Argument, "on") == 0)
				remote_struct.dw_TLS = 1;
			else
				remote_struct.dw_TLS = 0;
		}
		if (strstr(Variable, "dw_Password") != NULL) {
			if (strcmp(Argument, "on") == 0) {
				remote_struct.dw_Password = 1;
			} else {
				remote_struct.dw_Password = 0;
			}
		}
		if (strstr(Variable, "dw_Restrict") != NULL) {
			if (strcmp(Argument, "on") == 0)
				remote_struct.dw_Restrict = 1;
			else
				remote_struct.dw_Restrict = 0;
		}
	}

	remote_struct.dw_WebPort = atoi(web_port);
	if ((remote_struct.dw_WebPort < 1)
	    || (remote_struct.dw_WebPort > 65535)) {
		strncat(dest,
			"The Web Port value must be between 1 and 65535. Use the 'back' button to change the value.",
			size - strlen(dest));
	} else {
		void *rampointer = (void *) NULL;
		char *position;
		char inputbuffer[MAX_AUDIT_CONFIG_LINE];
		int headertype = 0;
		FILE *configfile = (FILE *)NULL;

		rampointer = Load_Config_File();

		if (!rampointer) {
			dw_error = 1;
		} else {
			int size = 0;
			int wroteconfig = 0;
			int skip = 0;

			position = (char *) rampointer;

			configfile = current_config("w");
			if (!configfile) {
				dw_error = 1;
				strncat(dest,
					"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
					size - strlen(dest));
				Clear_Config_File(rampointer);
				return (0);
			}

			while ((size =
				Grab_RAMConfig_Line(position, inputbuffer,
						    MAX_AUDIT_CONFIG_LINE))) {

				trim(inputbuffer);

				// Is this line a header?
				if (isheader(inputbuffer) || skip) {
					// Jump over any lines in the headers that we're writing out.
					if (!isheader(inputbuffer)) {
						position += size;
						continue;
					}

					fprintf(configfile, "%s\n",
						inputbuffer);

					headertype = getheader(inputbuffer);

					if (headertype == CONFIG_REMOTE) {
						wroteconfig = 1;

						if (remote_struct.dw_Allow) {
							fprintf(configfile,
								"	allow=1\n");
						}
						if (remote_struct.dw_TLS) {
							fprintf(configfile,
								"	https=1\n");
						}
						if (remote_struct.dw_WebPort) {
							fprintf(configfile,
								"	listen_port=%d\n",
								remote_struct.
								dw_WebPort);
						}
						if (strlen
						    (remote_struct.
						     str_RestrictIP)
						    && remote_struct.
						    dw_Restrict) {
							fprintf(configfile,
								"	restrict_ip=%s\n",
								remote_struct.
								str_RestrictIP);
						}
						// Reject passwords with backslashes.
						if (strlen
						    (remote_struct.str_Password)
						    && remote_struct.
						    dw_Password) {
							if (strstr(remote_struct.str_Password, "\\")) {
								strncat(dest,
									"Sorry, passwords with the backslash character are not allowed.<br>Please use the Back Button, and try another password.<br> The other ",
									size - strlen(dest));
								fprintf(configfile,
									"	accesskey=%s\n",
									OldPassword);

							} else {
								if (strcmp(remote_struct.str_Password,OldPassword)) {
									char *tpass;
									// The password has changed. Encrypt it.
									tpass = crypt(remote_struct.str_Password,SALT);
									if (tpass) {
										fprintf(configfile,
											"	accesskey=%s\n",
											tpass);
									} else {
										// Crypt failed. Fallback to whatever the user had before.
										fprintf(configfile,
											"	accesskey=%s\n",
											remote_struct.str_Password);
									}
								} else {
									// Otherwise, leave it in peace
									fprintf(configfile,
										"	accesskey=%s\n",
										remote_struct.str_Password);
								}
							}
						}
						skip = 1;
					} else {
						skip = 0;
					}
				} else {
					// Print this line to file.
					if (iscomment(inputbuffer)
					    || !strlen(inputbuffer)) {
						fprintf(configfile, "%s\n",
							inputbuffer);
					} else {
						fprintf(configfile, "	%s\n",
							inputbuffer);
					}
				}
				position += size;
			}

			if (!wroteconfig) {
				fprintf(configfile, "\n[Remote]\n");

				if (remote_struct.dw_Allow) {
					fprintf(configfile, "	allow=1\n");
				}
				if (remote_struct.dw_TLS) {
					fprintf(configfile, "	https=1\n");
				}

				if (remote_struct.dw_WebPort) {
					fprintf(configfile,
						"	listen_port=%d\n",
						remote_struct.dw_WebPort);
				}
				if (strlen(remote_struct.str_RestrictIP)
				    && remote_struct.dw_Restrict) {
					fprintf(configfile,
						"	restrict_ip=%s\n",
						remote_struct.str_RestrictIP);
				}
				if (strlen(remote_struct.str_Password)
				    && remote_struct.dw_Password) {
					fprintf(configfile, "	accesskey=%s\n",
						(char *)crypt(remote_struct.str_Password, SALT));
				}
				fprintf(configfile, "\n");
			}

			if (fclose(configfile)) {
				dw_error = 1;
				strncat(dest,
					"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
					size - strlen(dest));
				Clear_Config_File(rampointer);
				return (0);
			}

			Clear_Config_File(rampointer);
		}

		if (dw_error != 0) {
			strncat(dest,
				"Remote Control Values have NOT been changed. Report an error.",
				size - strlen(dest));
		} else {
			strncat(dest,
				"Remote Control Values have been changed.",
				size - strlen(dest));
		}
	}

	return (0);
}


int Objective_Config(char *source, char *dest, int size)
{
	struct Reg_Objective reg_objective;
	int i_objective_count = 0;
	char str_obj_count[10];
	char str_general_match_metachar_remove[SIZE_OF_GENERALMATCH * 2];
	char strtmp[500] = "";

	FILE *configfile = (FILE *) NULL;

	if (!source || !dest || !size) {
		return(0);
	}

	strncpy(dest,
		"<form action=/log/setobjective><H1><CENTER>SafedAgent Filtering Log Objectives Configuration</H1>",
		size);

	configfile = Find_First(CONFIG_OBJECTIVES);

	if (configfile) {
		strncat(dest,
			"<br>The following filtering objectives of the SafedAgent unit are active:<br><br>"
			"<table  width=100% border=1>", size - strlen(dest));

		strncat(dest,
			"<tr bgcolor=#F0F1F5><center><td width=\"10%\"><b>Action Required</b></td>"
			"<td width=\"10%\"><b>Include/Exclude</b></td>"
			"<td width=\"75%\"><b>Search Term</b></td>"
			"<td width=\"5%\"><b>Order</b></td>"
			"</center></tr>", size - strlen(dest));

		while (Get_Next_Objective(configfile, &reg_objective)) {
			snprintf(str_obj_count, 10, "%d", i_objective_count);

			if ((i_objective_count) == 0)
				strncat(dest,
					"<tr bgcolor=#DEDBD2><td><input type=submit name=",
					size - strlen(dest));
			else{
				snprintf(strtmp, sizeof(strtmp), "<div align=center style=\"margin-bottom: 5px; border-left: 2px solid #eeeeee; border-top: 2px solid #eeeeee; border-right: 2px solid #aaaaaa; border-bottom: 2px solid #aaaaaa; background-color: #dddddd\"><a href=\"/log/setobjective?%d=MoveDown\" style=\"font-size: 9px; color: #33aa33; text-decoration: none; display: block;\">&#9660;</a></div>",(i_objective_count-1));
				strncat(dest,strtmp,size - strlen(dest));
				strncat(dest, "</td></tr>", size - strlen(dest));
				strncat(dest,
					"<tr bgcolor=#E7E5DD><td><input type=submit name=",
					size - strlen(dest));
			}

			strncat(dest, str_obj_count, size - strlen(dest));
			strncat(dest, " value=Delete>     ",
				size - strlen(dest));

			strncat(dest, "<input type=submit name=",
				size - strlen(dest));
			strncat(dest, str_obj_count, size - strlen(dest));
			strncat(dest, " value=Modify>", size - strlen(dest));
			strncat(dest, "</td><td>", size - strlen(dest));

			if (strlen(reg_objective.str_general_match_type) == 0) {
				strncat(dest, "&nbsp", size - strlen(dest));
			} else {
				strncat(dest, reg_objective.str_general_match_type,
					size - strlen(dest));
			}
			strncat(dest, "</td><td>", size - strlen(dest));

			// Debracket the strings in here. For HTML display purposes, the HTML metacharacters
			// need to be replaced. This is done with the "debracket" routine.
			// Note that the new strings are allowed to be twice as long as the real strings
			debracket(reg_objective.str_general_match,
				  str_general_match_metachar_remove,
				  SIZE_OF_GENERALMATCH * 2);

			if (strlen(reg_objective.str_general_match) == 0) {
				strncat(dest, "&nbsp", size - strlen(dest));
			} else {
				strncat(dest, str_general_match_metachar_remove,
					size - strlen(dest));
			}
			strncat(dest, "</td>", size - strlen(dest));
			if (i_objective_count > 0){
				snprintf(strtmp, sizeof(strtmp), "<td><div align=center style=\"margin-bottom: 5px; border-left: 2px solid #eeeeee; border-top: 2px solid #eeeeee; border-right: 2px solid #aaaaaa; border-bottom: 2px solid #aaaaaa; background-color: #dddddd\"><a href=\"/log/setobjective?%d=MoveUp\" style=\"font-size: 9px; color: #33aa33; text-decoration: none; display: block;\">&#9650;</a></div>",i_objective_count);
				strncat(dest,strtmp,size - strlen(dest));



			}else
				strncat(dest,"<td>",size - strlen(dest));
			i_objective_count++;
		}

		strncat(dest, "</td></tr>", size - strlen(dest));
		Close_File(configfile);
		strncat(dest, "</table><br>", size - strlen(dest));
	} else {
		strncat(dest,
			"<br>There are no current filtering objectives active.<br><br>",
			size - strlen(dest));
	}

	strncat(dest, "Select this button to add a new objective.  ",
		size - strlen(dest));
	strncat(dest, "<input type=submit name=0", size - strlen(dest));
	strncat(dest, " value=Add>", size - strlen(dest));

	return (0);
}




int Objective_Display(char *source, char *dest, int size)
{
	struct Reg_Objective reg_objective;
	int dw_objective_error = 0, dw_objective_delete_error = 0;
	char str_objerr[10];
	int i_objective_count = 0, i_type = 0;
	char *psource = source, Variable[100], Argument[100];
	char str_temp[20], str_temp_objective[10];

	// This function will display an existing, or a blank, objective
	strncpy(dest,
		"<form action=/log/changeobjective><h1><center>SafedAgent Filtering Objective Configuration</h1>",
		size);

	// Determine whether the objective will be modified or deleted
	while ((psource =
		getNextArgument(psource, Variable, sizeof (Variable), Argument,
				sizeof (Argument))) != (char *) NULL) {
		if (strstr(Argument, "Delete") != NULL) {
			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp,
			       str_temp_objective);
			i_type = 0;
			break;
		}
		if (strstr(Argument, "Modify") != NULL) {
			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp,
			       str_temp_objective);
			i_type = 1;
			break;
		}
		if (strstr(Argument, "MoveUp") != NULL) {
			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp,
			       str_temp_objective);
			i_type = -2;
			break;
		}
		if (strstr(Argument, "MoveDown") != NULL) {
			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp,
			       str_temp_objective);
			i_type = -1;
			break;
		}
		if (strstr(Argument, "Add") != NULL) {
			strncpy(str_temp_objective, "-2",
				sizeof (str_temp_objective));
			i_type = 2;
			break;
		}
	}

	// Extract the objective number. I have to do this stuff, because atoi returns 0 if it cannot convert the string
	if (strcmp(str_temp_objective, "0") == 0)
		i_objective_count = -1;
	else
		i_objective_count = atoi(str_temp_objective);

	// If the objective number could not be successfully extracted, return immediately.
	if (i_objective_count == 0) {
		strncat(dest,
			"<br><b>NOTE: It appears the URL is encoded incorrectly.",
			size - strlen(dest));
		return 0;
	}

	if (i_objective_count == -1)
		i_objective_count = 0;

	// If the objective is being modified or added
	if (i_type > 0) {
		if (i_type == 1) {
			int count = 0;
			int returncode;
			FILE *configfile;
			configfile = Find_First(CONFIG_OBJECTIVES);
			while ((returncode =
				Get_Next_Objective(configfile, &reg_objective)))
			{
				if (count == i_objective_count)
					break;
				count++;
			}
			if (!(count == i_objective_count && returncode)) {
				dw_objective_error =
				    WEB_READ_OBJECTIVE_ERROR_CODE;
			}
			Close_File(configfile);
		} else {
			// Defaults
			strncpy(reg_objective.str_general_match, ".*",
				sizeof (reg_objective.str_general_match));
			strncpy(reg_objective.str_general_match_type, "Any",
				sizeof (reg_objective.str_general_match_type));
		}

		// Will display an error if unable to completely read from the config file
		if (dw_objective_error > 0) {
			dw_objective_error += WEB_READ_OBJECTIVE_ERROR_CODE;
			snprintf(str_objerr, 10, "%d", dw_objective_error);

			strncat(dest,
				"<br><b>NOTE: Some errors were encountered in reading the configuration file. Default values "
				"may be used.<br> Report error: ",
				size - strlen(dest));
			strncat(dest, str_objerr, size - strlen(dest));
			strncat(dest, "</b><br>", size - strlen(dest));
		}

		strncat(dest,
			"<br>The following parameters of the SafedAgent objective may be set:<br><br>"
			"<table  width=100% border=0>", size - strlen(dest));

		strncat(dest,
			"<tr bgcolor=#DEDBD2><td>Select the General Match Type</td><td>",
			size - strlen(dest));
		strncat(dest,
			"<input type=radio name=str_general_match_type value=Any",
			size - strlen(dest));

		if (strcmp(reg_objective.str_general_match, ".*") == 0) {
			strncat(dest, " checked", size - strlen(dest));
			strncpy(reg_objective.str_general_match_type, "Any", sizeof(reg_objective.str_general_match_type));
		}
		strncat(dest, ">Match Any String    ", size - strlen(dest));
		strncat(dest,
			"<input type=radio name=str_general_match_type value=Include",
			size - strlen(dest));
		if (strstr(reg_objective.str_general_match_type, "Include") !=
		    NULL) {
			strncat(dest, " checked", size - strlen(dest));
		}
		strncat(dest,
			">Include    <input type=radio name=str_general_match_type value=Exclude",
			size - strlen(dest));

		if (strstr(reg_objective.str_general_match_type, "Exclude") !=
		    NULL)
			strncat(dest, " checked", size - strlen(dest));
		strncat(dest, ">Exclude    </td></tr>", size - strlen(dest));

		strncat(dest,
			"<tr bgcolor=#E7E5DD><td>Search Term<br><i>(regular expression)</i></td><td><input type=text name=str_general_match size=50 value=\"",
			size - strlen(dest));
		strncat(dest, reg_objective.str_general_match,
			size - strlen(dest));
		strncat(dest, "\" onMouseover=\"ddrivetip(\'A filter expression, defined in extended regular expression format: .*session opened for user root.*  \')\" onMouseout=\"hideddrivetip()\"></td></tr>", size - strlen(dest));

		strncat(dest, "</table><br>", size - strlen(dest));
		strncat(dest, "<input type=hidden name=objnumber value=",
			size - strlen(dest));
		strncat(dest, str_temp_objective, size - strlen(dest));	// Objective number goes here
		strncat(dest,
			"><input type=submit value=\"Change Configuration\">    ",
			size - strlen(dest));
		strncat(dest, "<input type=reset value=\"Reset Form\"></form>",
			size - strlen(dest));
	} else {
		void *rampointer = (void *) NULL;
		char *position;
		char inputbuffer[2*MAX_AUDIT_CONFIG_LINE + 2];
		char inputbuffer_swap[2*MAX_AUDIT_CONFIG_LINE + 2];
		int headertype = 0;
		FILE *configfile;

		rampointer = Load_Config_File();
		if (!rampointer) {
			dw_objective_error = WEB_READ_CONFIG_ERROR_CODE;
			dw_objective_delete_error = 1;
		} else {
			int objectivecounter = 0;
			int size = 0;

			position = (char *) rampointer;

			configfile = current_config("w");
			if (!configfile) {
				strncat(dest,
					"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
					size - strlen(dest));
				Clear_Config_File(rampointer);
				return (0);
			}

			while ((size =
				Grab_RAMConfig_Line(position, inputbuffer,
						    MAX_AUDIT_CONFIG_LINE))) {
				trim(inputbuffer);
				if (headertype == CONFIG_OBJECTIVES) {
					if(i_type == -2){
						if (objectivecounter ==  (i_objective_count - 1)){
							strcpy(inputbuffer_swap,inputbuffer);
							position += size;
							objectivecounter++;
							continue;
						}else if (objectivecounter ==  i_objective_count){
							strcat(inputbuffer,"\n\t");
							strcat(inputbuffer,inputbuffer_swap);
						}
					}
					if(i_type == -1){
						if (objectivecounter ==  i_objective_count){
							strcpy(inputbuffer_swap,inputbuffer);
							position += size;
							objectivecounter++;
							continue;
						}else if (objectivecounter ==  (i_objective_count + 1)){
							strcat(inputbuffer,"\n\t");
							strcat(inputbuffer,inputbuffer_swap);
						}
					}
					if(i_type == 0){
						if (objectivecounter ==
							i_objective_count) {
							// Do not add this line back into the original file.
							position += size;
							objectivecounter++;
							continue;
						}
					}
					objectivecounter++;
				}

				if (!iscomment(inputbuffer)) {
					// Is this line a header?
					if (isheader(inputbuffer)) {
						headertype =
						    getheader(inputbuffer);
					}
				}
				// Print this line to file.
				if (isheader(inputbuffer)
				    || iscomment(inputbuffer)
				    || !strlen(inputbuffer)) {
					fprintf(configfile, "%s\n",
						inputbuffer);
				} else {
					fprintf(configfile, "	%s\n",
						inputbuffer);
				}

				// position+=strlen(inputbuffer)+1;
				position += size;
			}
			if (fclose(configfile)) {
				dw_objective_delete_error = 1;
				strncat(dest,
					"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
					size - strlen(dest));
				Clear_Config_File(rampointer);
				return (0);
			}

			Clear_Config_File(rampointer);
		}

		if (dw_objective_delete_error == 0){
			strncpy(source,"/objective", 10);
			Objective_Config(source,dest,size);

		}else
			strncat(dest,
				"<br>The objective was unable to be deleted.",
				size - strlen(dest));
	}

	return (0);
}

int Grab_RAMConfig_Line(char *source, char *dest, int size)
{
	int count = 0;

	if (!source || !dest || !size) {
		return (0);
	}

	while (*source && count < size) {
		*dest = *source;
		if (*source == '\n') {
			dest++;
			count++;
			break;
		}
		count++;
		dest++;
		source++;
	}
	*dest = '\0';
	if (*source == '\0') {
		return (0);
	}
	return (count);
}

void *Load_Config_File()
{
	FILE *configfile;
	char *location;
	char inputbuffer[MAX_AUDIT_CONFIG_LINE];
	long filesize = 0;
	int configsize = 0;

	configfile = current_config("r");
	if (!configfile) {
		return ((void *) NULL);
	}

	if (fseek(configfile, 0, SEEK_END)) {
		fclose(configfile);

		return ((void *) NULL);
	}

	filesize = ftell(configfile);
	if (!filesize) {
		fclose(configfile);

		return ((void *) NULL);
	}

	if (fseek(configfile, 0, SEEK_SET)) {
		fclose(configfile);

		return ((void *) NULL);
	}

	location = malloc(filesize + 1);

	if (!location) {
		fclose(configfile);

		return ((void *) NULL);
	}

	while (fgets(inputbuffer, MAX_AUDIT_CONFIG_LINE, configfile)) {
		if ((configsize + strlen(inputbuffer)) > filesize) {
			// We have run out of room.
			free(location);
			fclose(configfile);

			return ((void *) NULL);
		}
		strcpy(location + configsize, inputbuffer);	// Safe from overflow due to above check.
		configsize += strlen(inputbuffer);
	}

	fclose(configfile);

	return (location);
}

void Clear_Config_File(void *location)
{
	if (!location)
		return;

	free(location);
}



int Objective_Result(char *source, char *dest, int size)
{
	// All strncpy or strncat functions in this routine have been designed avoid overflows
	struct Reg_Objective reg_objective;
	int dw_objective_error = 0;
	int i_objective = 0;
	char str_obj_count[10];
	char *psource = source, Variable[100], Argument[100];
	char emsg[8320] = "";

	strncpy(dest,
		"<H1><CENTER>SafedAgent Filtering Objectives Configuration</CENTER></H1>",
		size);

	while ((psource =
		getNextArgument(psource, Variable, sizeof (Variable), Argument,
				sizeof (Argument))) != (char *) NULL) {

		if (strstr(Variable, "str_general_match") != NULL) {
			strncpy(reg_objective.str_general_match, Argument,
				sizeof (reg_objective.str_general_match));
		}
		
		if (strstr(Variable, "objnumber") != NULL) {
			strncpy(str_obj_count, Argument,
				sizeof (str_obj_count));
		}
		if (strstr(Variable, "str_general_match_type") != NULL) {
			strncpy(reg_objective.str_general_match_type, Argument,
				sizeof (reg_objective.str_general_match_type));
		}
	}
	regex_t regexpCompiled;
	int errorCode = regcomp(&regexpCompiled, reg_objective.str_general_match, REG_EXTENDED | REG_NOSUB);
	if (errorCode != 0) {
		char errorMsg[8192];
		regerror(errorCode, &regexpCompiled, errorMsg, 8192);
		sprintf(emsg, "<br>Error compiling the regular expression: %s<br> Error code = %d<br> Error message = %s<br>", reg_objective.str_general_match, errorCode, errorMsg);
		dw_objective_error = WEB_READ_CONFIG_ERROR_CODE;
	}


	if (!dw_objective_error) {

		i_objective = atoi(str_obj_count);

		//-2 = "Add a new objective"
		if (i_objective == -2) {
			void *rampointer = (void *) NULL;
			char *position;
			char inputbuffer[MAX_AUDIT_CONFIG_LINE];
			int headertype = 0;
			FILE *configfile;

			rampointer = Load_Config_File();
			if (!rampointer) {
				dw_objective_error = WEB_READ_CONFIG_ERROR_CODE;
			} else {
				int size = 0;
				int wroteconfig = 0;

				position = (char *) rampointer;

				configfile = current_config("w");
				if (!configfile) {
					dw_objective_error = 1;
					strncat(dest,
						"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
						size - strlen(dest));
					Clear_Config_File(rampointer);
					return (0);
				}

				while ((size =
					Grab_RAMConfig_Line(position,
							    inputbuffer,
							    MAX_AUDIT_CONFIG_LINE)))
				{
					trim(inputbuffer);

					// Is this line a header?
					if (isheader(inputbuffer)) {
						if(wroteconfig && (wroteconfig < 2)){
							char generalstring[8];
							// WRITE OUT NEW OBJECTIVE HERE

							if (strstr(reg_objective.str_general_match_type,"Any") != NULL) {
								strncpy(generalstring, "match", sizeof(generalstring));
								strncpy(reg_objective.str_general_match,".*",sizeof(reg_objective.str_general_match));
							} else {
								if (strstr(reg_objective.str_general_match_type,"Include") != NULL) {
									strncpy(generalstring, "match", sizeof(generalstring));
								} else {
									strncpy(generalstring, "match!", sizeof(generalstring));
								}
							}

							fprintf(configfile,
								"	%s=%s\n",
								generalstring,
								reg_objective.str_general_match);
							wroteconfig = 2;
						}

						fprintf(configfile, "%s\n",
							inputbuffer);
						headertype =
						    getheader(inputbuffer);
						if (headertype ==
						    CONFIG_OBJECTIVES) {
							wroteconfig = 1;
						}
					} else {

						// Print this line to file.
						if (iscomment(inputbuffer)
						    || !strlen(inputbuffer)) {
							fprintf(configfile,
								"%s\n",
								inputbuffer);
						} else {
							fprintf(configfile,
								"	%s\n",
								inputbuffer);
						}
					}
					position += size;
				}

				if (wroteconfig < 2) {
					// Must not have been an objective header in the file...
					char generalstring[8];
					// WRITE OUT NEW OBJECTIVE HERE

					if (strstr(reg_objective.str_general_match_type,"Any") != NULL) {
						strncpy(generalstring, "match", sizeof(generalstring));
						strncpy(reg_objective.str_general_match,".*",sizeof(reg_objective.str_general_match));
					} else {
						if (strstr(reg_objective.str_general_match_type,"Include") != NULL) {
							strncpy(generalstring, "match", sizeof(generalstring));
						} else {
							strncpy(generalstring, "match!", sizeof(generalstring));
						}
					}


					if(!wroteconfig){
						fprintf(configfile,
						"\n\n[Objectives]\n	%s=%s\n",
						generalstring,
						reg_objective.
						str_general_match);
					}else{
						fprintf(configfile,
							"	%s=%s\n",
							generalstring,
							reg_objective.str_general_match);
					}
				}

				if (fclose(configfile)) {
					dw_objective_error = 1;
					strncat(dest,
						"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
						size - strlen(dest));
					Clear_Config_File(rampointer);
					return (0);
				}

				Clear_Config_File(rampointer);
			}
		} else {
			// Modify an existing objective
			void *rampointer = (void *) NULL;
			char *position;
			char inputbuffer[MAX_AUDIT_CONFIG_LINE];
			int headertype = 0;
			FILE *configfile;

			rampointer = Load_Config_File();
			if (!rampointer) {
				dw_objective_error = WEB_READ_CONFIG_ERROR_CODE;
			} else {
				int objectivecounter = 0;
				int size = 0;

				position = (char *) rampointer;

				configfile = current_config("w");
				if (!configfile) {
					dw_objective_error = 1;
					strncat(dest,
						"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
						size - strlen(dest));
					Clear_Config_File(rampointer);
					return (0);
				}

				while ((size =
					Grab_RAMConfig_Line(position,
							    inputbuffer,
							    MAX_AUDIT_CONFIG_LINE)))
				{
					trim(inputbuffer);

					if (headertype == CONFIG_OBJECTIVES) {
						if (objectivecounter ==
						    i_objective) {
							// Replace this objective with the new version.
							char generalstring[8];
							// WRITE OUT NEW OBJECTIVE HERE

							if (strstr(reg_objective.str_general_match_type,"Any") != NULL) {
								strncpy(generalstring, "match", sizeof(generalstring));
								strncpy(reg_objective.str_general_match,".*",sizeof(reg_objective.str_general_match));
							} else {
								if (strstr(reg_objective.str_general_match_type,"Include") != NULL) {
									strncpy(generalstring, "match", sizeof(generalstring));
								} else {
									strncpy(generalstring, "match!", sizeof(generalstring));
								}
							}

							fprintf(configfile,
								"	%s=%s\n",
								generalstring,
								reg_objective.str_general_match);

							position += size;
							objectivecounter++;
							continue;
						}
						objectivecounter++;
					}

					if (!iscomment(inputbuffer)) {
						// Is this line a header?
						if (isheader(inputbuffer)) {
							headertype =
							    getheader
							    (inputbuffer);
						}
					}
					// Print this line to file.
					if (isheader(inputbuffer)
					    || iscomment(inputbuffer)
					    || !strlen(inputbuffer)) {
						fprintf(configfile, "%s\n",
							inputbuffer);
					} else {
						fprintf(configfile, "	%s\n",
							inputbuffer);
					}

					// position+=strlen(inputbuffer)+1;
					position += size;
				}

				if (fclose(configfile)) {
					dw_objective_error = 1;
					strncat(dest,
						"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
						size - strlen(dest));
					Clear_Config_File(rampointer);
					return (0);
				}

				Clear_Config_File(rampointer);
			}
		}


	}
	if (dw_objective_error == 0){
		strncpy(source,"/objective", 10);
		Objective_Config(source,dest,size);
	}else{
		strncat(dest,
			"<br>The objective was unable to be modified/added.",
			size - strlen(dest));
		if(strlen(emsg))
			strncat(dest,emsg,size - strlen(dest));
	}
	return (0);
}


int DefaultHeader(char *source, char *dest, int size)
{

	if (!source || !dest || !size) {
		return(0);
	}

	strncpy(dest, "<HTML><head>"
		"<title>Wurth Phoenix</title>"
		"<meta name=\"TITLE\" content=\"Wurth Phoenix\">"
		"<style type=\"text/css\">\n"
		"body {\n"
		" font-family: Verdana,Helvetica,sans-serif;\n"
		" font-size: 10px; font-weight: normal;\n"
		" margin: 0px;\n"
		"}\n"
		"font {\n"
		" font-family: Verdana,Helvetica,sans-serif;\n"
		" text-decoration: none; font-size: 10px;\n"
		" font-weight: normal;\n"
		"}\n"
		"table {\n"
		" margin: 0px; padding: 0px;\n"
		"}\n"
		"td {\n"
		" font-size: 75%;\n"
		"}\n"
		"#dhtmltooltip{\n"
		"position: absolute;\n"
		"left: -300px;\n"
		"width: 150px;\n"
		"border: 1px solid black;\n"
		"padding: 2px;\n"
		"background-color: lightyellow;\n"
		"visibility: hidden;\n"
		"z-index: 100;\n"
		"filter: progid:DXImageTransform.Microsoft.Shadow(color=gray,direction=135);\n"
		"}"
		"#dhtmlpointer{\n"
		"position:absolute;\n"
		"left: -300px;\n"
		"z-index: 101;\n"
		"visibility: hidden;\n"
		"}\n"
		"</style>\n"
		"<script type=\"text/javascript\">\n"
			"var offsetfromcursorX=12\n"
			"var offsetfromcursorY=10\n"
			"var offsetdivfrompointerX=10\n"
			"var offsetdivfrompointerY=14\n"
			"document.write('<div id=\"dhtmltooltip\"></div>')\n"
			"document.write('<img id=\"dhtmlpointer\" src=\"/arrow.gif\">')\n"
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
		"</head>"
		"<body text=black bgcolor=white link=#000066 vlink=#000044 alink=#000055>"
		"<table border=0 cellspacing=0 cellpadding=0 columns=3 width=100%>\n"
		"<tbody>\n"
		" <tr>\n"
		"	<td height=70 border=0 bgcolor=#E6E6E6 width=22%></td>\n"
		"  <td height=70 bgcolor=#c3c7d3><img src=/logo.gif alt=\"Wurth Phoenix\" width=70% height=70 hspace=0 vspace=0 border=0 align=Right>"
		"</td>\n"
		"<td height=70 border=0 bgcolor=#c3c7d3 width=18%></td>"
		" </tr>\n"
		"</tbody>\n"
		"</table>\n"
		"<table border=0 cellspacing=0 cellpadding=5 width=100% height=100%  bgcolor=#c3c7d3>\n"
		"<tbody>\n"
		" <tr>\n"
		"  <td valign=Top width=22% bgcolor=#E6E6E6>\n"
		"   <div align=Center>\n"
		"   <br>\n"
		"<table border=0 cellspacing=0 cellpadding=5 columns=2>", size);

		if (USER_CONFIG_FILENAME[0] == '\0')
			strncat(dest,"   <tr><td><img src=/list.gif alt=\"\"   align=Right></td><td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/dailylog\" style=\"color:black;text-decoration:none\">Daily Events</A></font></td></tr>" , size);
			//strncat(dest,"   <tr><td><img src=/cfg.gif alt=\"\"   align=Right></td><td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/switch\" style=\"color:black;text-decoration:none\">Switch Configuration Files</A><br></tr>\n", size);

		strncat(dest,
		"<tr>"
		"<td><img src=/cfg.gif alt=\"\"   align=Right></td>"
		"<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/network\" style=\"color:black;text-decoration:none\">Network Configuration</A><br>\n"
		"</tr>"
		"<tr>"
		"<td><img src=/cfg.gif alt=\"\"   align=Right></td>"
		"<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/remote\" style=\"color:black;text-decoration:none\">Remote Control Configuration</A><br>\n"
		"</tr>"
		"<tr>"
		"<td><img src=/cfg.gif alt=\"\"   align=Right></td>"
		"<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/log\" style=\"color:black;text-decoration:none\">LogFile Configuration</A><br>\n"
		"</tr>"
		"<tr>"
		"<td><img src=/cfg.gif alt=\"\"   align=Right></td>"
		"<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/log/objective\" style=\"color:black;text-decoration:none\">LogFile Objectives Configuration</A><br>\n"
		"</tr>"
#if defined(__sun) || defined(_AIX) || defined(__linux__)
		"<tr>"
		"<td><img src=/cfg.gif alt=\"\"   align=Right></td>"
		"<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/safed/objective\" style=\"color:black;text-decoration:none\">EventLog Objectives Configuration</A><br>\n"
		"</tr>"
#endif
#if defined(__linux__)
		"<tr>"
		"<td><img src=/cfg.gif alt=\"\"   align=Right></td>"
		"<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/safed/watch\" style=\"color:black;text-decoration:none\">Watches Configuration</A><br>\n"
		"</tr>"
#endif
		"<tr>"
		"<td><img src=/status.gif alt=\"\"   align=Right></td>"
		"<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/status\" style=\"color:black;text-decoration:none\">View Audit Service Status</A><br>\n"
		"</tr>"
		"<tr>"
		"<td><img src=/status.gif alt=\"\"   align=Right></td>"
		"<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/safedlog\" style=\"color:black;text-decoration:none\">Safed Log</A><br>\n"
		"</tr>"
		"<tr>"
		"<td><img src=/save.gif alt=\"\"   align=Right></td>"
		"<td><font face=\"Helvetica,Arial,sans-serif\" size=-1><B><A HREF=\"/restart\" style=\"color:black;text-decoration:none\">Apply the Latest Audit Configuration</A><br>\n"
		"</tr>"
		"<tr><td></td></tr>"
		"<tr><td></td></tr>"
		"<tr><td></td></tr>"
	    "<td><img src=/search.gif alt=\"\" align=Right></td>"
	    "<td><font face=\"Helvetica,Arial,sans-serif\" size=-2><A HREF=\"/GetConfig\" style=\"color:black;text-decoration:none\" target=\"_self\">Get Configuration</A></font></td>"\
	    "</tr>"
#ifdef TLSPROTOCOL
	    "<tr>"
	    "<td><img src=/cfg.gif alt=\"\" align=Right></td>"
	    "<td><font face=\"Helvetica,Arial,sans-serif\" size=-2><A HREF=\"/certs\" style=\"color:black;text-decoration:none\" target=\"_self\">Set Certificates</A></font></td>"
	    "</tr>"
#endif
	    "<tr>"
	    "<td><img src=/cfg.gif alt=\"\" align=Right></td>"
	    "<td><font face=\"Helvetica,Arial,sans-serif\" size=-2><A HREF=\"/config\" style=\"color:black;text-decoration:none\" target=\"_self\">Set Configuration</A></font></td>"
	    "</tr>"
		"<tr><td><br></td><td><br></td></tr>"
		"<tr>"
		"<td></td>"
		"<td><font face=\"Helvetica,Arial,sans-serif\" size=-2><A HREF=\"/License\" style=\"color:black;text-decoration:none\" target=\"SafedData\">About License</A><br>\n"
		"</tr>"
		"   </table> \n"
		"   </div>\n"
		"  </td>\n"
		"  <td width=100% valign=Top>\n"
		"   <table cellpadding=0 cellspacing=10 border=0 width=100%>\n"
		"    <tbody>\n"
		"    <tr>\n"
		"     <td valign=Top align=Justify>\n", size);

	return (0);
}

int DefaultFooter(char *source, char *dest, int size)
{

	if (!source || !dest || !size) {
		return(0);
	}

	strncpy(dest, "     </td>\n"
		"    </tr>\n"
		"    </tbody>\n"
		"   </table>\n"
		"<center>\n"
		"<BR><BR><FONT SIZE=-1>"
		"This site is powered by <A HREF=\"http://www.wuerth-phoenix.com/neteye\">SafedAgent for UNIX.</A></FONT>"
		"</center>\n"
		"</td></tr></tbody></table>\n"
		"</body></html>", size);

	return (0);
}


int Restart(char *source, char *dest, int size, int socketone, int sockettwo) {
	if (write(fds[1], "RESTART", 7) == -1) {
		perror("Restart: write");
	}
	strncpy(dest, "<H1><CENTER>Reapply the Latest Configuration</H1><P>Reapplying the configuration</CENTER>", size);
	return (0);
}

// General instructions:
// $ expr `./base64 logo.gif | wc -c` - `./base64 logo.gif | wc -l` "*" 2 + 1
//   2029
// ./base64 logo.gif | sed 's/^/   "/' | sed 's/.$/"  \\/' >out.txt
// 
//  mangle out.txt as appropriate - add the (wc -c) - ((wc -l)*2) + 1 figure to the buffer size.
int LogoImage(char *source, char *dest, int size)
{
	char LogoGif[15000];
	char temp[15000];
	int size2;

	if (!source || !dest || !size) {
		return(0);
	}

	strncpy(LogoGif,   "R0lGODlh5AN5AOf/ABkaGBocGRscGhwdGx0fHB4fHR8gHiAhHyEjICIkISMkIiQlIyQmJCUnJCYo"
			   "JScoJigpJ7cAIrYAKCkqKCkrKLgBIyosKbgCKcIAIsEAKMMAI8EALSstKrcDLsMAKSwtK8IBLsUC"
			   "Hs0AHC0uLMwAIbkFKdAAF8sAJ80AIs8AHc4AI8sALMQDJM0AKMwALS4vLc4AKaUMK7gGL7sHH8wA"
			   "M9ABHs4ALroHJdgAEy4wLdYAGsYFGcQEKdABJNkAFNcAGtYAILELINoAFcQEL9kAG9cAIdYAJrEL"
			   "JroIKtwAFtoAHNgAIs8CKdUALNcAJ8YGH9sAHdYALNgAKNoAI9kAKMYGJdsAI7AMK9IEGDAyL7oJ"
			   "L7wKINsAKbINIdEEH88DL6gQIuIAGcUHKuEAH90CF+MAGrkKNTEzMOQAG+MAIOEAJrwLJscJGjIz"
			   "MbIOJ9EFJbsLK7EOLOYAG+QAIeIAJ8cJIMUIMOcAHOUAIuQAJ90DHucAIzM0MtEGKr0NIbEPMcQJ"
			   "NbMQIscKJtwEJLMQJ9MIGTM1M7sNMdIIH9wEKtAHML0OJ8YLK7wOLMkMGt4GGLMRLdIJJc8IOqgU"
			   "N7QSKMgNITU3NN4HH8gNJr4QJ9QLGtIKK7QTLr8RIqwWKjY4Nd4IJcgOLL4RLccOMdQMIMoPItMM"
			   "Jjc5NqwXL7UVKTg5N7UVLskQJ7QVNK0YK78TKMkQLb8TLt8LIK4ZJjk6OLcWKr4UM8kRMrYXLzo7"
			   "ObYXNMAVLtQQLcoTLsAWNDs9OrcZNcEXL58hNTw+O7kaMeAQLbgbNj0/PN8QMrocLLocMj5APT9A"
			   "PtcVL0FCQEFDQbsgPkJEQa0mOENFQkRGQ0VHREZIRUdJRkhJR0pLSUpMSktNSkxOS6M3SU9RTlBS"
			   "T1FTUFNUUlRVU8U1R1VWVFZXVVZYVVdZVlhaV1xeW11fXF9hXmFjYGJkYWVmZGZnZWdoZmlraGps"
			   "aWttam5wbXJ0cXN1cnd5dnl7eICCf4aIhY2PjJOVkpial6Smo////yH+EUNyZWF0ZWQgd2l0aCBH"
			   "SU1QACH5BAEKAP8ALPgAHgD0AT0AAAj+AP8JHEiwoMGDCBMqXMiwocOHECNKnEixosWLGDNq3Mix"
			   "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"
			   "AHkXbAOwABbADNyX+aRf+qZ/+qif+qrPLQEBADs=", 15000);



	size2 = base64decode(temp, LogoGif);
	if(size2 < 15000){
		size2 = 15000;
	}
	if (size2 > size) {
		return(0);
	}

	memcpy(dest, temp, size2);
	return(size2);

}

int SearchImage(char *source, char *dest, int size)
{
	char Gif[1400];
	char temp[1400];
	int size2;

	strncpy(Gif,    "R0lGODlhEAAQAIcAAAAAACknJjY0Mj89O0NBPkpKSFBQT1ZVVFRXWVxaWF5bWF9eW19gYGNUVGVb"
   "V3RZVXhgWmNiYmVjY2ppaGpsbmxranVzcXl4eW92gnV/inuCj3qHl4E4KYc5KpA1J4tSO49RPJVN"
   "NLBjHJVeV4htbZd8fKdhW99uEO1qCfFrCoKAf/SONOq0RP/UOv/VPP/bPfLHTfPITPjHX4yLiIyL"
   "i4SHko6QmpGPi5aVkpmZn52cnp6en5CcpJifo5mdq5egqJikpqSjo6ClqKanqqqqqqmwtq6xta+x"
   "ta+zt7CwsLKysIms15ms1Ze666m+7ZTL/5jH95nM/5nN/5rN/57P/5/P/53T/6LR/6TS/6TY/6jT"
   "/6nV/6nX/6rW/6vW/6zX/7LA4rDF8rTI9LfP+bfQ4L7Q7bLX/7XW/7La/7Tb/7Td/7fc/7jb/rvf"
   "/7rg/7vg/7/g/8PDw8vLys3IyM/PztXV1cve58Lh/8Pi/8Xl/cfl/8fo/8jm/83n/8vo/8zo/87t"
   "/9Pl9NLp/9Pr/9Ts+tjp9djv/9jw/9nw/9ny/9vw/9vz/9v1/9/z//X0y+Ti4uji4ujk5Onk5Orm"
   "5uvm5uvr6+3p6eD0/+D3/+L1//Dr6/Dw7/f39/n5+fv7+/39/f///wAAAAAAAAAAAAAAAAAAAAAA"
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAMAAKAALAAAAAAQABAA"
   "AAjGAEGBooMjhw8bFmYIXLhQiQ4wYcQ4YVJDAUOBcnaMOSNI0SA2TTQsuHijzJU3eO7AcZNlyQEi"
   "DIOYeYJlixctVaxAwZCA4ZE1VKRImRJlChc1GwgwHOKnDZouW76k2ZMnwwCGKgIB+qNHD58+jMgg"
   "YMCQhpFFiQ4ZQoSJEI8Acy5WQFKoUaZLdn4AKWHiIqgJF4QU6UFBAAlHMkL4TSLBQIEIcUasaBED"
   "hF+/HlK4gPHh8sUOKF6wgOCZIYcTIhyUZvigAaiAADs="   ,1400);

	size2=base64decode (temp, Gif);

	memcpy(dest,temp,size2);
	return(size2);
}

int CfgImage(char *source, char *dest, int size)
{
	char Gif[1300];
	char temp[1300];
	int size2;

	if (!source || !dest || !size) {
		return(0);
	}

	strncpy(Gif, "R0lGODlhEAAQAIcAAAAAAEYqImVJOXhILndPMnRTN0FBQEJER0REQ0dISE5OTlFKS1dMS1BQUFBR"
			   "UVlZWVtcXWRNRGtUSm9dV3FWS3ddVmJhYmVlZWlpaWtsbG1tbmxub21ub3NoaHNrbXxubnZwb3xx"
			   "bnBwcHNzc3Byen1wcXx8f39/gZJKHZZMGYBNL75WFaJfMK9nJbRoILhwK712Oax9Trl0TN5tFb2d"
			   "csmVU9+YTtuYUteocuOiXOCyduO1fPe+ev/Cav/NfoCAg4eHiIuDgomJiY+JiY6Pjo6Pk5OFhpeX"
			   "m56Wl5iZmZ6enpucoKCgoKCjpKamp6anqKepqqmprKusrKytr6qwtrCwsbCxs7e3t7K0uLG3vrm5"
			   "ubi5u73Awr/Bxdi5lc++tP/TgP3Ql/7bn/3ftv/fvv/hm//mqP/nrcPDw8PGzcfKzMrJy87Ozs3P"
			   "0c3P1tLS0tHT1tPS19XV1dvb297e3v/zx//83eHj5uXl5ejm6Onp6evr6+3s7O/u7vPz8/f39/v7"
			   "+/39/f///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAMAAIIALAAAAAAQABAA"
			   "AAimAAUJFAjkxJElRUwwGcgQTQYucKI8mbIliQiGAjm0uWNlQwIEDR4o0MJwRBM1XdKQsIBRIBsM"
			   "QqRAyUKFRoGWgn7EWUPkAIgaYHREaKnBDRYDSkK46GEmxpCWEBxcEFiihQ8xBHBeYfjhRZkdAnBi"
			   "pHDjDA4JYhmq4FHHy4S0Ao3ACGPniwe4ggbkGENGRhC4SFjYmLGCAd4KKVAEcIJXUIcFVQQFBAA7", 1300);



	size2 = base64decode(temp, Gif);
	if(size2 < 1300){
		size2 = 1300;
	}
	if (size2 > size) {
		return(0);
	}

	memcpy(dest, temp, size2);
	return(size2);

}


int ListImage(char *source, char *dest, int size)
{
	char Gif[1300];
	char temp[1300];
	int size2;

	if (!source || !dest || !size) {
		return(0);
	}

	strncpy(Gif, "R0lGODlhEAAQAIcAAAAAAB8seiUtWSMuYyMwaD1CX1oVFkkjI00yM2I/P0tPaFFSY1hcd3RKSn9M"
				"SG1ufxo/mwc1pCQ5tzpJiDxNkQ5J0yhWzjp24khTlllclktXokpWqUlTuktts2dpsGdot2RovGhp"
				"tlhnwUZ55COC/ymE/1uDzUyQ+Eyc/06d/1SM81CN/1id/1mc/1yY+1+b/F2c/12g/2KN1Wab82Ke"
				"/3+u7HWq/3bC/33B/5YqK5czMp03NphRUZtTUZpvb8cXGdkbHPQNC/oPDf89NNpGPP9ANt1RR/9N"
				"Sv9PTY6OjpGRkZWVmpiYmbWWlruYmaCgoKqqqqurq6yrq7CwsLm5vry8vJub0bCw2oDC/4nG/7rg"
				"/8utrM+xsc/P1M/P1tfX19rZ2dra2t7e38rK5cvV8dHR6dfe88Ti/8rl/97r/+ba2v/NxP/Rx+Li"
				"4+np6e7r6/Pt7fX19ff39/Pz+////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAMAAHQALAAAAAAQABAA"
				"AAibAOkIHEhQIAgrGQoqpMNhhpYRDBYS3HDixoUCEp00odOFQocBTBb24LLFgcAlVRbyMMJmDZEE"
				"EgXmEFJkSBADMen4AILkyA8EBceE+ODBC50GO3QcmELwiggzc8hooEJHihKFEl6gSXNmRYCYFUrQ"
				"sAGDRIQoEi2kaBGDBQoITyRicIElCw4VAmJ2mSCjhgkCSXLSeaBgAZScAQEAOw==", 1300);



	size2 = base64decode(temp, Gif);
	if(size2 < 1300){
		size2 = 1300;
	}
	if (size2 > size) {
		return(0);
	}

	memcpy(dest, temp, size2);
	return(size2);

}



int StatusImage(char *source, char *dest, int size)
{
	char Gif[1400];
	char temp[1400];
	int size2;

	if (!source || !dest || !size) {
		return(0);
	}

	strncpy(Gif, "R0lGODlhEAAQAIcAAAAAAAQfmgYcmA0alAgfmgYinA4mnQ4qnxMjlxInmhcrmwAupgkqpQA0rgA7"
			   "pQA9rAA+rAA/rgA1shMzoxMzqQNBrQBBsgVGuQZHugZHuw1AtwtMvQxMvQ1PvxtArB1CqhJGuxNP"
			   "ux9ItB9JuylNqyhMrCZRrS1VryRQsyVStChRtCtVsitWsitWtDZlvwBDwwBIyw1LxgBH0ARSzg1S"
			   "wgpQyQBR0gBU2BBRyhVWzxlSyBtcyRtd0QBV4gFZ4B9hzhBg3g9i4SBYxyFczyNdzyRf0yBa2CRh"
			   "zCNs3C1t1DBo1TNv1j1x1jpw2SRy7C135Sd++Ct/9DNw4DJ97T164T9/801Qp05Rp1VerVlgrmJ0"
			   "uWR2unh4uHx8ukJvyUNyzU50yUB620x+30x/3kyA31KD3FSD2E2C4E6C4FWR9Vic+WmBwGqCwWGM"
			   "3G+c3nGZ3nid32qY52+b4G+c4Wyb6mqe8nKd53ed4HOg63Om93mm8Hqq8oePxYmQxYmSxoyVyZin"
			   "0pin04Kl4oCk5ISn4oir54+x54a09Iy1956+65G495a68pC6+pK+/Je++pTA+qPN+aPM+q7S/7jI"
			   "577N6bHW/7ba/8PD38XF4cvN5c3P5tHW6tLW6tLc69Pf7tXc7dTd7tTe7dfc7dbg6tvi6/X17/v5"
			   "7/H09fP29fb38fP0+PX1+vT2+Pf48vv7/f7+/v///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAMAALAALAAAAAAQABAA"
			   "AAjaAGEJHEiwoME1J1qoKKHFoEBALNw8OrQnDxkPfgoGcgGp0iJKk+zUSTOiD8EVkSQxMsRK1Rs0"
			   "Z6pQ0CSQjRxLjhDREQRnjBgmUoxgEWhCTSNFeAoNulOmiZIhPBQITAHFiZ44hE6halOESAYaBwSi"
			   "iNIDCJUwoFqZiXEhQgcDAklM8XFDRo5Qqb5IsACBAwKBW5YEsQEDR6dSXho8qKDBysAPT2a80EHK"
			   "FJgFDjYQwDTwjwgkNeZ4GpUoBAYGXQrymSAkyY8dR0AI4OIwU5YEBQIMuHLJoe+CAQEAOw==", 1400);



	size2 = base64decode(temp, Gif);
	if(size2 < 1400){
		size2 = 1400;
	}
	if (size2 > size) {
		return(0);
	}

	memcpy(dest, temp, size2);
	return(size2);

}


int SaveImage(char *source, char *dest, int size)
{
	char Gif[1400];
	char temp[1400];
	int size2;

	if (!source || !dest || !size) {
		return(0);
	}

	strncpy(Gif,  "R0lGODlhEAAQAIcAAAAAADQzez89ekEoJUkrMEU5O28zD3gwGGUzS0FCWUlNUUlJWE1NWk9PXU5O"
			   "X1BQXlBQX1FQX1NYUlpYWVJRYFNTcltbdHpaWmNjbGxseB8khSMkhSkqiigpmDA4mzlMukpIgEZF"
			   "kktInlVSgEFCrFBSpVhVsVtYtVtlvVpvtlNyvnNfq2pnlW5hmnx9mGJgvnJpv3lsvkdhymVmx2hm"
			   "w2lnx21owmN30ndswHBvz3Rz1H9+1Xl42XWR45BSB6dXG6xrAptbZptoQ4lxcKdzQ6d9VL5+WKJx"
			   "baNycNJzAcplJ4FwwrOLVuyaAP+vF96zWOWuU+ywevvFAf/dBf/fGP/OK+vOZPPdbPfZbP/wRv/9"
			   "WP/2YYWFi4yIjoyMjoKPnYeFqYqGoIyTp52dt5uguLiAg6ensLq6u42Dx42Hy4eO1I2Vxo2W05OC"
			   "1JSQ1ZSb8ISizJquxZe105640Iut85i+4K6Z0KCyxqO0wquwwqS50ai/0Lm+zKCr6KWi8amr96S7"
			   "/6i8/6m8/6m9/qq//6u+/72x5rK3/7O2/7Sz/ra0/rm3/rq4+by+/5jA85nB/qTC1q3C067I3rbE"
			   "2rPN36zG/LbP57jD/7rQ5bfT/77e/8CPj8Cngei/jPPyrcDBzcjIyMzM19PT3sDG/8LE/8XG/8fP"
			   "/8LZ6cHY7cnb78La8M3U/9fZ/9fe/8Pl/8Xl+8rt/9Hg6t3h7dnu+Nnx/9n1/9/3/+Li4ubm5uHm"
			   "/+/v8unv/+L0+uT0+/f39/H8//n5+fn5+vr6//j8//n+//r8//39/f39/v7//////wAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAMAAMkALAAAAAAQABAA"
			   "AAjwAJMJHEiwYLIOJGbQsAEDR4wlK8IU1JCizyhTq1rl2iXMTotkm5Ak26ACjpo/hxA1KsWqmCEE"
			   "RpQMESCjjhw2fhIpWkSKURkonqIcYPHBEaQ5a9KgcdMmyJMtVIgQGOPhkaQ4eyJRIiPEipYpQAaA"
			   "SsaBzis9d1DxYXIlixQfBQYG6AHLEqZJRbBUaWJgAsERN1ypOmWmk5MkRyoUBINCEy08Ejj9uJBK"
			   "zBmCoUpksvVFQZc8sZB94lIwRKVas3j1+kVsmCwMBUG8ATQoUKFAgghdslDQhQgTJ17UyKGDx44E"
			   "BjMwaPAAQgQKDhZ4GRgQADs=" , 1400);



	size2 = base64decode(temp, Gif);
	if(size2 < 1400){
		size2 = 1400;
	}
	if (size2 > size) {
		return(0);
	}

	memcpy(dest, temp, size2);
	return(size2);

}


int ArrowImage(char *source, char *dest, int size)
{
	char Gif[1300];
	char temp[1300];
	int size2;

	if (!source || !dest || !size) {
		return(0);
	}

	strncpy(Gif,  "R0lGODlhDwAPAPcAAAQCBPz+5Pz+/AAAAJWYoB7mMAASRQAAAJrjkB3q5wCQEgB8AAA06wDmhxUS"  \
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
			   "Ll9WVEmTY8yaAm/iDAgAOw==" , 1300);



	size2 = base64decode(temp, Gif);
	if(size2 < 1300){
		size2 = 1300;
	}
	if (size2 > size) {
		return(0);
	}

	memcpy(dest, temp, size2);
	return(size2);

}


int debracket(char *source, char *dest, int length)
{
	// This routine is simply to replace the HTML metacharacters "<" and ">" with
	// "&lt;" and "&gt;". That's all!

	int count = 0;
	char *copyofdest;
	copyofdest = dest;

	if (!source || !dest)
		return (1);

	while (*source) {
		if (*source == '<') {
			if (count < length) {
				*dest = '&';
				dest++;
				count++;
			}
			if (count < length) {
				*dest = 'l';
				dest++;
				count++;
			}
			if (count < length) {
				*dest = 't';
				dest++;
				count++;
			}
			if (count < length) {
				*dest = ';';
				dest++;
				count++;
			}
		} else if (*source == '>') {
			if (count < length) {
				*dest = '&';
				dest++;
				count++;
			}
			if (count < length) {
				*dest = 'g';
				dest++;
				count++;
			}
			if (count < length) {
				*dest = 't';
				dest++;
				count++;
			}
			if (count < length) {
				*dest = ';';
				dest++;
				count++;
			}
		} else {
			if (count < length) {
				*dest = *source;
				dest++;
				count++;
			}
		}
		source++;
	}
	*dest = '\0';

	dest = copyofdest;

	return (0);
}

int Read_Config_From_File(struct Reg_Config *config_struct) {
	FILE *configfile;
	char inputbuffer[MAX_AUDIT_CONFIG_LINE];
	int headertype = 0;

	configfile = current_config("r");
	if (!configfile)
		return (0);

	strcpy(config_struct->str_ClientName, "");

	while (fgets(inputbuffer, MAX_AUDIT_CONFIG_LINE, configfile)) {
		// Kill whitespace from start and end of line.
		trim(inputbuffer);
		if (!iscomment(inputbuffer)) {
			// Is this line a header?
			if (isheader(inputbuffer)) {
				headertype = getheader(inputbuffer);
			} else {
				if (headertype == CONFIG_HOSTID) {
					if (!strlen
					    (config_struct->str_ClientName)) {
						// Grab hostname here.
						if (!getconfstring(inputbuffer, config_struct->str_ClientName, SIZE_OF_CLIENTNAME)) {
							strncpy(config_struct-> str_ClientName, "", SIZE_OF_CLIENTNAME);
						}
					}
				} else if (headertype == CONFIG_OUTPUT) {
					if (isnetwork(inputbuffer)) {
						// Ignore network entries for now, we will come back to them later
					} else if (issyslog(inputbuffer)) {
						config_struct->dw_Syslog = getSyslogPriority(inputbuffer);
						if (!config_struct->dw_Syslog) {
							config_struct->dw_Syslog = 13;
						}
					}else if(isdays(inputbuffer)){
						config_struct->dw_NumberOfFiles = getMaxDaysInCache(inputbuffer);
					}else if(iswaittime(inputbuffer)){
						config_struct->dw_waitTime = getWaitTime(inputbuffer);
					}else if(ismaxmsgsize(inputbuffer)){
						config_struct->dw_MaxMsgSize = getMaxMsgSize(inputbuffer);
					}else if(issetaudit(inputbuffer)){
						config_struct->dw_SetAudit = getSetAudit(inputbuffer);
					}
				} else if (headertype == CONFIG_LOG) {
					if(isLogFileToKeep(inputbuffer)){
						config_struct->dw_NumberOfLogFiles = getLogFileToKeep(inputbuffer);
					}else if(isLogLevel(inputbuffer)){
						config_struct->dw_LogLevel = getLogLevel(inputbuffer);
					}
				}
			}
		}
	}
	// If we have made it this far, then we don't have any objectives.
	fclose(configfile);
	return (0);

}

int Read_Remote_From_File(struct Reg_Remote *remote_struct)
{
	FILE *configfile;
	char inputbuffer[MAX_AUDIT_CONFIG_LINE];
	int headertype = 0;

	configfile = current_config("r");
	if (!configfile)
		return (0);

	remote_struct->dw_Allow = 0;
	remote_struct->dw_TLS = 0;
	remote_struct->dw_WebPort = 80;
	remote_struct->dw_Restrict = 0;
	strncpy(remote_struct->str_RestrictIP, "", SIZE_OF_RESTRICTIP);
	remote_struct->dw_Password = 0;
	strncpy(remote_struct->str_Password, "", SIZE_OF_PASSWORD);	// Just a failsafe password - not a default.

	while (fgets(inputbuffer, MAX_AUDIT_CONFIG_LINE, configfile)) {
		// Kill whitespace from start and end of line.
		trim(inputbuffer);

		if (!iscomment(inputbuffer)) {
			// Is this line a header?
			if (isheader(inputbuffer)) {
				headertype = getheader(inputbuffer);
			} else {
				if (headertype == CONFIG_REMOTE) {
					if (regmatchInsensitive(inputbuffer, "^allow=")) {
						if (regmatchInsensitive
						    (inputbuffer, "=1")) {
							remote_struct->
							    dw_Allow = 1;
						}
					} else
						if (regmatchInsensitive(inputbuffer, "^https=")) {
							if (regmatchInsensitive
							    (inputbuffer, "=1")) {
								remote_struct->
								    dw_TLS = 1;
							}
					} else
					    if (regmatchInsensitive
						(inputbuffer,
						 "^listen_port=")) {
						remote_struct->dw_WebPort =
						    getport(inputbuffer);
					} else
					    if (regmatchInsensitive
						(inputbuffer,
						 "^restrict_ip=")) {
						if (!getconfstring
						    (inputbuffer,
						     remote_struct->
						     str_RestrictIP,
						     SIZE_OF_RESTRICTIP)) {
							remote_struct->
							    dw_Restrict = 0;
							strncpy(remote_struct->
								str_RestrictIP,
								"",
								SIZE_OF_RESTRICTIP);
						} else {
							remote_struct->
							    dw_Restrict = 1;
						}
					} else
					    if (regmatchInsensitive
						(inputbuffer, "^accesskey=")) {
						if (!getconfstring
						    (inputbuffer,
						     remote_struct->
						     str_Password,
						     SIZE_OF_PASSWORD)) {
							remote_struct->
							    dw_Password = 0;
							strncpy(remote_struct->
								str_Password,
								"",
								SIZE_OF_PASSWORD);
						} else {
							remote_struct->
							    dw_Password = 1;
						}
					}
				}
			}
		}
	}

	fclose(configfile);
	return (0);

}

// Return the host identifier
int getnetwork(char *string, char *host, int length, char *protocol)
{
	char *stringp = string;
	char *pos, *pos2;
	char strPort[10];

	stringp = strstr(string, "=");

	if (stringp != (char *) NULL) {
		stringp++;
		if (strlen(stringp)) {
			pos = strstr(stringp, ":");
			if (pos != (char *) NULL) {
				*pos = '\0';
				pos++;
				strncpy(host, stringp, length - 1);
				pos2 = strstr(pos, ":");
				if (pos2 != (char *) NULL) {
					*pos2 = '\0';
					pos2++;
					if(strlen(pos2))
						strncpy(protocol, pos2 , 10);
				}
				if(strlen(pos)){
					strncpy(strPort, pos , 10);
					return (atoi((char *) strPort));
				}else
					return(6162);
			} else {
				strncpy(host, stringp, length - 1);
				return(6162);
			}
		} else {
			return (0);
		}
	} else {
		return (0);
	}
}

void getlog(char *string, struct Reg_Log *log_struct)
{
	char *stringp;
	char *pos, *pos2;
	stringp = strstr(string, "=");
	stringp++;
	if (strlen(stringp)) {
		pos = strstr(stringp, ":");//for compatibility with format type:absolute path
		pos2 = strstr(stringp, "/");
		if (pos && pos2 && pos < pos2) {
			stringp = pos + 1;
		}
		pos = strstr(stringp, "|");//for file pattern
		if(pos){
			pos2 = pos + 1;
			*pos = '\0';
			strncpy(log_struct->format, pos2, MAX_AUDIT_CONFIG_LINE);
		}
		// Record the name and open the file for reading
		strncpy(log_struct->name, stringp, MAX_AUDIT_CONFIG_LINE);
	}
}

FILE *Find_First(int config_header)
{
	FILE *configfile;
	char inputbuffer[MAX_AUDIT_CONFIG_LINE];
	int headertype = 0;

	configfile = current_config("r");
	if (!configfile)
		return (configfile);
	while (fgets(inputbuffer, MAX_AUDIT_CONFIG_LINE, configfile)) {
		// Kill whitespace from start and end of line.
		trim(inputbuffer);
		if (!iscomment(inputbuffer)) {
			// Is this line a header?
			if (isheader(inputbuffer)) {
				headertype = getheader(inputbuffer);
				if (headertype == config_header) {
					return (configfile);
				}
			}
		}
	}
	// If we have made it this far, then we don't have any objectives.
	fclose(configfile);
	configfile = (FILE *) NULL;
	return (configfile);
}

int Get_Next_Network(FILE * configfile, struct Reg_Host *host_struct) {
	char inputbuffer[MAX_AUDIT_CONFIG_LINE];
	while (fgets(inputbuffer, MAX_AUDIT_CONFIG_LINE, configfile)) {
		trim(inputbuffer);

		if (isheader(inputbuffer)) {
			return (0);
		}

		if (strlen(inputbuffer) < 3) {
			continue;
		}

		if (isnetwork(inputbuffer)) {
			host_struct->dw_DestPort =
			    getnetwork(inputbuffer,
				       host_struct->
				       str_NetworkDestination,
				       SIZE_OF_DESTINATION,
				       host_struct->
				       str_Protocol);
			if (!host_struct->dw_DestPort) {
				// Give it the default value
				host_struct->dw_DestPort = 6162;
			}
			return(1);
		}
	}
	return (0);
}








int Get_Next_Objective(FILE * configfile, struct Reg_Objective *objective)
{
	char inputbuffer[MAX_AUDIT_CONFIG_LINE];
	// Save off enough space to store the data we need.
	char path[MAX_AUDIT_CONFIG_LINE];
	int excludematchflag = 0;

	while (fgets(inputbuffer, MAX_AUDIT_CONFIG_LINE, configfile)) {
		trim(inputbuffer);

		if (isheader(inputbuffer)) {
			return (0);
		}

		if (strlen(inputbuffer) < 3) {
			continue;
		}
		if (splitobjective(inputbuffer, path, &excludematchflag) > -1) {
			// add the objective to the linked list.

			if (excludematchflag) {
				strncpy(objective->str_general_match_type,
					"Exclude",
					sizeof (objective->
						str_general_match_type));
			} else {
				strncpy(objective->str_general_match_type,
					"Include",
					sizeof (objective->
						str_general_match_type));
			}

			strncpy(objective->str_general_match, path,
				SIZE_OF_GENERALMATCH);

			return (1);
		}
	}
	return (0);
}

int Get_Next_Log(FILE * configfile, struct Reg_Log *log_struct) {
	char inputbuffer[MAX_AUDIT_CONFIG_LINE];
	while (fgets(inputbuffer, MAX_AUDIT_CONFIG_LINE, configfile)) {
		trim(inputbuffer);

		if (isheader(inputbuffer)) return (0);

		if (strlen(inputbuffer) < 3) continue;

		if (islog(inputbuffer)) {
			getlog(inputbuffer, log_struct);
			return(1);
		}
	}
	return (0);
}

int Close_File(FILE * configfile)
{
	return (fclose(configfile));
}

int dir_exists(const char *path) {
	struct stat st;

	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int file_exists(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0;
}

int Log_Config(char *source, char *dest, int size)
{
	struct Reg_Log log_struct;
	int i_log_count= 0;
	char str_log_count[10];
	char str_name_metachar_remove[MAX_AUDIT_CONFIG_LINE * 2];

	FILE *configfile = (FILE *) NULL;

	if (!source || !dest || !size) {
		return(0);
	}

	strcpy(log_struct.name, "");

	strncpy(dest,
		"<form action=/setlog><H1><CENTER>SafedAgent Log Configuration</H1>",
		size);

	configfile = Find_First(CONFIG_INPUT);

	if (configfile) {
		strncat(dest,
			"<br>The following log files are being monitored by SafedAgent:<br><br>"
			"<table  width=100% border=1>", size - strlen(dest));

		strncat(dest,
			"<tr bgcolor=#F0F1F5><center><td width=\"10%\"><b>Action Required</b></td>"
			"<td width=\"90%\"><b>Log File</b>"
			"</td></center></tr>", size - strlen(dest));

		while (Get_Next_Log(configfile, &log_struct)) {
			snprintf(str_log_count, 10, "%d", i_log_count);

			if ((i_log_count) == 0)
				strncat(dest,
					"<tr bgcolor=#DEDBD2><td><input type=submit name=",
					size - strlen(dest));
			else
				strncat(dest,
					"<tr bgcolor=#E7E5DD><td><input type=submit name=",
					size - strlen(dest));

			strncat(dest, str_log_count, size - strlen(dest));
			strncat(dest, " value=Delete>     ",
				size - strlen(dest));

			strncat(dest, "<input type=submit name=",
				size - strlen(dest));
			strncat(dest, str_log_count, size - strlen(dest));
			strncat(dest, " value=Modify>", size - strlen(dest));
			strncat(dest, "</td><td>", size - strlen(dest));


			// Debracket the strings in here. For HTML display purposes, the HTML metacharacters
			// need to be replaced. This is done with the "debracket" routine.
			// Note that the new strings are allowed to be twice as long as the real strings
			debracket(log_struct.name,
				  str_name_metachar_remove,
				  MAX_AUDIT_CONFIG_LINE * 2);


			if (strlen(log_struct.name) == 0) {
				strncat(dest, "&nbsp", size - strlen(dest));
			} else {
				char *pos = strstr(str_name_metachar_remove, "|");
				if(pos){
					*pos = '\0';
				}
				strncat(dest, str_name_metachar_remove,
					size - strlen(dest));
			}
			strncat(dest, "</td></tr>", size - strlen(dest));

			i_log_count++;
		}
		Close_File(configfile);
		strncat(dest, "</table><br>", size - strlen(dest));
	} else {
		strncat(dest,
			"<br>There are no current log monitors active.<br><br>",
			size - strlen(dest));
	}

	strncat(dest, "Select this button to add a new log monitor.  ",
		size - strlen(dest));
	strncat(dest, "<input type=submit name=0", size - strlen(dest));
	strncat(dest, " value=Add>", size - strlen(dest));

	return (0);
}

int Log_Display(char *source, char *dest, int size)
{
	struct Reg_Log log_struct;
	int dw_log_error = 0, dw_log_delete_error = 0;
	char str_logerr[10];
	int i_log_count = 0, i_type = 0;
	char *psource = source, Variable[100], Argument[100];
	char str_temp[20], str_temp_log[10];

	// This function will display an existing, or a blank, log
	strncpy(dest,
		"<form action=/changelog><h1><center>SafedAgent Log Configuration</h1>",
		size);

	// Determine whether the log will be modified or deleted
	while ((psource =
		getNextArgument(psource, Variable, sizeof (Variable), Argument,
				sizeof (Argument))) != (char *) NULL) {
		if (strstr(Argument, "Delete") != NULL) {
			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp,
			       str_temp_log);
			i_type = 0;
			break;
		}
		if (strstr(Argument, "Modify") != NULL) {
			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp,
			       str_temp_log);
			i_type = 1;
			break;
		}
		if (strstr(Argument, "Add") != NULL) {
			strncpy(str_temp_log, "-2",
				sizeof (str_temp_log));
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
		strncat(dest,
			"<br><b>NOTE: It appears the URL is encoded incorrectly.",
			size - strlen(dest));
		return 0;
	}

	if (i_log_count == -1)
		i_log_count = 0;

	// If the log is being modified or added
	if (i_type > 0) {
		if (i_type == 1) {
			int count = 0;
			int returncode;
			FILE *configfile;
			configfile = Find_First(CONFIG_INPUT);
			while ((returncode =
				Get_Next_Log(configfile, &log_struct)))
			{
				if (count == i_log_count)
					break;
				count++;
			}
			if (!(count == i_log_count && returncode)) {
				dw_log_error =
				    WEB_READ_LOG_ERROR_CODE;
			}
			Close_File(configfile);
		} else {
			// Defaults
			strncpy(log_struct.name, "", sizeof(log_struct.name));
		}

		// Will display an error if unable to completely read from the config file
		if (dw_log_error > 0) {
			dw_log_error += WEB_READ_LOG_ERROR_CODE;
			snprintf(str_logerr, 10, "%d", dw_log_error);

			strncat(dest,
				"<br><b>NOTE: Some errors were encountered in reading the configuration file. Default values "
				"may be used.<br> Report error: ",
				size - strlen(dest));
			strncat(dest, str_logerr, size - strlen(dest));
			strncat(dest, "</b><br>", size - strlen(dest));
		}

		strncat(dest,
			"<br>The following parameters of the SafedAgent log inputs may be set:<br><br>"
			"<table  width=100% border=0>", size - strlen(dest));


		strncat(dest,
			"<tr bgcolor=#E7E5DD><td>Log File or Directory<br></td><td><input type=text name=str_log_name size=50 value=\"",
			size - strlen(dest));
		strncat(dest, log_struct.name,
			size - strlen(dest));
		strncat(dest, "\"></td></tr>", size - strlen(dest));

		strncat(dest,
				"<tr bgcolor=#DEDBD2><td>Log Name Format:<br />(optional)"
				"<a href=\"javascript:void(0)\" onClick=\"myWindow = window.open('', 'tinyWindow', 'width=350,height=300'); "
					"myWindow.document.write('<html><body><p>A percent sign (%) is used the represent the date format YYMMDD. Regular expressions are acceptable.</p>"
					"<p>e.g. log names like ISALOG_20060913_WEB_000.w3c would be represented as ISALOG_20%_WEB_*.w3c).</p>"
					"If this field is not defined, the first matching entry will be used (this is fine in most cases).</body></html>'); "
					"myWindow.document.close();"
					"\">Help</a></td>"
					"<td><input type=text name=str_log_format size=50 value=\"",
				size - strlen(dest));
		strncat(dest, log_struct.format,
			size - strlen(dest));
		strncat(dest, "\"></td></tr>", size - strlen(dest));


		strncat(dest, "</table><br>", size - strlen(dest));
		strncat(dest, "<input type=hidden name=lognumber value=",
			size - strlen(dest));
		strncat(dest, str_temp_log, size - strlen(dest));	// Log number goes here
		strncat(dest,
			"><input type=submit value=\"Change Configuration\">    ",
			size - strlen(dest));
		strncat(dest, "<input type=reset value=\"Reset Form\"></form>",
			size - strlen(dest));
	} else {
		void *rampointer = (void *) NULL;
		char *position;
		char inputbuffer[MAX_AUDIT_CONFIG_LINE];
		int headertype = 0;
		FILE *configfile;

		rampointer = Load_Config_File();
		if (!rampointer) {
			dw_log_error = WEB_READ_CONFIG_ERROR_CODE;
			dw_log_delete_error = 1;
		} else {
			int logcounter = 0;
			int size = 0;

			position = (char *) rampointer;

			configfile = current_config("w");
			if (!configfile) {
				strncat(dest,
					"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
					size - strlen(dest));
				Clear_Config_File(rampointer);
				return (0);
			}

			while ((size =
				Grab_RAMConfig_Line(position, inputbuffer,
						    MAX_AUDIT_CONFIG_LINE))) {
				trim(inputbuffer);

				if (headertype == CONFIG_INPUT) {
					if (logcounter ==
					    i_log_count) {
						// Do not add this line back into the original file.
						position += size;
						logcounter++;
						continue;
					}
					logcounter++;
				}

				if (!iscomment(inputbuffer)) {
					// Is this line a header?
					if (isheader(inputbuffer)) {
						headertype =
						    getheader(inputbuffer);
					}
				}
				// Print this line to file.
				if (isheader(inputbuffer)
				    || iscomment(inputbuffer)
				    || !strlen(inputbuffer)) {
					fprintf(configfile, "%s\n",
						inputbuffer);
				} else {
					fprintf(configfile, "	%s\n",
						inputbuffer);
				}

				// position+=strlen(inputbuffer)+1;
				position += size;
			}
			if (fclose(configfile)) {
				dw_log_delete_error = 1;
				strncat(dest,
					"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
					size - strlen(dest));
				Clear_Config_File(rampointer);
				return (0);
			}

			Clear_Config_File(rampointer);
		}

		if (dw_log_delete_error == 0){
			strncpy(source,"/log", 4);
			Log_Config(source,dest,size);

		}else
			strncat(dest,
				"<br>The log monitor was unable to be deleted.",
				size - strlen(dest));
	}

	return (0);
}

int Log_Result(char *source, char *dest, int size)
{
	// All strncpy or strncat functions in this routine have been designed avoid overflows
	struct Reg_Log log_struct;
	int dw_log_error = 0;
	int i_log = 0;
	char str_log_count[10];
	char *psource = source, Variable[100], Argument[100];

	strncpy(dest,
		"<form action=/setlog><H1><CENTER>SafedAgent Log Configuration</H1>",
		size);

	while ((psource =
		getNextArgument(psource, Variable, sizeof (Variable), Argument,
				sizeof (Argument))) != (char *) NULL) {

		if (strstr(Variable, "str_log_name") != NULL) {
			strncpy(log_struct.name, Argument,
				sizeof (log_struct.name));
		}
		
		if (strstr(Variable, "str_log_format") != NULL) {
			strncpy(log_struct.format, Argument,
				sizeof (log_struct.format));
		}

		if (strstr(Variable, "lognumber") != NULL) {
			strncpy(str_log_count, Argument,
				sizeof (str_log_count));
		}

	}

	if (!dw_log_error) {

		i_log = atoi(str_log_count);

		//-2 = "Add a new log monitor"
		if (i_log == -2) {
			void *rampointer = (void *) NULL;
			char *position;
			char inputbuffer[MAX_AUDIT_CONFIG_LINE];
			int headertype = 0;
			FILE *configfile;

			rampointer = Load_Config_File();
			if (!rampointer) {
				dw_log_error = WEB_READ_CONFIG_ERROR_CODE;
			} else {
				int size = 0;
				int wroteconfig = 0;

				position = (char *) rampointer;

				configfile = current_config("w");
				if (!configfile) {
					dw_log_error = 1;
					strncat(dest,
						"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
						size - strlen(dest));
					Clear_Config_File(rampointer);
					return (0);
				}

				while ((size =
					Grab_RAMConfig_Line(position,
							    inputbuffer,
							    MAX_AUDIT_CONFIG_LINE)))
				{
					trim(inputbuffer);

					// Is this line a header?
					if (isheader(inputbuffer)) {
						fprintf(configfile, "%s\n",
							inputbuffer);
						headertype =
						    getheader(inputbuffer);
						if (headertype ==
						    CONFIG_INPUT) {
							// WRITE OUT NEW LOG MONITOR HERE
							if(strlen(log_struct.format)){
								fprintf(configfile,
									"	log=GenericLog:%s|%s\n",
									log_struct.name,log_struct.format);
							}else{
								fprintf(configfile,
									"	log=GenericLog:%s\n",
									log_struct.name);
							}
							wroteconfig = 1;
						}
					} else {

						// Print this line to file.
						if (iscomment(inputbuffer)
						    || !strlen(inputbuffer)) {
							fprintf(configfile,
								"%s\n",
								inputbuffer);
						} else {
							fprintf(configfile,
								"	%s\n",
								inputbuffer);
						}
					}
					position += size;
				}

				if (!wroteconfig) {
					// Must not have been an input header in the file...
					// WRITE OUT NEW LOG MONITOR HERE
					if(strlen(log_struct.format)){
					fprintf(configfile,
						"\n\n[Input]\n	log=GenericLog:%s|%s\n",
						log_struct.name,log_struct.format);
					}else{
						fprintf(configfile,
							"\n\n[Input]\n	log=GenericLog:%s\n",
							log_struct.name);
					}
				}

				if (fclose(configfile)) {
					dw_log_error = 1;
					strncat(dest,
						"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
						size - strlen(dest));
					Clear_Config_File(rampointer);
					return (0);
				}

				Clear_Config_File(rampointer);
			}
		} else {
			// Modify an existing log monitor
			void *rampointer = (void *) NULL;
			char *position;
			char inputbuffer[MAX_AUDIT_CONFIG_LINE];
			int headertype = 0;
			FILE *configfile;

			rampointer = Load_Config_File();
			if (!rampointer) {
				dw_log_error = WEB_READ_CONFIG_ERROR_CODE;
			} else {
				int logcounter = 0;
				int size = 0;

				position = (char *) rampointer;

				configfile = current_config("w");
				if (!configfile) {
					dw_log_error = 1;
					strncat(dest,
						"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
						size - strlen(dest));
					Clear_Config_File(rampointer);
					return (0);
				}

				while ((size =
					Grab_RAMConfig_Line(position,
							    inputbuffer,
							    MAX_AUDIT_CONFIG_LINE)))
				{
					trim(inputbuffer);

					if (headertype == CONFIG_INPUT) {
						if (logcounter ==
						    i_log) {
							// Replace this log monitor with the new version.
							// WRITE OUT NEW LOG MONITOR HERE
							if(strlen(log_struct.format)){
							fprintf(configfile,
								"	log=GenericLog:%s|%s\n",
								log_struct.name,log_struct.format);
							}else{
							fprintf(configfile,
                                                                "       log=GenericLog:%s\n",
                                                                log_struct.name);
							}
							position += size;
							logcounter++;
							continue;
						}
						logcounter++;
					}

					if (!iscomment(inputbuffer)) {
						// Is this line a header?
						if (isheader(inputbuffer)) {
							headertype =
							    getheader
							    (inputbuffer);
						}
					}
					// Print this line to file.
					if (isheader(inputbuffer)
					    || iscomment(inputbuffer)
					    || !strlen(inputbuffer)) {
						fprintf(configfile, "%s\n",
							inputbuffer);
					} else {
						fprintf(configfile, "	%s\n",
							inputbuffer);
					}

					// position+=strlen(inputbuffer)+1;
					position += size;
				}

				if (fclose(configfile)) {
					dw_log_error = 1;
					strncat(dest,
						"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
						size - strlen(dest));
					Clear_Config_File(rampointer);
					return (0);
				}

				Clear_Config_File(rampointer);
			}
		}

		if (dw_log_error == 0){
//			strncat(dest,
//				"<br>The log monitor has been modified/added.",
//				size - strlen(dest));
			strncpy(source,"/log", 4);
			Log_Config(source,dest,size);

		}else
			strncat(dest,
				"<br>The log monitor was unable to be modified/added.",
				size - strlen(dest));
	}

	return (0);
}


FILE *current_config (char *mode)
{
	if (USER_CONFIG_FILENAME[0] == '\0') {
		return fopen(CONFIG_FILENAME,mode);
	} else {
		return fopen(USER_CONFIG_FILENAME,mode);
	}
}





int ShowLicense(char *dest, int size)
{
	strncpy(dest, "This program is free software; you can redistribute it and/or modify<br>"
	 "it under the terms of the GNU General Public License as published by<br>"
	 "the Free Software Foundation; either version 2 of the License, or<br>"
	 "(at your option) any later version.<br><br>"
	 "This program is distributed in the hope that it will be useful,<br>"
	 "but WITHOUT ANY WARRANTY; without even the implied warranty of<br>"
	 "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the<br>"
	 "GNU Library General Public License for more details.<br>"
	 "You should have received a copy of the GNU General Public License<br>"
	 "along with this program; if not, write to the Free Software<br>"
	 "Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.<br>", size - strlen(dest));
	return(0);

}

char* getFilename(char * date){
        char* current;
        char next[10];
        int year = 0;
        int month = 0;
        int day = 0;
        if(date && (strlen(date)==8)){
                current = date;
                strncpy(next, current, 4);
                next[4] = '\0';
                year = atoi(next);
                if((year < 2010) || (year > 3010) )return NULL;
                current = current + 4;
                strncpy(next, current, 2);
                next[2] = '\0';
                month = atoi(next);
                if((month < 1) || (month > 12) )return NULL;
                current = current + 2;
                strncpy(next, current, 2);
                next[2] = '\0';
                day = atoi(next);
                if((day < 1) || (day > 31) )return NULL;
                return calculateFileName(NULL, year, month, day);
        }else return NULL;
}

int Daily_Events(char *source, char *dest, int size, int at)
{
	char* filename;
	int savedLogs = 0;
	char line[LOGBUFSIZE];
	char *psource=source, Variable[100]="", Argument[100]="", number_s[100], date_s[10]="";
	int numberFrom = 0;
	int numberTo = 0;
	FILE *file = (FILE *)NULL;


	if(at){
		while((psource=getNextArgument(psource,Variable, sizeof(Variable),Argument,sizeof(Argument))) != (char *)NULL)
		{
			if (strstr(Variable,"numberFrom") != NULL) {
				strncpy(number_s ,Argument, sizeof(number_s));
				numberFrom = atoi(number_s) - 1;
			}
			if (strstr(Variable,"numberTo") != NULL) {
				strncpy(number_s ,Argument, sizeof(number_s));
				numberTo = atoi(number_s) - 1;
			}
			if (strstr(Variable,"thedate") != NULL) {
				strncpy(date_s,Argument,sizeof(date_s));
			}
		}
		if(!((numberFrom == -1) && (numberTo == -1))){
			if((numberFrom == -1) && !(numberTo == -1))numberFrom = numberTo;
			else if(!(numberFrom == -1) && (numberTo == -1))numberTo = numberFrom;
		}


	}
	if(strlen(date_s) >0){

		filename = getFilename(date_s);
		if(filename){
			file = fopen(filename,"r");
			savedLogs = getTotalSavedLogs(file);
			if(file){
				fclose(file);
			}

		}

		sprintf(dest,"<HTML><BODY><form method=get action=/geteventlogat><H2><CENTER>Daily Events for %s</H2></CENTER><P><center><br/>\n"
				"<CENTER>TOTAL Events : %d</CENTER><P><center><br />\n"
				"<table border=1 cellspacing=0 cellpadding=2 width=\"99%%\" bgcolor=\"white\">\n"
				"<tr bgcolor=\"#F0F1F5\"><td align=Center>Event Log</td></tr>\n",date_s, savedLogs);

	}else{
		time_t startime;
		time(&startime);
		struct tm *t = localtime(&startime);
		filename = calculateFileName(NULL, t->tm_year+1900, t->tm_mon+1, t->tm_mday);
		if(filename){
			file = fopen(filename,"r");
			savedLogs = getTotalSavedLogs(file);
			if(file){
				fclose(file);
			}
		}
		sprintf(dest,"<HTML><BODY><form method=get action=/geteventlogat><H2><CENTER>Daily Events for %04d%02d%02d</H2></CENTER><P><center><br />\n"
				"<CENTER>TOTAL Events : %d</CENTER><P><center><br />\n"
				"<table border=1 cellspacing=0 cellpadding=2 width=\"99%%\" bgcolor=\"white\">\n"
				"<tr bgcolor=\"#F0F1F5\"><td align=Center>Event Log</td></tr>\n",t->tm_year+1900, t->tm_mon+1, t->tm_mday,savedLogs);

	}
	if(at){
		if((numberFrom >= 0) && (numberTo >= numberFrom) && (numberTo < savedLogs)) {
			// if the date is not specified, then I ask the agent to send the messages via syslog
			if (strlen(date_s) <= 0) {
				sendRequestToAgent(numberFrom +1, numberTo +1);
			}
			// anyway, the specified messages will be given back via http
			if (filename) {
				file = fopen(filename,"r");
				if(file){
					getSavedLogAt(file, line, numberFrom);
					int i = 0;
					for (i=numberFrom;  i <= numberTo ; i++) {
						if (i - numberFrom <= 20){
							if (i%2)
								sprintf(dest,"%s<tr bgcolor=#FEFEFE><td>\n%s\n</td></tr>\n",dest,line);
							else
								sprintf(dest,"%s<tr bgcolor=#EEEEEE><td>\n%s\n</td></tr>\n",dest,line);

						}
						if(i<=numberTo)getSavedLogAt(file, line, 0);//get next line
					}
					fclose(file);
				}
			}

		}
	}


	free(filename);

	strcat(dest,"</table><br><br><table border=1 cellspacing=0 cellpadding=2 width=\"50%%\" bgcolor=\"white\">\n");
	strcat(dest,"<tr bgcolor=#F0F1F5><td>Insert the Date For Recovery Via HTTP</td><td><input type=text name=thedate size=12 value=\"\" onMouseover=\"ddrivetip(\'When entered the date the recovery of the event logs is only via Http with the max number of recovered event logs of 20. Otherwise the event logs are sent to the syslog server \')\" onMouseout=\"hideddrivetip()\"></td></tr>\n");
	strcat(dest,"<tr bgcolor=#F0F1F5><td>Insert the From Event Log Number </td><td><input type=text name=numberFrom size=12 value=\"\"></td></tr>\n"
					"<tr bgcolor=#F0F1F5><td>Insert the To Event Log Number </td><td><input type=text name=numberTo size=12 value=\"\"></td></tr>\n"
					"</table>\n");
	strcat(dest,"<input type=submit name=0 value=Send></CENTER></form></BODY></HTML>");


	return(0);
}


#ifdef TLSPROTOCOL
int GetConfig(int http_socket, gnutls_session_t session_https, char* fromServer)
#else
int GetConfig(int http_socket, char* fromServer)
#endif
{
	int retval;
	char* configFileName = NULL;
	char line[MAX_AUDIT_CONFIG_LINE];

	FILE *configfile = (FILE *)NULL;
	if (strlen(USER_CONFIG_FILENAME)) {
		configFileName = USER_CONFIG_FILENAME;
	} else {
		configFileName = CONFIG_FILENAME;
	}
	configfile = fopen(configFileName, "r");

	if (configfile == (FILE *)NULL) {
		perror("Cannot open audit configuration file.\n");
		exit(1);
	}
	strcpy(line, "HTTP/1.0 200 OK\r\n"
						"Server: SafedAgent/1.0\r\n"
						"MIME-version: 1.0\r\n"
						"Content-type: text/plain\r\n\r\n");
#ifdef TLSPROTOCOL
	if(remoteControlHttps)
		retval = sendTLS(line,session_https);
	else
#endif
		retval = send(http_socket,line,(int)strlen(line),0);
    char* posLST;
	while (fgets(line, MAX_AUDIT_CONFIG_LINE, configfile)) {
		posLST =strstr(line,"#LastSetTime");
		if(!posLST){
#ifdef TLSPROTOCOL
			if(remoteControlHttps)
				retval = sendTLS(line,session_https);
			else
#endif
			retval = send(http_socket,line,(int)strlen(line),0);
		}
	}

	fclose((FILE *)configfile);
	if(fromServer && strlen(fromServer) > 0){
		snprintf(getConfigStatus,sizeof(getConfigStatus),"%s %s\n", LGC_MSG, fromServer);
	}else{
		getConfigStatus[0]='\0';
	}

	return retval;
}



int Config(char *source, char *dest, int size)
{
	snprintf(dest,size,"<H2><CENTER>SafedAgent Version %s Set Configuration</H2></CENTER><P><center>",VERSION);
	strncat(dest,"<br>"
				"<table  width=70% border=0>"
				"<tbody>"
				"<tr bgcolor=#E7E5DD><form method=post action=/setconfig enctype=\"multipart/form-data\"><td>Select the configuration file: </td>"
				"<td><input type=file name=cfgname size=25 value=\"\"></td></tr><tr><td></td><td><input type=\"submit\" size=25  value=\"Set\"></td></tr></form><tr><td>",size);

	return(0);
}

int Certs(char *source, char *dest, int size)
{
	snprintf(dest,size,"<H2><CENTER>SafedAgent Version %s Set Certificates</H2></CENTER><P><center>",VERSION);
	strncat(dest,"<br>"\
				"<table  width=70% border=0>" \
				"<tbody>"\
				"<tr bgcolor=#E7E5DD><form method=post action=/setca enctype=\"multipart/form-data\"><td>Select the ca file: </td>" \
				"<td><input type=file name=caname size=25 value=\"\"></td></tr><tr><td></td><td><input type=\"submit\" size=25  value=\"Set CA\"></td></tr></form><tr><td>"\
				"<tr bgcolor=#E7E5DD><form method=post action=/setcert enctype=\"multipart/form-data\"><td>Select the cert file: </td>" \
				"<td><input type=file name=certname size=25 value=\"\"></td></tr><tr><td></td><td><input type=\"submit\" size=25  value=\"Set CERT\"></td></tr></form><tr><td>"\
				"<tr bgcolor=#E7E5DD><form method=post action=/setkey enctype=\"multipart/form-data\"><td>Select the key file: </td>" \
				"<td><input type=file name=keyname size=25 value=\"\"></td></tr><tr><td></td><td><input type=\"submit\" size=25  value=\"Set KEY\"></td></tr></form><tr><td>",size);

	return(0);
}

int SetConfig(char *source, char *dest, int size, char* fromServer) {
	char* pos = strstr(source,"\r\n\r\n");

	FILE *configfile = (FILE *)NULL;
	char* configFileName = CONFIG_FILENAME;

	if (pos) {
			pos = pos + 4;
			char* posEnd =strstr(source,"[End]");
			if (posEnd) {
				configfile = fopen(configFileName, "w");

				if (configfile == (FILE *)NULL) {
					perror("Cannot open audit configuration file.\n");
					exit(1); //TODO: se non riesce ad aprire il file di configurazione termina il web server? perchè? sarebbe da rivedere
				}

				dos2unix(pos);
				fputs(pos, configfile);

				if(fromServer && strlen(fromServer) > 0){
					char line[MAX_AUDIT_CONFIG_LINE];
					snprintf(setConfigStatus,sizeof(setConfigStatus),"%s %s\n", LSC_MSG, fromServer);
					snprintf(line, sizeof(line),"%s=%s\n", "\n#LastSetTime", fromServer);
					fputs(line, configfile);
				} else {
					setConfigStatus[0]='\0';
				}
				fflush(configfile);
				fclose((FILE *)configfile);
				strncpy(dest,"<h2><center>SafedAgent Configuration</h2>Values have been changed.",size);

			} else {
				strncpy(dest,"<h2><center>SafedAgent Configuration</h2>Error in received configuration! Values have not been changed.",size);
			}
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
			perror("Cannot open certificates files.\n");
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



