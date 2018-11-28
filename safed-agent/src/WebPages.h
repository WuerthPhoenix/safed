#ifndef _WEBPAGES_H_
#define _WEBPAGES_H_ 1

#define SIZE_OF_PASSWORD                 256
#define SIZE_OF_AN_OBJECTIVE     1056
#define SIZE_OF_CLIENTNAME               100
#define SIZE_OF_DESTINATION              100
#define SIZE_OF_PROTOCOL              10


#define SIZE_OF_GENERALMATCH     512
#define SIZE_OF_GENERAL_MATCH_TYPE  10

#define WEB_READ_CONFIG_ERROR_CODE              510000
#define WEB_READ_NETWORK_ERROR_CODE             530000
#define WEB_READ_REMOTE_ERROR_CODE              580000
#define WEB_READ_OBJECTIVE_ERROR_CODE   610000
#define WEB_READ_LOG_ERROR_CODE         630000
#define WEB_WRITE_CONFIG_ERROR_CODE             660000
#define WEB_WRITE_NETWORK_ERROR_CODE    720000
#define WEB_WRITE_REMOTE_ERROR_CODE             770000
#define WEB_WRITE_OBJECTIVE_ERROR_CODE  850000
#define WEB_RESTART_SERVICE_ERROR_CODE  890000






struct Reg_Host {
	char str_NetworkDestination[SIZE_OF_DESTINATION];
	int dw_DestPort;
	char str_Protocol[SIZE_OF_PROTOCOL];
	struct Reg_Host *next;
};


// The following structure has been defined to cater for the 'config' registry settings
struct Reg_Config {
	char str_ClientName[SIZE_OF_CLIENTNAME];
	int dw_NumberOfFiles;
	int dw_NumberOfLogFiles;
	int dw_LogLevel;
	int dw_waitTime;
	int dw_MaxMsgSize;
	int dw_Syslog;
	int dw_SetAudit;

};

struct Reg_Remote {
	int dw_Allow;
	int dw_WebPort;
	int dw_Restrict;
	char str_RestrictIP[SIZE_OF_RESTRICTIP];
	int dw_Password;
	char str_Password[SIZE_OF_PASSWORD];
	int dw_TLS;
};

struct Reg_Objective {
	char str_general_match[SIZE_OF_GENERALMATCH];
	char str_general_match_type[SIZE_OF_GENERAL_MATCH_TYPE];
};



struct Reg_Log {
	char name[MAX_AUDIT_CONFIG_LINE];
	char format[MAX_AUDIT_CONFIG_LINE];
};

// int          HandleWebPages(char *HTTPBuffer,char *HTTPOutputBuffer,int size);
#ifdef TLSPROTOCOL
int HandleWebPages(char *HTTPBuffer, char *HTTPOutputBuffer, int size,
		   int http_listen_socket, int http_message_socket, gnutls_session_t session_https, char* fromServer);
#else
int HandleWebPages(char *HTTPBuffer, char *HTTPOutputBuffer, int size,
		   int http_listen_socket, int http_message_socket, char* fromServer);
#endif
int Status_Page(char *source, char *dest, int size);
int DefaultHeader(char *source, char *dest, int size);


int ShowLicense(char *dest, int size);

int Daily_Events(char *source, char *dest, int size, int at);
int Network_Config(char *source, char *dest, int size);
int Remote_Config(char *source, char *dest, int size);
int Remote_Set(char *source, char *dest, int size);
int Objective_Config(char *source, char *dest, int size);
int DefaultFooter(char *source, char *dest, int size);

int InterSectImage(char *source, char *dest, int size);
int Objective_Display(char *source, char *dest, int size);
// int          Restart(char *source, char *dest, int size);
int Restart(char *source, char *dest, int size, int one, int two);
int Network_Set(char *source, char *dest, int size);
int Objective_Result(char *, char *, int);

FILE *Find_First(int config_header);
int Get_Next_Objective(FILE * configfile, struct Reg_Objective *objective);
int Get_Next_Network(FILE * configfile, struct Reg_Host *host_struct);
int Get_Next_Log(FILE * configfile, struct Reg_Log *log_struct);
int Close_File(FILE * configfile);

int ReadObjectives();
void destroyList(void);
int debracket(char *source, char *dest, int length);

#ifdef TLSPROTOCOL
int GetConfig(int http_socket, gnutls_session_t session_https, char* fromServer);
#else
int GetConfig(int http_socket, char* fromServer);
#endif
int		Config(char *source, char *dest, int size);
int		SetConfig(char *source, char *dest, int size, char* fromServer);

int		Certs(char *source, char *dest, int size);
int		SetCertificate(char *source, char *dest, int size, char* cert);


// Stuff we use from webserver.h
int base64decode(char *dest, char *src);
char *GetNextArgument(char *source, char *destvar, int varlength,
		      char *destval, int vallength);

void *Load_Config_File();
int Read_Config_From_File(struct Reg_Config *);
void Clear_Config_File(void *location);
int Grab_RAMConfig_Line(char *source, char *dest, int size);

int getnetwork(char *string, char *host, int length, char *protocol);
void getlog(char *string, struct Reg_Log *log_struct);

int Read_Remote_From_File(struct Reg_Remote *remote_struct);

int iswebfilename(char *string);
int isnetwork(char *string);
int islog(char *string);
FILE *current_config(char *mode);


#endif				// _WEBPAGES_H_
