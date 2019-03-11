#include "SafedTLS.h"

int		HandleWebPages(char *HTTPBuffer,char *HTTPOutputBuffer,int size,SOCKET http_socket, WOLFSSL* session_https,char* fromServer, HANDLE event);

int		Status_Page(char *source, char *dest, int size);
int		SafedLog_Page(char *source, char *dest, int size);
int		Current_Events(char *source, char *dest, int size);
int		Daily_Events(char *source, char *dest, int size, BOOL at);
int		DefaultHeader(char *source, char *dest, int size, int refreshflag=0, BOOL image=TRUE);
int		Network_Config(char *source, char *dest, int size);
int		SysAdmin_Config(char *source, char *dest, int size);
int		SysAdmin_Set(char *source, char *dest, int size);
int		Remote_Config(char *source, char *dest, int size);
int		Remote_Set(char *source, char *dest, int size);
int		Objective_Config(char *source, char *dest, int size);
int		DefaultFooter(char *source, char *dest, int size);
int		E_Objective_Result(char *source, char *dest, int size);
int		E_Objective_Display(char *source, char *dest, int size);
int		E_Objective_Config(char *source, char *dest, int size);
int		Log_Result(char *source, char *dest, int size);
int		Log_Display(char *source, char *dest, int size);
int		Log_Config(char *source, char *dest, int size);

int		LogoImage(char *source, char *dest, int size);
int		ImageCrit(char *source, char *dest, int size);
int		ImagePri(char *source, char *dest, int size);
int		ImageWarn(char *source, char *dest, int size);
int		ImageInfo(char *source, char *dest, int size);
int		ImageClear(char *source, char *dest, int size);
int		ImageStatus(char *source, char *dest, int size);
int		ImageCfg(char *source, char *dest, int size);
int		ImageSave(char *source, char *dest, int size);
int		ImageList(char *source, char *dest, int size);
int		ImageSearch(char *source, char *dest, int size);
int		ImageArrow(char *source, char *dest, int size);




int		Objective_Display(char *source, char *dest, int size);
int		Restart(char *source, char *dest, int size, HANDLE event);
int		Restart(char *source, char *dest, int size);
int		Network_Set(char *source, char *dest, int size);
int		Objective_Result(char *, char *, int);

int		debracket(char *source, char *dest, int length);

int		ShowLocalUsers(SOCKET http_socket, WOLFSSL* session_https);
int		ShowDomainUsers(SOCKET http_socket, WOLFSSL* session_https);

int		ShowLocalGroupMembers(SOCKET http_socket, WOLFSSL* session_https);
int		ShowThisLocalGroupMembers(WCHAR *Group,SOCKET http_socket, WOLFSSL* session_https);

int		GetCustomLogs(SOCKET http_socket, WOLFSSL* session_https);
int		GetSysAdmin(SOCKET http_socket, WOLFSSL* session_https);
int		ShowDomainGroupMembers(SOCKET http_socket, WOLFSSL* session_https);
int		ShowThisDomainGroupMembersNT(WCHAR *Group,WCHAR *PDC,SOCKET http_socket, WOLFSSL* session_https);
int		ShowDomainUserGroupsWin2k(SOCKET http_socket, WOLFSSL* session_https, char *PDC_cstr);

int		ShowLicense(SOCKET http_socket, WOLFSSL* session_https);

int		GetConfig(SOCKET http_socket, WOLFSSL* session_https, char* fromServer);
//int		SetConfig(char *source, SOCKET http_socket);
int		Config(char *source, char *dest, int size);
int		SetConfig(char *source, char *dest, int size, char* fromServer);

int		Certs(char *source, char *dest, int size);
int		SetCertificate(char *source, char *dest, int size, char* cert);

// HRESULT TestEnumObject( LPWSTR pszADsPath );

int		DumpRegistry(SOCKET http_socket, WOLFSSL* session_https, char *source, char * Output, int OutputSize);
int		RegDump(HKEY key, char * rootname, char *path, SOCKET http_socket, WOLFSSL* session_https);

BOOL	ADIsMixedMode(void);

// Stuff we use from webserver.h
int		base64decode(char *dest, char *src);
int		base64encode(char *dest, char *src, int len);
char *	GetNextArgument(char *source,char *destvar,int varlength,char *destval,int vallength);

int		DisplayTextHeader(SOCKET http_socket, WOLFSSL* session_https);
int		Display404(SOCKET http_socket, WOLFSSL* session_https);

BOOL	GetUserSid(LPTSTR szName,LPTSTR TextualSid,LPDWORD lpdwBufferLen,char *PrimaryDomain=NULL,char *PDC_cstr=NULL);

struct escape_struct {
	char from;
	const char * to;
};

const escape_struct escapes_general[] = {
	{ '<', "&lt;" },
	{ '>', "&gt;" },
	{ '&', "&amp;" },
	{ '\"', "&quot;" },
	//{ ' ', "&nbsp;" },
	{ '%', "&#37;" },
	{ 0, 0 }
};
int escape(const char *source, char *dest, int length, const escape_struct * escapes = escapes_general);


