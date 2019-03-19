//FIX Custom File - max 50 system  and total 1000
#define MAXCUSTOMLOGS     1000
//FIX Custom File - max size of log name - see also SIZE_OF_EVENTLOG 
#define MAX_SIZE_OF_EVENTLOG     120
BOOL	MyWriteProfileWString	(LPCTSTR,WCHAR *,LPCWSTR);
BOOL	MyWriteProfileString	(LPCTSTR,LPCTSTR,LPCTSTR);
BOOL	MyWriteProfileDWORD		(LPCTSTR,LPCTSTR,DWORD);
BOOL	MyGetProfileWString		(LPCTSTR,WCHAR *,LPCWSTR,DWORD);
BOOL	MyGetProfileString		(LPCTSTR,LPCTSTR,LPCTSTR,DWORD);
DWORD	MyGetProfileDWORD		(LPCTSTR,LPCTSTR,DWORD);
HKEY	MyGetSectionKey			(LPCTSTR);
HKEY	MyGetServiceRegistryKey	();
//FIX Custom File
DWORD	QueryKey(HKEY hKey,char result[MAXCUSTOMLOGS][MAX_SIZE_OF_EVENTLOG], int first, int second); 
