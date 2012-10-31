#define MAXCUSTOMLOGS     100
BOOL	MyWriteProfileWString	(LPCTSTR,WCHAR *,LPCWSTR);
BOOL	MyWriteProfileString	(LPCTSTR,LPCTSTR,LPCTSTR);
BOOL	MyWriteProfileDWORD		(LPCTSTR,LPCTSTR,DWORD);
BOOL	MyGetProfileWString		(LPCTSTR,WCHAR *,LPCWSTR,DWORD);
BOOL	MyGetProfileString		(LPCTSTR,LPCTSTR,LPCTSTR,DWORD);
DWORD	MyGetProfileDWORD		(LPCTSTR,LPCTSTR,DWORD);
HKEY	MyGetSectionKey			(LPCTSTR);
HKEY	MyGetServiceRegistryKey	();
DWORD	QueryKey(HKEY hKey,char result[10][35], int first, int second); 
