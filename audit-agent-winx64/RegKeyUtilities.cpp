#include <windows.h>
#include <winsvc.h>
#include "RegKeyUtilities.h"
#include <stdio.h>

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

// Write a DWORD to the registry
BOOL MyWriteProfileDWORD(LPCTSTR lpszSection, LPCTSTR lpszEntry, DWORD nValue)
{
	HKEY hSecKey = MyGetSectionKey(lpszSection);
	if (hSecKey == NULL)
		return TRUE;
	LONG lResult = RegSetValueEx(hSecKey, lpszEntry, NULL, REG_DWORD,
		(LPBYTE)&nValue, sizeof(nValue));
	RegCloseKey(hSecKey);
	return lResult == ERROR_SUCCESS;
}

// Get a DWORD from the registry
DWORD MyGetProfileDWORD(LPCTSTR lpszSection, LPCTSTR lpszEntry, DWORD nDefault)
{
	HKEY hSecKey = MyGetSectionKey(lpszSection);
	if (hSecKey == NULL)
		return nDefault;
	DWORD dwValue;
	DWORD dwType;
	DWORD dwCount = sizeof(DWORD);
	LONG lResult = RegQueryValueEx(hSecKey, (LPTSTR)lpszEntry, NULL, &dwType,
		(LPBYTE)&dwValue, &dwCount);
	RegCloseKey(hSecKey);
	if (lResult == ERROR_SUCCESS)
	{
		return dwValue;
	}
	return nDefault;
}

// Write a string to the registry
BOOL MyWriteProfileString(LPCTSTR lpszSection, LPCTSTR lpszEntry, LPCTSTR lpszString)
{
	HKEY hSecKey = MyGetSectionKey(lpszSection);
	if (hSecKey == NULL)
		return TRUE;
	LONG lResult = RegSetValueEx(hSecKey, lpszEntry, NULL, REG_SZ,
		(unsigned char *)lpszString, (DWORD)(strlen(lpszString)+1));
//		(unsigned char *)lpszString, (strlen(lpszString)+1) * sizeof(LPCTSTR));
	RegCloseKey(hSecKey);
	return lResult == ERROR_SUCCESS;
}

// Get a string from the registry
BOOL MyGetProfileString(LPCTSTR lpszSection, LPCTSTR lpszEntry, LPCTSTR lpszString, DWORD dwStringBuffer)
{
	HKEY hSecKey = MyGetSectionKey(lpszSection);
	if (hSecKey == NULL)
		return TRUE;
	DWORD dwSize = dwStringBuffer;
	DWORD dwType;
	LONG lResult = RegQueryValueEx(hSecKey, (LPCTSTR)lpszEntry, NULL, &dwType,
		(LPBYTE)lpszString, &dwSize);
	RegCloseKey(hSecKey);
	return lResult == ERROR_SUCCESS;
}

// Get the setion registry key
HKEY MyGetSectionKey(LPCTSTR lpszSection)
{
	HKEY hSectionKey = NULL;
	HKEY hAppKey = MyGetServiceRegistryKey();
	if (hAppKey == NULL)
		return NULL;
	
	DWORD dw;
	RegCreateKeyEx(hAppKey, lpszSection, 0, REG_NONE,
		REG_OPTION_NON_VOLATILE, KEY_WRITE|KEY_READ, NULL,
		&hSectionKey, &dw);
	RegCloseKey(hAppKey);
	return hSectionKey;
}

HKEY MyGetServiceRegistryKey()
{
	// Store the information within the Wuerth Phoenix high level key.
	char m_sServiceName[256]="Wuerth Phoenix";
	
	HKEY hServicesKey = NULL;
	static HKEY hParametersKey = NULL;
	HKEY hAppKey = NULL;
	
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE", 0, KEY_WRITE|KEY_READ,
		&hServicesKey) == ERROR_SUCCESS)
	{
		DWORD dw;
		if (RegCreateKeyEx(hServicesKey, m_sServiceName, 0, REG_NONE,
			REG_OPTION_NON_VOLATILE, KEY_WRITE|KEY_READ, NULL,
			&hAppKey, &dw) == ERROR_SUCCESS)
		{
			RegCreateKeyEx(hAppKey, "AuditService", 0, REG_NONE,
				REG_OPTION_NON_VOLATILE, KEY_WRITE|KEY_READ, NULL,
				&hParametersKey, &dw);
		}
	}
	if (hServicesKey != NULL)
		RegCloseKey(hServicesKey);
	if (hAppKey != NULL)
		RegCloseKey(hAppKey);
	
	return hParametersKey;
}



 
DWORD QueryKey(HKEY hKey, char result[MAXCUSTOMLOGS][35], int first, int second) 
{ 
    TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string 
    TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys=0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 
 
    DWORD i, retCode; 
 
    TCHAR  achValue[MAX_VALUE_NAME]; 
    DWORD cchValue = MAX_VALUE_NAME; 
 
    // Get the class name and the value count. 
    retCode = RegQueryInfoKey(
        hKey,                    // key handle 
        achClass,                // buffer for class name 
        &cchClassName,           // size of class string 
        NULL,                    // reserved 
        &cSubKeys,               // number of subkeys 
        &cbMaxSubKey,            // longest subkey size 
        &cchMaxClass,            // longest class string 
        &cValues,                // number of values for this key 
        &cchMaxValue,            // longest value name 
        &cbMaxValueData,         // longest value data 
        &cbSecurityDescriptor,   // security descriptor 
        &ftLastWriteTime);       // last write time 
 
    
    if (cSubKeys)
    {
        for (i=0; i<cSubKeys; i++) 
        { 
            cbName = MAX_KEY_LENGTH;
            retCode = RegEnumKeyEx(hKey, i,
                     achKey, 
                     &cbName, 
                     NULL, 
                     NULL, 
                     NULL, 
                     &ftLastWriteTime); 
            if (retCode == ERROR_SUCCESS) 
            {
				if(i < first)strncpy_s(result[i],second,achKey,_TRUNCATE);
            }
        }
    }
	return cSubKeys;
}



