/*
Copyright 2011 Luca Di Stefano <luca.distefano@wuerth-phoenix.com>

This file is part of ADQuery.

ADQuery is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ADQuery is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ADQuery.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "stdafx.h"

#include "util.h"

#include <atlbase.h>

#include <assert.h>

#include <activeds.h>
#include <sddl.h>

extern bool adq_debug;
extern int	adq_indent;

extern LPWSTR	adq_provider;

extern FILE * log_file;


void DebugV(LPWSTR fmt, va_list argp) {
	char buf[256];
	int i;
	for(i=0;i<adq_indent*3;i++){
		buf[i]=' ';
	}
	buf[i]=0;

	if(log_file) {
		fputs(buf,log_file);
		LPWSTR tmpbuf = new WCHAR[8192];
		_vsnwprintf(tmpbuf,8192,fmt,argp);
		fputws(tmpbuf,log_file);
		delete[] tmpbuf;
	}else{
		printf("%s", buf);
		vwprintf(fmt, argp);
	}
}

void Debug(LPWSTR fmt, ...){
	va_list argp;
	va_start(argp, fmt);
	DebugV(fmt, argp);
	va_end(argp);
}

void PrintIADSObject(IADs * pIADs)
{
	assert(pIADs);

	BSTR bsResult;

	pIADs->get_Name(&bsResult); 
	Debug(L" NAME: %s\n", bsResult);
	SysFreeString(bsResult);

	pIADs->get_ADsPath(&bsResult); 
	Debug(L" ADSPATH: %s\n", bsResult);
	SysFreeString(bsResult);

	/*
	pIADs->get_Class(&bsResult); 
	Debug(L" CLASS: %s\n", bsResult);
	SysFreeString(bsResult);

	pIADs->get_Parent(&bsResult); 
	Debug(L" PARENT: %s\n", bsResult);
	SysFreeString(bsResult);

	pIADs->get_GUID(&bsResult); 
	Debug(L" GUID: %s\n", bsResult);
	SysFreeString(bsResult);

	pIADs->get_Schema(&bsResult); 
	Debug(L" SCHEMA: %s\n", bsResult);
	SysFreeString(bsResult);	
	*/
}

HRESULT CheckErrorAD(LPWSTR txt, HRESULT hr){
	// Call ADsGetLastError to see if the search is waiting for a response.
	wprintf(L"\n");
	Debug(L"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n", hr);
	Debug(L"An error occurred in %s, HRESULT: %x\n",txt, hr);
	//hr = 0x80072116 Name translation: Could not find the name or insufficient right to see name. 
	//0x8007203aL	LDAP_SERVER_DOWN	ERROR_DS_SERVER_DOWN	Cannot contact the LDAP server.
	//http://msdn.microsoft.com/en-us/library/aa746528%28v=vs.85%29.aspx

	// If facility is Win32, get the Win32 error 
	if (HRESULT_FACILITY(hr)==FACILITY_WIN32)
	{
		DWORD dwLastError;
		WCHAR szErrorBuf[MAX_PATH];
		WCHAR szNameBuf[MAX_PATH];
		// Get extended error value.
		HRESULT hr_return =S_OK;
		hr_return = ADsGetLastError( &dwLastError,
			szErrorBuf,
			MAX_PATH,
			szNameBuf,
			MAX_PATH);
		if (SUCCEEDED(hr_return))
		{
			Debug(L"Error Code: %d Error Text: %ws Provider: %ws\n", dwLastError, szErrorBuf, szNameBuf);
		}
	}
	Debug(L"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n", hr);

	return hr;
}


HRESULT TranslateWinNT2LDAP(LPWSTR szNtName, LPWSTR szLdapPath)
{
	IADsNameTranslate *pNto;
	HRESULT hr;

	hr = CoCreateInstance(CLSID_NameTranslate,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_IADsNameTranslate,
		(void**)&pNto);

	if(SUCCEEDED(hr)) {
		hr = pNto->Init(ADS_NAME_INITTYPE_GC, L"");
		if (SUCCEEDED(hr))
		{ 
			hr =pNto->Set(ADS_NAME_TYPE_NT4, szNtName);
			if(SUCCEEDED(hr))
			{
				CComBSTR sbstr;

				hr = pNto->Get(ADS_NAME_TYPE_1779, &sbstr);
				if(SUCCEEDED(hr)){
					wcscpy_s(szLdapPath,MAX_PATH,sbstr);
					SysFreeString(sbstr);
				}
			}
		}

		pNto->Release();
	}

	return hr;
}

/*
* return and normalize the netbios name of an item in form <DOMAIN>/<ACCOUNTNAME>
*/
HRESULT GetLDAPPath(IADs *pADs, LPWSTR szLDAPPath){
	HRESULT hr;
	BSTR bsResult;

	LPWSTR szNtName = new WCHAR[MAX_PATH];

	pADs->get_Parent(&bsResult); 
	wcscpy_s(szNtName, MAX_PATH, StripProvider(bsResult));
	wcscat_s(szNtName, MAX_PATH, L"\\");
	SysFreeString(bsResult);

	pADs->get_Name(&bsResult); 
	wcscat_s(szNtName, MAX_PATH, bsResult);
	SysFreeString(bsResult);

	hr = TranslateWinNT2LDAP(szNtName, szLDAPPath);

	delete[] szNtName;
	return hr;
}

HRESULT TranslateLDAP2WiNT(LPWSTR szLdapPath, LPWSTR szNtName)
{
	IADsNameTranslate *pNto;
	HRESULT hr;

	hr = CoCreateInstance(CLSID_NameTranslate,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_IADsNameTranslate,
		(void**)&pNto);

	if(SUCCEEDED(hr)) {
		hr = pNto->Init(ADS_NAME_INITTYPE_GC, L"");
		if (SUCCEEDED(hr))
		{ 
			hr =pNto->Set(ADS_NAME_TYPE_1779, szLdapPath);
			if(SUCCEEDED(hr))
			{
				CComBSTR sbstr;

				hr = pNto->Get(ADS_NAME_TYPE_NT4, &sbstr);
				if(SUCCEEDED(hr)){
					wcscpy_s(szNtName,MAX_PATH,sbstr);
					SysFreeString(sbstr);
				}
			}
		}

		pNto->Release();
	}

	return hr;
}

BOOL GetNetbiosNameEx(IADs *pADs, LPWSTR szNtName){
	WCHAR szSid[MAX_PATH];
	WCHAR szAccountName[MAX_PATH];
	WCHAR szDomainName[MAX_PATH];
	DWORD cchDomainName=MAX_PATH;
	DWORD cchAccountName=MAX_PATH;
	HRESULT hr;
	PSID pSid;
	SID_NAME_USE snu;
	BOOL bSuccess = FALSE;

	hr = GetSid(pADs,szSid);
	if(SUCCEEDED(hr)){
		if(ConvertStringSidToSidW(szSid,&pSid)){		
			if(LookupAccountSidW(NULL,pSid,
						szAccountName,
						&cchAccountName,
						szDomainName,
						&cchDomainName,
						&snu
						)){
				wcscpy_s(szNtName,MAX_PATH,szDomainName);
				wcscat_s(szNtName,MAX_PATH,L"/");
				wcscat_s(szNtName,MAX_PATH,szAccountName);
				bSuccess = TRUE;
			}

			FreeSid(pSid);
		}
	}
	return bSuccess;
}

/*
* return and normalize the netbios name of an item in form <DOMAIN>/<ACCOUNTNAME>
*/
HRESULT GetNetBiosName(IADs *pADs, LPWSTR szNtName){
	HRESULT hr;
	BSTR bsResult;

	if(GetNetbiosNameEx(pADs,szNtName))
		return S_OK;

	//should never here
	hr = pADs->get_ADsPath(&bsResult); 

	if(STARTS_WITH(adq_provider, bsResult)){
		hr = TranslateLDAP2WiNT(StripProvider(bsResult), szNtName);
		//normalize in a WinNT:// reusable form
		if(SUCCEEDED(hr)){
			for(unsigned int i = 0; i<wcslen(szNtName); i++){
				if(szNtName[i]=='\\'){
					szNtName[i]='/';// slash for reuse in queries
					break; //I suppose there is only one backslash
				}
			}
		} else {
			//Workaround
			SysFreeString(bsResult);
			if(STARTS_WITH(L"CN=",StripProvider(bsResult))){
				WCHAR szSid[MAX_PATH];
				hr = GetSid(pADs,szSid);
				wcscpy_s(szNtName, MAX_PATH, L"<SID=");
				wcscat_s(szNtName, MAX_PATH, szSid);
				wcscat_s(szNtName, MAX_PATH, L">");				
			}else{
				pADs->get_Parent(&bsResult); 
				wcscpy_s(szNtName, MAX_PATH, StripProvider(bsResult));
				wcscat_s(szNtName, MAX_PATH, L"/");

				VARIANT var;
				VariantInit(&var);
				hr = pADs->Get(ATTR_ACCOUNTNAME, &var);
				wcscat_s(szNtName, MAX_PATH, var.bstrVal);
				VariantClear(&var);
			}
		}
	} else {
		SysFreeString(bsResult);

		pADs->get_Parent(&bsResult); 
		wcscpy_s(szNtName, MAX_PATH, StripProvider(bsResult));
		wcscat_s(szNtName, MAX_PATH, L"/");// slash for reuse in queries
		SysFreeString(bsResult);

		pADs->get_Name(&bsResult); 
		wcscat_s(szNtName, MAX_PATH, bsResult);
	}

	if(FAILED(hr) && adq_debug){
		CheckErrorAD(L"GetNetBiosName",hr);
		//hr = 0x80072116 Name translation: Could not find the name or insufficient right to see name. 
		//insufficent rights???@@$#%$^%^!
		//questo è un mistero...	
	}

	SysFreeString(bsResult);
	return hr;
}

//gets the sid of an IADs got with WinNT provider
//the pszSid must be already allocated
HRESULT GetSid(IADs *pItem, LPWSTR pszSid){
	HRESULT hr;
	VARIANT vOctet;
	DWORD dwSLBound;
	DWORD dwSUBound;
	void HUGEP *pArray = NULL;

	VariantInit(&vOctet);
	hr = pItem->Get(ATTR_OBJECTSID, &vOctet);

	//Get a pointer to the bytes in the octet string.
	if (SUCCEEDED(hr))
	{
		hr = SafeArrayGetLBound( V_ARRAY(&vOctet),
			1,
			(long FAR *) &dwSLBound );
		hr = SafeArrayGetUBound( V_ARRAY(&vOctet),
			1,
			(long FAR *) &dwSUBound );
		if (SUCCEEDED(hr))
		{
			hr = SafeArrayAccessData( V_ARRAY(&vOctet),
				&pArray );


			PSID pObjectSID = (PSID) pArray;
			//Convert SID to string.
			LPWSTR szSID = NULL;
			ConvertSidToStringSidW(pObjectSID, &szSID);
			wcscpy_s(pszSid, MAX_PATH, szSID);
			LocalFree(szSID);

			SafeArrayUnaccessData( V_ARRAY(&vOctet) );
		}
		VariantClear(&vOctet);
	}

	if(FAILED(hr) && adq_debug)
		CheckErrorAD(L"GetSid",hr);

	return hr;
}

bool IsLdap(IADs *pADs){
	BSTR bsResult;
	pADs->get_ADsPath(&bsResult); 
	bool val = STARTS_WITH(adq_provider, bsResult);	
	SysFreeString(bsResult);
	return val;
}

HRESULT GetGuid(IADs *pADs, LPWSTR pszSid){
	HRESULT hr;
	BSTR bsResult;
	hr = pADs->get_GUID(&bsResult); 
	wcscpy_s(pszSid, MAX_PATH, bsResult);
	SysFreeString(bsResult);
	return hr;
}

bool IsDomainItem(IADs *pADs)
{
	HRESULT hr;
	BSTR bstr;
	bool isDomain = false;
	IADs *pParentADs;

	hr = pADs->get_Parent(&bstr);
	hr = ADsGetObject(bstr, IID_IADs,(void **) &pParentADs);	
	SysFreeString(bstr);

	if(SUCCEEDED(hr))
	{
		hr = pParentADs->get_Class(&bstr);

		isDomain = (_wcsicmp(bstr,TYPE_DOMAIN)==0);

		SysFreeString(bstr);
		pParentADs->Release();
	}

	return isDomain;
}

PrincipalId RemoveDomain(PrincipalId name)
{
	size_t i = name.find_first_of(L"/");
	if(i>0)
		return name.substr(i+1);
	else
		return name;
}

bool Exists(PrincipalId name, PrincipalList list){
	for(unsigned int x=0; x<list.size(); x++)
	{
		if(list[x].compare(name) == 0)
		{
			return true;
		}
	}
	return false;
}

void Destroy(PrincipalList& list)
{
	list.clear();

	PrincipalList v;
	list.swap(v);
}

LPWSTR StripProvider(LPWSTR szPath){
	for(unsigned int i = 0; i<wcslen(szPath); i++){
		if(wcsncmp(szPath+i, L"://", 3)==0){
			return szPath+i+3;
		}
	}
	return szPath;
}