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

#include "adquery.h"
#include "util.h"

#include <stdio.h>
#include <wchar.h>
#include <time.h>

#include <Iads.h>

#include <atlbase.h>
#include <activeds.h>

#include <Ntsecapi.h>

typedef struct ADSQCacheT{
	PrincipalList adq_users;
	PrincipalList adq_groups;
	PrincipalList adq_browsed;
} ADSQCache;

extern int adq_indent;

//flags
#ifdef _DEBUG
bool adq_debug	= true;
#else
bool adq_debug	= false;
#endif
bool adq_useGC	= false; //browses same groups with both providers winnt and ldap
bool adq_useWa	= true;
bool adq_useXWL	= true; //re browse groups from winnt in ldap
bool adq_useXLW	= true; //re browse groups from ldap in winnt

//discovered
bool adq_hasWinNT	= true;
bool adq_hasLDAP		= true;

FILE * log_file=(FILE *)NULL;


//internal
int adq_indent = 0;
LPWSTR	adq_provider		= PROVIDER_LDAP;

HRESULT EvaluateItem(IADs *pADs,ADSQCache *cache);

/*
* performs a lookup of the object and browses the item if found
*/
HRESULT BindItem(LPCWSTR szPath,ADSQCache *cache)
{
	HRESULT hr;
	IADs *pADs;
	hr = ADsGetObject(szPath,IID_IADs,(void **) &pADs);
	if(SUCCEEDED(hr))
	{
		hr = EvaluateItem(pADs,cache);
		pADs->Release();
	} else
		if(adq_debug)
			CheckErrorAD(L"ADsGetObject",hr);
	return hr;
}

/*
* performs a lookup in AD of the object and browses the item if found
*/
HRESULT BindLDAP(LPCWSTR str,ADSQCache *cache)
{
	HRESULT hr;
	LPWSTR szPath = new WCHAR[MAX_PATH];
	wcscpy_s(szPath,MAX_PATH, adq_provider);
	wcscat_s(szPath,MAX_PATH, str);
	hr = BindItem(szPath,cache);
	delete[] szPath;
	return hr;
}

/*
* performs a lookup of the object using the winnt provider and browses the item if found
*/
HRESULT BindWinNT(LPCWSTR str,ADSQCache *cache)
{
	HRESULT hr;
	LPWSTR szPath = new WCHAR[MAX_PATH];
	wcscpy_s(szPath,MAX_PATH, PROVIDER_WINNT);
	wcscat_s(szPath,MAX_PATH, str);
	hr = BindItem(szPath,cache);
	delete[] szPath;
	return hr;
}

/*
* browse all members of the given group
* NOT works with WINT provider items, for this use BrowseGroup
*/
HRESULT BrowseGroupLDAP(IADsGroup *pGroup,ADSQCache *cache){
	HRESULT hr;
	VARIANT var;

	VariantInit(&var);
	hr = pGroup->Get(ATTR_MEMBER, &var);
	if(SUCCEEDED(hr))
	{
		if(HAS_BIT_STYLE(var.vt, VT_ARRAY)){
			DWORD dwSLBound;
			DWORD dwSUBound;
			VARIANT HUGEP *pArray;

			SAFEARRAY *psa = V_ARRAY(&var);
			hr = SafeArrayGetLBound( psa,	1, (long FAR *) &dwSLBound );
			hr = SafeArrayGetUBound( psa,	1, (long FAR *) &dwSUBound );
			hr = SafeArrayAccessData( psa,(void HUGEP* FAR*) &pArray );

			for(DWORD i = dwSLBound; i<dwSUBound; i++){
				hr = BindLDAP(V_BSTR(&pArray[i]),cache);
			}

			SafeArrayUnaccessData( V_ARRAY(&var));
		}
		else if(HAS_BIT_STYLE(var.vt,VT_BSTR)){
			hr = BindLDAP(V_BSTR(&var),cache);
		}
	}
	else
		if(adq_debug)
			CheckErrorAD(L"GetMembersLDAP", hr);

	VariantClear(&var);
	return hr;
}
/*
* browse all members of the given group
* NOT works with LDAP provider items, for this use BrowseGroupWithLDAP
*/
HRESULT BrowseGroup(IADsGroup *pGroup,ADSQCache *cache){
	HRESULT hr;
	IADsMembers *pMembers = NULL;

	hr = pGroup->Members(&pMembers);
	if(SUCCEEDED(hr)){
		//create an enumeration over members
		IUnknown *pUnk = NULL;
		hr = pMembers->get__NewEnum(&pUnk);

		if(SUCCEEDED(hr)){
			//fill values
			IEnumVARIANT *pEnum = NULL;
			hr = pUnk->QueryInterface(IID_IEnumVARIANT,(void**)&pEnum);

			if(SUCCEEDED(hr)){
				// Now Enumerate
				VARIANT var;
				IADs *pADs = NULL;
				ULONG lFetch;
				IDispatch *pDisp = NULL;

				VariantInit(&var);
				while(pEnum->Next(1, &var, &lFetch) == S_OK)
				{
					if (lFetch == 1)
					{
						pDisp = V_DISPATCH(&var);
						pDisp->QueryInterface(IID_IADs, (void**)&pADs);
						pDisp->Release();

						hr = EvaluateItem(pADs,cache);
					}
					VariantClear(&var);
				}
				VariantClear(&var);
				pEnum->Release();	
			}
			else
				if(adq_debug)
					CheckErrorAD(L"QueryInterface", hr);

			pUnk->Release();
		}
		pMembers->Release();	
	}
	else
		if(adq_debug)
			CheckErrorAD(L"GetMembers", hr);

	return hr;
}

/*
*  lookup and browse an WINT provider item using LDAP provider
*  this function is necessary for the workaround of above ...
*/
HRESULT BrowseWinNTItemWithLDAP(IADs *pItem,ADSQCache *cache){
	HRESULT hr;
	BSTR domain = NULL;

	if(adq_debug){
		LPWSTR szNtName = new WCHAR[MAX_PATH];
		szNtName[0] = '?';
		szNtName[1] = 0;
		hr = GetNetBiosName(pItem, szNtName);
		Debug(L"Re-Browsing with %s: %s\n", adq_provider, szNtName);
		delete[] szNtName;
	}


	LPWSTR pszQuery = new WCHAR[MAX_PATH];

	LPWSTR pszSid = new WCHAR[MAX_PATH];
	hr = GetSid(pItem, pszSid);

	LPWSTR pszDomain = new WCHAR[MAX_PATH];
	pItem->get_Parent(&domain);
	wcscpy_s(pszDomain,MAX_PATH,domain);
	SysFreeString(domain);

	wcscpy_s(pszQuery, MAX_PATH, StripProvider(pszDomain));
	wcscat_s(pszQuery, MAX_PATH, L"/<SID=");
	wcscat_s(pszQuery, MAX_PATH, pszSid);
	wcscat_s(pszQuery, MAX_PATH, L">");

	delete[] pszSid;
	delete[] pszDomain;

	hr = BindLDAP(pszQuery,cache);

	delete[] pszQuery;

	return hr;
}

/*
*  lookup and browse an LDAP provider item using WinNT provider
*  this function is necessary for the workaround of above ...
*/
HRESULT BrowseLDAPItemWithWinNT(IADs *pItem,ADSQCache *cache){
	HRESULT hr;

	LPWSTR pszName = new WCHAR[MAX_PATH];
	hr = GetNetBiosName(pItem, pszName);

	if(adq_debug){
		Debug(L"Re-Browsing with WinNT: %s\n", pszName);
	}

	if(SUCCEEDED(hr)){
		wcscat_s(pszName, MAX_PATH, L",group");
		hr = BindWinNT(pszName,cache);
	}
	else
		if(adq_debug)
			Debug(L"Cannot browse WinNT: %s\n", pszName);

	delete[] pszName;
	return hr;
}

/*
* adds the item in the list if not yet present
* in the list items are added in form of <DOMAIN>/<ACCOUNTNAME>
* returns S_OK if added S_FALSE if not
*/
HRESULT AddItem(IADs *pUser,ADSQCache *cache, PrincipalList& list, LPWSTR type){
	HRESULT hr;

	PrincipalId name;
	PrincipalId key;
	LPWSTR szNtName = new WCHAR[MAX_PATH];

	hr = GetSid(pUser, szNtName);
	if(SUCCEEDED(hr))
		key = szNtName;

	hr = GetNetBiosName(pUser, szNtName);
	if(SUCCEEDED(hr))
		name = szNtName;
	else
		name = key;

	if(adq_debug){
		Debug(L"-------------- %s: %s -------------\n", type, name.c_str());
	}

	delete[] szNtName;

	if(adq_useWa)
		key = (IsLdap(pUser)?L"L":L"W") + key;

	if(!Exists(key,cache->adq_browsed)){
		cache->adq_browsed.push_back(key);

		if(!Exists(name, list)){
			list.push_back(name);
			if(adq_debug){
				PrintIADSObject(pUser);
			}
		} else {
			if(adq_debug){
				Debug(L"     ALREADY ADDED\n");
			}
		}

		return S_OK;
	} else {
		if(adq_debug){
			Debug(L"     ALREADY BROWSED\n");
		}

		return S_FALSE;
	}
}

HRESULT AddUser(IADsUser *pUser,ADSQCache *cache){
	return AddItem(pUser,cache, cache->adq_users, L"USER");
}
HRESULT AddGroup(IADsGroup *pUser,ADSQCache *cache){
	return AddItem(pUser,cache, cache->adq_groups, L"GROUP");
}

/*
* resolves references to principals defined in another domain
*/
HRESULT ResolveForeignSecurityPrincipal(IADs *pADs,ADSQCache *cache){
	HRESULT hr;

	LPWSTR szNtName = new WCHAR[MAX_PATH];
	hr = GetNetBiosName(pADs,szNtName);
	if(SUCCEEDED(hr)){
		if(adq_debug){
			Debug(L"-------------- FOREIGN: %s -------------\n", szNtName);
		}

		hr = BindWinNT(szNtName,cache);
	}

	delete[] szNtName;

	return hr;
}


/*
* checks the type of the item and if it is a group then browses into the group
* else adds the user to the list
*/
HRESULT EvaluateItem(IADs *pADs,ADSQCache *cache)
{
	HRESULT hr;
	BSTR szType;
	hr = pADs->get_Class(&szType);

	if( wcscmp(szType,TYPE_GROUP)==0){
		//TODO skip specials S-1-5-4 S-1-5-11 ... /NT AUTHORITY/
		if(AddGroup((IADsGroup *)pADs,cache) == S_OK){
			adq_indent++;
			hr = BrowseGroup((IADsGroup *)pADs,cache);
			adq_indent--;

			//This is a workaround:
			//if a machine domain group contains foreign references, they will not returned as members
			//as workaround we browse each domain group using LDAP:// instead of WinNT://
			//The strange is that if the whole group or user belongs to a different domain, they will be
			//  resolved correctly

			//Only if iads is a domain principal
			if(adq_useXWL && adq_hasLDAP && IsDomainItem(pADs))
				hr = BrowseWinNTItemWithLDAP(pADs,cache);
		}
	} else if(wcscmp(szType,TYPE_USER)==0){
		hr = AddUser((IADsUser *)pADs,cache);
	} else if(wcscmp(szType,TYPE_GROUP_LDAP)==0){
		if(AddGroup((IADsGroup *)pADs,cache) == S_OK){
			adq_indent++;
			hr = BrowseGroupLDAP((IADsGroup *)pADs,cache);
			adq_indent--;

			if(adq_useXLW && adq_hasWinNT)
				hr = BrowseLDAPItemWithWinNT(pADs,cache);
		}
	} else if(wcscmp(szType,TYPE_USER_LDAP)==0){
		hr = AddUser((IADsUser *)pADs,cache);
	} else if(wcscmp(szType,TYPE_FOREIGN_SP_LDAP)==0){
		hr = ResolveForeignSecurityPrincipal(pADs,cache);
	} else {
		Debug(L"Unsupported member type: %s\n", szType);
		PrintIADSObject(pADs);
		hr = S_FALSE;
	}	

	SysFreeString(szType);
	//delete[] szType;
	return hr;
}

/*
* fills szDomain with the domain associated to the machine
* returns true if computer belongs to an AD domain
*/
bool ComputerBelongsToDomain(LPWSTR szDomain)
{
	bool ret = false;

	LSA_OBJECT_ATTRIBUTES objectAttributes;
	LSA_HANDLE policyHandle;
	NTSTATUS status;
	PPOLICY_PRIMARY_DOMAIN_INFO info;

	// Object attributes are reserved, so initialize to zeros.
	ZeroMemory(&objectAttributes, sizeof(objectAttributes));

	status = LsaOpenPolicy(NULL, &objectAttributes, GENERIC_READ | POLICY_VIEW_LOCAL_INFORMATION, &policyHandle);
	if (!status)
	{
		status = LsaQueryInformationPolicy(policyHandle, PolicyPrimaryDomainInformation, (LPVOID*)&info);
		if (!status)
		{
			if (info->Sid)
				ret = true;
			wcscpy_s(szDomain, MAX_PATH, info->Name.Buffer);

			LsaFreeMemory(info);
		}

		LsaClose(policyHandle);
	}

	return ret;
}

/*
* fills list with all principals found in the given group or in his sub-groups
* if domains is false all domain names are removed from account names
* returns S_OK if no error, S_FALSE if some throubles are found...
* example szPath: ./MyGroup,group or WP/DomainGroup,group or <SID=S-1-5-32-544>
*/
HRESULT GetUsersOf(LPWSTR szPath, PrincipalList& list, bool domains )
{
	HRESULT hr;
	clock_t start = clock();

	ADSQCache *cache = new ADSQCache;

	hr = BindWinNT(szPath,cache);

	if(adq_debug) {
		Debug(L"Browsed %s: %d groups, %d users in %d ms.\n",szPath, cache->adq_groups.size(), cache->adq_users.size(), clock()-start);
	}
	//fill the user collection
	PrincipalId id;
	for(unsigned int x=0; x<cache->adq_users.size(); x++)
	{
		if(domains)
			id = cache->adq_users[x];
		else
			id = RemoveDomain(cache->adq_users[x]);
		if(!Exists(id,list))
			list.push_back(id);
	}

	if(adq_debug)
	{
		for(unsigned int x=0; x<cache->adq_groups.size(); x++)
		{
			Debug(L"Group %02d: %s\n",x, cache->adq_groups[x].c_str());
		}
	}

 	Destroy(cache->adq_users);
 	Destroy(cache->adq_groups);
 	Destroy(cache->adq_browsed);
	delete cache;

	return hr;
}

/*
* fills list with all admin users of the current machine (and domain admins if machine is in domain)
* if domains is false all domain names are removed from account names
* returns S_OK if no error, S_FALSE if some throubles are found...
*/
HRESULT GetAdminUsers(PrincipalList& list, bool domains )
{
	HRESULT hr;

	LPWSTR szPath = new WCHAR[MAX_PATH];
	if(ComputerBelongsToDomain(szPath)){
		wcscat_s(szPath,MAX_PATH,L"/Domain Admins,group");
		hr = GetUsersOf(StripProvider(szPath),list ,domains);
	} else if(adq_debug)
		Debug(L"Machine is not in domain\n");
	delete[] szPath;


	//TODO localize name  Administrators
	//QueryInDomain(pszDomain,pszQuery)
	//hr = GetUsersOf(L"<SID=S-1-5-32-544>",list ,domains);
	if(adq_debug)
		Debug(L"Getting local machine admins\n");

	hr = GetUsersOf(L"./Administrators,group",list ,domains);
	if(FAILED(hr))
		CheckErrorAD(L"GetUsersOf", hr);

	return hr;
}

HRESULT GetAllProviders()
{	
	IEnumVARIANT   *pEnum;
	IADsContainer  *pCont;
	IADs           *pADs;
	IDispatch      *pDisp;
	VARIANT        var;
	BSTR           bstr;
	ULONG          lFetch;
	HRESULT        hr;

	// Bind to ADs namespace
	hr = ADsGetObject(L"ADs:",IID_IADsContainer, (void**) &pCont);
	if(SUCCEEDED(hr)){
		//Create an enumerator object in the container.
		hr = ADsBuildEnumerator(pCont, &pEnum);
		if(SUCCEEDED(hr)){
			adq_hasLDAP = false;
			adq_hasWinNT = false;

			// Now enumerate through all providers 
			while(hr == S_OK)
			{
				hr = ADsEnumerateNext(pEnum, 1, &var, &lFetch);
				if (lFetch == 1)
				{
					pDisp = V_DISPATCH(&var);
					pDisp->QueryInterface(IID_IADs, (void**)&pADs);
					pDisp->Release();

					pADs->get_Name(&bstr);
					
					if(wcsncmp(L"LDAP:",bstr,5)==0)
						adq_hasLDAP = true;
					else if(wcsncmp(L"WinNT:",bstr,6)==0)
						adq_hasWinNT = true;
					if(adq_debug)
						Debug(L"Provider %s\n",(LPWSTR)bstr);
					
					pADs->Release();
					SysFreeString(bstr);
				}
			}

			//Release the enumerator.	
			ADsFreeEnumerator(pEnum);
		}
		pCont->Release();
	}

	if(FAILED(hr))
		CheckErrorAD(L"GetAllProviders", hr);

	return hr;
}

/*
* initializes COM and COM security
*/
HRESULT InitCom(){
	HRESULT hr;
	//COINIT_APARTMENTTHREADED f
	//hr = CoInitialize(NULL);
	hr = CoInitializeEx(NULL,COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE);
	/*
	if (FAILED(hr))
	return hr;

	hr =  CoInitializeSecurity(
	NULL, 
	-1,                          // COM authentication
	NULL,                        // Authentication services
	NULL,                        // Reserved
	RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
	RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
	NULL,                        // Authentication info
	EOAC_NONE,                   // Additional capabilities 
	NULL                         // Reserved
	);
	*/
	return hr;
}


void writeToRegistry(PrincipalList& list){
	int size = list.size()*sizeof(PrincipalId)+ list.size() + 5 + 1;//list.size() of | +#DONE\0
	char* stradmins = (char*)malloc(size);
	int err = 0;
	if(stradmins){
		stradmins[0]='\0';
		for(unsigned int x=0; x<list.size(); x++)
		{
			const wchar_t* wstr = list[x].c_str();
			char* out = (char*)malloc(wcslen(wstr)+1);
			if(out){
				wcstombs_s(NULL,out,wcslen(wstr)+1,wstr,wcslen(wstr)+1);//convert wchar_t to char
				strncat_s(stradmins,size,out,_TRUNCATE);
				strncat_s(stradmins,size,"|",_TRUNCATE);
				free(out);
			}else {
				err = 1;
				break;
			}
		}
		if(!err)strncat_s(stradmins,size,"#DONE",_TRUNCATE);
		HKEY hKey;
		if ( RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Wuerth Phoenix\\AuditService\\SysAdmin\\", 0, KEY_ALL_ACCESS,&hKey ) == ERROR_SUCCESS ){
			if(RegSetValueEx(hKey, "Objective",0,REG_SZ, (CONST BYTE *) stradmins,(DWORD)strlen(stradmins)) != ERROR_SUCCESS){
				if(adq_debug)
					Debug(L"Failed to write to Key SOFTWARE\\Wuerth Phoenix\\AuditService\\SysAdmin\\");
			}
			RegCloseKey(hKey);
		}else{
			if(adq_debug)
				Debug(L"Failed to open the Key SOFTWARE\\Wuerth Phoenix\\AuditService\\SysAdmin\\");
		
		}
		free(stradmins);
	}
}

int main(int argc, char* argv[])
{
#ifndef UNICODE
	USES_CONVERSION;
#endif
	HRESULT hr;
	bool domains = false;
	PrincipalList list;

	char* query = NULL;


	for(int i = 1; i<argc; i++){
		char *arg = argv[i];
		bool val = !(strncmp("-no",arg,3)==0);
		if(val)
			arg+=1;
		else
			arg+=3;
		if(strcmp("debug",arg)==0)
			adq_debug = val;
		else
			if(strcmp("domains",arg)==0)
				domains = val;
			else
				if(strcmp("usexwl",arg)==0)
					adq_useXWL = val;
				else
					if(strcmp("usexlw",arg)==0)
						adq_useXLW = val;
					else
						if(strcmp("lookup",arg)==0)
							query = argv[++i];
						else
							if(strcmp("usegc",arg)==0){
								adq_useGC = val;
								adq_provider = PROVIDER_GC;
							}
							else
								if(strcmp("usewa",arg)==0){
									adq_useWa = val;
									adq_useXLW = val;
									adq_useXWL = val;
								}
								else
									if(strstr(arg,"logfile=")){
										char* logfile = NULL;
										logfile = (arg + 8);
										if(logfile){
											fopen_s(&log_file,logfile,"a");
										
										}
										if(!log_file){
											Debug(L"Unknown log file: %s",  logfile);
											return 1;
										}
									}
									else{
										Debug(L"Unknown parameter: %s",  argv[i]);
										return 1;
									}
	}



	hr = InitCom();
    if (SUCCEEDED(hr))
    {
		hr = GetAdminUsers(list,domains);
		if(adq_debug)
			Debug(L"SAD found %d users",list.size());
		writeToRegistry(list);
		Destroy(list);

	}else{
		if(adq_debug)
			Debug(L"Failed to initialize the com interface");
	}
	CoUninitialize();
	if(log_file) {
			fflush(log_file);
			fclose(log_file);
	}										
}







		