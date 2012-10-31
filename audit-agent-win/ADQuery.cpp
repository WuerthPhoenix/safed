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


#include "adquery.h"
#include "util.h"

#include <stdio.h>
#include <wchar.h>
#include <time.h>

#include <Iads.h>

#include <atlbase.h>
#include <activeds.h>

#include <Ntsecapi.h>
#include "LogUtils.h"


typedef struct ADSQCacheT{
	PrincipalList adq_users;
	PrincipalList adq_groups;
	PrincipalList adq_browsed;
} ADSQCache;

extern int adq_indent;

//flags

bool adq_useGC	= false; //browses same groups with both providers winnt and ldap
bool adq_useWa	= true;
bool adq_useXWL	= true; //re browse groups from winnt in ldap
bool adq_useXLW	= true; //re browse groups from ldap in winnt

//discovered
bool adq_hasWinNT	= true;
bool adq_hasLDAP		= true;

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
				CheckErrorAD(L"QueryInterface", hr);

			pUnk->Release();
		}
		pMembers->Release();	
	}
	else
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

	LPWSTR szNtName = new WCHAR[MAX_PATH];
	szNtName[0] = '?';
	szNtName[1] = 0;
	hr = GetNetBiosName(pItem, szNtName);
	LogExtMsg(INFORMATION_LOG,"Re-Browsing with %s: %s\n", adq_provider, szNtName);
	delete[] szNtName;


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

	LogExtMsg(INFORMATION_LOG,"Re-Browsing with WinNT: %s\n", pszName);

	if(SUCCEEDED(hr)){
		wcscat_s(pszName, MAX_PATH, L",group");
		hr = BindWinNT(pszName,cache);
	}
	else
		LogExtMsg(INFORMATION_LOG,"Cannot browse WinNT: %s\n", pszName);

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

	LogExtMsg(DEBUG_LOG,"-------------- %s: %s -------------\n", type, name.c_str());

	delete[] szNtName;

	if(adq_useWa)
		key = (IsLdap(pUser)?L"L":L"W") + key;

	if(!Exists(key,cache->adq_browsed)){
		cache->adq_browsed.push_back(key);

		if(!Exists(name, list)){
			list.push_back(name);
			PrintIADSObject(pUser);
		} else {
			LogExtMsg(DEBUG_LOG,"     ALREADY ADDED\n");
		}

		return S_OK;
	} else {
		LogExtMsg(DEBUG_LOG,"     ALREADY BROWSED\n");

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
		LogExtMsg(DEBUG_LOG,"-------------- FOREIGN: %s -------------\n", szNtName);

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
		LogExtMsg(INFORMATION_LOG,"Unsupported member type: %s\n", szType);
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

	LogExtMsg(INFORMATION_LOG,"Browsed %s: %d groups, %d users in %d ms.\n",szPath, cache->adq_groups.size(), cache->adq_users.size(), clock()-start);
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

	for(unsigned int x=0; x<cache->adq_groups.size(); x++)
	{
		LogExtMsg(DEBUG_LOG,"Group %02d: %S\n",x, cache->adq_groups[x].c_str());
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
	} else 	LogExtMsg(INFORMATION_LOG,"Machine is not in domain\n");
	delete[] szPath;


	//TODO localize name  Administrators
	//QueryInDomain(pszDomain,pszQuery)
	//hr = GetUsersOf(L"<SID=S-1-5-32-544>",list ,domains);
	LogExtMsg(INFORMATION_LOG,"Getting local machine admins\n");

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
					LogExtMsg(INFORMATION_LOG,"Provider %s\n",(LPWSTR)bstr);
					
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

