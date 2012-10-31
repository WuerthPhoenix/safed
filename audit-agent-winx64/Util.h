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

#ifndef UTIL_H
#define UTIL_H

#include "adquery.h"

#include <activeds.h>

#include <wchar.h>
#include <string>

//#define MAX_PATH	512
#define PROVIDER_LDAP			L"LDAP://"
#define PROVIDER_WINNT			L"WinNT://"
#define PROVIDER_GC				L"GC://"

#define HAS_BIT_STYLE(val, style) ((val & style) == style)

#define STARTS_WITH(CONST,VAR)	wcsncmp(CONST, VAR, wcslen(CONST))==0

#define ATTR_ACCOUNTNAME		L"sAMAccountName"
#define ATTR_MEMBER				L"member"
#define ATTR_OBJECTSID			L"objectSid"
#define ATTR_DN					L"distinguishedName"

#define ATTR_PATH				L"ADsPath"
#define ATTR_TYPE				L"objectCategory"

#define TYPE_GROUP				L"Group"
#define TYPE_USER				L"User"
#define TYPE_FOREIGN_SP_LDAP	L"foreignSecurityPrincipal"
#define TYPE_GROUP_LDAP			L"group"
#define TYPE_USER_LDAP			L"user"
#define TYPE_DOMAIN				L"Domain"

void Debug(LPWSTR fmt, ...);
void PrintIADSObject(IADs * pIADs);

bool Exists(PrincipalId name, PrincipalList list);
void Destroy(PrincipalList& list);
LPWSTR StripProvider(LPWSTR szPath);

HRESULT CheckErrorAD(LPWSTR txt, HRESULT hr);
bool IsLdap(IADs *pADs);
bool IsDomainItem(IADs *pADs);
PrincipalId RemoveDomain(PrincipalId name);

HRESULT GetLDAPPath(IADs *pADs, LPWSTR szLDAPPath);
HRESULT GetNetBiosName(IADs *pADs, LPWSTR szNtName);
HRESULT GetSid(IADs *pItem, LPWSTR pszSid);
HRESULT GetGuid(IADs *pADs, LPWSTR pszSid);

#endif