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

#ifndef ADQUERY_H
#define ADQUERY_H

#include <activeds.h>

#include <wchar.h>
#include <string>
#include <vector>

typedef std::basic_string<wchar_t> PrincipalId;
typedef std::vector<PrincipalId> PrincipalList;

HRESULT GetAdminUsers(PrincipalList& list, bool domains = true);
HRESULT GetUsersOf(LPWSTR szPath, PrincipalList& list, bool domains = true);
HRESULT InitCom();

#endif