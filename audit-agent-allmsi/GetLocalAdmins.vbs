'***********************************************************
'***
'*** Enumerate passed arguments. Expect FilePath for logfile
'***
'***********************************************************

Set objArgs = WScript.Arguments

if objArgs.Count <> 1 then

	sReturn = sReturn & "To run GetLocalAdmins.vbs you need to pass the following parameters:" & vbcrlf & "- LogfilePath e.g. C:\Temp\LocalAdmins.csv" & vbcrlf & "- Resolve Group Membership: TRUE or FALSE" & vbcrlf & vbcrlf & "e.g.: GetLocalAdmins.vbs " & chr(34) & "C:\Temp\LocalAdmins.csv" & chr(34) & " TRUE" & "<BR>"


	WScript.Quit
end if

'cLogFile = objArgs(0)
cResolve = objArgs(0)

if UCase(cResolve) ="TRUE" then

	lResolve = true
else
	lResolve = False
end if

'***********************************************************
'***
'*** Execute Main
'***
'***********************************************************

on error resume next
SetLocale(1031)
Dim Command
Dim con
Dim cServer
Dim cDNDomain
Dim sReturn
Dim rReturn

'***********************************************************
'***
'*** Init ADS access if possible
'***
'***********************************************************
InitADS()
'File = cLogFile 

'***********************************************************
'***
'*** Define WSH Objects
'***
'***********************************************************
Set WSHShell     = WScript.CreateObject("WScript.Shell")
Set WSHNetwork   = WScript.CreateObject("WScript.Network") 
set WshShell     = WScript.CreateObject("WScript.Shell")
'Set fso          = WScript.CreateObject("Scripting.FileSystemObject") 

'***********************************************************
'***
'*** Open Logfile
'***
'***********************************************************
Set FileOut      = fso.OpenTextFile( File , 2, true) 


strComputername  = WSHNetwork.Computername			'*** Get Computer- and Username
cDomain          = WSHNetwork.UserDomain

'***********************************************************
'***
'*** If running on Domaincontrollers/Domain Computers / Domain Clients
'*** retrieve the Domain Admins Group Name
'***
'***********************************************************
cDomainAdminGroupSID = ""
cEnterpriseGroupSID  = ""
Call GetDomainAdminsGroupName( strComputername )


'***********************************************************
'***
'*** Execute the local Administrator Group
'***
'***********************************************************
cAdminGroupName  = GetNameBySID("S-1-5-32-544", strComputername)	'*** Get Name of local Admingroup (e.g. Administratoren or Administrators or....)
Set Admins       = GetObject("WinNT://" & strComputername & "/" & cAdminGroupName & ",group")   
Call GetGroupMembers(Admins, "direct member in Administrators")


'***********************************************************
'***
'*** If available, execute Domain Admins Group
'***
'***********************************************************
if IsCurrentComputerDC(strComputername) then
	Err.Clear
	cDomainAdminGroupName  = GetNameBySID(cDomainAdminGroupSID, strComputername)	'*** Get Name of local Admingroup (e.g. Administratoren or Administrators or....)
	Set Admins       = GetObject("WinNT://" & strComputername & "/" & cDomainAdminGroupName & ",group")   
	If Err.Number = 0 then

		Call GetGroupMembers(Admins, "direct member in Domain Admins")
	end if
end if

'***********************************************************
'***
'*** Write to registry
'***
'***********************************************************
if Left(rReturn,1) then
	rReturn = Mid(rReturn, 2)
end if
rReturn = rReturn&"|#DONE" 
Call WSHShell.RegWrite("HKLM\SOFTWARE\Wuerth Phoenix\AuditService\SysAdmin\Objective", rReturn, "REG_SZ")

'***********************************************************
'***
'*** Done
'***
'***********************************************************
sReturn = sReturn&"DONE"
WScript.Echo sReturn






'*******************************************************************************************************************
Public Function InitADS()
		'*** -----------------------------------
		'*** open Access to ADS
		'*** user ADODB
   		'*** -----------------------------------

	Set con      = CreateObject("ADODB.Connection")
	Set command  = CreateObject("ADODB.Command")

		'*** -----------------------------------
		'*** connect/open
		'*** -----------------------------------
   
	con.provider = "ADSDSOObject"
	con.open
	Set command.ActiveConnection = con

		'*** -----------------------------------
		'*** get main infos from ADS Provider
		'*** -----------------------------------
   
	Set rootDSE 		 = GetObject("LDAP://rootDSE")
	cServer     		 = rootDSE.get("dnsHostName")		
	cDNDomain   		 = rootDSE.Get("defaultNamingContext")
	cConfigurationNamingContext = rootDSE.Get("ConfigurationNamingContext")
	cRootDomainNamingContext    = rootDSE.Get("RootDomainNamingContext")


End Function

'*******************************************************************************************************************

Public Function GetNameBySID(cSID, cComputer)
	'*** -----------------------------------
	'*** Receive Principalname by SID
	'*** -----------------------------------

	Set objLocator = CreateObject("WbemScripting.SWbemLocator")
	Set objWMIService = objLocator.ConnectServer(cComputer,"root\cimv2","", "")
	objWMIService.Security_.ImpersonationLevel = 3

	Set wmiSID = objWMIService.Get("Win32_SID.SID='" & cSID & "'")
	GetNameBySID = wmiSID.AccountName

End Function

'*********************************************************************************************************************

Public Function GetDomainAdminsGroupName( strComputername )
	'***
	'*** Get the REAL Name of Domain Admins (in case of somebody renamed the group or the local name is not Domain Admins
	'***
	cAdminGrpName  = GetNameBySID("S-1-5-32-544", strComputername)	'*** Get Name of local Admingroup (e.g. Administratoren or Administrators or....)
	Set AdminGroup = GetObject("WinNT://" & strComputername & "/" & cAdminGrpName & ",group")  

	'****
	'*** Find Administrator in group members (S-1-5-domainsid-500)
	'***

	For Each Member in AdminGroup.Members
		Set MemberInfo = GetObject(Member.Adspath)	
		cADSPath= MemberInfo.ADSPath
		aHelp = Split(cADSPath,"/")
		cDomain = aHelp(2)
		cUsername = aHelp(3)

		cSID = GetSIDByName(strComputername,cUsername,cDomain)
		if right(cSID,4)="-500" then						'*** Admin Found, exit for
			cDomainAdminGroupSID = left(cSID,len(cSID)-4) & "-512"
			cEnterpriseGroupSID  = left(cSID,len(cSID)-4) & "-519"
			Exit for
		end if
	Next

End Function


'*************************************************************************************************************
'***
'*** Retrieve all members of local group
'***
'*************************************************************************************************************
Public Function GetGroupMembers(xAdmins, cDirectText )
   
   Dim Admin 
   Dim AdsInfo
   Dim myAdmins

   For Each Admin in xAdmins.Members
	Set AdsInfo = GetObject(Admin.adspath)
	on error resume next
	
	if lResolve then						'*** Resolve Group Members recursive
		Err.Clear
		Set myAdmins  = GetObject(Admin.adspath & ",group")
			if err.number = 0 then	
				call GetGroupMembers(myAdmins, "group member of "   & AdsInfo.Name)
			end if						
	end if
	on error goto 0
	'*** -----------------------------------
  	'*** if computer name shows up then this principal is a local account/group
	'*** -----------------------------------

	if InStr(UCase(AdsInfo.Parent),UCase(strComputername)) <> 0  Then 	
		
		err.clear
		'FileOut.WriteLine strComputername & ";WinNT://" & strComputername & "/" & AdsInfo.Name & ";" & cDirectText
		rReturn = rReturn & "|" & AdsInfo.Name
		sReturn = sReturn & ";" & AdsInfo.Name & ";WinNT://" & strComputername & "/" & AdsInfo.Name & "<BR>"
		if err.number <> 0 then									
			'*** FileOut.Writeline "Error reading local user :" & Err.Number & "   " & Err.description
		end if
	Else
	
		'*** -----------------------------------
		'*** otherwise the principal is a domain account/group
		'*** -----------------------------------

		'*** -----------------------------------
		'*** get the principals domain name/sid
		'*** -----------------------------------

		cParent = AdsInfo.Parent
		
		strDomain =  Mid (AdsInfo.Parent, 9 , len(AdsInfo.Parent))	'*** separate WinNT:// Provider from string

		'*** -----------------------------------
		'*** für DomainUser 
		'*** -----------------------------------

		err.clear
		if Left(AdsInfo.Name,5) = "S-1-5" then						'*** found SID, no username!?
			on error resume next
			'FileOut.WriteLine "WinNT://" & AdsInfo.Name & " / Domain Account not available"
			rReturn = rReturn & "|" & AdsInfo.Name
			sReturn = sReturn & "WinNT://" & AdsInfo.Name & " / Domain Account not available" & "<BR>"

		else
			'FileOut.WriteLine strComputerName & ";" & strDomain & "\" & AdsInfo.Name & ";" & cDirectText
			rReturn = rReturn & "|" & AdsInfo.Name
			sReturn = sReturn & ";" & AdsInfo.Name & ";" & strDomain & "\\" & AdsInfo.Name & "<BR>"
			err.clear

			'*** -----------------------------------
			'*** try searching in ADS for samAccountNames
			'*** -----------------------------------

			Command.CommandText = "Select ADSPath from 'LDAP://" & cServer & "/" & cDNDomain & "' where samAccountName = '" & AdsInfo.Name & "'"			
			Command.Properties("Searchscope") = 2
			Set rs = Command.Execute

			'*** -----------------------------------
			'*** found in ADS?
			'*** -----------------------------------

			if not rs.eof then					
				Set objTempUser = GetObject(rs.fields("ADSPath"))

				'*** -----------------------------------
				'*** Get the SID
				'*** -----------------------------------
				cSid = GetSid			
				if cSID <> "" then						
					'FileOut.WriteLine "WinNT://" & cSID
					rReturn = rReturn & "|" & cSID
					sReturn = sReturn & "WinNT://" & cSID & "<BR>"
					if err.number <> 0 then
						'FileOut.Writeline "Error " & Err.Number & "    " & Err.description
						sReturn = sReturn & "ERROR " & Err.Number & "    " & Err.description & "<BR>" 
					end if
				end if
			end if				
		end if
	end if 
   Next 
End Function

'************************************************************************************************************************+
function GetSID
	'*** -----------------------------------
	'*** GetSID History
	'*** -----------------------------------

	on error resume next
	set adsSID 	= CreateObject("ADsSID")
	iSIDType 	= 0 					' 0=ADS_SID_RAW
	adsSID.SetAs iSIDType, objTempUser.Get("sidHistory")
	GetSID 	= adsSID.GetAs(4)				' 4=ADS_SID_SDDL

end function
'*************************************************************************************************************************

Public Function GetSidByName(strComputer,cAccountName,cDomain)
	'***
	'*** Retrieves the Pricipals name by SID
	'***
	on error resume next
	Set objLocator = CreateObject("WbemScripting.SWbemLocator")
	Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")

	Set colItems = objWMIService.ExecQuery("Select * from Win32_UserAccount where Name='" & cAccountName & "' and Domain='" & cDomain & "'",,48)
	For Each objItem in colItems
		Exit for
	Next

	GetSidByName=objItem.SID

End Function
'*************************************************************************************************************************

Public Function IsCurrentComputerDC(strComputername)
	'***
	'*** Determines if the current computer is a domain controller
	'***

	Dim lDC
	on error resume next
	err.clear
	cxGroupName  = GetNameBySID("S-1-5-32-548", strComputername)
	if err.number = 0 then
		lDC=TRUE
	else
		lDC=False
	end if
	IsCurrentComputerDC = lDC
End Function
