#ifndef _WEBPAGESAUDIT_H_
#define _WEBPAGESAUDIT_H_ 1

#define CRITICAL_TOKEN "Critical"
#define PRIORITY_TOKEN "Priority"
#define WARNING_TOKEN "Warning"
#define INFORMATION_TOKEN "Information"
#define CLEAR_TOKEN "Clear"



#define SIZE_OF_EVENTIDMATCH     256
#define SIZE_OF_USERMATCH                256
#define SIZE_OF_A_GENERALMATCH     512
#define SIZE_OF_EVENTLOG                 35
#define SIZE_OF_CRITICALITY              12
#define SIZE_OF_USER_MATCH_TYPE  10
#define SIZE_OF_A_GENERAL_MATCH_TYPE  10



#define SUCCESS_TOKEN "Success"
#define FAILURE_TOKEN "Failure"
#define ALL_TOKEN ".*"

/*
 #if defined(__linux__)
#define OPEN_EVENTS "open,creat,link,symlink,truncate,ftruncate,mknod,rename,truncate64,ftruncate64,access"
#define FILE_REMOVE_EVENTS "unlink,rmdir"
#define PROCESS_EVENTS "execve"
#define ATTRIBUTE_EVENTS "chmod,chown,lchown,fchmod,fchown,fchown32,lchown32,chown32"
#define ADMIN_EVENTS "mount,umount,umount2,settimeofday,swapon,swapoff,reboot,setdomainname,create_module,delete_module,quotactl"
#define NETWORK_EVENTS "socketcall"
#define AUTH_EVENTS "login_auth,login_start,logout"
#define ACCT_EVENTS "acct_mgmt"

#define OPEN_TOKEN "Read/Write a File/Directory"
#define REMOVE_TOKEN "Remove a File/Directory"
#define PROCESS_TOKEN "Start/Stop Program"
#define ATTRIBUTE_TOKEN "Modify File/Directory Attributes"
#define ADMIN_TOKEN "Administrative Events"
#define NETWORK_TOKEN "Network Socketcall Events"
#define AUTH_TOKEN "Authentication Events"
#define ACCT_TOKEN "Account Administration Events"

#endif

 */


#define OPEN_TOKEN "File_Read_Write"
#define FILE_REMOVE_TOKEN "File_Remove"
#define PROCESS_TOKEN "Process_Events"
#define FILE_ATTRIB_TOKEN "File_Attrib"
#define ADMIN_TOKEN "Admin_Events"
#define SOCKET_TOKEN "Socket_Events"
#define LOGONOFF_TOKEN "Logon_Logoff"
#define USER_TOKEN "User_Events"
#define FILE_READ_TOKEN "File_Read"
#define FILE_WRITE_TOKEN "File_Write"


#if defined(__linux__)
#define OPEN_EVENTS "open,creat,link,symlink,truncate,ftruncate,mknod,rename,truncate64,ftruncate64,access"
#define FILE_REMOVE_EVENTS "unlink,rmdir"
#define PROCESS_EVENTS "execve"
#define FILE_ATTRIB_EVENTS "chmod,chown,lchown,fchmod,fchown,fchown32,lchown32,chown32"
#define ADMIN_EVENTS "mount,umount,umount2,settimeofday,swapon,swapoff,reboot,setdomainname,create_module,delete_module,quotactl"
#define SOCKET_EVENTS "socketcall"
#define LOGON_LOGOFF_EVENTS "login_auth,login_start,logout"
#define USER_EVENTS "acct_mgmt"


#endif

#if defined(_AIX)
#define LOGON_LOGOFF_EVENTS "USER_SU,USER_Login,USER_Logout,PASSWORD_Change"
#define FILE_READ_EVENTS "FILE_Open(^[0]?$)"
#define FILE_WRITE_EVENTS "FILE_Open([2367]),FILE_Mknod,DEV_Create,DEV_Remove,FILE_Link,FILE_Unlink,FILE_Rename,FILE_Truncate,FILE_Symlink,FS_Mkdir,FS_Rmdir"
#define PROCESS_EVENTS "PROC_Execute,PROC_Delete,PROC_LPExecute,PROC_Kill"
#define FILE_ATTRIB_EVENTS "FILE_Owner,FILE_Mode,FILE_Fchmod,FILE_Fchown,FILE_Acl,FILE_Facl,FILE_Chpriv,FILE_Fchpriv"
#define ADMIN_EVENTS "USER_Change,USER_Remove,USER_Create,USER_SetGroups,GROUP_User,GROUP_Adms,GROUP_Change,GROUP_Create,GROUP_Remove,PASSWORD_Flags,USER_Reboot,PROC_Adjtime,FS_Mount,FS_Umount,AT_JobAdd,AT_JobRemove,CRON_JobAdd,CRON_JobRemove"



#endif

#if defined(__sun)
#define LOGON_LOGOFF_EVENTS "login,logout,telnet,rlogin,su,rexecd,passwd,rexd,ftpd,admin_authenticate,ssh"
#define FILE_READ_EVENTS "open_r,readlink"
#define FILE_WRITE_EVENTS "open_rc,open_rt,open_rtc,open_w,open_wc,open_wt,open_wtc,open_rw,open_rwc,open_rwt,open_rwtc,creat,mkdir,mknod,xmknod,link,symlink,rmdir,unlink,rename,truncate,ftruncate"
#define FILE_REMOVE_EVENTS "rmdir,unlink"
#define FILE_ATTRIB_EVENTS "chmod,fchmod,chown,fchown,mctl,fcntl,lchown,aclset,faclset"
#define PROCESS_EVENTS "exec,execve"
#define USER_EVENTS "setgroups,setpgrp,setuid,setgid,seteuid,setegid,setauid,setreuid,setregid,osetuid,osetpgrp"
#define SOCKET_EVENTS "connect,shutdown,setsockopt"



#endif

struct Reg_Audit_Objective {
	char str_critic[SIZE_OF_CRITICALITY];
	char str_event_type[SIZE_OF_EVENTLOG];
	char str_eventid_match[SIZE_OF_EVENTIDMATCH];
	char str_user_match[SIZE_OF_USERMATCH];
	char str_general_match[SIZE_OF_A_GENERALMATCH];
	char str_user_match_type[SIZE_OF_USER_MATCH_TYPE];
	char str_general_match_type[SIZE_OF_A_GENERAL_MATCH_TYPE];
};

struct Reg_Watch {
	char str_general_match[SIZE_OF_GENERALMATCH];
	char str_general_match_type[SIZE_OF_GENERAL_MATCH_TYPE];
	char str_new[SIZE_OF_GENERAL_MATCH_TYPE];
};

int Audit_Objective_Config(char *source, char *dest, int size);
int Audit_Objective_Display(char *source, char *dest, int size);
int Audit_Objective_Result(char *, char *, int);
int Watch_Config(char *source, char *dest, int size);
int Watch_Display(char *source, char *dest, int size);
int Watch_Result(char *, char *, int);


int Get_Next_Audit_Objective(FILE * configfile, struct Reg_Audit_Objective *objective);
int Get_Next_Watch(FILE * configfile, struct Reg_Watch *watch);
void stripPs(char* str);
void replaceEvents(char* event);
int Add_Audit_Objective_To_File(struct Reg_Audit_Objective objective_audit_struct, char *dest, int size, int end) ;
int Modify_Audit_Objective_In_File (struct Reg_Audit_Objective objective_audit_struct, int i_objective, char *dest, int size);
int Clear_Audit_Objectives_From_File(int i_objective,int i_type,char *dest, int size);
#endif				// _WEBPAGESAUDIT_H_
