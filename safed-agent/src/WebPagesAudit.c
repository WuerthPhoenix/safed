#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "Configuration.h"
#include "Misc.h"
#include "webserver.h"
#include "WebPages.h"
#include "WebPagesAudit.h"
#include "webutilities.h"
#include "MessageFile.h"
#include "Configuration.h"



int Audit_Objective_Config(char *source, char *dest, int size)
{
	struct Reg_Audit_Objective objective_audit_struct;
	int i_objective_count = 0;
	char str_obj_count[15];
	char str_user_match_metachar_remove[SIZE_OF_USERMATCH * 2];
	char str_eventid_match_metachar_remove[SIZE_OF_EVENTIDMATCH * 2];
	char str_general_match_metachar_remove[SIZE_OF_A_GENERALMATCH * 2];
	char strtmp[500] = "";

	FILE *configfile = (FILE *) NULL;

	if (!source || !dest || !size) {
		return(0);
	}

	strncpy(dest,"<form action=/safed/setobjective><H1><CENTER>SafedAgent Filtering Objectives Configuration</H1>",size);

	configfile = Find_First(AUDIT_CONFIG_OBJECTIVES);

	if (configfile) {
		strncat(dest,
			"<br>The following audit filtering objectives of the SafedAgent unit are active:<br><br>"
			"<table  width=100% border=1>", sizeof(dest) - strlen(dest) -1);

		strncat(dest,
			"<tr bgcolor=#F0F1F5><center><td><b>Action Required</b></td><td><b>Criticality</b></td>"
			"<td><b>Event ID Match</b></td>"
			"<td><b>User Any/Include/Exclude</b></td>"
			"<td><b>User Match</b></td>"
			"<td><b>General Match Any/Include/Exclude</b></td>"
			"<td><b>General Match</b></td>"
			"<td><b>Return</b></td>"
			"<td><b>Order</b></td>"
			"</center></tr>", size - strlen(dest) - 1);
		while (Get_Next_Audit_Objective(configfile, &objective_audit_struct)) {


			snprintf(str_obj_count, 15, "%d", i_objective_count);



			if ((i_objective_count) == 0)
				strncat(dest,
					"<tr bgcolor=#DEDBD2><td><input type=submit name=",
					sizeof(dest) - strlen(dest) -1);
			else{
				snprintf(strtmp, sizeof(strtmp), "<div align=center style=\"margin-bottom: 5px; border-left: 2px solid #eeeeee; border-top: 2px solid #eeeeee; border-right: 2px solid #aaaaaa; border-bottom: 2px solid #aaaaaa; background-color: #dddddd\"><a href=\"/safed/setobjective?%d=MoveDown\" style=\"font-size: 9px; color: #33aa33; text-decoration: none; display: block;\">&#9660;</a></div>",(i_objective_count-1));
				strncat(dest,strtmp,size - strlen(dest) - 1);
				strncat(dest, "</td></tr>", size - strlen(dest) - 1);
				if ((i_objective_count%2) == 0)
					strncat(dest,"<tr bgcolor=#E7E5DD><td><input type=submit name=",size - strlen(dest) - 1);
				else
					strncat(dest,"<tr bgcolor=#DEDBD2><td><input type=submit name=",size - strlen(dest) - 1);
			}

			strncat(dest,str_obj_count, size - strlen(dest) - 1);
			strncat(dest," value=Delete>     ",size - strlen(dest) - 1);

			strncat(dest,"<input type=submit name=",size - strlen(dest) - 1);
			strncat(dest,str_obj_count, size - strlen(dest) - 1);
			strncat(dest," value=Modify>", size - strlen(dest) - 1);
			strncat(dest,"</td><td>", size - strlen(dest) - 1);

			strncat(dest, objective_audit_struct.str_critic,
				size - strlen(dest) - 1);
			strncat(dest, "</td><td>", size - strlen(dest) - 1);

			// Debracket the strings in here. For HTML display purposes, the HTML metacharacters
			// need to be replaced. This is done with the "debracket" routine.
			// Note that the new strings are allowed to be twice as long as the real strings
			debracket(objective_audit_struct.str_user_match,
				  str_user_match_metachar_remove,
				  SIZE_OF_USERMATCH * 2);
			debracket(objective_audit_struct.str_eventid_match,
				  str_eventid_match_metachar_remove,
				  SIZE_OF_EVENTIDMATCH * 2);
			debracket(objective_audit_struct.str_general_match,
				  str_general_match_metachar_remove,
				  SIZE_OF_A_GENERALMATCH * 2);

			if (strlen(objective_audit_struct.str_eventid_match) == 0) {
				strncat(dest, "&nbsp", sizeof(dest) - strlen(dest) -1);
			} else {
				strncat(dest, str_eventid_match_metachar_remove,
					size - strlen(dest) - 1);
			}
			strncat(dest, "</td><td>      ", size - strlen(dest) - 1);

			strncat(dest, objective_audit_struct.str_user_match_type, size - strlen(dest) - 1);
			strncat(dest, "</td><td>", size - strlen(dest) - 1);
			if (strlen(objective_audit_struct.str_user_match) == 0) {
				strncat(dest, "&nbsp", size - strlen(dest) - 1);
			} else {
				strncat(dest, str_user_match_metachar_remove,
					sizeof(dest) - strlen(dest) -1);
			}
			strncat(dest, "</td><td>", size - strlen(dest) - 1);

			strncat(dest, objective_audit_struct.str_general_match_type, sizeof(dest) - strlen(dest) -1);
			strncat(dest, "</td><td>", sizeof(dest) - strlen(dest) -1);
			if (strlen(objective_audit_struct.str_general_match) == 0) {
				strncat(dest,"&nbsp",sizeof(dest) - strlen(dest) -1);
			} else {
				strncat(dest,str_general_match_metachar_remove,sizeof(dest) - strlen(dest) -1);
			}
			strncat(dest, "</td><td>", sizeof(dest) - strlen(dest) -1);

			strncat(dest, objective_audit_struct.str_event_type, sizeof(dest) - strlen(dest) -1);
			strncat(dest, "</td>", sizeof(dest) - strlen(dest) -1);
			if (i_objective_count > 0){
				snprintf(strtmp, sizeof(strtmp), "<td><div align=center style=\"margin-bottom: 5px; border-left: 2px solid #eeeeee; border-top: 2px solid #eeeeee; border-right: 2px solid #aaaaaa; border-bottom: 2px solid #aaaaaa; background-color: #dddddd\"><a href=\"/safed/setobjective?%d=MoveUp\" style=\"font-size: 9px; color: #33aa33; text-decoration: none; display: block;\">&#9650;</a></div>",i_objective_count);
				strncat(dest,strtmp,sizeof(dest) - strlen(dest) -1);



			}else
				strncat(dest,"<td>",sizeof(dest) - strlen(dest) -1);
			i_objective_count++;
		}
		strncat(dest, "</td></tr>", sizeof(dest) - strlen(dest) -1);
		Close_File(configfile);
		strncat(dest,"</table><br>",sizeof(dest) - strlen(dest) -1);
	} else {
		strncat(dest,"<br>There are no current filtering objectives active.<br><br>",sizeof(dest) - strlen(dest) -1);
	}

	strncat(dest,"Select this button to add a new objective.  ",sizeof(dest) - strlen(dest) -1);
	strncat(dest,"<input type=submit name=0",sizeof(dest) - strlen(dest) -1);
	strncat(dest," value=Add>",sizeof(dest) - strlen(dest) -1);
	return(0);
}


 int Audit_Objective_Display(char *source, char *dest, int size)
 {
 	struct Reg_Audit_Objective objective_audit_struct;
 	int dw_objective_error = 0, dw_objective_delete_error = 0;
 	char str_objerr[10];
 	int i_set = 0, i_objective_count = 0, i_type = 0, isany = 0;
 	char *psource=source, Variable[100], Argument[100];
 	char str_temp[20], str_temp_objective[10];

 	//This function will display an existing, or a blank, objective
 	strncpy(dest,"<form action=/safed/changeobjective><h1><center>SafedAgent Filtering Objective Configuration</h1>",size);

 	//Determine whether the objective will be modified or deleted
 	while ((psource = getNextArgument(psource, Variable, sizeof (Variable), Argument,	sizeof (Argument))) != (char *) NULL) {

 		if (strstr(Argument, "Delete") != NULL) {
 		 	sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp, str_temp_objective);
 			i_type = 0;
 			break;
 		}
 		if (strstr(Argument, "Modify") != NULL) {
 			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp, str_temp_objective);
 			i_type = 1;
 			break;
 		}
		if (strstr(Argument, "MoveUp") != NULL) {
			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp, str_temp_objective);
			i_type = -2;
			break;
		}
		if (strstr(Argument, "MoveDown") != NULL) {
			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp, str_temp_objective);
			i_type = -1;
			break;
		}
 		if (strstr(Argument, "Add") != NULL) {
			strncpy(str_temp_objective, "-2",
				sizeof (str_temp_objective));
 			i_type = 2;
 			break;
 		}
 	}

 	//Extract the objective number. I have to do this stuff, because atoi returns 0 if it cannot convert the string
 	if (strcmp(str_temp_objective,"0") == 0)
 		i_objective_count = -1;
 	else
 		i_objective_count = atoi(str_temp_objective);

 	//If the objective number could not be successfully extracted, return immediately.
 	if (i_objective_count == 0) {
 		strncat(dest,"<br><b>NOTE: It appears the URL is encoded incorrectly.",sizeof(dest) - strlen(dest) -1);
 		return 0;
 	}

 	if (i_objective_count == -1)
 		i_objective_count = 0;

 	//If the objective is being modified or added
 	if (i_type > 0) {
 		if (i_type == 1) {
 			int count = 0;
 			int returncode;
 			FILE *configfile;
 			configfile = Find_First(AUDIT_CONFIG_OBJECTIVES);
 			while ((returncode = Get_Next_Audit_Objective(configfile, &objective_audit_struct)))
 			{
 				if (count == i_objective_count)
 					break;
 				count++;
 			}
 			if (!(count == i_objective_count && returncode)) {
 				dw_objective_error = WEB_READ_OBJECTIVE_ERROR_CODE;
 			}
 			Close_File(configfile);
 		} else {
 			// Defaults
 			strncpy(objective_audit_struct.str_event_type, ALL_TOKEN,
 				sizeof (objective_audit_struct.str_event_type));
 			strncpy(objective_audit_struct.str_critic, CRITICAL_TOKEN,
 				sizeof (objective_audit_struct.str_critic));
 			strncpy(objective_audit_struct.str_eventid_match, LOGONOFF_TOKEN,
 				sizeof (objective_audit_struct.str_eventid_match));
 			strncpy(objective_audit_struct.str_general_match, ".*",
 				sizeof (objective_audit_struct.str_general_match));
 			strncpy(objective_audit_struct.str_general_match_type, "Any",
 				sizeof (objective_audit_struct.str_general_match_type));
 			strncpy(objective_audit_struct.str_user_match_type, "Any",
 				sizeof (objective_audit_struct.str_user_match_type));
 			strncpy(objective_audit_struct.str_user_match, ".*",
 				sizeof (objective_audit_struct.str_user_match));
 		}

 		// Will display an error if unable to completely read from the config file
 		if (dw_objective_error > 0) {
 			dw_objective_error += WEB_READ_OBJECTIVE_ERROR_CODE;
 			snprintf(str_objerr, 10, "%d", dw_objective_error);

 			strncat(dest,
 				"<br><b>NOTE: Some errors were encountered in reading the configuration file. Default values "
 				"may be used.<br> Report error: ",
 				sizeof(dest) - strlen(dest) -1);
 			strncat(dest, str_objerr, sizeof(dest) - strlen(dest) -1);
 			strncat(dest, "</b><br>", sizeof(dest) - strlen(dest) -1);
 		}

 		strncat(dest,
 			"<br>The following parameters of the SafedAgent objective may be set:<br><br>"
 			"<table  width=100% border=0>", sizeof(dest) - strlen(dest) -1);

 		// Identify the high level event. Note that there is a table within a table in these radio buttons.
 		i_set = 0;
 		isany = 0;

 		strncat(dest,"<tr bgcolor=#E7E5DD><td>Identify the high level event</td><td><table  width=100% border=0><tr>",	sizeof(dest) - strlen(dest) -1);

 #if defined(__linux__)
 		strncat(dest,"<td><input type=radio name=str_eventid_match value=",	sizeof(dest) - strlen(dest) -1);
 		strncat(dest, LOGONOFF_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, LOGONOFF_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">User Logon or Logoff  </td><td><input type=radio name=str_eventid_match value=",	sizeof(dest) - strlen(dest) -1);
 		strncat(dest, OPEN_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, OPEN_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Open a file/dir for reading/writing  </td></tr><tr><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, FILE_REMOVE_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, FILE_REMOVE_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Remove file or directory  </td><td><input type=radio name=str_eventid_match value=",	sizeof(dest) - strlen(dest) -1);
 		strncat(dest, FILE_ATTRIB_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, FILE_ATTRIB_TOKEN ) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Modify system, file or directory attributes  </td></tr><tr><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, PROCESS_TOKEN , sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, PROCESS_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Start or stop program execution  </td><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, SOCKET_TOKEN , sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, SOCKET_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Network socketcall events  </td></tr><tr><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, USER_TOKEN , sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, USER_TOKEN)  == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Account administration avents  </td><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, ADMIN_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, ADMIN_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Administrative Events   </td></tr><tr><td>&nbsp;</td><td><input type=radio name=str_eventid_match value=Any_Event",sizeof(dest) - strlen(dest) -1);
 #endif
 #if defined(__sun)

		strncat(dest,"<td><input type=radio name=str_eventid_match value=",	sizeof(dest) - strlen(dest) -1);
 		strncat(dest, LOGONOFF_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, LOGONOFF_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">User Logon or Logoff  </td><td><input type=radio name=str_eventid_match value=",	sizeof(dest) - strlen(dest) -1);
 		strncat(dest, FILE_READ_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, FILE_READ_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Open a file/dir for reading only  </td></tr><tr><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, FILE_WRITE_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, FILE_WRITE_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Open a file/dir for writing only  </td><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, FILE_REMOVE_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, FILE_REMOVE_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Remove file or directory  </td></tr><tr><td><input type=radio name=str_eventid_match value=",	sizeof(dest) - strlen(dest) -1);
 		strncat(dest, FILE_ATTRIB_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, FILE_ATTRIB_TOKEN ) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Modify system, file or directory attributes  </td><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, PROCESS_TOKEN , sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, PROCESS_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Start or stop program execution  </td></tr><tr><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, SOCKET_TOKEN , sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, SOCKET_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Network socketcall events  </td><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, USER_TOKEN , sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, USER_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Account administration avents   </td></tr><tr><td>&nbsp;</td><td><input type=radio name=str_eventid_match value=Any_Event",sizeof(dest) - strlen(dest) -1);
 #endif
 #if defined(_AIX)


		strncat(dest,"<td><input type=radio name=str_eventid_match value=",	sizeof(dest) - strlen(dest) -1);
 		strncat(dest, LOGONOFF_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, LOGONOFF_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">User Logon or Logoff  </td><td><input type=radio name=str_eventid_match value=",	sizeof(dest) - strlen(dest) -1);
 		strncat(dest, FILE_READ_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, FILE_READ_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Open a file/dir for reading only  </td></tr><tr><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, FILE_WRITE_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, FILE_WRITE_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Open a file/dir for writing only  </td><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, FILE_ATTRIB_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, FILE_ATTRIB_TOKEN ) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Modify system, file or directory attributes  </td></tr><tr><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
 		strncat(dest, PROCESS_TOKEN , sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, PROCESS_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Start or stop program execution  </td><td><input type=radio name=str_eventid_match value=",sizeof(dest) - strlen(dest) -1);
  		strncat(dest, ADMIN_TOKEN , sizeof(dest) - strlen(dest) -1);
 		if (strcmp(objective_audit_struct.str_eventid_match, ADMIN_TOKEN) == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,">Administrative Events   </td></tr><tr><td>&nbsp;</td><td><input type=radio name=str_eventid_match value=Any_Event",sizeof(dest) - strlen(dest) -1);
 #endif

 		if (i_set == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 			isany = 1;
 		}
 		strncat(dest,
 			">Any event(s) </td></tr></table></td></tr>",
 			sizeof(dest) - strlen(dest) -1);

 		strncat(dest,
 			"<tr bgcolor=#DEDBD><td>Event ID Search Term<br><i>Optional, Comma separated: only used by the 'Any Event' setting above </i></td><td><input type=text name=str_eventid_text size=50 value=\"",
 			sizeof(dest) - strlen(dest) -1);
 		if(isany)
 			strncat(dest, objective_audit_struct.str_eventid_match,	sizeof(dest) - strlen(dest) -1);
 		strncat(dest, "\"></td></tr>", sizeof(dest) - strlen(dest) -1);

 		strncat(dest,
 			"<tr bgcolor=#E7E5DD><td>Select the General Match Type</td><td>",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest,
 			"<input type=radio name=str_general_match_type value=Any",
 			sizeof(dest) - strlen(dest) -1);

 		if (strcmp(objective_audit_struct.str_general_match_type, "Any") == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			strncpy(objective_audit_struct.str_general_match_type, "Any", sizeof(objective_audit_struct.str_general_match_type));
 		}
 		strncat(dest, ">Match Any Event    ", sizeof(dest) - strlen(dest) -1);
 		strncat(dest,
 			"<input type=radio name=str_general_match_type value=Include",
 			sizeof(dest) - strlen(dest) -1);
 		if (strstr(objective_audit_struct.str_general_match_type, "Include") !=
 		    NULL) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 		}
 		strncat(dest,
 			">Include    <input type=radio name=str_general_match_type value=Exclude",
 			sizeof(dest) - strlen(dest) -1);

 		if (strstr(objective_audit_struct.str_general_match_type, "Exclude") !=
 		    NULL)
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 		strncat(dest, ">Exclude    </td></tr>", sizeof(dest) - strlen(dest) -1);

 		strncat(dest,
 			"<tr bgcolor=#DEDBD><td>General Search Term<br><a href=\"http://en.wikipedia.org/wiki/Regular_expression\"><i>Regular expressions accepted</i></a></td><td><input type=text name=str_general_match size=50 value=\"",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, objective_audit_struct.str_general_match,
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, "\"></td></tr>", sizeof(dest) - strlen(dest) -1);

 		strncat(dest,
 			"<tr bgcolor=#E7E5DD><td>Select the User Match Type</td><td>",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest,
 			"<input type=radio name=str_user_match_type value=Any",
 			sizeof(dest) - strlen(dest) -1);

 		if (strcmp(objective_audit_struct.str_user_match_type, "Any") == 0) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			strncpy(objective_audit_struct.str_user_match_type, "Any", sizeof(objective_audit_struct.str_user_match_type));
 		}
 		strncat(dest, ">Match Any User    ", sizeof(dest) - strlen(dest) -1);
 		strncat(dest,
 			"<input type=radio name=str_user_match_type value=Include",
 			sizeof(dest) - strlen(dest) -1);
 		if (strstr(objective_audit_struct.str_user_match_type, "Include") !=
 		    NULL) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 		}
 		strncat(dest,
 			">Include    <input type=radio name=str_user_match_type value=Exclude",
 			sizeof(dest) - strlen(dest) -1);

 		if (strstr(objective_audit_struct.str_user_match_type, "Exclude") !=
 		    NULL)
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 		strncat(dest, ">Exclude    </td></tr>", sizeof(dest) - strlen(dest) -1);

 		strncat(dest,
 			"<tr bgcolor=#DEDBD><td>User Search Term<br><i>(comma separated user list)</i> </td><td><input type=text name=str_user_match size=50 value=\"",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, objective_audit_struct.str_user_match,
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, "\"></td></tr>", sizeof(dest) - strlen(dest) -1);

 		// Identify the event type to capture. Note that there is a table within a table in these radio buttons.
 		i_set = 0;

 		strncat(dest,
 			"<tr bgcolor=#E7E5DD><td>Identify the event types to be captured</td><td><table  width=100% border=0><tr>",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest,
 			"<td><input type=checkbox name=str_event_type_succ value=",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, SUCCESS_TOKEN, sizeof(dest) - strlen(dest) -1);

 		if (!strcmp(objective_audit_struct.str_event_type, SUCCESS_TOKEN)
 		    || !strcmp(objective_audit_struct.str_event_type, ALL_TOKEN)) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest,
 			">Success Audit  </td><td><input type=checkbox name=str_event_type_fail value=",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, FAILURE_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (!strcmp(objective_audit_struct.str_event_type, FAILURE_TOKEN)
 		    || !strcmp(objective_audit_struct.str_event_type, ALL_TOKEN)) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 			i_set = 1;
 		}
 		strncat(dest, ">Failure Audit  </td></tr>",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, "</table></td></tr>", sizeof(dest) - strlen(dest) -1);

 		// Identify the log type to capture. Note that there is a table within a table in these radio buttons.
 		i_set = 0;

 		strncat(dest,
 			"<tr bgcolor=#DEDBD><td>Select the Alert Level</td><td>",
 			sizeof(dest) - strlen(dest) -1);

 		// Determine the criticality level
 		strncat(dest, "<input type=radio name=str_critic value=",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, CRITICAL_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strstr(objective_audit_struct.str_critic, CRITICAL_TOKEN) != NULL)
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 		strncat(dest,
 			">Critical    <input type=radio name=str_critic value=",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, PRIORITY_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strstr(objective_audit_struct.str_critic, PRIORITY_TOKEN) != NULL)
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 		strncat(dest,
 			">Priority    <input type=radio name=str_critic value=",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, WARNING_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strstr(objective_audit_struct.str_critic, WARNING_TOKEN) != NULL)
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 		strncat(dest,
 			">Warning    <input type=radio name=str_critic value=",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, INFORMATION_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strstr(objective_audit_struct.str_critic, INFORMATION_TOKEN) != NULL)
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 		strncat(dest,
 			">Information    <input type=radio name=str_critic value=",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, CLEAR_TOKEN, sizeof(dest) - strlen(dest) -1);
 		if (strstr(objective_audit_struct.str_critic, CLEAR_TOKEN) != NULL)
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 		strncat(dest, ">Clear    </td></tr>", sizeof(dest) - strlen(dest) -1);

 		strncat(dest, "</table><br>", sizeof(dest) - strlen(dest) -1);
 		strncat(dest, "<input type=hidden name=objnumber value=",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, str_temp_objective, sizeof(dest) - strlen(dest) -1);	// Objective number goes here
 		strncat(dest,
 			"><input type=submit value=\"Change Configuration\">    ",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, "<input type=reset value=\"Reset Form\"></form>",
 			sizeof(dest) - strlen(dest) -1);
 	} else {

 		dw_objective_delete_error = Clear_Audit_Objectives_From_File(i_objective_count,i_type,dest, size);
		if (dw_objective_delete_error == 0){
			strncpy(source,"/safed/objective", 10);
			Audit_Objective_Config(source,dest,size);

		}else
			strncat(dest,
				"<br>The objective was unable to be deleted.",
				sizeof(dest) - strlen(dest) -1);

 	}

 	return (0);
 }

 int Audit_Objective_Result(char *source, char *dest, int size)
 {
 	// All strncpy or strncat functions in this routine have been designed avoid overflows
 	struct Reg_Audit_Objective objective_admin_struct;
 	int dw_objective_error = 0;
 	int i_objective = 0, i_event_type_set = 0;
 	char str_eventid_radio[50], str_eventid_text[SIZE_OF_EVENTIDMATCH];
 	char *psource=source, Variable[100]="", Argument[512]="";
 	char emsg[8320] = "";

 	strncpy(dest,"<H1><CENTER>SafedAgent Filtering Objectives Configuration</CENTER></H1>",size);

 	strncpy(objective_admin_struct.str_event_type, "",
 		sizeof (objective_admin_struct.str_event_type));

 	while ((psource =
 		getNextArgument(psource, Variable, sizeof (Variable), Argument,
 				sizeof (Argument))) != (char *) NULL) {
 		if (strstr(Variable, "str_user_match") != NULL) {
 			strncpy(objective_admin_struct.str_user_match, Argument,
 				sizeof (objective_admin_struct.str_user_match));
 		}

 		if (strstr(Variable, "str_general_match") != NULL) {
 			strncpy(objective_admin_struct.str_general_match, Argument,
 				sizeof (objective_admin_struct.str_general_match));
 		}

 		if (strstr(Variable, "str_event_type_succ") != NULL) {
 			if (i_event_type_set == 1) {
  				strncpy(objective_admin_struct.str_event_type, ALL_TOKEN,
 					sizeof (objective_admin_struct.str_event_type));
 			} else {
 				strncat(objective_admin_struct.str_event_type,
 					SUCCESS_TOKEN,
 					sizeof (objective_admin_struct.str_event_type) -
 					strlen(objective_admin_struct.str_event_type));
 			}
 			i_event_type_set = 1;
 		}

 		if (strstr(Variable, "str_event_type_fail") != NULL) {
 			if (i_event_type_set == 1) {
 				// A token has already been added
 				// Turn on both success and failure
 				strncpy(objective_admin_struct.str_event_type, ALL_TOKEN,
 					sizeof (objective_admin_struct.str_event_type));
 			} else {
 				strncat(objective_admin_struct.str_event_type,
 					FAILURE_TOKEN,
 					sizeof (objective_admin_struct.str_event_type) -
 					strlen(objective_admin_struct.str_event_type));
 			}
 			i_event_type_set = 1;
 		}

 		if (strstr(Variable, "str_eventid_match") != NULL) {
 			strncpy(str_eventid_radio, Argument,
 				sizeof (str_eventid_radio));
 		}
 		if (strstr(Variable, "str_eventid_text") != NULL) {
 			strncpy(str_eventid_text, Argument,
 				sizeof (str_eventid_text));
 		}
 		if (strstr(Variable, "objnumber") != NULL) {
 			i_objective = atoi(Argument);
 		}
 		if (strstr(Variable, "str_critic") != NULL) {
 			strncpy(objective_admin_struct.str_critic, Argument,
 				sizeof (objective_admin_struct.str_critic));
 		}
 		if (strstr(Variable, "str_user_match_type") != NULL) {
 			strncpy(objective_admin_struct.str_user_match_type, Argument,
 				sizeof (objective_admin_struct.str_user_match_type));
 		}
 		if (strstr(Variable, "str_general_match_type") != NULL) {
 			strncpy(objective_admin_struct.str_general_match_type, Argument,
 				sizeof (objective_admin_struct.str_general_match_type));
 		}
 	}

 	if (!i_event_type_set) {
 		strncat(objective_admin_struct.str_event_type,
 			ALL_TOKEN,
 			sizeof (objective_admin_struct.str_event_type) -
 			strlen(objective_admin_struct.str_event_type));
 		strncat(dest,
 			"<br>Either Success or Failure (or both) must be specified. I have defaulted this objective to BOTH.<p>",
 			sizeof(dest) - strlen(dest) -1);
 	}

 	if (strstr(str_eventid_radio, "Any_Event") != NULL) {
 		strncpy(objective_admin_struct.str_eventid_match, str_eventid_text,
 			sizeof (objective_admin_struct.str_eventid_match));
 	} else {
#if defined(__linux__)
 		if (strstr(str_eventid_radio, LOGONOFF_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				LOGON_LOGOFF_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, FILE_ATTRIB_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				FILE_ATTRIB_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, FILE_REMOVE_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				FILE_REMOVE_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, PROCESS_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				PROCESS_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, ADMIN_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				ADMIN_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, OPEN_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				OPEN_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, SOCKET_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				SOCKET_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, USER_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				USER_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else {
			strncpy(objective_admin_struct.str_eventid_match,
				str_eventid_radio,
				sizeof(objective_admin_struct.str_eventid_match));
		}
#endif
#if defined(__sun)
 		if (strstr(str_eventid_radio, LOGONOFF_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				LOGON_LOGOFF_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, FILE_READ_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				FILE_READ_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, FILE_WRITE_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				FILE_WRITE_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, FILE_ATTRIB_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				FILE_ATTRIB_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, PROCESS_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				PROCESS_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, FILE_REMOVE_EVENTS ) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				FILE_REMOVE_TOKEN,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, SOCKET_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				SOCKET_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, USER_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				USER_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		}else {
			strncpy(objective_admin_struct.str_eventid_match,
				str_eventid_radio,
				sizeof(objective_admin_struct.str_eventid_match));
		}
#endif
#if defined(_AIX)
 		if (strstr(str_eventid_radio, LOGONOFF_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				LOGON_LOGOFF_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, FILE_READ_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				FILE_READ_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, FILE_WRITE_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				FILE_WRITE_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, FILE_ATTRIB_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				FILE_ATTRIB_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, PROCESS_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				PROCESS_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		} else if (strstr(str_eventid_radio, ADMIN_TOKEN) != NULL) {
 			strncpy(objective_admin_struct.str_eventid_match,
 				ADMIN_EVENTS,
 				sizeof(objective_admin_struct.str_eventid_match));
 		}else {
			strncpy(objective_admin_struct.str_eventid_match,
				str_eventid_radio,
				sizeof(objective_admin_struct.str_eventid_match));
		}
#endif

 	}

#if defined(__sun) || defined(_AIX)
	regex_t regexpCompiled;
	int errorCode = regcomp(&regexpCompiled, objective_admin_struct.str_general_match, REG_EXTENDED | REG_NOSUB);
	if (errorCode != 0) {
		char errorMsg[8192];
		regerror(errorCode, &regexpCompiled, errorMsg, 8192);
		sprintf(emsg, "<br>Error compiling the regular expression: %s<br> Error code = %d<br> Error message = %s<br>", objective_admin_struct.str_general_match, errorCode, errorMsg);
		dw_objective_error = WEB_READ_CONFIG_ERROR_CODE;
	}
#endif

 	if (!dw_objective_error) {

 		//-2 = "Add a new objective"
 		if (i_objective == -2) {
 			dw_objective_error = Add_Audit_Objective_To_File(objective_admin_struct,dest,size, 0);
 		} else {
 			// Modify an existing objective
 			dw_objective_error = Modify_Audit_Objective_In_File(objective_admin_struct,i_objective,dest,size);
 		}
 	}

	if (dw_objective_error == 0){
		strncpy(source,"/safed/objective", 10);
		Audit_Objective_Config(source,dest,size);
	}else{
		strncat(dest,
			"<br>The objective was unable to be modified/added.",
			sizeof(dest) - strlen(dest) -1);
		if(strlen(emsg))
			strncat(dest,emsg,sizeof(dest) - strlen(dest) -1);
	}
 	return(0);
 }


 int Clear_Audit_Objectives_From_File(int i_objective_count,int i_type,char *dest, int size){
		void *rampointer = (void *) NULL;
		char *position;
		char inputbuffer[MAX_AUDIT_CONFIG_LINE];
		char inputbuffer_swap[2*MAX_AUDIT_CONFIG_LINE + 2];
		int headertype = 0;
		FILE *configfile;
	 	int dw_objective_delete_error = 0;


		rampointer = Load_Config_File();
		if (!rampointer) {
			dw_objective_delete_error = 1;
		} else {
			int objectivecounter = 0;
			int currentsize = 0;

			position = (char *) rampointer;

			configfile = fopen(CONFIG_FILENAME, "w");
			if (!configfile) {
				strncat(dest,
					"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
					sizeof(dest) - strlen(dest) -1);
				Clear_Config_File(rampointer);
				return (dw_objective_delete_error);
			}

			while ((currentsize =
				Grab_RAMConfig_Line(position, inputbuffer,
						    MAX_AUDIT_CONFIG_LINE))) {
				trim(inputbuffer);

				if (headertype == AUDIT_CONFIG_OBJECTIVES) {
					if(i_type == -2){
						if (objectivecounter ==  (i_objective_count - 1)){
							strcpy(inputbuffer_swap,inputbuffer);
							position += currentsize;
							objectivecounter++;
							continue;
						}else if (objectivecounter ==  i_objective_count){
							strcat(inputbuffer,"\n\t");
							strcat(inputbuffer,inputbuffer_swap);
						}
					}
					if(i_type == -1){
						if (objectivecounter ==  i_objective_count){
							strcpy(inputbuffer_swap,inputbuffer);
							position += currentsize;
							objectivecounter++;
							continue;
						}else if (objectivecounter ==  (i_objective_count + 1)){
							strcat(inputbuffer,"\n\t");
							strcat(inputbuffer,inputbuffer_swap);
						}
					}
					if(i_type == 0){
						if (objectivecounter ==
							i_objective_count) {
							// Do not add this line back into the original file.
							position += currentsize;
							objectivecounter++;
							continue;
						}
					}
					objectivecounter++;
				}

				if (!iscomment(inputbuffer)) {
					// Is this line a header?
					if (isheader(inputbuffer)) {
						headertype =
						    getheader(inputbuffer);
					}
				}
				// Print this line to file.
				if (isheader(inputbuffer)
				    || iscomment(inputbuffer)
				    || !strlen(inputbuffer)) {
					fprintf(configfile, "%s\n",
						inputbuffer);
				} else {
					fprintf(configfile, "	%s\n",
						inputbuffer);
				}

				// position+=strlen(inputbuffer)+1;
				position += currentsize;
			}
			if (fclose(configfile)) {
				dw_objective_delete_error = 1;
				strncat(dest,
					"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
					sizeof(dest) - strlen(dest) -1);
				Clear_Config_File(rampointer);
				return (dw_objective_delete_error);
			}

			Clear_Config_File(rampointer);
		}
		return(dw_objective_delete_error);

 }


 int Modify_Audit_Objective_In_File (struct Reg_Audit_Objective objective_audit_struct, int i_objective, char *dest, int size) {
 	void *rampointer = (void *) NULL;
 	char *position;
 	char inputbuffer[MAX_AUDIT_CONFIG_LINE];
 	int headertype = 0;
 	int dw_objective_error = 0;
 	FILE *configfile;

 	rampointer = Load_Config_File();
 	if (!rampointer) {
 		dw_objective_error = WEB_READ_CONFIG_ERROR_CODE;
 	} else {
 		int objectivecounter = 0;
 		int currentsize = 0;

 		position = (char *) rampointer;

 		configfile = fopen(CONFIG_FILENAME, "w");
 		if (!configfile) {
 			dw_objective_error = 1;
 			strncat(dest,
 				"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
 				sizeof(dest) - strlen(dest) -1);
 			Clear_Config_File(rampointer);
 			return (dw_objective_error);
 		}

 		while ((currentsize =
 			Grab_RAMConfig_Line(position,
 					    inputbuffer,
 					    MAX_AUDIT_CONFIG_LINE)))
 		{
 			trim(inputbuffer);

 			if (headertype == AUDIT_CONFIG_OBJECTIVES) {
 				if (objectivecounter ==
 				    i_objective) {
 					// Replace this objective with the new version.
 					int critic = 0;
 					char userstring[8]="";
 					char generalstring[8]="";
 					// WRITE OUT NEW OBJECTIVE HERE
 					if (strstr
 					    (objective_audit_struct.
 					     str_critic,
 					     CRITICAL_TOKEN)) {
 						critic =
 						    CRITICALITY_CRITICAL;
 					} else
 					    if (strstr
 						(objective_audit_struct.
 						 str_critic,
 						 PRIORITY_TOKEN))
 					{
 						critic =
 						    CRITICALITY_PRIORITY;
 					} else
 					    if (strstr
 						(objective_audit_struct.
 						 str_critic,
 						 WARNING_TOKEN))
 					{
 						critic =
 						    CRITICALITY_WARNING;
 					} else
 					    if (strstr
 						(objective_audit_struct.
 						 str_critic,
 						 INFORMATION_TOKEN))
 					{
 						critic =
 						    CRITICALITY_INFO;
 					} else {
 						critic =
 						    CRITICALITY_CLEAR;
 					}


 					if (strstr(objective_audit_struct.str_general_match_type,"Any") != NULL) {
 						strncpy(generalstring, "match", sizeof(generalstring));
 						strncpy(objective_audit_struct.str_general_match,"*",sizeof(objective_audit_struct.str_general_match));
 					} else {
 						if (strstr(objective_audit_struct.str_general_match_type,"Include") != NULL) {
 							strncpy(generalstring, "match", sizeof(generalstring));
 						} else {
 							strncpy(generalstring, "match!", sizeof(generalstring));
 						}
 					}


 					if (strstr(objective_audit_struct.str_user_match_type,"Any") != NULL) {
 						strncpy(userstring, "user", sizeof(userstring));
 						strncpy(objective_audit_struct.str_user_match,"*",sizeof(objective_audit_struct.str_user_match));
 					} else {
  						if (strstr(objective_audit_struct.str_user_match_type,"Include") != NULL) {
 							strncpy(userstring, "user", sizeof(userstring));
 						} else {
 							strncpy(userstring, "user!", sizeof(userstring));
 						}
 					}

 					if (strstr(objective_audit_struct.str_event_type,ALL_TOKEN) != NULL) {
 						strncpy(objective_audit_struct.str_event_type,"*",sizeof(objective_audit_struct.str_event_type));
 					}

 					fprintf(configfile,
 							"	criticality=%d	event=(%s)	return=(%s)	%s=(%s)	%s=(%s)\n",
 						critic,
 						objective_audit_struct.str_eventid_match,
 						objective_audit_struct.str_event_type,
 						userstring,
 						objective_audit_struct.str_user_match,
 						generalstring,
 						objective_audit_struct.str_general_match);

 					position += currentsize;
 					objectivecounter++;
 					continue;
 				}
 				objectivecounter++;
 			}

 			if (!iscomment(inputbuffer)) {
 				// Is this line a header?
 				if (isheader(inputbuffer)) {
 					headertype =
 					    getheader
 					    (inputbuffer);
 				}
 			}
 			// Print this line to file.
 			if (isheader(inputbuffer)
 			    || iscomment(inputbuffer)
 			    || !strlen(inputbuffer)) {
 				fprintf(configfile, "%s\n",
 					inputbuffer);
 			} else {
 				fprintf(configfile, "	%s\n",
 					inputbuffer);
 			}

 			// position+=strlen(inputbuffer)+1;
 			position += currentsize;
 		}

 		if (fclose(configfile)) {
 			dw_objective_error = 1;
 			strncat(dest,
 				"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
 				sizeof(dest) - strlen(dest) -1);
 			Clear_Config_File(rampointer);
 			return (dw_objective_error);
 		}

 		Clear_Config_File(rampointer);
 	}
 	return (dw_objective_error);
 }

 int Add_Audit_Objective_To_File(struct Reg_Audit_Objective objective_audit_struct, char *dest, int size, int end) {
 	void *rampointer = (void *) NULL;
 	char *position;
 	char inputbuffer[MAX_AUDIT_CONFIG_LINE];
 	int headertype = 0;
 	int oldheadertype = 0;
 	int dw_objective_error = 0;
 	FILE *configfile;

 	rampointer = Load_Config_File();
 	if (!rampointer) {
 		dw_objective_error = WEB_READ_CONFIG_ERROR_CODE;
 	} else {
 		int currentsize = 0;
 		int wroteconfig = 0;

 		position = (char *) rampointer;

 		configfile = fopen(CONFIG_FILENAME, "w");
 		if (!configfile) {
 			dw_objective_error = 1;
 			strncat(dest,
 				"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
 				sizeof(dest) - strlen(dest) -1);
 			Clear_Config_File(rampointer);
 			return (dw_objective_error);
 		}

 		while ((currentsize =
 			Grab_RAMConfig_Line(position, inputbuffer, MAX_AUDIT_CONFIG_LINE)))
 		{
 			trim(inputbuffer);
 			// Is this line a header?
 			if (isheader(inputbuffer)) {
 				if (!end || headertype != AUDIT_CONFIG_OBJECTIVES) fprintf(configfile, "%s\n", inputbuffer);
 				oldheadertype = headertype;
 				headertype = getheader(inputbuffer);
 				if ((!end && headertype == AUDIT_CONFIG_OBJECTIVES) || (end && oldheadertype == AUDIT_CONFIG_OBJECTIVES)) {
 					int critic = 0;
 					char userstring[8]="";
 					char generalstring[8]="";
 					// WRITE OUT NEW OBJECTIVE HERE
 					if (strstr(objective_audit_struct.str_critic,CRITICAL_TOKEN)) {
 						critic = CRITICALITY_CRITICAL;
 					} else
 					    if (strstr(objective_audit_struct.str_critic, PRIORITY_TOKEN)) {
 						critic = CRITICALITY_PRIORITY;
 					} else
 					    if (strstr(objective_audit_struct.str_critic, WARNING_TOKEN)) {
 						critic = CRITICALITY_WARNING;
 					} else
 					    if (strstr(objective_audit_struct.str_critic, INFORMATION_TOKEN)) {
 						critic = CRITICALITY_INFO;
 					} else {
 						critic = CRITICALITY_CLEAR;
 					}


 					if (strstr(objective_audit_struct.str_general_match_type,"Any") != NULL) {
 						strncpy(generalstring, "match", sizeof(generalstring));
 						strncpy(objective_audit_struct.str_general_match,"*",sizeof(objective_audit_struct.str_general_match));
 					} else {
 						if (strstr(objective_audit_struct.str_general_match_type,"Include") != NULL) {
 							strncpy(generalstring, "match", sizeof(generalstring));
 						} else {
 							strncpy(generalstring, "match!", sizeof(generalstring));
 						}
 					}


 					if (strstr(objective_audit_struct.str_user_match_type,"Any") != NULL) {
 						strncpy(userstring, "user", sizeof(userstring));
 						strncpy(objective_audit_struct.str_user_match,"*",sizeof(objective_audit_struct.str_user_match));
 					} else {
  						if (strstr(objective_audit_struct.str_user_match_type,"Include") != NULL) {
 							strncpy(userstring, "user", sizeof(userstring));
 						} else {
 							strncpy(userstring, "user!", sizeof(userstring));
 						}
 					}

 					if (strstr(objective_audit_struct.str_event_type,ALL_TOKEN) != NULL) {
 						strncpy(objective_audit_struct.str_event_type,"*",sizeof(objective_audit_struct.str_event_type));
 					}

					fprintf(configfile,
 						"	criticality=%d	event=(%s)	return=(%s)	%s=(%s)	%s=(%s)\n",
 						critic,
 						objective_audit_struct.str_eventid_match,
 						objective_audit_struct.str_event_type,
 						userstring,
 						objective_audit_struct.str_user_match,
 						generalstring,
 						objective_audit_struct.str_general_match);

 					wroteconfig = 1;
 				}
 				if (end && oldheadertype == AUDIT_CONFIG_OBJECTIVES) fprintf(configfile, "%s\n", inputbuffer);
 			} else {

 				// Print this line to file.
 				if (iscomment(inputbuffer)
 				    || !strlen(inputbuffer)) {
 					fprintf(configfile,
 						"%s\n",
 						inputbuffer);
 				} else {
 					fprintf(configfile,
 						"	%s\n",
 						inputbuffer);
 				}
 			}
 			position += currentsize;
 		}

 		if (!wroteconfig) {
 			// Must not have been an objective header in the file...
 			// if (end) or the objectives are at the end of the file
 			int critic = 0;
 			char userstring[8]="";
 			char generalstring[8]="";
 			// WRITE OUT NEW OBJECTIVE HERE
 			if (strstr(objective_audit_struct.str_critic, CRITICAL_TOKEN)) {
 				critic = CRITICALITY_CRITICAL;
 			} else if (strstr(objective_audit_struct.str_critic, PRIORITY_TOKEN)) {
 				critic = CRITICALITY_PRIORITY;
 			} else if (strstr(objective_audit_struct.str_critic, WARNING_TOKEN)) {
 				critic = CRITICALITY_WARNING;
 			} else if (strstr(objective_audit_struct.str_critic, INFORMATION_TOKEN)) {
 				critic = CRITICALITY_INFO;
 			} else {
 				critic = CRITICALITY_CLEAR;
 			}

			if (strstr(objective_audit_struct.str_general_match_type,"Any") != NULL) {
				strncpy(generalstring, "match", sizeof(generalstring));
				strncpy(objective_audit_struct.str_general_match,"*",sizeof(objective_audit_struct.str_general_match));
			} else {
				if (strstr(objective_audit_struct.str_general_match_type,"Include") != NULL) {
					strncpy(generalstring, "match", sizeof(generalstring));
				} else {
					strncpy(generalstring, "match!", sizeof(generalstring));
				}
			}


			if (strstr(objective_audit_struct.str_user_match_type,"Any") != NULL) {
				strncpy(userstring, "user", sizeof(userstring));
				strncpy(objective_audit_struct.str_user_match,"*",sizeof(objective_audit_struct.str_user_match));
			} else {
				if (strstr(objective_audit_struct.str_user_match_type,"Include") != NULL) {
					strncpy(userstring, "user", sizeof(userstring));
				} else {
					strncpy(userstring, "user!", sizeof(userstring));
				}
			}

			if (strstr(objective_audit_struct.str_event_type,ALL_TOKEN) != NULL) {
				strncpy(objective_audit_struct.str_event_type,"*",sizeof(objective_audit_struct.str_event_type));
			}

		fprintf(configfile,
				"	criticality=%d	event=(%s)	return=(%s)	%s=(%s)	%s=(%s)\n",
				critic,
				objective_audit_struct.str_eventid_match,
				objective_audit_struct.str_event_type,
				userstring,
				objective_audit_struct.str_user_match,
				generalstring,
				objective_audit_struct.str_general_match);
 		}

 		if (fclose(configfile)) {
 			dw_objective_error = 1;
 			strncat(dest,
 				"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
 				sizeof(dest) - strlen(dest) -1);
 			Clear_Config_File(rampointer);
 			return (dw_objective_error);
 		}

 		Clear_Config_File(rampointer);
 	}
 	return (dw_objective_error);
 }


 //  		for ($count=0; $count < $arraysize + $AddObjective;$count++) {
 //			@elements=split(/[ \t]*([a-z0-9:]+)(\!*=)([^ \t]+)[ \t]*/,$Config{"OBJECTIVES"}{$count});
 //			$type=0;
 //			%ObjectiveMatch=();
 //			foreach $component (@elements) {
 //				if($component =~ /^[ \t]*$/ || $component eq "") {
 //					next;
 //				}
 //				if($type==0) {
 //					$token=$component;
 //					$type++;
 //				} elsif($type == 1) {
 //					$comp=$component;
 //					$type++;
 //				} elsif($type == 2) {
 //					$match=$component;
 //					if ($token =~ /(criticality|uid|return|event)/) {
 //						$ObjectiveMatch{$token}=$match;
 //						$ObjectiveCompare{$token}=$comp;
 //					} elsif ($token =~ /watch/) {
 //						# ignore
 //					} else {
 //						$elements=keys(%{$ObjectiveMatch{$token}});
 //						$ObjectiveMatch{$token}{$elements}=$match;
 //						$ObjectiveCompare{$token}{$elements}=$comp;
 //					}
 //					$type=0;
 //				}
 //			}

 //criticality=0   event=execve    exe=/sbin/auditctl
 //criticality=1   event=execve    exe=*ciccio*    exe=*passwd*
 //criticality=2   event=execve    uid=*,(root)
 //criticality=2   event=(login_auth,login_start,logout)   return=*,yes    uid!=*,(root)
 //criticality=3   event=(mount,umount,umount2,settimeofday,swapon,swapoff,reboot,setdomainname,create_module,delete_module,quotactl)

 // Strip out our ( and ) characters
 void stripPs(char* str){
 	if (str[0] == '(' && strlen(str) >= 2) {
 		int count;
 		int slen = strlen(str);
 		if (str[slen - 1] == ')') {
 			for (count = 0; count < slen - 2; count++) {
 				str[count] = str[count + 1];
 			}
 			str[slen - 2] = '\0';
 		}
 	}
 }
 #if defined(__linux__)
 void replaceEvents(char* event){
 	if(strcmp(event,OPEN_EVENTS) == 0)	{
 		strncpy(event,OPEN_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,FILE_REMOVE_EVENTS) == 0) {
 		strncpy(event,FILE_REMOVE_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,PROCESS_EVENTS) == 0) {
 		strncpy(event,PROCESS_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,FILE_ATTRIB_EVENTS) == 0) {
 		strncpy(event,FILE_ATTRIB_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,ADMIN_EVENTS) == 0) {
 		strncpy(event,ADMIN_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,SOCKET_EVENTS) == 0) {
 		strncpy(event,SOCKET_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,LOGON_LOGOFF_EVENTS) == 0) {
 		strncpy(event,LOGONOFF_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,USER_EVENTS) == 0) {
 		strncpy(event,USER_TOKEN,SIZE_OF_EVENTIDMATCH);
 	}

 }
 #endif


 #if defined(_AIX)
 void replaceEvents(char* event){
 	if(strcmp(event,LOGON_LOGOFF_EVENTS) == 0)	{
 		strncpy(event,LOGONOFF_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,FILE_READ_EVENTS) == 0) {
 		strncpy(event,FILE_READ_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,FILE_WRITE_EVENTS) == 0) {
 		strncpy(event,FILE_WRITE_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,FILE_ATTRIB_EVENTS) == 0) {
 		strncpy(event,FILE_ATTRIB_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,PROCESS_EVENTS) == 0) {
 		strncpy(event,PROCESS_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,ADMIN_EVENTS) == 0) {
 		strncpy(event,ADMIN_TOKEN,SIZE_OF_EVENTIDMATCH);
 	}

 }

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


 #define LOGONOFF_TOKEN "Logon_Logoff"
 #define FILE_READ_TOKEN "File_Read"
 #define FILE_WRITE_TOKEN "File_Write"
 #define FILE_ATTRIB_TOKEN "File_Attrib"
 #define FILE_REMOVE_TOKEN "File_Remove"
 #define PROCESS_TOKEN "Process_Events"
 #define USER_TOKEN "User_Events"
 #define SOCKET_TOKEN "Socket_Events"


 void replaceEvents(char* event){
 	if(strcmp(event,LOGON_LOGOFF_EVENTS) == 0)	{
 		strncpy(event,LOGONOFF_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,FILE_READ_EVENTS) == 0) {
 		strncpy(event,FILE_READ_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,FILE_WRITE_EVENTS) == 0) {
 		strncpy(event,FILE_WRITE_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,FILE_ATTRIB_EVENTS) == 0) {
 		strncpy(event,FILE_ATTRIB_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,PROCESS_EVENTS) == 0) {
 		strncpy(event,PROCESS_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,FILE_REMOVE_EVENTS) == 0) {
 		strncpy(event,FILE_REMOVE_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,USER_EVENTS) == 0) {
 		strncpy(event,USER_TOKEN,SIZE_OF_EVENTIDMATCH);
 	} else if (strcmp(event,SOCKET_EVENTS) == 0) {
 		strncpy(event,SOCKET_TOKEN,SIZE_OF_EVENTIDMATCH);
 	}

 }


 #endif


 int Get_Next_Audit_Objective(FILE * configfile, struct Reg_Audit_Objective *objective)
 {
 	char inputbuffer[MAX_AUDIT_CONFIG_LINE];
 	// Save off enough space to store the data we need.
 	char event[MAX_AUDIT_CONFIG_LINE] ="", user[MAX_AUDIT_CONFIG_LINE]="", path[MAX_AUDIT_CONFIG_LINE]="";
 	int criticality;
 	int returncode = 0;
 	int excludeflag = 0;
 	int excludematchflag = 0;

 	objective->str_critic[0]='\0';
 	objective->str_event_type[0]='\0';
 	objective->str_eventid_match[0]='\0';
 	objective->str_user_match[0]='\0';
 	objective->str_general_match[0]='\0';
 	objective->str_user_match_type[0]='\0';
 	objective->str_general_match_type[0]='\0';

 	while (fgets(inputbuffer, MAX_AUDIT_CONFIG_LINE, configfile)) {
 		trim(inputbuffer);
 		if (isheader(inputbuffer)) {
 			return (0);
 		}

 		if (strlen(inputbuffer) < 3) {
 			continue;
 		}

 		if ((criticality =
 		     split_audit_objective(inputbuffer, event, user, path,
 				    &excludeflag, &excludematchflag, &returncode)) > -1) {
 			// add the objective to the linked list.
 			trim(event);
 			stripPs(event);
#if defined(__sun) || defined(_AIX) || defined(__linux__)
 			replaceEvents(event);
#endif
 			strncpy(objective->str_eventid_match, event,
 				SIZE_OF_EVENTIDMATCH);

 			if(strlen(path) > 0){
 				if (excludematchflag) {
 					strncpy(objective->str_general_match_type,
 						"Exclude",
 						sizeof (objective->
 							str_general_match_type));
 				} else {
 					strncpy(objective->str_general_match_type,
 						"Include",
 						sizeof (objective->
 							str_general_match_type));
 				}

 				// Strip out our ( and ) characters
 				stripPs(path);
 				strncpy(objective->str_general_match, path,
 					SIZE_OF_A_GENERALMATCH);
 			}else{
 				strncpy(objective->str_general_match_type,
 					"Any",
 					sizeof (objective->
 						str_general_match_type));
 				strncpy(objective->str_general_match, ALL_TOKEN,
 					SIZE_OF_A_GENERALMATCH);

 			}

 			if(strlen(user) > 0){
 				if (excludeflag) {
 					strncpy(objective->str_user_match_type,
 						"Exclude",
 						sizeof (objective->
 							str_user_match_type));
 				} else {
 					strncpy(objective->str_user_match_type,
 						"Include",
 						sizeof (objective->
 							str_user_match_type));
 				}

 				// Strip out our ( and ) characters
 				stripPs(user);
 				strncpy(objective->str_user_match, user,
 					SIZE_OF_USERMATCH);
 			}else{
 				strncpy(objective->str_user_match_type,
 					"Any",
 					sizeof (objective->
 						str_user_match_type));
 				strncpy(objective->str_user_match, ALL_TOKEN,
 					SIZE_OF_USERMATCH);


 			}

 			if (returncode == RETURNCODE_SUCCESS) {
 				strncpy(objective->str_event_type,
 					SUCCESS_TOKEN, SIZE_OF_EVENTLOG);
 			} else if (returncode == RETURNCODE_FAILURE) {
 				strncpy(objective->str_event_type,
 					FAILURE_TOKEN, SIZE_OF_EVENTLOG);
 			} else {
 				strncpy(objective->str_event_type, ALL_TOKEN,
 					SIZE_OF_EVENTLOG);
 			}

 			if (criticality == CRITICALITY_CRITICAL) {
 				strncpy(objective->str_critic, CRITICAL_TOKEN,
 					SIZE_OF_CRITICALITY);
 			} else if (criticality == CRITICALITY_PRIORITY) {
 				strncpy(objective->str_critic, PRIORITY_TOKEN,
 					SIZE_OF_CRITICALITY);
 			} else if (criticality == CRITICALITY_WARNING) {
 				strncpy(objective->str_critic, WARNING_TOKEN,
 					SIZE_OF_CRITICALITY);
 			} else if (criticality == CRITICALITY_INFO) {
 				strncpy(objective->str_critic,
 					INFORMATION_TOKEN, SIZE_OF_CRITICALITY);
 			} else {
 				strncpy(objective->str_critic, CLEAR_TOKEN,
 					SIZE_OF_CRITICALITY);
 			}
 			return (1);
 		}
 	}
 	return (0);
 }


 int Watch_Config(char *source, char *dest, int size)
 {
 	struct Reg_Watch reg_watch;
 	int i_watch_count = 0;
 	char str_watch_count[15];
 	char str_general_match_metachar_remove[SIZE_OF_GENERALMATCH * 2];
 	char strtmp[500] = "";

 	FILE *configfile = (FILE *) NULL;

 	if (!source || !dest || !size) {
 		return(0);
 	}

 	strncpy(dest,
 		"<form action=/safed/setwatch><H1><CENTER>SafedAgent Watch Configuration</H1>",
 		size);

 	configfile = Find_First(CONFIG_WATCH);

 	if (configfile) {
 		strncat(dest,
 			"<br>The following watches of the SafedAgent unit are active:<br><br>"
 			"<table  width=100% border=1>", sizeof(dest) - strlen(dest) -1);

 		strncat(dest,
 			"<tr bgcolor=#F0F1F5><center><td width=\"10%\"><b>Action Required</b></td>"
 			"<td width=\"10%\"><b>Include/Exclude</b></td>"
 	 		"<td width=\"75%\"><b>Path</b></td>"
 	 		"<td width=\"75%\"><b>New File</b></td>"
 			"<td width=\"5%\"><b>Order</b></td>"
 			"</center></tr>", sizeof(dest) - strlen(dest) -1);

 		while (Get_Next_Watch(configfile, &reg_watch)) {
 			snprintf(str_watch_count, 15, "%d", i_watch_count);

 			if ((i_watch_count) == 0)
 				strncat(dest,
 					"<tr bgcolor=#DEDBD2><td><input type=submit name=",
 					sizeof(dest) - strlen(dest) -1);
 			else{
 				snprintf(strtmp, sizeof(strtmp), "<div align=center style=\"margin-bottom: 5px; border-left: 2px solid #eeeeee; border-top: 2px solid #eeeeee; border-right: 2px solid #aaaaaa; border-bottom: 2px solid #aaaaaa; background-color: #dddddd\"><a href=\"/safed/setwatch?%d=MoveDown\" style=\"font-size: 9px; color: #33aa33; text-decoration: none; display: block;\">&#9660;</a></div>",(i_watch_count-1));
 				strncat(dest,strtmp,sizeof(dest) - strlen(dest) -1);
 				strncat(dest, "</td></tr>", sizeof(dest) - strlen(dest) -1);
 				strncat(dest,
 					"<tr bgcolor=#E7E5DD><td><input type=submit name=",
 					sizeof(dest) - strlen(dest) -1);
 			}

 			strncat(dest, str_watch_count, sizeof(dest) - strlen(dest) -1);
 			strncat(dest, " value=Delete>     ",
 				sizeof(dest) - strlen(dest) -1);

 			strncat(dest, "<input type=submit name=",
 				sizeof(dest) - strlen(dest) -1);
 			strncat(dest, str_watch_count, sizeof(dest) - strlen(dest) -1);
 			strncat(dest, " value=Modify>", sizeof(dest) - strlen(dest) -1);
 			strncat(dest, "</td><td>", sizeof(dest) - strlen(dest) -1);

 			if (strlen(reg_watch.str_general_match_type) == 0) {
 				strncat(dest, "&nbsp", sizeof(dest) - strlen(dest) -1);
 			} else {
 				strncat(dest, reg_watch.str_general_match_type,
 					sizeof(dest) - strlen(dest) -1);
 			}
 			strncat(dest, "</td><td>", sizeof(dest) - strlen(dest) -1);

 			// Debracket the strings in here. For HTML display purposes, the HTML metacharacters
 			// need to be replaced. This is done with the "debracket" routine.
 			// Note that the new strings are allowed to be twice as long as the real strings
 			debracket(reg_watch.str_general_match,
 				  str_general_match_metachar_remove,
 				  SIZE_OF_GENERALMATCH * 2);

 			if (strlen(reg_watch.str_general_match) == 0) {
 				strncat(dest, "&nbsp", sizeof(dest) - strlen(dest) -1);
 			} else {
 				strncat(dest, str_general_match_metachar_remove,
 					sizeof(dest) - strlen(dest) -1);
 			}
 			strncat(dest, "</td><td>", sizeof(dest) - strlen(dest) -1);

 			if (strlen(reg_watch.str_new) == 0) {
 				strncat(dest, "&nbsp", sizeof(dest) - strlen(dest) -1);
 			} else {
 				strncat(dest, reg_watch.str_new,
 					sizeof(dest) - strlen(dest) -1);
 			}
 			strncat(dest, "</td>", sizeof(dest) - strlen(dest) -1);

 			if (i_watch_count > 0){
 				snprintf(strtmp, sizeof(strtmp), "<td><div align=center style=\"margin-bottom: 5px; border-left: 2px solid #eeeeee; border-top: 2px solid #eeeeee; border-right: 2px solid #aaaaaa; border-bottom: 2px solid #aaaaaa; background-color: #dddddd\"><a href=\"/safed/setwatch?%d=MoveUp\" style=\"font-size: 9px; color: #33aa33; text-decoration: none; display: block;\">&#9650;</a></div>",i_watch_count);
 				strncat(dest,strtmp,sizeof(dest) - strlen(dest) -1);



 			}else
 				strncat(dest,"<td>",sizeof(dest) - strlen(dest) -1);
 			i_watch_count++;
 		}

 		strncat(dest, "</td></tr>", sizeof(dest) - strlen(dest) -1);
 		Close_File(configfile);
 		strncat(dest, "</table><br>", sizeof(dest) - strlen(dest) -1);
 	} else {
 		strncat(dest,
 			"<br>There are no current watches active.<br><br>",
 			sizeof(dest) - strlen(dest) -1);
 	}

 	strncat(dest, "Select this button to add a new watch.  ",
 		sizeof(dest) - strlen(dest) -1);
 	strncat(dest, "<input type=submit name=0", sizeof(dest) - strlen(dest) -1);
 	strncat(dest, " value=Add>", sizeof(dest) - strlen(dest) -1);

 	return (0);
 }


 int isdir(char* path){

	 struct stat s;
	 if( stat(path,&s) == 0 )
	 {
	     if( s.st_mode & S_IFDIR )
	     {
	         return 1;
	     }else{
	    	 return 0;
	     }
	 }
	 else
	 {
	     return -1;
	 }

 }

 int Watch_Display(char *source, char *dest, int size)
 {
 	struct Reg_Watch reg_watch;
 	int dw_watch_error = 0, dw_watch_delete_error = 0;
 	char str_objerr[10];
 	int i_watch_count = 0, i_type = 0;
 	char *psource = source, Variable[100], Argument[100];
 	char str_temp[20], str_temp_watch[10];

 	// This function will display an existing, or a blank, watch
 	strncpy(dest,
 		"<form action=/safed/changewatch><h1><center>SafedAgent Watches Configuration</h1>",
 		size);
 	// Determine whether the watch will be modified or deleted
 	while ((psource =
 		getNextArgument(psource, Variable, sizeof (Variable), Argument,
 				sizeof (Argument))) != (char *) NULL) {
 		if (strstr(Argument, "Delete") != NULL) {
 			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp,
 			       str_temp_watch);
 			i_type = 0;
 			break;
 		}
 		if (strstr(Argument, "Modify") != NULL) {
 			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp, str_temp_watch);
 			i_type = 1;
 			break;
 		}
 		if (strstr(Argument, "MoveUp") != NULL) {
 			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp,
 			       str_temp_watch);
 			i_type = -2;
 			break;
 		}
 		if (strstr(Argument, "MoveDown") != NULL) {
 			sscanf(Variable, "%20[^?]?%10[^\n]\n", str_temp,
 			       str_temp_watch);
 			i_type = -1;
 			break;
 		}
 		if (strstr(Argument, "Add") != NULL) {
 			strncpy(str_temp_watch, "-2",
 				sizeof (str_temp_watch));
 			i_type = 2;
 			break;
 		}
 	}

 	// Extract the watch number. I have to do this stuff, because atoi returns 0 if it cannot convert the string
 	if (strcmp(str_temp_watch, "0") == 0)
 		i_watch_count = -1;
 	else
 		i_watch_count = atoi(str_temp_watch);

 	// If the watch number could not be successfully extracted, return immediately.
 	if (i_watch_count == 0) {
 		strncat(dest,
 			"<br><b>NOTE: It appears the URL is encoded incorrectly.",
 			sizeof(dest) - strlen(dest) -1);
 		return 0;
 	}

 	if (i_watch_count == -1)
 		i_watch_count = 0;

 	// If the watch is being modified or added
 	if (i_type > 0) {
 		if (i_type == 1) {
 			int count = 0;
 			int returncode;
 			FILE *configfile;
 			configfile = Find_First(CONFIG_WATCH);
 			while ((returncode =
 					Get_Next_Watch(configfile, &reg_watch)))
 			{
 				if (count == i_watch_count)
 					break;
 				count++;
 			}
 			if (!(count == i_watch_count && returncode)) {
 				dw_watch_error =
 				    WEB_READ_OBJECTIVE_ERROR_CODE;
 			}
 			Close_File(configfile);
 		} else {
 			// Defaults
 			strncpy(reg_watch.str_general_match, "",
 				sizeof (reg_watch.str_general_match));
 			strncpy(reg_watch.str_general_match_type, "Include",
 				sizeof (reg_watch.str_general_match_type));
 			strncpy(reg_watch.str_new, "No",
 				sizeof (reg_watch.str_new));

 		}

 		// Will display an error if unable to completely read from the config file
 		if (dw_watch_error > 0) {
 			dw_watch_error += WEB_READ_OBJECTIVE_ERROR_CODE;
 			snprintf(str_objerr, 10, "%d", dw_watch_error);

 			strncat(dest,
 				"<br><b>NOTE: Some errors were encountered in reading the configuration file. Default values "
 				"may be used.<br> Report error: ",
 				sizeof(dest) - strlen(dest) -1);
 			strncat(dest, str_objerr, sizeof(dest) - strlen(dest) -1);
 			strncat(dest, "</b><br>", sizeof(dest) - strlen(dest) -1);
 		}

 		strncat(dest,
 			"<br>The following parameters of the SafedAgent watch may be set:<br><br>"
 			"<table  width=100% border=0>", sizeof(dest) - strlen(dest) -1);

 		strncat(dest,
 			"<tr bgcolor=#DEDBD2><td>Select the General Match Type</td><td>",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest,
 			"<input type=radio name=str_general_match_type value=Include",
 			sizeof(dest) - strlen(dest) -1);
 		if (strstr(reg_watch.str_general_match_type, "Include") != NULL) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 		}
 		strncat(dest,
 			">Include    <input type=radio name=str_general_match_type value=Exclude",
 			sizeof(dest) - strlen(dest) -1);

 		if (strstr(reg_watch.str_general_match_type, "Exclude") !=
 		    NULL)
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 		strncat(dest, ">Exclude    </td></tr>", sizeof(dest) - strlen(dest) -1);

 		strncat(dest,
 			"<tr bgcolor=#E7E5DD><td>Path</td><td><input type=text name=str_general_match size=50 value=\"",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, reg_watch.str_general_match,
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, "\"></td></tr>", sizeof(dest) - strlen(dest) -1);

 		strncat(dest,
 			"<tr bgcolor=#DEDBD2><td>New File</td><td><input type=checkbox name=dw_newfile",
 			sizeof(dest) - strlen(dest) -1);
 		if (strstr(reg_watch.str_new, "Yes") != NULL) {
 			strncat(dest, " checked", sizeof(dest) - strlen(dest) -1);
 		}else if((isdir(reg_watch.str_general_match) <= 0) || (strstr(reg_watch.str_general_match_type, "Exclude") != NULL)){
 			strncat(dest, " disabled", sizeof(dest) - strlen(dest) -1);
 		}
 		strncat(dest, "></td></tr>", sizeof(dest) - strlen(dest) -1);


 		strncat(dest, "</table><br>", sizeof(dest) - strlen(dest) -1);
 		strncat(dest, "<input type=hidden name=watchnumber value=",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, str_temp_watch, sizeof(dest) - strlen(dest) -1);	// Watch number goes here
 		strncat(dest,
 			"><input type=submit value=\"Change Configuration\">    ",
 			sizeof(dest) - strlen(dest) -1);
 		strncat(dest, "<input type=reset value=\"Reset Form\"></form>",
 			sizeof(dest) - strlen(dest) -1);
 	} else {
 		void *rampointer = (void *) NULL;
 		char *position;
 		char inputbuffer[2*MAX_AUDIT_CONFIG_LINE + 2];
 		char inputbuffer_swap[2*MAX_AUDIT_CONFIG_LINE + 2];
 		int headertype = 0;
 		FILE *configfile;

 		rampointer = Load_Config_File();
 		if (!rampointer) {
 			dw_watch_error = WEB_READ_CONFIG_ERROR_CODE;
 			dw_watch_delete_error = 1;
 		} else {
 			int watchcounter = 0;
 			int currentsize = 0;

 			position = (char *) rampointer;

 			configfile = current_config("w");
 			if (!configfile) {
 				strncat(dest,
 					"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
 					sizeof(dest) - strlen(dest) -1);
 				Clear_Config_File(rampointer);
 				return (0);
 			}

 			while ((currentsize =
 				Grab_RAMConfig_Line(position, inputbuffer,
 						    MAX_AUDIT_CONFIG_LINE))) {
 				trim(inputbuffer);
 				if (headertype == CONFIG_WATCH) {
 					if(i_type == -2){
 						if (watchcounter ==  (i_watch_count - 1)){
 							strcpy(inputbuffer_swap,inputbuffer);
 							position += currentsize;
 							watchcounter++;
 							continue;
 						}else if (watchcounter ==  i_watch_count){
 							strcat(inputbuffer,"\n\t");
 							strcat(inputbuffer,inputbuffer_swap);
 						}
 					}
 					if(i_type == -1){
 						if (watchcounter ==  i_watch_count){
 							strcpy(inputbuffer_swap,inputbuffer);
 							position += currentsize;
 							watchcounter++;
 							continue;
 						}else if (watchcounter ==  (i_watch_count + 1)){
 							strcat(inputbuffer,"\n\t");
 							strcat(inputbuffer,inputbuffer_swap);
 						}
 					}
 					if(i_type == 0){
 						if (watchcounter ==
 							i_watch_count) {
 							// Do not add this line back into the original file.
 							position += currentsize;
 							watchcounter++;
 							continue;
 						}
 					}
 					watchcounter++;
 				}

 				if (!iscomment(inputbuffer)) {
 					// Is this line a header?
 					if (isheader(inputbuffer)) {
 						headertype =
 						    getheader(inputbuffer);
 					}
 				}
 				// Print this line to file.
 				if (isheader(inputbuffer)
 				    || iscomment(inputbuffer)
 				    || !strlen(inputbuffer)) {
 					fprintf(configfile, "%s\n",
 						inputbuffer);
 				} else {
 					fprintf(configfile, "	%s\n",
 						inputbuffer);
 				}

 				// position+=strlen(inputbuffer)+1;
 				position += currentsize;
 			}
 			if (fclose(configfile)) {
 				dw_watch_delete_error = 1;
 				strncat(dest,
 					"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
 					sizeof(dest) - strlen(dest) -1);
 				Clear_Config_File(rampointer);
 				return (0);
 			}

 			Clear_Config_File(rampointer);
 		}

 		if (dw_watch_delete_error == 0){
 			strncpy(source,"/safed/watch", 12);
 			Watch_Config(source,dest,size);

 		}else
 			strncat(dest,
 				"<br>The watch was unable to be deleted.",
 				sizeof(dest) - strlen(dest) -1);
 	}

 	return (0);
 }

 int Watch_Result(char *source, char *dest, int size)
 {
 	// All strncpy or strncat functions in this routine have been designed avoid overflows
 	struct Reg_Watch reg_watch;
 	int dw_watch_error = 0;
 	int i_watch = 0;
 	char str_watch_count[10];
 	char *psource = source, Variable[100], Argument[100];

 	strncpy(dest,
 		"<H1><CENTER>SafedAgent Watches Configuration</CENTER></H1>",
 		size);

 	while ((psource =
 		getNextArgument(psource, Variable, sizeof (Variable), Argument,
 				sizeof (Argument))) != (char *) NULL) {

 		if (strstr(Variable, "str_general_match") != NULL) {
 			strncpy(reg_watch.str_general_match, Argument,
 				sizeof (reg_watch.str_general_match));
 		}

 		if (strstr(Variable, "watchnumber") != NULL) {
 			strncpy(str_watch_count, Argument,
 				sizeof (str_watch_count));
 		}
 		if (strstr(Variable, "str_general_match_type") != NULL) {
 			strncpy(reg_watch.str_general_match_type, Argument,
 				sizeof (reg_watch.str_general_match_type));
 		}
		if (strstr(Variable, "dw_newfile") != NULL) {
			if (strcmp(Argument, "on") == 0)
	 			strncpy(reg_watch.str_new, "Yes",
	 				sizeof (reg_watch.str_general_match_type));
			else
	 			strncpy(reg_watch.str_new, "No",
	 				sizeof (reg_watch.str_general_match_type));
		}
 	}


 	if (!dw_watch_error) {

 		i_watch = atoi(str_watch_count);

 		//-2 = "Add a new watch"
 		if (i_watch == -2) {
 			void *rampointer = (void *) NULL;
 			char *position;
 			char inputbuffer[MAX_AUDIT_CONFIG_LINE];
 			int headertype = 0;
 			FILE *configfile;

 			rampointer = Load_Config_File();
 			if (!rampointer) {
 				dw_watch_error = WEB_READ_CONFIG_ERROR_CODE;
 			} else {
 				int currentsize = 0;
 				int wroteconfig = 0;

 				position = (char *) rampointer;

 				configfile = current_config("w");
 				if (!configfile) {
 					dw_watch_error = 1;
 					strncat(dest,
 						"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
 						sizeof(dest) - strlen(dest) -1);
 					Clear_Config_File(rampointer);
 					return (0);
 				}

 				while ((currentsize =
 					Grab_RAMConfig_Line(position,
 							    inputbuffer,
 							    MAX_AUDIT_CONFIG_LINE)))
 				{
 					trim(inputbuffer);

 					// Is this line a header?
 					if (isheader(inputbuffer)) {
 						if(wroteconfig && (wroteconfig < 2)){
 							char generalstring[8];
 							// WRITE OUT NEW WATCH HERE

							if (strstr(reg_watch.str_general_match_type,"Include") != NULL) {
								if (strstr(reg_watch.str_new,"Yes") != NULL) {
									strncpy(generalstring, "path~", sizeof(generalstring));
								}else{
									strncpy(generalstring, "path", sizeof(generalstring));
								}
							} else {
								strncpy(generalstring, "path!", sizeof(generalstring));
							}

 							fprintf(configfile,
 								"	%s=%s\n",
 								generalstring,
 								reg_watch.str_general_match);
 							wroteconfig = 2;
 						}

 						fprintf(configfile, "%s\n",
 							inputbuffer);
 						headertype =
 						    getheader(inputbuffer);
 						if (headertype ==
 						    CONFIG_WATCH) {
 							wroteconfig = 1;
 						}
 					} else {

 						// Print this line to file.
 						if (iscomment(inputbuffer)
 						    || !strlen(inputbuffer)) {
 							fprintf(configfile,
 								"%s\n",
 								inputbuffer);
 						} else {
 							fprintf(configfile,
 								"	%s\n",
 								inputbuffer);
 						}
 					}
 					position += currentsize;
 				}

 				if (wroteconfig < 2) {
 					// Must not have been an watch header in the file...
 					char generalstring[8];
 					// WRITE OUT NEW WATCH HERE

					if (strstr(reg_watch.str_general_match_type,"Include") != NULL) {
						if (strstr(reg_watch.str_new,"Yes") != NULL) {
							strncpy(generalstring, "path~", sizeof(generalstring));
						}else{
							strncpy(generalstring, "path", sizeof(generalstring));
						}
					} else {
						strncpy(generalstring, "path!", sizeof(generalstring));
					}


 					if(!wroteconfig){
 						fprintf(configfile,
 						"\n\n[Watch]\n	%s=%s\n",
 						generalstring,
 						reg_watch.
 						str_general_match);
 					}else{
 						fprintf(configfile,
 							"	%s=%s\n",
 							generalstring,
 							reg_watch.str_general_match);
 					}
 				}

 				if (fclose(configfile)) {
 					dw_watch_error = 1;
 					strncat(dest,
 						"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
 						sizeof(dest) - strlen(dest) -1);
 					Clear_Config_File(rampointer);
 					return (0);
 				}

 				Clear_Config_File(rampointer);
 			}
 		} else {
 			// Modify an existing watch
 			void *rampointer = (void *) NULL;
 			char *position;
 			char inputbuffer[MAX_AUDIT_CONFIG_LINE];
 			int headertype = 0;
 			FILE *configfile;

 			rampointer = Load_Config_File();
 			if (!rampointer) {
 				dw_watch_error = WEB_READ_CONFIG_ERROR_CODE;
 			} else {
 				int watchcounter = 0;
 				int currentsize = 0;

 				position = (char *) rampointer;

 				configfile = current_config("w");
 				if (!configfile) {
 					dw_watch_error = 1;
 					strncat(dest,
 						"<br><b>NOTE: Could not open the configuration file for writing. Please verify the permissions set on the audit config file.",
 						sizeof(dest) - strlen(dest) -1);
 					Clear_Config_File(rampointer);
 					return (0);
 				}

 				while ((currentsize =
 					Grab_RAMConfig_Line(position,
 							    inputbuffer,
 							    MAX_AUDIT_CONFIG_LINE)))
 				{
 					trim(inputbuffer);

 					if (headertype == CONFIG_WATCH) {
 						if (watchcounter ==
 						    i_watch) {
 							// Replace this watch with the new version.
 							char generalstring[8];
 							// WRITE OUT NEW WATCH HERE

							if (strstr(reg_watch.str_general_match_type,"Include") != NULL) {
								if (strstr(reg_watch.str_new,"Yes") != NULL) {
									strncpy(generalstring, "path~", sizeof(generalstring));
								}else{
									strncpy(generalstring, "path", sizeof(generalstring));
								}
							} else {
								strncpy(generalstring, "path!", sizeof(generalstring));
							}

 							fprintf(configfile,
 								"	%s=%s\n",
 								generalstring,
 								reg_watch.str_general_match);

 							position += currentsize;
 							watchcounter++;
 							continue;
 						}
 						watchcounter++;
 					}

 					if (!iscomment(inputbuffer)) {
 						// Is this line a header?
 						if (isheader(inputbuffer)) {
 							headertype =
 							    getheader
 							    (inputbuffer);
 						}
 					}
 					// Print this line to file.
 					if (isheader(inputbuffer)
 					    || iscomment(inputbuffer)
 					    || !strlen(inputbuffer)) {
 						fprintf(configfile, "%s\n",
 							inputbuffer);
 					} else {
 						fprintf(configfile, "	%s\n",
 							inputbuffer);
 					}

 					// position+=strlen(inputbuffer)+1;
 					position += currentsize;
 				}

 				if (fclose(configfile)) {
 					dw_watch_error = 1;
 					strncat(dest,
 						"<br><b>NOTE: Could not write to the configuration file. Does the system have enough free disk space?.",
 						sizeof(dest) - strlen(dest) -1);
 					Clear_Config_File(rampointer);
 					return (0);
 				}

 				Clear_Config_File(rampointer);
 			}
 		}


 	}
 	if (dw_watch_error == 0){
 		strncpy(source,"/safed/watch", 10);
 		Watch_Config(source,dest,size);
 	}else{
 		strncat(dest,
 			"<br>The watch was unable to be modified/added.",
 			sizeof(dest) - strlen(dest) -1);
 	}
 	return (0);
 }


 int Get_Next_Watch(FILE * configfile, struct Reg_Watch *watch)
 {
 	char inputbuffer[MAX_AUDIT_CONFIG_LINE];
 	// Save off enough space to store the data we need.
 	char path[MAX_AUDIT_CONFIG_LINE];
 	int excludematchflag = 0;
 	int newfile = 0;

 	while (fgets(inputbuffer, MAX_AUDIT_CONFIG_LINE, configfile)) {
 		trim(inputbuffer);

 		if (isheader(inputbuffer)) {
 			return (0);
 		}

 		if (strlen(inputbuffer) < 3) {
 			continue;
 		}
 		if (splitwatch(inputbuffer, path, &excludematchflag, &newfile) > -1) {
 			// add the watch to the linked list.

 			if (excludematchflag) {
 				strncpy(watch->str_general_match_type,
 					"Exclude",
 					sizeof (watch->
 						str_general_match_type));
 			} else {
 				strncpy(watch->str_general_match_type,
 					"Include",
 					sizeof (watch->
 						str_general_match_type));
 			}

 			if (newfile) {
 				strncpy(watch->str_new,
 					"Yes",
 					sizeof (watch->
 							str_new));
 			} else {
 				strncpy(watch->str_new,
 					"No",
 					sizeof (watch->
 							str_new));
 			}


 			strncpy(watch->str_general_match, path,
 				SIZE_OF_GENERALMATCH);

 			return (1);
 		}
 	}
 	return (0);
 }
