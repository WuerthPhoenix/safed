/**********************************************************
 * SAFED for AIX
 * Author: Wuerth-Phoenix s.r.l.,
 * made starting from:
 * Snare for AIX header file
 *
 * Author: InterSect Alliance Pty Ltd
 *
 * Copyright 2001-2010 InterSect Alliance Pty Ltd
 *
 * Last Modified: 7/10/2004
 *
 * Available under the terms of the GNU Public Licence.
 * - See www.gnu.org
 *
 **********************************************************
 *
 * History:
 *       7/10/2004  Initial working version
 *
 **********************************************************/

// AIX maximum path size
#define MAX_PATH		MAXPATHLEN

#define LOGBUFFERSIZE 4096	/* MAX UDP string buffer size */
#define HOSTSIZE 1024		/* MAX hostname */
#define MAXAUDIT 65535		/* Maximum number of audit events */
#define MAX_AUDIT_CONFIG_LINE	4096
#define CONFIG_FILENAME "/etc/safed/safed.conf"

#define CONFIG_AUDITTYPE	1
#define	CONFIG_OBJECTIVES	2
#define CONFIG_EVENTS		3
#define CONFIG_OUTPUT		4
#define CONFIG_DELIVERY		5
#define CONFIG_HOSTID		6
#define CONFIG_LOG			8

#define MAX_HOSTID		256	// Host identifier - usually the fully qualified hostname.
#define MAX_AUDITREC MAX_PATH+4096	// How much buffer to reserve for the textual representation of an audit event.
#define MAX_USERNAME		256
#define MAX_OPTIONS		256
#define MAX_EVENTNAME		32
#define MAX_USERREG		MAX_PATH
#define MAX_HOSTID		256	// Host identifier - usually the fully qualified hostname.
#define MAXCOMMAND 		16

#define CRITICALITY_CLEAR	0
#define CRITICALITY_INFO	1
#define CRITICALITY_WARNING 2
#define CRITICALITY_PRIORITY 3
#define CRITICALITY_CRITICAL 4

#define	RETURNCODE_FAILURE	0
#define RETURNCODE_SUCCESS	1
#define RETURNCODE_ANY		999

#define AUDIT_TO_STDOUT		1
#define AUDIT_TO_FILE           2
#define AUDIT_TO_NETWORK        4
#define AUDIT_TO_SYSLOG         8

#define AUDIT_ALL	-1

#ifdef SILLY_AIX
#ifndef _H_SNPRINTF
#define _H_SNPRINTF

#ifndef _H_STANDARDS
#include <standards.h>
#endif

#ifndef _SIZE_T
#define _SIZE_T
typedef unsigned long   size_t;
#endif


#ifdef _NO_PROTO
extern int snprintf();
extern int vsnprintf();
#else                   /* use ANSI C required prototypes */
extern int snprintf(char *, size_t, const char *, ...);
#ifdef _VA_LIST
extern int vsnprintf(char *, size_t, const char *, va_list);
#else
#define _VA_LIST
typedef char *va_list;

extern int vsnprintf(char *string, size_t length, const char * format,
va_list);
#endif /* _VA_LIST */
#endif /* _NO_PROTO */

#endif /* _H_SNPRINTF */

#endif /* SILLY_AIX */


