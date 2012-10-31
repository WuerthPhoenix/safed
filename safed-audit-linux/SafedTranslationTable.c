/**********************************************************
 * SAFED AUDIT for Linux
 * Author: Wuerth-Phoenix s.r.l.,
 * made starting from:
 *
 * Snare Audit Dispatcher for Linux - translation table creator
 * (c) Copyright 2010 InterSect Alliance Pty Ltd
 *
 * Compile with gcc -laudit
 **********************************************************/


#include <stdio.h>

extern const char *audit_syscall_to_name(int sc, int machine);
extern int audit_detect_machine(void);

int main()
{
	FILE * fp;
	int machine;
	const char *rsyscall;
	int i;

	fp=fopen("/etc/safed-xlate.conf","w");
	if(!fp) {
		perror("Cannot write to safed-xlate.conf");
		return(1);
	}

	machine=audit_detect_machine();

	for(i=0;i<2048;i++) {
		rsyscall=audit_syscall_to_name(i,machine);
		if(rsyscall) {
			fprintf(fp,"%i:%s\n",i,rsyscall);
		}
	}
	fclose(fp);
	return(0);
}
