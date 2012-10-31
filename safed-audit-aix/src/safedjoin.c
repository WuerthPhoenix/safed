#include <stdio.h>
#include <strings.h>

#define NORMAL 1
#define TRAIL 2
int main()
{
	char inbuffer[8192];
	int LastEvent=0;

	while(fgets(inbuffer,sizeof(inbuffer),stdin)) {
		// Kill the newline
		if(strlen(inbuffer) <= 1) {
			continue;
		}
		inbuffer[strlen(inbuffer)-1]='\0';
		if(inbuffer[0]==' ') {
			LastEvent=TRAIL;
			printf("	%s\n",inbuffer);
			fflush(stdout);
		} else {
			if(LastEvent==NORMAL) {
				putc('\n',stdout);
				fflush(stdout);
			}
			printf("%s",inbuffer);
			LastEvent=NORMAL;
		}
	}
	fflush(stdout);
	return(0);
}
