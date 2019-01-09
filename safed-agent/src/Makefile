CC = gcc
# Include BUILD cflags if they exist (from spec file)


GNUTLS = $(shell ./checkgnutls.sh)
GNUTLS_D = $(shell ./checkgnutls.sh $(GNUTLS) -d)
GNUTLS_C = $(shell ./checkgnutls.sh $(GNUTLS) -c)
GNUTLS_L = $(shell ./checkgnutls.sh $(GNUTLS) -l)


CFLAGS =  -D TLSPROTOCOL -Wall -O2 $(BCFLAGS)
#CFLAGS = $(GNUTLS_D) -Wall -O2 $(BCFLAGS)
#CFLAGS = -D DEBUG $(GNUTLS_D) -g -O0 $(BCFLAGS)

all: safed

safed: safed.o Configuration.o MemoryCache.o Misc.o webserver.o WebPages.o WebPagesAudit.o webutilities.o MessageFile.o SafedTLS.o
	$(CC) $(LDFLAGS) $^ -lpthread -lcrypt -lnsl -lrt -lwolfssl -o safed
	

SafedTLS.o:	SafedTLS.c SafedTLS.h
	$(CC) $(CFLAGS) -c $< -o $@
webutilities.o:	webutilities.c webutilities.h
	$(CC) $(CFLAGS) -c $< -o $@
MemoryCache.o:	MemoryCache.c MemoryCache.h
	$(CC) $(CFLAGS) -c $< -o $@
Misc.o:	Misc.c Misc.h
	$(CC) $(CFLAGS) -c $< -o $@
MessageFile.o:	MessageFile.c MessageFile.h
	$(CC) $(CFLAGS) -c $< -o $@
webserver.o: webserver.c webserver.h
	$(CC) $(CFLAGS) -c $< -o $@
WebPages.o: WebPages.c WebPages.h
	$(CC) $(CFLAGS) -c $< -o $@
WebPagesAudit.o: WebPagesAudit.c WebPagesAudit.h
	$(CC) $(CFLAGS) -c $< -o $@
Configuration.o: Configuration.c Configuration.h
	$(CC) $(CFLAGS) -c $< -o $@
safed.o: safed.c safed.h
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	rm -f safed core.* *.o
