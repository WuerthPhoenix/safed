SAFED-VERSION=1.6.0
bindir = $(prefix)/usr/sbin
confdir = $(prefix)/etc
safedpipe = $(prefix)/tmp/safedpipe

CC = gcc
# Include BUILD cflags if they exist (from spec file)
CFLAGS = -Wall $(BCFLAGS)
#CFLAGS = -Wall -O2 $(BCFLAGS)

all: xlate SafedDH

xlate: SafedTranslationTable.o
	$(CC) $(LDFLAGS) -l audit -o SafedTranslationTable $^

SafedTranslationTable.o: SafedTranslationTable.c
	$(CC) $(CFLAGS) -c $< -o $@

SafedDH: SafedDispatchHelper.o
	$(CC) $(LDFLAGS) -laudit -lpthread -o SafedDispatchHelper $^
	chmod 750 SafedDispatchHelper

SafedDispatchHelper.o: SafedDispatchHelper.c
	$(CC) $(CFLAGS) -c $< -o $@

semodule:
	checkmodule -M -m -o safed.mod safed.te
	semodule_package -o safed.pp -m safed.mod

install:
	cp SafedDispatcher.pl $(bindir)/SafedDispatcher
	cp SafedDispatchHelper $(bindir)/SafedDispatchHelper
	chmod 750 $(bindir)/SafedDispatchHelper
	cp SafedTranslationTable $(bindir)/SafedTranslationTable
	if [ ! -d $(confdir) ]; then mkdir -p $(confdir);fi
	if [ ! -p $(safedpipe) ]; then mkfifo $(safedpipe);fi
	$(bindir)/SafedTranslationTable
	./Installer.sh -i $(confdir) $(bindir) $(safedpipe)

uninstall:
	if [ -f $(bindir)/SafedDispatcher ]; then rm -f $(bindir)/SafedDispatcher;fi
	if [ -f $(bindir)/SafedDispatchHelper ]; then rm -f $(bindir)/SafedDispatchHelper;fi
#	if [ -p $(safedpipe) ]; then rm -f $(safedpipe);fi
	./Installer.sh -u $(confdir) $(bindir) $(safedpipe)
	if [ -f $(confdir)/safed-xlate.conf ]; then rm -f $(confdir)/safed-xlate.conf; fi

clean:
	rm -f SafedTranslationTable SafedDispatchHelper core.* *.o
