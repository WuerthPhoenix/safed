# Set this to your installation directory.

SAFED-VERSION=1.6.0

CC = gcc
# Include BUILD cflags if they exist (from spec file)
CFLAGS = -Wall -O2 $(BCFLAGS)

all: safedcore safedjoin test

test:
	$(CC) $(LDFLAGS) -o bintest bintest.c

safedcore: safedcore.o
	$(CC) $(LDFLAGS) -O2 -o safedcore safedcore.o

safedjoin: safedjoin.o

safedjoin.o: safedjoin.c
	$(CC) $(CFLAGS) -c $< -o $@

safedcore.o: safedcore.c safedcore.h
	$(CC) $(CFLAGS) -c $< -o $@

install: safedcore safedjoin
	echo "Please use the install.sh script"

clean:
	rm -f bintest safedcore safedjoin core.* *.o

oclean:
	rm -f core.* *.o
