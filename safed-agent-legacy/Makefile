SUBDIRS = src
TESTDIRS = test

all:
	@for i in $(SUBDIRS); do \
	echo "make all in $$i..."; \
	(cd $$i; make all); done
	cp src/safed .

clean:
	rm -f safed
	@for i in $(SUBDIRS); do \
	echo "make clean in $$i..."; \
	(cd $$i; make clean); done

compiletest:
	@for i in $(TESTDIRS); do \
	echo "make all in $$i..."; \
	(cd $$i; make all); done

testall:
	@for i in $(TESTDIRS); do \
	echo "make test in $$i..."; \
	(cd $$i; make test); done
