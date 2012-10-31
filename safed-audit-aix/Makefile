SUBDIRS = src

all:
	@for i in $(SUBDIRS); do \
	echo "make all in $$i..."; \
	(cd $$i; make all); done

clean:
	@for i in $(SUBDIRS); do \
	echo "make clean in $$i..."; \
	(cd $$i; make clean); done
