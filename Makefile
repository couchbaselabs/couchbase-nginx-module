GET := wget -q -O
GUNZIP := gzip -d
PLATFORM = $(shell uname -sm)
MOCK = ./cbgb
PKGNAME := nginx-couchbase-module-$(shell git describe --long)

NGX_VERSIONS := v1.2.6 v1.4.0

all:
	$(MAKE) -C.. all

check:
	@for ver in ${NGX_VERSIONS} ; do \
		echo "==========================" ; \
		echo "Checking with nginx $$ver" ; \
		if (cd ../nginx; git checkout $$ver) && \
			$(MAKE) -C../nginx clean && \
			$(MAKE) -C.. check ; \
		then \
			res="$$res\n$$ver - OK" ; \
		else \
			res="$$res\n$$ver - FAILURE" ; \
		fi \
	done; \
	printf "$$res\n"

cbgb-run: cbgb
	$(MOCK) > $(MOCK).log 2>&1 &
	@echo wait 1 seconds until cbgb will start
	@sleep 1

cbgb:
ifeq ($(PLATFORM),Linux x86_64)
	$(GET) $(MOCK).gz http://cbgb.io/cbgb.lin64.gz
else
	@echo "Unknown OS. Update cbgb target in Makefile"
	@exit 1
endif
	$(GUNZIP) $(MOCK).gz
	chmod a+x $(MOCK)

dist:
	git clean -dfx
	mkdir $(PKGNAME)
	cp -a config src etc doc README.markdown t $(PKGNAME)
	tar cf - $(PKGNAME) | gzip -9 - > $(PKGNAME).tar.gz
	rm -rf $(PKGNAME)
