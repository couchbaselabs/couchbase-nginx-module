GET := wget -q -O
GUNZIP := gzip -d
PLATFORM = $(shell uname -sm)
MOCK = ./cbgb
PKGNAME := nginx-couchbase-module-$(shell git describe --long)

all:
	$(MAKE) -C.. all

check:
	$(MAKE) -C.. check

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
