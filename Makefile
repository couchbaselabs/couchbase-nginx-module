GET := wget -q -O
GUNZIP := gzip -d
PLATFORM = $(shell uname -sm)
MOCK = ./cbgb
PKGNAME := nginx-couchbase-module-$(shell git describe --long)

NGX_VERSIONS := v1.2.6 v1.4.0
AB_CONCURRENCY := 10
AB_REQUESTS := 1000
AB_NGX_CONFIG := etc/nginx.stress.conf
AB_URI := http://localhost:8080/lcb?cmd=set&key=foo&val=bar

all:
	$(MAKE) -C.. all

check:
	@for ver in ${NGX_VERSIONS} ; do \
		echo "==========================" ; \
		echo "Checking with nginx $$ver" ; \
		if (cd ../nginx; git checkout $$ver && git clean -dfx) && \
			$(MAKE) -C.. check ; \
		then \
			res="$$res\n$$ver - OK" ; \
		else \
			res="$$res\n$$ver - FAILURE" ; \
		fi \
	done; \
	printf "$$res\n"

stress:
	@for ver in ${NGX_VERSIONS} ; do \
		echo "==========================" ; \
		echo "Stressing with nginx $$ver" ; \
		pid=`cat ../install/logs/nginx.pid 2>/dev/null` ; \
		if [ -n $$pid ] ; then \
			kill $$pid > /dev/null 2>&1 ; \
		fi ; \
		if (cd ../nginx; git checkout $$ver && git clean -dfx) && \
			$(MAKE) -C.. all WARNINGS= DEBUG=0 && \
			cp $(AB_NGX_CONFIG) ../install/conf/nginx.conf && \
			../install/sbin/nginx && \
			ab -c $(AB_CONCURRENCY) -n $(AB_REQUESTS) '$(AB_URI)' ; \
		then \
			res="$$res\n$$ver - OK" ; \
		else \
			res="$$res\n$$ver - FAILURE" ; \
		fi ; \
		pid=`cat ../install/logs/nginx.pid 2>/dev/null` ; \
		if [ -n $$pid ] ; then \
			kill $$pid > /dev/null 2>&1 ; \
		fi ; \
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
