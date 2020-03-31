
all: build/libchiabls.a

build/libchiabls.a:
	$(AM_V_at)$(MAKE) -C ./build/

.PHONY distdir: 
	cp -r $(srcdir). $(distdir)
	rm -rf $(distdir)/build/

clean: 
	$(AM_V_at)$(MAKE) -C ./build/ clean
	rm -f ./build/libchiabls.a
	
distclean:
	rm -rf ./build/

check: all
	./build/src/runtest

install:
	$(AM_V_at)$(MAKE) -C ./build/ install
