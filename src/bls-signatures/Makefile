
all: build/libchiabls.la

build/libchiabls.la:
	$(AM_V_at)$(MAKE) -C ./build/

.PHONY distdir: 
	cp -r $(srcdir). $(distdir)
	rm -rf $(distdir)/build/

clean: 
	$(AM_V_at)$(MAKE) -C ./build/ clean
	rm -f ./build/libchiabls.la ./build/.libs/libchiabls.a
	
distclean:
	rm -rf ./build/

check: all

install:
# do nothing
