
all: build/libchiabls.a

build/libchiabls.a:
	$(AM_V_at)$(MAKE) -C ./build/

.PHONY distdir: 
	cp -r $(srcdir). $(distdir)

clean: 
	$(MAKE) -C ./build/ clean
	rm -f ./build/libchiabls.a
	
distclean:
	rm -rf ./build/
