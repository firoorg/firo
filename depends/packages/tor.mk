PACKAGE=tor
$(package)_version=0.4.3.5
$(package)_download_path=https://archive.torproject.org/tor-package-archive
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=616a0e4ae688d0e151d46e3e4258565da4d443d1ddbd316db0b90910e2d5d868
$(package)_dependencies=zlib openssl libevent
$(package)_patches = configure.patch
$(package)_lib_files = \
    src/core/libtor-app.a \
    src/lib/libtor-meminfo.a \
    src/lib/libtor-term.a \
    src/lib/libtor-osinfo.a \
    src/lib/libtor-geoip.a \
    src/lib/libtor-math.a \
    src/lib/libtor-tls.a \
    src/lib/libtor-process.a \
    src/lib/libtor-evloop.a \
    src/lib/libtor-thread.a \
    src/lib/libtor-compress.a \
    src/lib/libtor-net.a \
    src/lib/libtor-buf.a \
    src/lib/libtor-time.a \
    src/lib/libtor-err.a \
    src/lib/libtor-log.a \
    src/lib/libtor-pubsub.a \
    src/lib/libtor-dispatch.a \
    src/lib/libtor-confmgt.a \
    src/lib/libtor-container.a \
    src/lib/libtor-crypt-ops.a \
    src/lib/libtor-fs.a \
    src/lib/libtor-fdio.a \
    src/lib/libtor-sandbox.a \
    src/lib/libtor-memarea.a \
    src/lib/libtor-encoding.a \
    src/lib/libtor-smartlist-core.a \
    src/lib/libtor-lock.a \
    src/lib/libtor-wallclock.a \
    src/lib/libtor-string.a \
    src/lib/libtor-malloc.a \
    src/lib/libtor-version.a \
    src/lib/libtor-intmath.a \
    src/lib/libtor-ctime.a \
    src/trunnel/libor-trunnel.a \
    src/lib/libcurve25519_donna.a \
    src/ext/ed25519/donna/libed25519_donna.a \
    src/ext/ed25519/ref10/libed25519_ref10.a \
    src/ext/keccak-tiny/libkeccak-tiny.a

define $(package)_set_vars
  $(package)_config_opts+=--disable-system-torrc --disable-systemd --disable-lzma --disable-asciidoc --disable-libscrypt --disable-gcc-hardening --enable-pic --disable-unittests --disable-tool-name-check
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub . && \
  patch -p1 < $($(package)_patch_dir)/configure.patch
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) && \
  mkdir objfiles && cd objfiles && \
  for lib in $($(package)_lib_files); do \
    (l=$$$${lib##*/} && mkdir $$$$l && cd $$$$l && $($(package)_ar) x ../../$$$${lib}); \
  done && \
  $($(package)_ar) cr libtor.a `find . -name *.o | LC_ALL=C sort`
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/lib && \
  install -m 644 objfiles/libtor.a $($(package)_staging_prefix_dir)/lib
endef
