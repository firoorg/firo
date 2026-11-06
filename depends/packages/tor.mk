PACKAGE=tor
$(package)_version=0.4.9.15
$(package)_download_path=https://archive.torproject.org/tor-package-archive
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=1911f5b216a6814ed143a08bbcff1c6dc96d2ca3b505df9a21876080a92963f3
$(package)_dependencies=zlib openssl libevent
$(package)_patches = configure.patch

define $(package)_set_vars
  $(package)_config_opts+=--disable-system-torrc --disable-systemd --disable-lzma --disable-asciidoc --disable-libscrypt --disable-gcc-hardening --enable-pic --disable-unittests --disable-tool-name-check --disable-seccomp ac_cv_header_sys_capability_h=no ac_cv_lib_cap_cap_init=no ac_cv_func_cap_set_proc=no
  $(package)_cflags+=-std=gnu11 -fPIC
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub . && \
  patch -p1 < $($(package)_patch_dir)/configure.patch
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) libtor.a
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/lib && \
  install -m 644 libtor.a $($(package)_staging_prefix_dir)/lib
endef
