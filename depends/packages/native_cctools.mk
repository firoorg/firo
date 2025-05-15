package=native_cctools
$(package)_version=877.8-ld64-253.9-1
$(package)_download_path=https://github.com/tpoechtrager/cctools-port/archive
$(package)_file_name=cctools-$($(package)_version).tar.gz
$(package)_sha256_hash=c88b0631b1d7bb5186dd6466a62f5220dc6191f2b2d9c7c122b327385e734aaf
$(package)_build_subdir=cctools
$(package)_dependencies=native_libtapi

define $(package)_set_vars
  $(package)_config_opts=--target=$(host)
  $(package)_ldflags+=-Wl,-rpath=\\$$$$$$$$\$$$$$$$$ORIGIN/../lib
  ifeq ($(strip $(FORCE_USE_SYSTEM_CLANG)),)
  $(package)_config_opts+=--enable-lto-support --with-llvm-config=$(build_prefix)/bin/llvm-config
  endif
  $(package)_cc=$(clang_prog)
  $(package)_cxx=$(clangxx_prog)
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub cctools
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share
endef
