package=gmp
$(package)_version=6.2.1
$(package)_download_path=https://ftp.gnu.org/gnu/gmp/
$(package)_file_name=gmp-$($(package)_version).tar.bz2
$(package)_sha256_hash=eae9326beb4158c386e39a356818031bd28f3124cf915f8c5b1dc4c7a36b4d7c
$(package)_patches=applem1.patch

define $(package)_set_vars
$(package)_config_opts+=--enable-cxx --with-pic --disable-shared
ifndef GUIX_ENVIRONMENT
  $(package)_config_opts += --enable-fat
else
  ifneq ($(HOST),x86_64-apple-darwin)
    $(package)_config_opts += --enable-fat
  endif
endif
$(package)_config_opts_arm64_darwin+=--build=$(BUILD) --host=$(subst arm64,aarch64,$(HOST))
$(package)_cflags_armv7l_linux+=-march=armv7-a
$(package)_config_opts_mingw32+=CC_FOR_BUILD=gcc gmp_cv_prog_exeext_for_build=
endef

# Guix tries to use lld as the linker, but it does not support arm64-darwin
# --disable-assembly needs to disable fat
ifdef GUIX_ENVIRONMENT
$(package)_cflags_darwin+=-fuse-ld=lld
$(package)_cxxflags_darwin+=-fuse-ld=lld
$(package)_config_opts_x86_64_darwin+=--disable-assembly
endif

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_preprocess_cmds
  patch -p1 <$($(package)_patch_dir)/applem1.patch
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef