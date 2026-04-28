package := native_expat
$(package)_version := $(expat_version)
$(package)_download_path := https://github.com/libexpat/libexpat/releases/download/R_$(subst .,_,$($(package)_version))/
$(package)_file_name := expat-$($(package)_version).tar.bz2
$(package)_sha256_hash := $(expat_sha256_hash)

define $(package)_set_vars
$(package)_config_opts := --disable-shared --enable-static
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