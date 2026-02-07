package := libffi
$(package)_version := 3.5.2
$(package)_download_path := https://github.com/libffi/$(package)/releases/download/v$($(package)_version)
$(package)_file_name := $(package)-$($(package)_version).tar.gz
$(package)_sha256_hash := f3a3082a23b37c293a4fcd1053147b371f2ff91fa7ea1b2a52e335676bac82dc

define $(package)_set_vars
  $(package)_config_opts := --enable-option-checking --disable-dependency-tracking
  $(package)_config_opts += --enable-shared --disable-static --disable-docs
  $(package)_config_opts += --disable-multi-os-directory
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
