package=freetype
$(package)_version=2.13.3
$(package)_download_path=https://download.savannah.gnu.org/releases/$(package)
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=0550350666d427c74daeb85d5ac7bb353acba5f76956395995311a9c6f063289

define $(package)_set_vars
  $(package)_config_opts=--without-zlib --without-png --without-harfbuzz --without-bzip2
  $(package)_config_opts += --enable-option-checking
  $(package)_config_opts_linux=--with-pic
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
  rm lib/*.la
endef
