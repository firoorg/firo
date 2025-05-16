package=libxcb_util_render
$(package)_version=0.3.10
$(package)_download_path=https://xcb.freedesktop.org/dist
$(package)_file_name=xcb-util-renderutil-$($(package)_version).tar.xz
$(package)_sha256_hash=3e15d4f0e22d8ddbfbb9f5d77db43eacd7a304029bf25a6166cc63caa96d04ba
$(package)_dependencies=libxcb

define $(package)_set_vars
$(package)_config_opts=--disable-devel-docs --without-doxygen
$(package)_config_opts += --disable-dependency-tracking --enable-option-checking
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub .
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
  rm -rf share/man share/doc lib/*.la
endef
