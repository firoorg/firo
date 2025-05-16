package=libxcb_util_keysyms
$(package)_version=0.4.1
$(package)_download_path=https://xcb.freedesktop.org/dist
$(package)_file_name=xcb-util-keysyms-$($(package)_version).tar.xz
$(package)_sha256_hash=7c260a5294412aed429df1da2f8afd3bd07b7cba3fec772fba15a613a6d5c638
$(package)_dependencies=libxcb xproto

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
