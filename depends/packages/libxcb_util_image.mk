package=libxcb_util_image
$(package)_version=0.4.1
$(package)_download_path=https://xcb.freedesktop.org/dist
$(package)_file_name=xcb-util-image-$($(package)_version).tar.xz
$(package)_sha256_hash=ccad8ee5dadb1271fd4727ad14d9bd77a64e505608766c4e98267d9aede40d3d
$(package)_dependencies=libxcb libxcb_util

define $(package)_set_vars
$(package)_config_opts=--disable-devel-docs --without-doxygen
$(package)_config_opts+= --disable-dependency-tracking --enable-option-checking
$(package)_config_opts+= --disable-shared
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
  rm -rf share/man share/doc lib/*.la && mkdir -p _util && (cd _util && ar x $(host_prefix)/lib/libxcb-util.a) && ar qc lib/libxcb-image.a _util/*.o && ranlib lib/libxcb-image.a && rm -rf _util
endef
