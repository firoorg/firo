package=native_protobuf
$(package)_version=30.2
$(package)_download_path=https://github.com/google/protobuf/releases/download/v$($(package)_version)
$(package)_file_name=protobuf-$($(package)_version).tar.gz
$(package)_sha256_hash=fb06709acc393cc36f87c251bb28a5500a2e12936d4346099f2c6240f6c7a941

define $(package)_set_vars
$(package)_config_opts=--disable-shared --without-zlib
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) -C src protoc
endef

define $(package)_stage_cmds
  $(MAKE) -C src DESTDIR=$($(package)_staging_dir) install-strip
endef

define $(package)_postprocess_cmds
  rm -rf lib include
endef
