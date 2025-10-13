package=native_cmake
$(package)_version=3.27.9
$(package)_download_path=https://cmake.org/files/v3.27/
$(package)_file_name=cmake-$($(package)_version).tar.gz
$(package)_sha256_hash=609a9b98572a6a5ea477f912cffb973109ed4d0a6a6b3f9e2353d2cdc048708e

define $(package)_set_vars
  $(package)_config_opts=
endef

define $(package)_config_cmds
  ./bootstrap --prefix=$(build_prefix)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
