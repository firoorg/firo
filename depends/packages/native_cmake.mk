package=native_cmake
$(package)_version=3.22.2
$(package)_download_path=https://cmake.org/files/v3.22/
$(package)_file_name=cmake-$($(package)_version).tar.gz
$(package)_sha256_hash=3c1c478b9650b107d452c5bd545c72e2fad4e37c09b89a1984b9a2f46df6aced

define $(package)_set_vars
  $(package)_config_opts=
endef

define $(package)_config_cmds
  ./bootstrap --prefix=$(build_prefix) -- -DCMAKE_USE_OPENSSL=OFF
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
