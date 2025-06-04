package=zlib
$(package)_version=1.3.1
$(package)_download_path=http://www.zlib.net
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23

define $(package)_set_vars
$(package)_cflags=-fPIC
$(package)_cxxflags=-fPIC
endef

define $(package)_config_cmds
  echo "Configuring $($(package)_file_name) for $($(package)_staging_dir)" && \
  cmake -S . -B . -DZLIB_BUILD_TESTING=OFF -DCMAKE_PREFIX_PATH=$($(package)_staging_dir)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

