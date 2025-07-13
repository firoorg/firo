package=zlib
$(package)_version=1.3.1
$(package)_download_path=http://www.zlib.net
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23

define $(package)_set_vars
$(package)_build_opts= CC="$($(package)_cc)"
$(package)_build_opts+=CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC"
$(package)_build_opts+=RANLIB="$($(package)_ranlib)"
$(package)_build_opts+=AR="$($(package)_ar)"
$(package)_build_opts_darwin+=AR="$($(package)_libtool)"
$(package)_build_opts_darwin+=ARFLAGS="-o"
endef

define $(package)_config_cmds
  ./configure --static --prefix=$(host_prefix)
endef

define $(package)_build_cmds
  $(MAKE) $($(package)_build_opts) libz.a
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install $($(package)_build_opts)
endef

