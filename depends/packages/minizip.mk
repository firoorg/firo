package=minizip
parent_package=zlib
$(package)_version=1.2.11
$(package)_download_path=http://www.zlib.net
$(package)_file_name=$(parent_package)-$($(package)_version).tar.gz
$(package)_sha256_hash=c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1
$(package)_build_subdir=contrib/$(package)
$(package)_dependencies=$(parent_package)

define $(package)_set_vars
$(package)_cxxflags_linux=-fPIC
$(package)_build_opts_darwin= CC="$($(package)_cc)"
$(package)_build_opts_darwin+=CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC"
$(package)_config_opts_linux=--with-pic
$(package)_config_opts_darwin= AR="$($(package)_ar)"
$(package)_config_opts_darwin+=RANLIB="$($(package)_ranlib)"
$(package)_config_opts_darwin+=LIBTOOL="$($(package)_libtool)"
$(package)_config_opts_darwin+=LDFLAGS="$($(package)_ldflags)"
$(package)_config_opts_darwin+=CFLAGS="-pipe"
$(package)_config_opts_mingw32= --host=${HOST}
$(package)_config_opts=--prefix=$(host_prefix)
$(package)_config_opts+=--enable-shared=no
endef

define $(package)_config_cmds
  autoreconf -fi; \
  ./configure $($(package)_config_opts); \
  sed -i 's|-DPACKAGE_STRING=\\\"minizip\\\ 1.2.11\\\"|-DPACKAGE_STRING=\"minizip-1.2.11\"|g' Makefile; \
  sed -i 's|PACKAGE_STRING = minizip 1.2.11|PACKAGE_STRING = minizip-1.2.11|g' Makefile
endef

define $(package)_build_cmds
  $(MAKE) $($(package)_build_opts)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install $($(package)_build_opts)
endef