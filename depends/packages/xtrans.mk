package=xtrans
$(package)_version=1.6.0
$(package)_download_path=http://xorg.freedesktop.org/releases/individual/lib/
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=faafea166bf2451a173d9d593352940ec6404145c5d1da5c213423ce4d359e92
$(package)_dependencies=

define $(package)_set_vars
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
