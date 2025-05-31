package=libXext
$(package)_version=1.3.6
$(package)_download_path=http://xorg.freedesktop.org/releases/individual/lib/
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=edb59fa23994e405fdc5b400afdf5820ae6160b94f35e3dc3da4457a16e89753
$(package)_dependencies=xproto libXau

define $(package)_set_vars
  $(package)_config_opts=
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
