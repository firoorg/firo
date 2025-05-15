package=libXext
$(package)_version=1.3.6
$(package)_download_path=http://xorg.freedesktop.org/releases/individual/lib/
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=74d0e4dfa3d39ad8939e99bda37f5967aba528211076828464d2777d477fc0fb
$(package)_dependencies=xproto xextproto libX11 libXau

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
