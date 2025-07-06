package=libSM
$(package)_version=1.2.6
$(package)_download_path=http://xorg.freedesktop.org/releases/individual/lib/
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=be7c0abdb15cbfd29ac62573c1c82e877f9d4047ad15321e7ea97d1e43d835be
$(package)_dependencies=xtrans xproto libICE

define $(package)_set_vars
  $(package)_config_opts=--without-libuuid  --without-xsltproc  --disable-docs
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
