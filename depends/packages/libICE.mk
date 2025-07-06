package=libICE
$(package)_version=1.1.2
$(package)_download_path=http://xorg.freedesktop.org/releases/individual/lib/
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=974e4ed414225eb3c716985df9709f4da8d22a67a2890066bc6dfc89ad298625
$(package)_dependencies=xtrans xproto

define $(package)_set_vars
  $(package)_config_opts=--disable-docs --disable-specs --without-xsltproc
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
