package=expat
$(package)_version=2.7.1
$(package)_download_path=https://github.com/libexpat/libexpat/releases/download/R_2_7_1/
$(package)_file_name=$(package)-$($(package)_version).tar.bz2
$(package)_sha256_hash=45c98ae1e9b5127325d25186cf8c511fa814078e9efeae7987a574b482b79b3d

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
