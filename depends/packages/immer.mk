package=immer
$(package)_version=0.9.1
$(package)_download_path=https://github.com/arximboldi/immer/archive/refs/tags
$(package)_download_file=v$($(package)_version).tar.gz
$(package)_file_name=$(package)-$($(package)_download_file)
$(package)_sha256_hash=b18b92ba60ec3186dc36ef671d3c2ae542cbb63eb6dc0e258476c6111a67c971

define $(package)_set_vars
$(package)_config_opts := -Dimmer_BUILD_TESTS=OFF
$(package)_config_opts += -Dimmer_BUILD_EXAMPLES=OFF
$(package)_config_opts += -Dimmer_BUILD_DOCS=OFF
$(package)_config_opts += -Dimmer_BUILD_EXTRAS=OFF
endef

define $(package)_config_cmds
  $($(package)_cmake) -S . -B .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
