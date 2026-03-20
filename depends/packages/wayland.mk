package := wayland
native_package := native_wayland_scanner
$(package)_version = $($(native_package)_version)
$(package)_download_path = $($(native_package)_download_path)
$(package)_file_name = $($(native_package)_file_name)
$(package)_sha256_hash = $($(native_package)_sha256_hash)
$(package)_dependencies = $(native_package) libffi expat

define $(package)_config_cmds
  PKG_CONFIG_LIBDIR=$(host_prefix)/lib/pkgconfig:$(build_prefix)/lib/pkgconfig \
  PKG_CONFIG_PATH=$(host_prefix)/share/pkgconfig \
  CC="$$($(package)_cc)" CXX="$$($(package)_cxx)" \
  CFLAGS="-D_GNU_SOURCE $$($(package)_cppflags) $$($(package)_cflags)" \
  CXXFLAGS="$$($(package)_cppflags) $$($(package)_cxxflags)" \
  LDFLAGS="$$($(package)_ldflags)" \
  meson setup build --prefix=$(host_prefix) \
    --libdir=lib \
    -Dlibraries=true \
    -Dscanner=false \
    -Ddocumentation=false \
    -Dtests=false \
    -Ddtd_validation=false
endef

define $(package)_build_cmds
  ninja -C build
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) ninja -C build install
endef

define $(package)_postprocess_cmds
  rm -f lib/*.la
endef
