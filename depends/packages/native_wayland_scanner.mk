package := native_wayland_scanner
$(package)_version := 1.20.0
$(package)_download_path := https://wayland.freedesktop.org/releases
$(package)_file_name := wayland-$($(package)_version).tar.xz
$(package)_sha256_hash := b8a034154c7059772e0fdbd27dbfcda6c732df29cae56a82274f6ec5d7cd8725
$(package)_dependencies := libffi expat

define $(package)_config_cmds
  PKG_CONFIG_LIBDIR=$(host_prefix)/lib/pkgconfig:$(build_prefix)/lib/pkgconfig \
  PKG_CONFIG_PATH=$(build_prefix)/share/pkgconfig \
  CC="$$($(package)_cc)" CXX="$$($(package)_cxx)" \
  meson setup build --prefix=$(build_prefix) \
    --libdir=lib \
    -Dc_link_args="['-Wl,-rpath,$(build_prefix)/lib', '-Wl,-rpath,$(host_prefix)/lib']" \
    -Dlibraries=false \
    -Dscanner=true \
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
