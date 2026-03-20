package := native_wayland_scanner
$(package)_version := 1.20.0
$(package)_download_path := https://wayland.freedesktop.org/releases
$(package)_file_name := wayland-$($(package)_version).tar.xz
$(package)_sha256_hash := b8a034154c7059772e0fdbd27dbfcda6c732df29cae56a82274f6ec5d7cd8725
$(package)_dependencies := libffi

define $(package)_config_cmds
  PKG_CONFIG_LIBDIR=$(build_prefix)/lib/pkgconfig \
  PKG_CONFIG_PATH=$(build_prefix)/share/pkgconfig \
  EXPAT_LIBS=$$$$(env -u PKG_CONFIG_LIBDIR PKG_CONFIG_PATH=$(SYSTEM_PKG_CONFIG_PATH) pkg-config --libs expat) \
  EXPAT_CFLAGS=$$$$(env -u PKG_CONFIG_LIBDIR PKG_CONFIG_PATH=$(SYSTEM_PKG_CONFIG_PATH) PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --cflags expat) \
  meson setup build --prefix=$(build_prefix) \
    --libdir=lib \
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
