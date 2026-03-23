package := libglvnd
$(package)_version := 1.4.0
$(package)_download_path := https://gitlab.freedesktop.org/glvnd/$(package)/-/archive/v$($(package)_version)
$(package)_file_name := $(package)-v$($(package)_version).tar.bz2
$(package)_sha256_hash := fdf395391d95f270528dbff6ce2ee54c186753d286ad62e0da5f62c6f67ba915

define $(package)_set_vars
  $(package)_config_opts := --enable-option-checking --disable-dependency-tracking
  $(package)_config_opts += --enable-shared --disable-static
  $(package)_config_opts += --disable-x11 --disable-gles1
endef

define $(package)_config_cmds
  PKG_CONFIG_LIBDIR=$(host_prefix)/lib/pkgconfig \
  CC="$$($(package)_cc)" CXX="$$($(package)_cxx)" \
  CFLAGS="$$($(package)_cppflags) $$($(package)_cflags)" \
  CXXFLAGS="$$($(package)_cppflags) $$($(package)_cxxflags)" \
  LDFLAGS="$$($(package)_ldflags)" \
  meson setup build --prefix=$(host_prefix) \
    --libdir=lib \
    --default-library=shared \
    -Dx11=disabled \
    -Dgles1=false
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
