package := libglvnd
$(package)_version := 1.4.0
$(package)_download_path := https://gitlab.freedesktop.org/glvnd/$(package)/-/archive/v$($(package)_version)
$(package)_file_name := $(package)-v$($(package)_version).tar.bz2
$(package)_sha256_hash := fdf395391d95f270528dbff6ce2ee54c186753d286ad62e0da5f62c6f67ba915
$(package)_patches := fix-typeof-gcc14.patch

define $(package)_set_vars
  $(package)_config_opts := --enable-option-checking --disable-dependency-tracking
  $(package)_config_opts += --enable-shared --disable-static
  $(package)_config_opts += --disable-x11 --disable-gles1
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/fix-typeof-gcc14.patch
endef

define $(package)_config_cmds
  cross_arg="" ; \
  if [ "$(host)" != "$(build)" ]; then \
    CC="$$($(package)_cc)" ; \
    CXX="$$($(package)_cxx)" ; \
    cc_first=$$$${CC%% *} ; \
    cc_rest=$$$${CC#* } ; \
    cxx_first=$$$${CXX%% *} ; \
    cxx_rest=$$$${CXX#* } ; \
    if [ "$$$$cc_first" = "$$$$CC" ]; then \
      cc_line="c = ['$$$$CC']" ; \
    else \
      cc_line="c = ['$$$$cc_first', '$$$$cc_rest']" ; \
    fi ; \
    if [ "$$$$cxx_first" = "$$$$CXX" ]; then \
      cxx_line="cpp = ['$$$$CXX']" ; \
    else \
      cxx_line="cpp = ['$$$$cxx_first', '$$$$cxx_rest']" ; \
    fi ; \
    printf '%s\n' "[binaries]" "$$$$cc_line" "$$$$cxx_line" \
      "ar = '$$($(package)_ar)'" \
      "pkg-config = 'pkg-config'" \
      "strip = '$(host_STRIP)'" \
      "" \
      "[built-in options]" \
      "pkg_config_path = ['$(host_prefix)/lib/pkgconfig', '$(host_prefix)/share/pkgconfig']" \
      "" \
      "[properties]" \
      "needs_exe_wrapper = true" \
      "" \
      "[host_machine]" \
      "system = 'linux'" \
      "cpu_family = '$(host_arch)'" \
      "cpu = '$(host_arch)'" \
      "endian = 'little'" \
      > cross.ini ; \
    cross_arg="--cross-file cross.ini" ; \
  fi && \
  PKG_CONFIG_LIBDIR=$(host_prefix)/lib/pkgconfig \
  PKG_CONFIG_PATH=$(host_prefix)/share/pkgconfig \
  CC="$$($(package)_cc)" CXX="$$($(package)_cxx)" \
  CFLAGS="$$($(package)_cppflags) $$($(package)_cflags) -D_GNU_SOURCE" \
  CXXFLAGS="$$($(package)_cppflags) $$($(package)_cxxflags)" \
  LDFLAGS="$$($(package)_ldflags)" \
  meson setup build --prefix=$(host_prefix) \
    $$$$cross_arg \
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
