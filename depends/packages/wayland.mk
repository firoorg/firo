package := wayland
native_package := native_wayland_scanner
$(package)_version = $($(native_package)_version)
$(package)_download_path = $($(native_package)_download_path)
$(package)_file_name = $($(native_package)_file_name)
$(package)_sha256_hash = $($(native_package)_sha256_hash)
$(package)_dependencies = $(native_package) libffi expat

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
      "strip = '$$($(package)_ranlib)'" \
      "pkg-config = 'pkg-config'" \
      "" \
      "[built-in options]" \
      "pkg_config_path = ['$(host_prefix)/lib/pkgconfig', '$(build_prefix)/lib/pkgconfig', '$(host_prefix)/share/pkgconfig']" \
      "" \
      "[host_machine]" \
      "system = 'linux'" \
      "cpu_family = '$(host_arch)'" \
      "cpu = '$(host_arch)'" \
      "endian = 'little'" \
      > cross.ini ; \
    cross_arg="--cross-file cross.ini" ; \
  fi && \
  PKG_CONFIG_LIBDIR=$(host_prefix)/lib/pkgconfig:$(build_prefix)/lib/pkgconfig \
  PKG_CONFIG_PATH=$(host_prefix)/share/pkgconfig \
  CC="$$($(package)_cc)" CXX="$$($(package)_cxx)" \
  CFLAGS="-D_GNU_SOURCE $$($(package)_cppflags) $$($(package)_cflags)" \
  CXXFLAGS="$$($(package)_cppflags) $$($(package)_cxxflags)" \
  LDFLAGS="$$($(package)_ldflags)" \
  meson setup build --prefix=$(host_prefix) \
    $$$$cross_arg \
    --libdir=lib \
    --default-library=static \
    -Dlibraries=true \
    -Dscanner=false \
    -Ddocumentation=false \
    -Dtests=false \
    -Ddtd_validation=false
endef

define $(package)_build_cmds
  LD_LIBRARY_PATH="$(host_prefix)/lib:$(build_prefix)/lib$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}" \
  ninja -C build
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) ninja -C build install
endef

define $(package)_postprocess_cmds
  rm -f lib/*.la
endef
