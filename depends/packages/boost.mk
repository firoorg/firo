package=boost
$(package)_version=1.81.0
$(package)_download_path=https://archives.boost.io/release/$($(package)_version)/source/
$(package)_file_name=boost_$(subst .,_,$($(package)_version)).tar.bz2
$(package)_sha256_hash=71feeed900fbccca04a3b4f2f84a7c217186f28a940ed8b7ed4725986baf99fa
$(package)_dependencies=native_b2

define $(package)_set_vars
$(package)_config_opts_release=variant=release
$(package)_config_opts_debug=variant=debug
$(package)_config_opts+=--layout=system --user-config=user-config.jam
$(package)_config_opts+=threading=multi link=static -sNO_BZIP2=1 -sNO_ZLIB=1
$(package)_config_opts_linux=threadapi=pthread runtime-link=shared
$(package)_config_opts_android=threadapi=pthread runtime-link=static target-os=android
$(package)_config_opts_darwin=--toolset=darwin runtime-link=shared target-os=darwin
$(package)_config_opts_mingw32=binary-format=pe target-os=windows threadapi=win32 runtime-link=static
$(package)_config_opts_x86_64_mingw32=address-model=64
$(package)_config_opts_i686_mingw32=address-model=32
$(package)_config_opts_i686_linux=address-model=32 architecture=x86
$(package)_toolset_$(host_os)=gcc
$(package)_archiver_$(host_os)=$($(package)_ar)
$(package)_toolset_darwin=darwin
$(package)_cxxflags=-std=c++17
$(package)_cxxflags_linux+=-fPIC
$(package)_cxxflags_freebsd+=-fPIC
$(package)_cxxflags_darwin+=-ffile-prefix-map=$($(package)_extract_dir)=/usr
endef

define $(package)_preprocess_cmds
  echo "using $($(package)_toolset_$(host_os)) : : $($(package)_cxx) : <cflags>\"$($(package)_cflags)\" <cxxflags>\"$($(package)_cxxflags)\" <compileflags>\"$($(package)_cppflags)\" <linkflags>\"$($(package)_ldflags)\" <archiver>\"$($(package)_archiver_$(host_os))\" <striper>\"$(host_STRIP)\"  <ranlib>\"$(host_RANLIB)\" <rc>\"$(host_WINDRES)\" : ;" > user-config.jam && cat user-config.jam
endef

# Detect if GUIX_ENVIRONMENT is set AND it is compiling to apple then patch with fix_boost_jam_cross-compilation.patch
define $(package)_config_cmds
  ./bootstrap.sh --without-icu --with-toolset=$($(package)_toolset_$(host_os)) --with-bjam=b2 && \
  if [ -n "$$GUIX_ENVIRONMENT" ] && [ "$(host_os)" = "darwin" ]; then \
    echo "GUIX_ENVIRONMENT detected and building for Darwin - applying patch"; \
    echo "Patching with fix_boost_jam_cross-compilation.patch"; \
    patch -p1 < $($(package)_patch_dir)/fix_boost_jam_cross-compilation.patch; \
  else \
    echo "Skipping patch: GUIX_ENVIRONMENT=$$GUIX_ENVIRONMENT, host_os=$(host_os)"; \
  fi
endef

define $(package)_build_cmds
  b2 -d2 -j`nproc` -d1 --prefix=$($(package)_staging_prefix_dir) $($(package)_config_opts) toolset=$($(package)_toolset_$(host_os)) --with-atomic --with-chrono --with-filesystem --with-program_options --with-system --with-thread --with-test --no-cmake-config stage
endef

define $(package)_stage_cmds
  b2 -d2 -j`nproc` --prefix=$($(package)_staging_prefix_dir) $($(package)_config_opts) toolset=$($(package)_toolset_$(host_os)) --with-atomic --with-chrono --with-filesystem --with-program_options --with-system --with-thread --with-test --no-cmake-config install
endef