package=qt
include packages/qt_details.mk
$(package)_version=$(qt_details_version)
$(package)_download_path=$(qt_details_download_path)
$(package)_file_name=$(qt_details_qtbase_file_name)
$(package)_sha256_hash=$(qt_details_qtbase_sha256_hash)
ifneq ($(host),$(build))
$(package)_dependencies := native_$(package)
endif
$(package)_linux_dependencies := freetype fontconfig libxcb libxkbcommon libxcb_util libxcb_util_cursor libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm
$(package)_freebsd_dependencies := $($(package)_linux_dependencies)
$(package)_patches_path := $(qt_details_patches_path)
$(package)_patches := dont_hardcode_pwd.patch
$(package)_patches += qtbase-moc-ignore-gcc-macro.patch
$(package)_patches += qtbase_avoid_native_float16.patch
$(package)_patches += qtbase_avoid_qmain.patch
$(package)_patches += qtbase_platformsupport.patch
$(package)_patches += qtbase_plugins_cocoa.patch
$(package)_patches += qtbase_skip_tools.patch
$(package)_patches += rcc_hardcode_timestamp.patch
$(package)_patches += qttools_skip_dependencies.patch

$(package)_qttranslations_file_name=$(qt_details_qttranslations_file_name)
$(package)_qttranslations_sha256_hash=$(qt_details_qttranslations_sha256_hash)

$(package)_qttools_file_name=$(qt_details_qttools_file_name)
$(package)_qttools_sha256_hash=$(qt_details_qttools_sha256_hash)

$(package)_extra_sources := $($(package)_qttranslations_file_name)
$(package)_extra_sources += $($(package)_qttools_file_name)

$(package)_top_download_path=$(qt_details_top_download_path)
$(package)_top_cmakelists_file_name=$(qt_details_top_cmakelists_file_name)
$(package)_top_cmakelists_download_file=$(qt_details_top_cmakelists_download_file)
$(package)_top_cmakelists_sha256_hash=$(qt_details_top_cmakelists_sha256_hash)
$(package)_top_cmake_download_path=$(qt_details_top_cmake_download_path)
$(package)_top_cmake_ecmoptionaladdsubdirectory_file_name=$(qt_details_top_cmake_ecmoptionaladdsubdirectory_file_name)
$(package)_top_cmake_ecmoptionaladdsubdirectory_download_file=$(qt_details_top_cmake_ecmoptionaladdsubdirectory_download_file)
$(package)_top_cmake_ecmoptionaladdsubdirectory_sha256_hash=$(qt_details_top_cmake_ecmoptionaladdsubdirectory_sha256_hash)
$(package)_top_cmake_qttoplevelhelpers_file_name=$(qt_details_top_cmake_qttoplevelhelpers_file_name)
$(package)_top_cmake_qttoplevelhelpers_download_file=$(qt_details_top_cmake_qttoplevelhelpers_download_file)
$(package)_top_cmake_qttoplevelhelpers_sha256_hash=$(qt_details_top_cmake_qttoplevelhelpers_sha256_hash)

$(package)_extra_sources += $($(package)_top_cmakelists_file_name)-$($(package)_version)
$(package)_extra_sources += $($(package)_top_cmake_ecmoptionaladdsubdirectory_file_name)-$($(package)_version)
$(package)_extra_sources += $($(package)_top_cmake_qttoplevelhelpers_file_name)-$($(package)_version)

define $(package)_set_vars
$(package)_config_env = QT_MAC_SDK_NO_VERSION_CHECK=1
$(package)_config_opts_release = -release
$(package)_config_opts_debug = -debug
$(package)_config_opts = -no-egl
$(package)_config_opts_debug += -optimized-tools
$(package)_config_opts += -bindir $(build_prefix)/bin
$(package)_config_opts += -c++std c++20
$(package)_config_opts += -confirm-license
$(package)_config_opts += -no-cups
$(package)_config_opts += -no-egl
$(package)_config_opts += -no-eglfs
$(package)_config_opts += -no-evdev
$(package)_config_opts += -no-gif
$(package)_config_opts += -no-glib
$(package)_config_opts += -no-icu
$(package)_config_opts += -no-zstd
$(package)_config_opts += -no-ico
$(package)_config_opts += -no-kms
$(package)_config_opts += -no-linuxfb
$(package)_config_opts += -no-libjpeg
$(package)_config_opts += -no-libproxy
$(package)_config_opts += -no-libudev
$(package)_config_opts += -no-mtdev
$(package)_config_opts += -no-opengl
$(package)_config_opts += -no-openssl
$(package)_config_opts += -no-openvg
$(package)_config_opts += -no-reduce-relocations
$(package)_config_opts += -no-schannel
$(package)_config_opts += -no-sctp
$(package)_config_opts += -no-securetransport
$(package)_config_opts += -no-sql-db2
$(package)_config_opts += -no-sql-ibase
$(package)_config_opts += -no-sql-oci
$(package)_config_opts += -no-sql-mysql
$(package)_config_opts += -no-sql-odbc
$(package)_config_opts += -no-sql-psql
$(package)_config_opts += -no-sql-sqlite
$(package)_config_opts += -no-system-proxies
$(package)_config_opts += -no-use-gold-linker
$(package)_config_opts += -no-zstd
$(package)_config_opts += -nomake examples
$(package)_config_opts += -nomake tests
$(package)_config_opts += -nomake tools
$(package)_config_opts += -opensource
$(package)_config_opts += -prefix $(host_prefix)
$(package)_config_opts += -qt-doubleconversion
$(package)_config_opts += -qt-harfbuzz
ifneq ($(host),$(build))
$(package)_config_opts += -qt-host-path $(build_prefix)
endif
$(package)_config_opts += -qt-libpng
$(package)_config_opts += -qt-pcre
$(package)_config_opts += -system-zlib
$(package)_config_opts += -qt-zlib
$(package)_config_opts += -static
$(package)_config_opts += -no-feature-backtrace
$(package)_config_opts += -no-feature-colordialog
$(package)_config_opts += -no-feature-concurrent
$(package)_config_opts += -no-feature-dial
$(package)_config_opts += -no-feature-gssapi
$(package)_config_opts += -no-feature-http
$(package)_config_opts += -no-feature-image_heuristic_mask
$(package)_config_opts += -no-feature-keysequenceedit
$(package)_config_opts += -no-feature-lcdnumber
$(package)_config_opts += -no-feature-libresolv
$(package)_config_opts += -no-feature-networkdiskcache
$(package)_config_opts += -no-feature-pdf
$(package)_config_opts += -no-feature-printdialog
$(package)_config_opts += -no-feature-printer
$(package)_config_opts += -no-feature-printpreviewdialog
$(package)_config_opts += -no-feature-printpreviewwidget
$(package)_config_opts += -no-feature-networkproxy
$(package)_config_opts += -no-feature-printsupport
$(package)_config_opts += -no-feature-sessionmanager
$(package)_config_opts += -no-feature-socks5
$(package)_config_opts += -no-feature-sql
$(package)_config_opts += -no-feature-sqlmodel
$(package)_config_opts += -no-feature-syntaxhighlighter
$(package)_config_opts += -no-feature-textmarkdownwriter
$(package)_config_opts += -no-feature-textmarkdownreader
$(package)_config_opts += -no-feature-textodfwriter
$(package)_config_opts += -no-feature-topleveldomain
$(package)_config_opts += -no-feature-udpsocket
$(package)_config_opts += -no-feature-undocommand
$(package)_config_opts += -no-feature-undogroup
$(package)_config_opts += -no-feature-undostack
$(package)_config_opts += -no-feature-undoview
$(package)_config_opts += -no-feature-vnc

$(package)_config_opts_darwin = -no-dbus
$(package)_config_opts_darwin += -no-opengl
$(package)_config_opts_darwin += -no-feature-corewlan
$(package)_config_opts += -no-feature-vulkan

# Core tools.
$(package)_config_opts += -no-feature-androiddeployqt
$(package)_config_opts += -no-feature-macdeployqt
$(package)_config_opts += -no-feature-qmake
$(package)_config_opts += -no-feature-windeployqt

ifeq ($(host),$(build))
# Qt Tools module.
$(package)_config_opts += -feature-linguist
$(package)_config_opts += -no-feature-assistant
$(package)_config_opts += -no-feature-clang
$(package)_config_opts += -no-feature-clangcpp
$(package)_config_opts += -no-feature-designer
$(package)_config_opts += -no-feature-pixeltool
$(package)_config_opts += -no-feature-qdoc
$(package)_config_opts += -no-feature-qtattributionsscanner
$(package)_config_opts += -no-feature-qtdiag
$(package)_config_opts += -no-feature-qtplugininfo
endif

$(package)_config_opts_darwin := -no-dbus
$(package)_config_opts_darwin += -no-opengl
$(package)_config_opts_darwin += -pch
$(package)_config_opts_darwin += -no-feature-printsupport
$(package)_config_opts_darwin += -no-freetype
$(package)_config_opts_darwin += -no-pkg-config

$(package)_config_opts_linux := -dbus-runtime
$(package)_config_opts_linux += -fontconfig
$(package)_config_opts_linux += -no-feature-process
$(package)_config_opts_linux += -no-feature-xlib
$(package)_config_opts_linux += -no-xcb-xlib
$(package)_config_opts_linux += -pkg-config
$(package)_config_opts_linux += -system-freetype
$(package)_config_opts_linux += -fontconfig
$(package)_config_opts_linux += -no-opengl
$(package)_config_opts_linux += -no-feature-vulkan
$(package)_config_opts_linux += -dbus-runtime
$(package)_config_opts_linux += -feature-xcb
ifneq ($(LTO),)
$(package)_config_opts_linux += -ltcg
endif
$(package)_config_opts_freebsd := $$($(package)_config_opts_linux)

$(package)_config_opts_mingw32 := -no-dbus
$(package)_config_opts_mingw32 += -no-freetype
$(package)_config_opts_mingw32 += -no-pkg-config

$(package)_config_env := CC="$$($(package)_cc)"
$(package)_config_env += CXX="$$($(package)_cxx)"
$(package)_config_env_darwin := OBJC="$$($(package)_cc)"
$(package)_config_env_darwin += OBJCXX="$$($(package)_cxx)"

$(package)_cmake_opts := -DCMAKE_PREFIX_PATH=$(host_prefix)
$(package)_cmake_opts += -DQT_FEATURE_cxx20=ON
$(package)_cmake_opts += -DQT_ENABLE_CXX_EXTENSIONS=OFF

ifeq ($(host_os),mingw32)
$(package)_cmake_opts += -DCMAKE_SYSTEM_NAME=Windows
$(package)_windres := $(host)-windres
$(package)_cmake_opts += -DCMAKE_RC_COMPILER=$$($(package)_windres)
endif
ifneq ($(V),)
$(package)_cmake_opts += --log-level=STATUS
endif

$(package)_cmake_opts += -DQT_USE_DEFAULT_CMAKE_OPTIMIZATION_FLAGS=ON

# Here we used firstword and filter-out functions (guix-functions) to extract the compiler and flags seperately.
# They defined together in darwin.mk, because for autotools we would pass them together as CC/CXX, but for cmake, we should seperate them.
$(package)_cmake_opts += -DCMAKE_C_COMPILER="$$(firstword $$($(package)_cc))"
$(package)_cmake_opts += -DCMAKE_C_FLAGS="$$(filter-out $$(firstword $$($(package)_cc)),$$($(package)_cc)) $($(package)_cflags) $($(package)_cppflags)"
$(package)_cmake_opts += -DCMAKE_C_FLAGS_RELEASE="$$(filter-out $$(firstword $$($(package)_cc)),$$($(package)_cc)) $($(package)_release_cflags) $($(package)_release_cppflags)"
$(package)_cmake_opts += -DCMAKE_C_FLAGS_DEBUG="$$(filter-out $$(firstword $$($(package)_cc)),$$($(package)_cc)) $($(package)_debug_cflags) $($(package)_debug_cppflags)"
$(package)_cmake_opts += -DCMAKE_CXX_COMPILER="$$(firstword $$($(package)_cxx))"
$(package)_cmake_opts += -DCMAKE_CXX_FLAGS="$$(filter-out $$(firstword $$($(package)_cxx)),$$($(package)_cxx)) $($(package)_cxxflags) $($(package)_cppflags)"
$(package)_cmake_opts += -DCMAKE_CXX_FLAGS_RELEASE="$$(filter-out $$(firstword $$($(package)_cxx)),$$($(package)_cxx)) $($(package)_release_cxxflags) $($(package)_release_cppflags)"
$(package)_cmake_opts += -DCMAKE_CXX_FLAGS_DEBUG="$$(filter-out $$(firstword $$($(package)_cxx)),$$($(package)_cxx)) $($(package)_debug_cxxflags) $($(package)_debug_cppflags)"
$(package)_cmake_opts += -DCMAKE_EXE_LINKER_FLAGS="$($(package)_ldflags)"
$(package)_cmake_opts += -DCMAKE_EXE_LINKER_FLAGS_RELEASE="$($(package)_ldflags)"
$(package)_cmake_opts += -DCMAKE_EXE_LINKER_FLAGS_DEBUG="$($(package)_ldflags)"
$(package)_cmake_opts += -DCMAKE_SHARED_LINKER_FLAGS="$($(package)_ldflags)"
$(package)_cmake_opts += -DCMAKE_SHARED_LINKER_FLAGS_RELEASE="$($(package)_ldflags)"
$(package)_cmake_opts += -DCMAKE_SHARED_LINKER_FLAGS_DEBUG="$($(package)_ldflags)"
ifeq ($(host_os),darwin)
$(package)_cmake_opts += -DCMAKE_OBJC_FLAGS="$($(package)_cflags) $($(package)_cppflags) -ffile-prefix-map=$$($(package)_extract_dir)=/usr"
$(package)_cmake_opts += -DCMAKE_OBJC_FLAGS_RELEASE="$$($$($(package)_type)_release_CFLAGS)"
$(package)_cmake_opts += -DCMAKE_OBJC_FLAGS_DEBUG="$$($$($(package)_type)_debug_CFLAGS)"
$(package)_cmake_opts += -DCMAKE_OBJCXX_FLAGS="$($(package)_cxxflags) $($(package)_cppflags) -ffile-prefix-map=$$($(package)_extract_dir)=/usr"
$(package)_cmake_opts += -DCMAKE_OBJCXX_FLAGS_RELEASE="$$($$($(package)_type)_release_CXXFLAGS)"
$(package)_cmake_opts += -DCMAKE_OBJCXX_FLAGS_DEBUG="$$($$($(package)_type)_debug_CXXFLAGS)"
endif

ifeq ($(host_os),linux)
$(package)_cmake_opts += -DQT_FEATURE_xcb=ON
endif

ifdef GUIX_ENVIRONMENT
export QT_MAC_SDK_NO_VERSION_CHECK=1
ifneq ($(host_os),darwin)
$(package)_config_env_darwin += AR="$$($(package)_ar)"
$(package)_config_env_darwin += RANLIB="$$($(package)_ranlib)"
endif
endif

ifneq ($(host),$(build))
$(package)_cmake_opts += -DCMAKE_SYSTEM_NAME=$($(host_os)_cmake_system_name)
$(package)_cmake_opts += -DCMAKE_SYSTEM_VERSION=$($(host_os)_cmake_system_version)
$(package)_cmake_opts += -DCMAKE_SYSTEM_PROCESSOR=$(host_arch)
$(package)_cmake_opts += -DQT_HOST_PATH=$(build_prefix)
# Native packages cannot be used during cross-compiling. However,
# Qt still unconditionally tries to find them, which causes issues
# in some cases, such as when cross-compiling from macOS to Windows.
# Explicitly disable this unnecessary Qt behaviour.
$(package)_cmake_opts += -DCMAKE_DISABLE_FIND_PACKAGE_Libb2=TRUE
$(package)_cmake_opts += -DCMAKE_DISABLE_FIND_PACKAGE_WrapSystemDoubleConversion=TRUE
$(package)_cmake_opts += -DCMAKE_DISABLE_FIND_PACKAGE_WrapSystemMd4c=TRUE
$(package)_cmake_opts += -DCMAKE_DISABLE_FIND_PACKAGE_WrapZSTD=TRUE
ifneq ($(host_os), darwin)
$(package)_cmake_opts += -DCMAKE_ASM_COMPILER=$$(firstword $$($(package)_cc))
endif
endif

ifeq ($(host_os),darwin)
$(package)_cmake_opts += -DCMAKE_INSTALL_NAME_TOOL=true
$(package)_cmake_opts += -DCMAKE_FRAMEWORK_PATH=$(OSX_SDK)/System/Library/Frameworks
$(package)_cmake_opts += -DQT_INTERNAL_APPLE_SDK_VERSION=$(OSX_SDK_VERSION)
$(package)_cmake_opts += -DQT_INTERNAL_XCODE_VERSION=$(XCODE_VERSION)
$(package)_cmake_opts += -DQT_NO_APPLE_SDK_MAX_VERSION_CHECK=ON
$(package)_config_env_darwin += unset LIBRARY_PATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH OBJCPLUS_INCLUDE_PATH;
endif
endef

define $(package)_fetch_cmds
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_qttranslations_file_name),$($(package)_qttranslations_file_name),$($(package)_qttranslations_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_qttools_file_name),$($(package)_qttools_file_name),$($(package)_qttools_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_top_download_path),$($(package)_top_cmakelists_download_file),$($(package)_top_cmakelists_file_name)-$($(package)_version),$($(package)_top_cmakelists_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_top_cmake_download_path),$($(package)_top_cmake_ecmoptionaladdsubdirectory_download_file),$($(package)_top_cmake_ecmoptionaladdsubdirectory_file_name)-$($(package)_version),$($(package)_top_cmake_ecmoptionaladdsubdirectory_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_top_cmake_download_path),$($(package)_top_cmake_qttoplevelhelpers_download_file),$($(package)_top_cmake_qttoplevelhelpers_file_name)-$($(package)_version),$($(package)_top_cmake_qttoplevelhelpers_sha256_hash))
endef

ifeq ($(host),$(build))
define $(package)_extract_cmds
  mkdir -p $($(package)_extract_dir) && \
  echo "$($(package)_sha256_hash)  $($(package)_source)" > $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_qttranslations_sha256_hash)  $($(package)_source_dir)/$($(package)_qttranslations_file_name)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_qttools_sha256_hash)  $($(package)_source_dir)/$($(package)_qttools_file_name)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_top_cmakelists_sha256_hash)  $($(package)_source_dir)/$($(package)_top_cmakelists_file_name)-$($(package)_version)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_top_cmake_ecmoptionaladdsubdirectory_sha256_hash)  $($(package)_source_dir)/$($(package)_top_cmake_ecmoptionaladdsubdirectory_file_name)-$($(package)_version)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_top_cmake_qttoplevelhelpers_sha256_hash)  $($(package)_source_dir)/$($(package)_top_cmake_qttoplevelhelpers_file_name)-$($(package)_version)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  mkdir qtbase && \
  $(build_TAR) --no-same-owner --strip-components=1 -xf $($(package)_source) -C qtbase && \
  mkdir qttranslations && \
  $(build_TAR) --no-same-owner --strip-components=1 -xf $($(package)_source_dir)/$($(package)_qttranslations_file_name) -C qttranslations && \
  mkdir qttools && \
  $(build_TAR) --no-same-owner --strip-components=1 -xf $($(package)_source_dir)/$($(package)_qttools_file_name) -C qttools && \
  cp $($(package)_source_dir)/$($(package)_top_cmakelists_file_name)-$($(package)_version) ./$($(package)_top_cmakelists_file_name) && \
  mkdir cmake && \
  cp $($(package)_source_dir)/$($(package)_top_cmake_ecmoptionaladdsubdirectory_file_name)-$($(package)_version) cmake/$($(package)_top_cmake_ecmoptionaladdsubdirectory_file_name) && \
  cp $($(package)_source_dir)/$($(package)_top_cmake_qttoplevelhelpers_file_name)-$($(package)_version) cmake/$($(package)_top_cmake_qttoplevelhelpers_file_name) && \
  rm -rf qtbase/src/qtbase/tests/ && \
  rm -rf qtbase/src/qtbase/tools/ && \
  rm -rf qtbase/src/qtbase/examples/
endef
else
define $(package)_extract_cmds
  mkdir -p $($(package)_extract_dir) && \
  echo "$($(package)_sha256_hash)  $($(package)_source)" > $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_top_cmakelists_sha256_hash)  $($(package)_source_dir)/$($(package)_top_cmakelists_file_name)-$($(package)_version)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_top_cmake_ecmoptionaladdsubdirectory_sha256_hash)  $($(package)_source_dir)/$($(package)_top_cmake_ecmoptionaladdsubdirectory_file_name)-$($(package)_version)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_top_cmake_qttoplevelhelpers_sha256_hash)  $($(package)_source_dir)/$($(package)_top_cmake_qttoplevelhelpers_file_name)-$($(package)_version)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  mkdir qtbase && \
  $(build_TAR) --no-same-owner --strip-components=1 -xf $($(package)_source) -C qtbase && \
  cp $($(package)_source_dir)/$($(package)_top_cmakelists_file_name)-$($(package)_version) ./$($(package)_top_cmakelists_file_name) && \
  mkdir cmake && \
  cp $($(package)_source_dir)/$($(package)_top_cmake_ecmoptionaladdsubdirectory_file_name)-$($(package)_version) cmake/$($(package)_top_cmake_ecmoptionaladdsubdirectory_file_name) && \
  cp $($(package)_source_dir)/$($(package)_top_cmake_qttoplevelhelpers_file_name)-$($(package)_version) cmake/$($(package)_top_cmake_qttoplevelhelpers_file_name) && \
  rm -rf qtbase/src/qtbase/tests/ && \
  rm -rf qtbase/src/qtbase/tools/ && \
  rm -rf qtbase/src/qtbase/examples/
endef
endif

define $(package)_preprocess_cmds
  patch -p1 -i $($(package)_patch_dir)/dont_hardcode_pwd.patch && \
  patch -p1 -i $($(package)_patch_dir)/qtbase-moc-ignore-gcc-macro.patch && \
  patch -p1 -i $($(package)_patch_dir)/qtbase_avoid_native_float16.patch && \
  patch -p1 -i $($(package)_patch_dir)/qtbase_avoid_qmain.patch && \
  patch -p1 -i $($(package)_patch_dir)/qtbase_platformsupport.patch && \
  patch -p1 -i $($(package)_patch_dir)/qtbase_plugins_cocoa.patch && \
  patch -p1 -i $($(package)_patch_dir)/qtbase_skip_tools.patch && \
  patch -p1 -i $($(package)_patch_dir)/rcc_hardcode_timestamp.patch
endef
ifeq ($(host),$(build))
  $(package)_preprocess_cmds += && patch -p1 -i $($(package)_patch_dir)/qttools_skip_dependencies.patch
endif
define $(package)_config_cmds
  cd qtbase && \
  $($(package)_config_env) ./configure -top-level $($(package)_config_opts) -- $($(package)_cmake_opts)
endef

define $(package)_build_cmds
  $($(package)_config_env) cmake --build . --parallel
endef

define $(package)_stage_cmds
  cmake --install . --prefix $($(package)_staging_prefix_dir)
endef

define $(package)_postprocess_cmds
  rm -rf doc/
endef
