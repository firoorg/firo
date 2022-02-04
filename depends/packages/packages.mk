packages:=boost openssl libevent gmp zlib backtrace tor bls-dash
darwin_packages:=zeromq
linux_packages:=zeromq
native_packages := native_ccache native_comparisontool native_cmake

qt_native_packages = native_protobuf
qt_packages = qrencode protobuf

qt_linux_packages:=qt expat libxcb xcb_proto libXau xproto freetype fontconfig libxkbcommon

qt_darwin_packages=qt
qt_mingw32_packages=qt

bdb_packages=bdb
sqlite_packages=sqlite

upnp_packages=miniupnpc

darwin_native_packages = native_ds_store native_mac_alias

$(host_arch)_$(host_os)_native_packages += native_b2

ifneq ($(build_os),darwin)
darwin_native_packages += native_cctools native_libtapi native_libdmg-hfsplus

ifeq ($(strip $(FORCE_USE_SYSTEM_CLANG)),)
darwin_native_packages+= native_clang
endif

endif

