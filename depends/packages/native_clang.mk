package=native_clang
$(package)_version=19.1.7
$(package)_download_path=https://github.com/llvm/llvm-project/releases/download/llvmorg-$($(package)_version)
ifneq (,$(findstring aarch64,$(BUILD)))
$(package)_download_file=clang+llvm-$($(package)_version)-aarch64-linux-gnu.tar.xz
$(package)_file_name=clang+llvm-$($(package)_version)-aarch64-linux-gnu.tar.xz
$(package)_sha256_hash=a73d9326e5d756e3937df6a9f621664d76403b59119f741901106b387e53a6ae
else
$(package)_download_file=LLVM-$($(package)_version)-Linux-X64.tar.xz
$(package)_file_name=LLVM-$($(package)_version)-Linux-X64.tar.xz
$(package)_sha256_hash=4a5ec53951a584ed36f80240f6fbf8fdd46b4cf6c7ee87cc2d5018dc37caf679
endif

define $(package)_preprocess_cmds
  rm -f $($(package)_extract_dir)/lib/libc++abi.so*
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/lib/clang/$($(package)_version)/include && \
  mkdir -p $($(package)_staging_prefix_dir)/bin && \
  mkdir -p $($(package)_staging_prefix_dir)/include && \
  cp bin/clang $($(package)_staging_prefix_dir)/bin/ && \
  cp -P bin/clang++ $($(package)_staging_prefix_dir)/bin/ && \
  cp bin/dsymutil $($(package)_staging_prefix_dir)/bin/$(host)-dsymutil && \
  cp bin/llvm-config $($(package)_staging_prefix_dir)/bin/ && \
  cp lib/libLTO.so $($(package)_staging_prefix_dir)/lib/ && \
  cp -rf lib/clang/$($(package)_version)/include/* $($(package)_staging_prefix_dir)/lib/clang/$($(package)_version)/include/
endef

define $(package)_postprocess_cmds
  rmdir include
endef
