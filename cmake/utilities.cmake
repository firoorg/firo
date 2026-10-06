# Copyright (c) 2025-present The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

function(apply_wrapped_exception_flags target_name)
  if(ENABLE_CRASH_HOOKS AND CRASH_HOOKS_WRAPPED_CXX_ABI)
    # Wraps are linker options; passing them to compilation only produces unused
    # argument warnings and does not affect symbol wrapping.
    # Apple linker does not support -Wl,--wrap=
    if(NOT APPLE)
      target_link_options(${target_name} PRIVATE ${LDFLAGS_WRAP_EXCEPTIONS})
    endif()
  endif()
endfunction()

# Set platform-specific output name for an executable target
# Usage: set_platform_output_name(target_name base_name_variable)
function(set_platform_output_name target_name base_name_variable)
  set_target_properties(${target_name} PROPERTIES OUTPUT_NAME "${${base_name_variable}}")
endfunction()
