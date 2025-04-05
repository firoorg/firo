# Copyright (c) 2025-present The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

function(apply_wrapped_exception_flags target_name)
  if(ENABLE_CRASH_HOOKS AND CRASH_HOOKS_WRAPPED_CXX_ABI)
    # We need to wrap exceptions to catch them in the crash handler
    # We need to pass both compile flags and link flags to ensure that the wrapped exceptions are used in all cases
    target_compile_options(${target_name} PRIVATE ${LDFLAGS_WRAP_EXCEPTIONS})
    # Apple linker does not support -Wl,--wrap=
    if(NOT APPLE)
      target_link_options(${target_name} PRIVATE ${LDFLAGS_WRAP_EXCEPTIONS})
    endif()
  endif()
endfunction()

# Set platform-specific output name for an executable target
# Usage: set_platform_output_name(target_name base_name_variable)
function(set_platform_output_name target_name base_name_variable)
  if(WIN32)
    set_target_properties(${target_name} PROPERTIES OUTPUT_NAME "${${base_name_variable}}.exe")
  else()
    set_target_properties(${target_name} PROPERTIES OUTPUT_NAME "${${base_name_variable}}")
  endif()
endfunction()