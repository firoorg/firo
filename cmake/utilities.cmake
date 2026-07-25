# Copyright (c) 2025-present The Firo Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

function(apply_wrapped_exception_flags target_name)
  if(ENABLE_CRASH_HOOKS AND CRASH_HOOKS_WRAPPED_CXX_ABI)
    get_target_property(target_type ${target_name} TYPE)
    if(target_type STREQUAL "STATIC_LIBRARY")
      set(wrap_scope INTERFACE)
    else()
      set(wrap_scope PRIVATE)
    endif()

    # The wrappers are resolved by the final executable link step. Static
    # libraries therefore propagate the requirement to their consumers.
    if(NOT APPLE)
      target_link_options(${target_name} ${wrap_scope} ${LDFLAGS_WRAP_EXCEPTIONS})
    endif()
  endif()
endfunction()

# Set platform-specific output name for an executable target
# Usage: set_platform_output_name(target_name base_name_variable)
function(set_platform_output_name target_name base_name_variable)
  set_target_properties(${target_name} PROPERTIES OUTPUT_NAME "${${base_name_variable}}")
endfunction()
