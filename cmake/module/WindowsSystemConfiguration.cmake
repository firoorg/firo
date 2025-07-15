# WindowsSystemConfiguration.cmake

if(WIN32)
  
  add_library(windows_system INTERFACE)
  target_link_libraries(windows_system INTERFACE
      ws2_32 iphlpapi userenv
      dwmapi uxtheme shlwapi
      wtsapi32 imm32 netapi32
      $<$<BOOL:${ENABLE_CRASH_HOOKS}>:dbghelp>
      version winmm crypt32 bcrypt
      ole32 oleaut32 uuid
      comdlg32 advapi32
      shell32 gdi32 user32
      kernel32 winspool
  )

  find_library(LIBEVENT_EXTRA event_extra REQUIRED)
  find_library(LIBEVENT_CORE event_core REQUIRED)

  if(MINGW AND NOT STATIC_BUILD)
    message(STATUS "Configuring extra DLL copy steps for MinGW runtime dependencies (${MINGW_ARCH}-bit).")

    # Determine architecture-specific settings
    if(MINGW_ARCH STREQUAL "64")
      set(MINGW_TRIPLET "x86_64-w64-mingw32")
      set(LIBGCC_DLL "libgcc_s_seh-1.dll")
    elseif(MINGW_ARCH STREQUAL "32")
      set(MINGW_TRIPLET "i686-w64-mingw32")
      set(LIBGCC_DLL "libgcc_s_dw2-1.dll")
    else()
      message(FATAL_ERROR "Unsupported MINGW_ARCH: ${MINGW_ARCH}. Must be 32 or 64.")
    endif()

    # List the DLL names you require with architecture-specific libgcc
    set(NEEDED_DLLS
      "${LIBGCC_DLL}"
      "libssp-0.dll"
      "libstdc++-6.dll"
      "libwinpthread-1.dll"
    )

    # Use the compiler's -print-file-name option to determine the correct path for each DLL.
    # We use CMAKE_C_COMPILER as it should be set to the appropriate MinGW gcc.
    set(FOUND_DLLS "")
    foreach(dll ${NEEDED_DLLS})
      # Check if this DLL is on the PATH
      execute_process(
        COMMAND ${CMAKE_COMMAND} -E which ${dll}
        OUTPUT_VARIABLE DLL_IN_PATH
        RESULT_VARIABLE FOUND_IN_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )
      if(FOUND_IN_PATH EQUAL 0 AND EXISTS "${DLL_IN_PATH}")
        message(STATUS "Found ${dll} in PATH at ${DLL_IN_PATH}")
        list(APPEND FOUND_DLLS "${DLL_IN_PATH}")
      else()
        # Fallback to compiler detection
        message(STATUS "Not found in PATH, checking with -print-file-name for ${dll}")
        execute_process(
          COMMAND ${CMAKE_C_COMPILER} -print-file-name=${dll}
          OUTPUT_VARIABLE DLL_PATH
          OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(NOT DLL_PATH OR DLL_PATH STREQUAL "${dll}")
          message(WARNING "Could not determine path for DLL: ${dll}, skipping.")
        else()
          message(STATUS "Found ${dll} at ${DLL_PATH}")
          list(APPEND FOUND_DLLS "${DLL_PATH}")
        endif()
      endif()
    endforeach()

    # Set the output binary directory (adjust if needed)
    set(PROJECT_BIN_DIR "${CMAKE_BINARY_DIR}/bin")

    # Create a custom target to copy the DLLs to the bin folder.
    add_custom_target(copy_mingw_dlls ALL
      COMMAND ${CMAKE_COMMAND} -E make_directory "${PROJECT_BIN_DIR}"
      COMMAND ${CMAKE_COMMAND} -E echo "Copying MinGW ${MINGW_ARCH}-bit runtime DLLs to ${PROJECT_BIN_DIR}"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different ${FOUND_DLLS} "${PROJECT_BIN_DIR}"
      COMMENT "Copying required MinGW ${MINGW_ARCH}-bit DLLs to binary folder."
    )

    # Optionally, make your executables depend on the copy target
    # add_dependencies(firo-cli copy_mingw_dlls)

    # Install the DLLs to the install package bin folder
    install(FILES ${FOUND_DLLS} DESTINATION bin)
  endif() # MINGW AND NOT STATIC_BUILD
  
endif()