# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  enable_language(OBJCXX)
  set(CMAKE_OBJCXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
  set(CMAKE_OBJCXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
  set(CMAKE_OBJCXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
  set(CMAKE_OBJCXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL}")
  string(APPEND CMAKE_OBJCXX_COMPILE_OBJECT " ${APPEND_CPPFLAGS} ${APPEND_CXXFLAGS}")
endif()

get_target_property(qt_lib_type Qt6::Core TYPE)

function(import_plugins target)
  if(qt_lib_type STREQUAL "STATIC_LIBRARY")
    set(plugins Qt6::QMinimalIntegrationPlugin)
    if(CMAKE_SYSTEM_NAME MATCHES "^(Linux|FreeBSD)$")
      list(APPEND plugins Qt6::QXcbIntegrationPlugin)
    elseif(WIN32)
      list(APPEND plugins Qt6::QWindowsIntegrationPlugin Qt6::QModernWindowsStylePlugin)
    elseif(APPLE)
      list(APPEND plugins Qt6::QCocoaIntegrationPlugin Qt6::QMacStylePlugin)
    endif()
    qt6_import_plugins(${target}
      INCLUDE ${plugins}
      EXCLUDE_BY_TYPE
        accessiblebridge
        platforms
        platforms_darwin
        xcbglintegrations
        platformthemes
        platforminputcontexts
        generic
        iconengines
        imageformats
        egldeviceintegrations
        styles
        networkaccess
        networkinformation
        tls
    )
  endif()
endfunction()

# For Qt-specific commands and variables, please consult:
#  - https://cmake.org/cmake/help/latest/manual/cmake-qt.7.html
#  - https://doc.qt.io/qt-5/cmake-manual.html

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOMOC_MOC_OPTIONS "-p${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOUIC_SEARCH_PATHS forms)

# Generate QM files from TS files
file(GLOB TS_FILES "${CMAKE_CURRENT_SOURCE_DIR}/locale/*.ts")
set(LOCALE_BUILD_DIR "${CMAKE_BINARY_DIR}/src/qt/locale")
file(MAKE_DIRECTORY ${LOCALE_BUILD_DIR})
foreach(TS_FILE ${TS_FILES})
  get_filename_component(TS_NAME ${TS_FILE} NAME_WE)
  set(QM_FILE "${LOCALE_BUILD_DIR}/${TS_NAME}.qm")
  add_custom_command(
    OUTPUT ${QM_FILE}
    COMMAND Qt6::lrelease ${TS_FILE} -qm ${QM_FILE}
    DEPENDS ${TS_FILE}
    COMMENT "Generating ${TS_NAME}.qm in build directory"
  )
  list(APPEND QM_FILES ${QM_FILE})
endforeach()

add_custom_target(translations ALL DEPENDS ${QM_FILES})

configure_file(bitcoin_locale.qrc bitcoin_locale.qrc USE_SOURCE_PERMISSIONS COPYONLY)

# The bitcoinqt sources have to include headers in
# order to parse them to collect translatable strings.
add_library(firoqt STATIC EXCLUDE_FROM_ALL
  ${CMAKE_CURRENT_SOURCE_DIR}/bitcoin.qrc
  ${CMAKE_CURRENT_BINARY_DIR}/bitcoin_locale.qrc
  ${CMAKE_CURRENT_SOURCE_DIR}/addressbookpage.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/addresstablemodel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/askpassphrasedialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/automintdialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/automintmodel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/automintnotification.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bantablemodel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bitcoinaddressvalidator.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bitcoinamountfield.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bitcoingui.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bitcoinstrings.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bitcoinunits.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/cancelpassworddialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/clientmodel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coincontroldialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coincontroltreewidget.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/csvmodelwriter.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/editaddressdialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/guiutil.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/intro.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/manualmintdialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/masternodelist.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/modaloverlay.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/networkstyle.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/notificator.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/notifymnemonic.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/openuridialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/optionsdialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/optionsmodel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/overviewpage.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/paymentserver.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/peertablemodel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/platformstyle.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/qvalidatedlineedit.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/qvaluecombobox.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/receivecoinsdialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/receiverequestdialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/recentrequeststablemodel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/recover.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpcconsole.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sendcoinsdialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sendcoinsentry.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/signverifymessagedialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sparkmodel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/splashscreen.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/trafficgraphwidget.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/transactiondesc.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/transactiondescdialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/transactionfilterproxy.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/transactionrecord.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/transactiontablemodel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/transactionview.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/utilitydialog.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/walletframe.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/walletmodel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/walletmodeltransaction.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/walletview.cpp
  $<$<PLATFORM_ID:Darwin>:${CMAKE_CURRENT_SOURCE_DIR}/macdockiconhandler.h>
  $<$<PLATFORM_ID:Darwin>:${CMAKE_CURRENT_SOURCE_DIR}/macdockiconhandler.mm>
  $<$<PLATFORM_ID:Darwin>:${CMAKE_CURRENT_SOURCE_DIR}/macnotificationhandler.h>
  $<$<PLATFORM_ID:Darwin>:${CMAKE_CURRENT_SOURCE_DIR}/macnotificationhandler.mm>
  $<$<BOOL:${WIN32}>:${CMAKE_CURRENT_SOURCE_DIR}/winshutdownmonitor.cpp>
  $<$<BOOL:${WIN32}>:${CMAKE_CURRENT_SOURCE_DIR}/winshutdownmonitor.h>
)
target_compile_definitions(firoqt
  PUBLIC
    QT_NO_KEYWORDS
    QT_USE_QSTRINGBUILDER
)
target_include_directories(firoqt
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/qt> 
)
set_property(SOURCE macnotificationhandler.mm
  # Ignore warnings "'NSUserNotificationCenter' is deprecated: first deprecated in macOS 11.0".
  APPEND PROPERTY COMPILE_OPTIONS -Wno-deprecated-declarations
)
# Add this to skip specific files from UIC processing
set_source_files_properties(
    ${CMAKE_CURRENT_SOURCE_DIR}/clientmodel.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/clientmodel.h
    PROPERTIES SKIP_AUTOUIC ON 
)
target_link_libraries(firoqt
  PUBLIC
    leveldb
    secp256k1
    univalue
    secp256k1pp
    Qt6::Widgets
    Qt6::Network
  PRIVATE
    core_interface
    firo_cli
    firo_node
    Boost::headers   
    $<TARGET_NAME_IF_EXISTS:QRencode::QRencode>
    $<$<PLATFORM_ID:Darwin>:-framework\ AppKit>
    Boost::thread
    $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    ${TOR_LIBRARY}
    $<$<BOOL:${WITH_ZMQ}>:firo_zmq>
    $<$<BOOL:${WIN32}>:windows_system>
)

# Make sure translations are built before firoqt
add_dependencies(firoqt translations)

if(ENABLE_WALLET)
  target_sources(firoqt
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/addressbookpage.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/automintdialog.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/automintnotification.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/addresstablemodel.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/askpassphrasedialog.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/coincontroldialog.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/coincontroltreewidget.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/editaddressdialog.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/exportviewkeydialog.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/manualmintdialog.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/openuridialog.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/overviewpage.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/paymentserver.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/receivecoinsdialog.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/receiverequestdialog.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/recentrequeststablemodel.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/sendcoinsdialog.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/sendcoinsentry.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/signverifymessagedialog.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/transactiondesc.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/transactiondescdialog.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/transactionfilterproxy.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/transactionrecord.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/transactiontablemodel.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/transactionview.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/walletframe.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/walletmodel.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/walletmodeltransaction.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/masternodelist.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/walletview.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/automintmodel.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/sparkmodel.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/createsparknamepage.cpp
  )
  target_link_libraries(firoqt
    PRIVATE
      firo_wallet
      Qt6::Network
  )
endif()

if(WITH_DBUS AND NOT MINGW)
  target_link_libraries(firoqt PRIVATE Qt6::DBus)
endif()

if(qt_lib_type STREQUAL "STATIC_LIBRARY")
  # We want to define static plugins to link ourselves, thus preventing
  # automatic linking against a "sane" set of default static plugins.
  qt6_import_plugins(firoqt
    EXCLUDE_BY_TYPE
      bearer
      accessiblebridge
      platforms
      platforms_darwin
      xcbglintegrations
      platformthemes
      platforminputcontexts
      generic
      iconengines
      imageformats
      egldeviceintegrations
      styles
      networkaccess
      networkinformation
      tls
  )
endif()

add_executable(firo-qt
  ${CMAKE_CURRENT_SOURCE_DIR}/bitcoin.cpp
)

add_windows_resources(firo-qt res/bitcoin-qt-res.rc)
target_link_libraries(firo-qt
  PUBLIC
    core_interface
    firoqt
    Qt6::Widgets
    firo_node
    firo_cli
    univalue
    $<TARGET_NAME_IF_EXISTS:firo_wallet>
    $<$<BOOL:${WITH_ZMQ}>:firo_zmq>
    Boost::thread
    Boost::filesystem
    Boost::thread
    Boost::program_options
    $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    ${TOR_LIBRARY}
)

# Add macOS-specific frameworks
if(APPLE)
    target_link_libraries(firo-qt PRIVATE
        "-framework CoreVideo"
        "-framework IOKit"
        "-framework IOSurface"
        "-framework ApplicationServices"
        "-framework QuartzCore"
        "-framework Security"
        "-framework SystemConfiguration"
        "-framework Metal"
        "-framework Foundation"
        "-framework AppKit"
        "-framework Carbon"
    )
endif()

apply_wrapped_exception_flags(firo-qt)
import_plugins(firo-qt)
set_platform_output_name(firo-qt FIRO_GUI_NAME)
list(APPEND installable_targets firo-qt)
set(installable_targets ${installable_targets} PARENT_SCOPE)
if(NOT WIN32)
  install(FILES ${PROJECT_SOURCE_DIR}/doc/man/bitcoin-qt.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
    RENAME firo-qt.1
  )
endif()
if(WIN32)
  set_target_properties(firo-qt PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

if(WITH_MULTIPROCESS)
  add_executable(bitcoin-gui
  ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
  )
  target_link_libraries(bitcoin-gui
    core_interface
    firoqt
    firo_node
    bitcoin_ipc
  )
  import_plugins(bitcoin-gui)
  install_binary_component(bitcoin-gui)
  if(WIN32)
    set_target_properties(bitcoin-gui PROPERTIES WIN32_EXECUTABLE TRUE)
  endif()
endif()

if(BUILD_GUI_TESTS AND NOT WIN32 AND NOT MINGW)
  add_subdirectory(test)
else()
  message(STATUS "Skipping GUI tests when cross-compiling for Windows")
  if(BUILD_GUI_TESTS)
    message(WARNING "BUILD_GUI_TESTS is enabled, but GUI tests are not supported when cross-compiling for Windows")
  endif()
endif()

# Gets sources to be parsed to gather translatable strings.
function(get_translatable_sources var)
  set(result)
  foreach(dir IN ITEMS ${ARGN})
    # Use file() instead of get_directory_property() to avoid target dependency issues
    file(GLOB_RECURSE dir_sources 
      ${PROJECT_SOURCE_DIR}/${dir}/*.cpp
      ${PROJECT_SOURCE_DIR}/${dir}/*.h
      ${PROJECT_SOURCE_DIR}/${dir}/*.mm
    )
    
    foreach(source IN LISTS dir_sources)
      # Skip resource files and generated files
      get_filename_component(source_name ${source} NAME)
      if(source_name MATCHES "^(moc_|ui_|qrc_)")
        continue()
      endif()
      
      cmake_path(GET source EXTENSION LAST_ONLY ext)
      if(ext STREQUAL ".qrc")
        continue()
      endif()
      
      # Check if file is generated (best effort without target dependencies)
      get_filename_component(source_dir ${source} DIRECTORY)
      get_filename_component(build_dir ${CMAKE_BINARY_DIR} REALPATH)
      get_filename_component(source_dir_real ${source_dir} REALPATH)
      string(FIND "${source_dir_real}" "${build_dir}" is_in_build_dir)
      if(NOT is_in_build_dir EQUAL -1)
        continue()  # Skip files in build directory (likely generated)
      endif()
      
      list(APPEND result ${source})
    endforeach()
  endforeach()
  set(${var} ${result} PARENT_SCOPE)
endfunction()

find_program(XGETTEXT_EXECUTABLE xgettext)
find_program(SED_EXECUTABLE sed)
if(NOT XGETTEXT_EXECUTABLE)
  add_custom_target(translate
    COMMAND ${CMAKE_COMMAND} -E echo "Error: GNU gettext-tools not found"
  )
elseif(NOT SED_EXECUTABLE)
  add_custom_target(translate
    COMMAND ${CMAKE_COMMAND} -E echo "Error: GNU sed not found"
  )
else()
  set(translatable_sources_directories src src/qt src/util)
  if(ENABLE_WALLET)
    list(APPEND translatable_sources_directories src/wallet)
  endif()
  get_translatable_sources(translatable_sources ${translatable_sources_directories})
  get_translatable_sources(qt_translatable_sources src/qt)
  file(GLOB ui_files ${CMAKE_CURRENT_SOURCE_DIR}/forms/*.ui)
  add_custom_target(translate
    COMMAND ${CMAKE_COMMAND} -E env XGETTEXT=${XGETTEXT_EXECUTABLE} COPYRIGHT_HOLDERS=${COPYRIGHT_HOLDERS} $<TARGET_FILE:Python3::Interpreter> ${PROJECT_SOURCE_DIR}/share/qt/extract_strings_qt.py ${translatable_sources}
    COMMAND Qt6::lupdate -no-obsolete -I ${PROJECT_SOURCE_DIR}/src -locations relative ${CMAKE_CURRENT_SOURCE_DIR}/bitcoinstrings.cpp ${ui_files} ${qt_translatable_sources} -ts ${CMAKE_CURRENT_SOURCE_DIR}/locale/bitcoin_en.ts
    COMMAND Qt6::lconvert -drop-translations -o ${CMAKE_CURRENT_SOURCE_DIR}/locale/bitcoin_en.xlf -i ${CMAKE_CURRENT_SOURCE_DIR}/locale/bitcoin_en.ts
    COMMAND ${SED_EXECUTABLE} -i.old -e "s|source-language=\"en\" target-language=\"en\"|source-language=\"en\"|" -e "/<target xml:space=\"preserve\"><\\/target>/d" ${CMAKE_CURRENT_SOURCE_DIR}/locale/bitcoin_en.xlf
    COMMAND ${CMAKE_COMMAND} -E rm ${CMAKE_CURRENT_SOURCE_DIR}/locale/bitcoin_en.xlf.old
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
    VERBATIM
  )
endif()
