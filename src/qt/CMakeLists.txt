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

get_target_property(qt_lib_type Qt5::Core TYPE)

function(import_plugins target)
  if(qt_lib_type STREQUAL "STATIC_LIBRARY")
    set(plugins Qt5::QMinimalIntegrationPlugin)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      list(APPEND plugins Qt5::QXcbIntegrationPlugin)
    elseif(WIN32)
      list(APPEND plugins Qt5::QWindowsIntegrationPlugin Qt5::QWindowsVistaStylePlugin)
    elseif(APPLE)
      list(APPEND plugins Qt5::QCocoaIntegrationPlugin Qt5::QMacStylePlugin)
    endif()
    qt5_import_plugins(${target}
      INCLUDE ${plugins}
      EXCLUDE_BY_TYPE imageformats iconengines
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

# TODO: The file(GLOB ...) command should be replaced with an explicit
# file list. Such a change must be synced with the corresponding change
# to https://github.com/bitcoin-core/bitcoin-maintainer-tools/blob/main/update-translations.py
file(GLOB ts_files RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} locale/*.ts)
set_source_files_properties(${ts_files} PROPERTIES OUTPUT_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/locale)
qt5_add_translation(qm_files ${ts_files})

configure_file(bitcoin_locale.qrc bitcoin_locale.qrc USE_SOURCE_PERMISSIONS COPYONLY)

# The firoqt sources have to include headers in
# order to parse them to collect translatable strings.
add_library(firoqt STATIC EXCLUDE_FROM_ALL
  $<$<PLATFORM_ID:Darwin>:macdockiconhandler.h>
  $<$<PLATFORM_ID:Darwin>:macdockiconhandler.mm>
  $<$<PLATFORM_ID:Darwin>:macnotificationhandler.h>
  $<$<PLATFORM_ID:Darwin>:macnotificationhandler.mm>
  $<$<PLATFORM_ID:Windows>:winshutdownmonitor.cpp>
  $<$<PLATFORM_ID:Windows>:winshutdownmonitor.h>
  bitcoin.qrc
  ${CMAKE_CURRENT_BINARY_DIR}/bitcoin_locale.qrc
  addressbookpage.cpp
  addresstablemodel.cpp
  askpassphrasedialog.cpp
  automintdialog.cpp
  automintmodel.cpp
  automintnotification.cpp
  bantablemodel.cpp
  bitcoinaddressvalidator.cpp
  bitcoinamountfield.cpp
  bitcoingui.cpp
  bitcoinstrings.cpp
  bitcoinunits.cpp
  cancelpassworddialog.cpp
  clientmodel.cpp
  coincontroldialog.cpp
  coincontroltreewidget.cpp
  csvmodelwriter.cpp
  editaddressdialog.cpp
  guiutil.cpp
  intro.cpp
  lelantuscoincontroldialog.cpp
  lelantusdialog.cpp
  lelantusmodel.cpp
  manualmintdialog.cpp
  masternodelist.cpp
  modaloverlay.cpp
  networkstyle.cpp
  notificator.cpp
  notifymnemonic.cpp
  openuridialog.cpp
  optionsdialog.cpp
  optionsmodel.cpp
  overviewpage.cpp
  paymentserver.cpp
  pcodemodel.cpp
  peertablemodel.cpp
  platformstyle.cpp
  qvalidatedlineedit.cpp
  qvaluecombobox.cpp
  receivecoinsdialog.cpp
  receiverequestdialog.cpp
  recentrequeststablemodel.cpp
  recover.cpp
  rpcconsole.cpp
  sendcoinsdialog.cpp
  sendcoinsentry.cpp
  sendtopcodedialog.cpp
  signverifymessagedialog.cpp
  sparkmodel.cpp
  splashscreen.cpp
  trafficgraphwidget.cpp
  transactiondesc.cpp
  transactiondescdialog.cpp
  transactionfilterproxy.cpp
  transactionrecord.cpp
  transactiontablemodel.cpp
  transactionview.cpp
  utilitydialog.cpp
  walletframe.cpp
  walletmodel.cpp
  walletmodeltransaction.cpp
  walletview.cpp
  winshutdownmonitor.cpp
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
    clientmodel.cpp
    clientmodel.h
    PROPERTIES SKIP_AUTOUIC ON 
)
target_link_libraries(firoqt
  PUBLIC
    leveldb
    secp256k1
    univalue
    secp256k1pp
    Qt5::Widgets
    Qt5::Network
  PRIVATE
    core_interface
    firo_cli
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:QRencode::QRencode>
    $<$<PLATFORM_ID:Darwin>:-framework\ AppKit>
    $<$<CXX_COMPILER_ID:MSVC>:shlwapi>
)

if(ENABLE_WALLET)
  target_sources(firoqt
    PRIVATE
        addressbookpage.cpp
        automintdialog.cpp
        automintnotification.cpp
        addresstablemodel.cpp
        askpassphrasedialog.cpp
        coincontroldialog.cpp
        coincontroltreewidget.cpp
        editaddressdialog.cpp
        manualmintdialog.cpp
        openuridialog.cpp
        overviewpage.cpp
        pcodemodel.cpp
        paymentserver.cpp
        receivecoinsdialog.cpp
        receiverequestdialog.cpp
        recentrequeststablemodel.cpp
        sendcoinsdialog.cpp
        sendcoinsentry.cpp
        sendtopcodedialog.cpp
        signverifymessagedialog.cpp
        transactiondesc.cpp
        transactiondescdialog.cpp
        transactionfilterproxy.cpp
        transactionrecord.cpp
        transactiontablemodel.cpp
        transactionview.cpp
        walletframe.cpp
        walletmodel.cpp
        walletmodeltransaction.cpp
        masternodelist.cpp
        walletview.cpp
        lelantusmodel.cpp
        lelantusdialog.cpp
        lelantuscoincontroldialog.cpp
        automintmodel.cpp
        sparkmodel.cpp
  )
  target_link_libraries(firoqt
    PRIVATE
      firo_wallet
      Qt5::Network
  )
endif()

if(WITH_DBUS)
  target_link_libraries(firoqt PRIVATE Qt5::DBus)
endif()

if(qt_lib_type STREQUAL "STATIC_LIBRARY")
  # We want to define static plugins to link ourselves, thus preventing
  # automatic linking against a "sane" set of default static plugins.
  qt5_import_plugins(firoqt
      EXCLUDE_BY_TYPE bearer iconengines imageformats platforms styles
  )
endif()

add_executable(firo-qt
  bitcoin.cpp
)

add_windows_resources(firo-qt res/bitcoin-qt-res.rc)
target_link_libraries(firo-qt
  PUBLIC
    core_interface
    Qt5::Widgets
    firoqt
    firo_node
    Qt5::Dependencies
    )

import_plugins(firo-qt)
install_binary_component(firo-qt HAS_MANPAGE)
if(WIN32)
  set_target_properties(firo-qt PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

if(WITH_MULTIPROCESS)
  add_executable(bitcoin-gui
    main.cpp
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

if(BUILD_GUI_TESTS)
  add_subdirectory(test)
endif()


# Gets sources to be parsed to gather translatable strings.
function(get_translatable_sources var)
  set(result)
  set(targets)
  foreach(dir IN ITEMS ${ARGN})
    get_directory_property(dir_targets DIRECTORY ${PROJECT_SOURCE_DIR}/${dir} BUILDSYSTEM_TARGETS)
    list(APPEND targets ${dir_targets})
  endforeach()
  foreach(target IN LISTS targets)
    get_target_property(target_sources ${target} SOURCES)
    if(target_sources)
      foreach(source IN LISTS target_sources)
        # Get an expression from the generator expression, if any.
        if(source MATCHES ":([^>]+)>$")
          set(source ${CMAKE_MATCH_1})
        endif()
        cmake_path(GET source EXTENSION LAST_ONLY ext)
        if(ext STREQUAL ".qrc")
          continue()
        endif()
        if(NOT IS_ABSOLUTE source)
          get_target_property(target_source_dir ${target} SOURCE_DIR)
          cmake_path(APPEND target_source_dir ${source} OUTPUT_VARIABLE source)
        endif()
        get_property(is_generated
          SOURCE  ${source} TARGET_DIRECTORY ${target}
          PROPERTY GENERATED
        )
        if(NOT is_generated)
          list(APPEND result ${source})
        endif()
      endforeach()
    endif()
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
    COMMAND ${CMAKE_COMMAND} -E env XGETTEXT=${XGETTEXT_EXECUTABLE} COPYRIGHT_HOLDERS=${COPYRIGHT_HOLDERS} ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/share/qt/extract_strings_qt.py ${translatable_sources}
    COMMAND Qt5::lupdate -no-obsolete -I ${PROJECT_SOURCE_DIR}/src -locations relative ${CMAKE_CURRENT_SOURCE_DIR}/bitcoinstrings.cpp ${ui_files} ${qt_translatable_sources} -ts ${CMAKE_CURRENT_SOURCE_DIR}/locale/bitcoin_en.ts
    COMMAND Qt5::lconvert -drop-translations -o ${CMAKE_CURRENT_SOURCE_DIR}/locale/bitcoin_en.xlf -i ${CMAKE_CURRENT_SOURCE_DIR}/locale/bitcoin_en.ts
    COMMAND ${SED_EXECUTABLE} -i.old -e "s|source-language=\"en\" target-language=\"en\"|source-language=\"en\"|" -e "/<target xml:space=\"preserve\"><\\/target>/d" ${CMAKE_CURRENT_SOURCE_DIR}/locale/bitcoin_en.xlf
    COMMAND ${CMAKE_COMMAND} -E rm ${CMAKE_CURRENT_SOURCE_DIR}/locale/bitcoin_en.xlf.old
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
    VERBATIM
  )
endif()
