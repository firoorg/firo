# Copyright 2013 Corgan Labs
# This file is part of the Zerocoin project
# See LICENSE file or http://opensource.org/licenses/MIT for terms

if(DEFINED __INCLUDED_BOOSTCONFIG_CMAKE)
    return()
endif()

set(__INCLUDED_BOOSTCONFIG_CMAKE TRUE)

set(BOOST_REQUIRED_COMPONENTS
  system
)

find_package(Boost "1.48" COMPONENTS ${BOOST_REQUIRED_COMPONENTS})

set(Boost_ADDITIONAL_VERSIONS
  "1.45.0" "1.45" "1.46.0" "1.46" "1.47.0" "1.47" "1.48.0" "1.48" "1.49.0" "1.49"
  "1.50.0" "1.50" "1.51.0" "1.51" "1.52.0" "1.52" "1.53.0" "1.53" "1.54.0" "1.54"
  "1.55.0" "1.55" "1.56.0" "1.56" "1.57.0" "1.57" "1.58.0" "1.58" "1.59.0" "1.59"
  "1.60.0" "1.60" "1.61.0" "1.61" "1.62.0" "1.62" "1.63.0" "1.63" "1.64.0" "1.64"
  "1.65.0" "1.65" "1.66.0" "1.66" "1.67.0" "1.67" "1.68.0" "1.68" "1.69.0" "1.69"
)

list(APPEND Boost_LIBRARIES
  ${Boost_SYSTEM_LIBRARY}
)
