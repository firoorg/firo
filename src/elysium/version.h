#ifndef ELYSIUM_VERSION_H
#define ELYSIUM_VERSION_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#else
#endif // HAVE_CONFIG_H

//
// *-res.rc includes this file, but it cannot cope with real c++ code.
// WINDRES_PREPROC is defined to indicate that its pre-processor is running.
// Anything other than a define should be guarded below:
//

#include <string>

//
// Elysium version information are also to be defined in configure.ac.
//
// During the configuration, this information are used for other places.
//

// Increase with every consensus affecting change
//#define ELYSIUM_VERSION_MAJOR 0

const int ELYSIUM_VERSION_MAJOR = 0;

// Increase with every non-consensus affecting feature
//#define ELYSIUM_VERSION_MINOR 3
const int ELYSIUM_VERSION_MINOR = 3;

// Increase with every patch, which is not a feature or consensus affecting
//#define ELYSIUM_VERSION_PATCH 0
const int ELYSIUM_VERSION_PATCH = 0;

// Non-public build number/revision (usually zero)
//#define ELYSIUM_VERSION_BUILD 0
const int ELYSIUM_VERSION_BUILD = 0;

//! Elysium client version
static const int ELYSIUM_VERSION = // lgtm [cpp/unused-static-variable]
                    +100000000000 * ELYSIUM_VERSION_MAJOR
                    +    10000000 * ELYSIUM_VERSION_MINOR
                    +        1000 * ELYSIUM_VERSION_PATCH
                    +           1 * ELYSIUM_VERSION_BUILD;

//! Returns formatted Elysium version, e.g. "1.2.0"
const std::string ElysiumVersion();

//! Returns formatted Bitcoin Core version, e.g. "0.10", "0.9.3"
const std::string FiroCoreVersion();

#endif // ELYSIUM_VERSION_H
