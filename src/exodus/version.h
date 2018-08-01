#ifndef EXODUS_VERSION_H
#define EXODUS_VERSION_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#else
#endif // HAVE_CONFIG_H

//#if !defined(WINDRES_PREPROC)

//
// *-res.rc includes this file, but it cannot cope with real c++ code.
// WINDRES_PREPROC is defined to indicate that its pre-processor is running.
// Anything other than a define should be guarded below:
//

#include <string>

//
// Exodus version information are also to be defined in configure.ac.
//
// During the configuration, this information are used for other places.
//

// Increase with every consensus affecting change
//#define EXODUS_VERSION_MAJOR 0

const int EXODUS_VERSION_MAJOR = 0;

// Increase with every non-consensus affecting feature
//#define EXODUS_VERSION_MINOR 3
const int EXODUS_VERSION_MINOR = 3;

// Increase with every patch, which is not a feature or consensus affecting
//#define EXODUS_VERSION_PATCH 0
const int EXODUS_VERSION_PATCH = 0;

// Non-public build number/revision (usually zero)
//#define EXODUS_VERSION_BUILD 0
const int EXODUS_VERSION_BUILD = 0;

//! Exodus client version
static const int EXODUS_VERSION =
                    +100000000000 * EXODUS_VERSION_MAJOR
                    +    10000000 * EXODUS_VERSION_MINOR
                    +        1000 * EXODUS_VERSION_PATCH
                    +           1 * EXODUS_VERSION_BUILD;

//! Returns formatted Exodus version, e.g. "1.2.0"
const std::string ExodusVersion();

//! Returns formatted Bitcoin Core version, e.g. "0.10", "0.9.3"
const std::string ZcoinCoreVersion();


//#endif // WINDRES_PREPROC

#endif // EXODUS_VERSION_H
