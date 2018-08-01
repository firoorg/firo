#include "exodus/version.h"

#include "clientversion.h"
#include "tinyformat.h"

#include <string>

#ifdef HAVE_BUILD_INFO
#    include "build.h"
#endif

#ifdef EXODUS_VERSION_STATUS
#    define EXODUS_VERSION_SUFFIX STRINGIZE(EXODUS_VERSION_STATUS)
#else
#    define EXODUS_VERSION_SUFFIX ""
#endif

extern const int EXODUS_VERSION_MAJOR;
extern const int EXODUS_VERSION_MINOR;
extern const int EXODUS_VERSION_PATCH;
extern const int EXODUS_VERSION_BUILD;

//! Returns formatted Exodus version, e.g. "1.2.0" or "1.3.4.1"
const std::string ExodusVersion()
{
    if (EXODUS_VERSION_BUILD) {
        return strprintf("%d.%d.%d.%d",
                EXODUS_VERSION_MAJOR,
                EXODUS_VERSION_MINOR,
                EXODUS_VERSION_PATCH,
                EXODUS_VERSION_BUILD);
    } else {
        return strprintf("%d.%d.%d",
                EXODUS_VERSION_MAJOR,
                EXODUS_VERSION_MINOR,
                EXODUS_VERSION_PATCH);
    }
}

//! Returns formatted Zcoin Core version, e.g. "0.10", "0.9.3"
const std::string ZcoinCoreVersion()
{
    if (CLIENT_VERSION_BUILD) {
        return strprintf("%d.%d.%d.%d",
                CLIENT_VERSION_MAJOR,
                CLIENT_VERSION_MINOR,
                CLIENT_VERSION_REVISION,
                CLIENT_VERSION_BUILD);
    } else {
        return strprintf("%d.%d.%d",
                CLIENT_VERSION_MAJOR,
                CLIENT_VERSION_MINOR,
                CLIENT_VERSION_REVISION);
    }
}
