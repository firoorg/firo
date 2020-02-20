#include "exodus/version.h"

#include "clientversion.h"
#include "tinyformat.h"

#include <string>

#ifdef HAVE_BUILD_INFO
#    include "build.h"
#endif

#ifdef ELYSIUM_VERSION_STATUS
#    define ELYSIUM_VERSION_SUFFIX STRINGIZE(ELYSIUM_VERSION_STATUS)
#else
#    define ELYSIUM_VERSION_SUFFIX ""
#endif

extern const int ELYSIUM_VERSION_MAJOR;
extern const int ELYSIUM_VERSION_MINOR;
extern const int ELYSIUM_VERSION_PATCH;
extern const int ELYSIUM_VERSION_BUILD;

//! Returns formatted Exodus version, e.g. "1.2.0" or "1.3.4.1"
const std::string ExodusVersion()
{
    if (ELYSIUM_VERSION_BUILD) {
        return strprintf("%d.%d.%d.%d",
                ELYSIUM_VERSION_MAJOR,
                ELYSIUM_VERSION_MINOR,
                ELYSIUM_VERSION_PATCH,
                ELYSIUM_VERSION_BUILD);
    } else {
        return strprintf("%d.%d.%d",
                ELYSIUM_VERSION_MAJOR,
                ELYSIUM_VERSION_MINOR,
                ELYSIUM_VERSION_PATCH);
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
