#include "property.h"

namespace exodus {

bool IsEnabledFlag(SigmaStatus status)
{
    return status == SigmaStatus::SoftEnabled || status == SigmaStatus::HardEnabled;
}

}
