#ifndef ZCOIN_MBSTRING_H
#define ZCOIN_MBSTRING_H

#include <string>

/** Replaces invalid UTF-8 characters or character sequences with question marks. */
std::string SanitizeInvalidUTF8(const std::string& s);

#endif // ZCOIN_MBSTRING_H
