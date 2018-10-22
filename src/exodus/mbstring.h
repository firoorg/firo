#ifndef EXODUS_MBSTRING_H
#define EXODUS_MBSTRING_H

#include <stdint.h>
#include <string>

namespace exodus
{
/** Replaces invalid UTF-8 characters or character sequences with question marks. */
std::string SanitizeInvalidUTF8(const std::string& s);
}

#endif // EXODUS_MBSTRING_H
