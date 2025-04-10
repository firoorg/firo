#ifndef COMPAT_MACROS_H
#define COMPAT_MACROS_H

#if defined(HAVE_MAYBE_UNUSED)
    #define __firo_unused [[maybe_unused]]
#elif defined(HAVE_ATTRIBUTE_UNUSED)
    #define __firo_unused __attribute__((unused))
#else
    #define __firo_unused
#endif

#endif