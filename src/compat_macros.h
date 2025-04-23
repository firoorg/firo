#ifndef COMPAT_MACROS_H
#define COMPAT_MACROS_H

#ifdef __cplusplus
    #if defined(HAVE_MAYBE_UNUSED)
         #define __firo_unused [[maybe_unused]]
    #elif defined(HAVE_ATTRIBUTE_UNUSED)
         #define __firo_unused __attribute__((unused))
    #else
         #define __firo_unused
    #endif
#else
    // In C mode, if the compiler supports __attribute__((unused)), use it.
    #if defined(__has_attribute)
       #if __has_attribute(unused)
         #define __firo_unused __attribute__((unused))
       #else
         #define __firo_unused
       #endif
    #else
       #define __firo_unused
    #endif
#endif

#endif