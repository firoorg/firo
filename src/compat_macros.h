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

#if defined(__cplusplus) && (__cplusplus >= 201703L) \
    && defined(__has_attribute) && __has_attribute(fallthrough)
  #define FIRO_FALLTHROUGH [[fallthrough]]
#elif !defined(__clang__) && defined(__has_attribute)
 #if __has_attribute(gnu::fallthrough)
  #define FIRO_FALLTHROUGH [[gnu::fallthrough]]
 #endif
#elif defined(__has_attribute) && __has_attribute(fallthrough)
  #define FIRO_FALLTHROUGH __attribute__((fallthrough))
#elif defined(__GNUC__) && (__GNUC__ >= 7) && !defined(__clang__)
  #define FIRO_FALLTHROUGH __attribute__((fallthrough))
#else
  #define FIRO_FALLTHROUGH /* fallthrough */
#endif

#endif // COMPAT_MACROS_H
