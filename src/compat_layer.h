#ifndef COMPAT_LAYER_H
#define COMPAT_LAYER_H

#ifdef __cplusplus
    #if defined(HAVE_MAYBE_UNUSED)
         #define FIRO_UNUSED [[maybe_unused]]
    #elif defined(HAVE_ATTRIBUTE_UNUSED)
         #define FIRO_UNUSED __attribute__((unused))
    #else
         #define FIRO_UNUSED
    #endif
#else
    // In C mode, if the compiler supports __attribute__((unused)), use it.
    #if defined(__has_attribute)
       #if __has_attribute(unused)
         #define FIRO_UNUSED __attribute__((unused))
       #else
         #define FIRO_UNUSED
       #endif
    #else
       #define FIRO_UNUSED
    #endif
#endif

#if defined(__cplusplus) && (__cplusplus >= 201703L)
    #if defined(__has_attribute) && __has_attribute(fallthrough)
        #define FIRO_FALLTHROUGH [[fallthrough]]
    #elif !defined(__clang__) && defined(__has_attribute)
        #if __has_attribute(gnu::fallthrough)
            #define FIRO_FALLTHROUGH [[gnu::fallthrough]]
        #endif
    #elif defined(__has_attribute) && __has_attribute(fallthrough)
        #define FIRO_FALLTHROUGH __attribute__((fallthrough))
    #elif defined(__GNUC__) && (__GNUC__ >= 7) && !defined(__clang__)
        #define FIRO_FALLTHROUGH __attribute__((fallthrough))
    #endif
#else
  #define FIRO_FALLTHROUGH /* fallthrough */
#endif

#ifdef __cplusplus

  #include <type_traits>
  #include <limits>

  namespace detail {
  template<class T, class U>
  constexpr void check_integral_types() noexcept {
      static_assert(std::is_integral_v<T> && std::is_integral_v<U>,
          "cmp_* functions require integral types.");
  }
  } // namespace detail

  namespace cmp {

      template<class T, class U>
      constexpr bool equal(T t, U u) noexcept
      {
          // detail::check_integral_types<T,U>(); // Option 1: use helper
          static_assert(std::is_integral_v<T> && std::is_integral_v<U>, // Option 2: repeat
              "cmp::* functions require integral types.");
          if constexpr (std::is_signed_v<T> == std::is_signed_v<U>)
              return t == u;
          else if constexpr (std::is_signed_v<T>) // T is signed, U is unsigned
              // If t is negative, it cannot be equal to an unsigned u.
              // Otherwise, convert t to its unsigned type for comparison.
              return t >= 0 && std::make_unsigned_t<T>(t) == u;
          else // T is unsigned, U is signed
              // If u is negative, it cannot be equal to an unsigned t.
              // Otherwise, convert u to its unsigned type for comparison.
              return u >= 0 && t == std::make_unsigned_t<U>(u);
      }

      template<class T, class U>
      constexpr bool not_equal(T t, U u) noexcept
      {
          // No separate static_assert needed here as equal has it.
          return !equal(t, u);
      }

      template<class T, class U>
      constexpr bool less(T t, U u) noexcept
      {
          // detail::check_integral_types<T,U>(); // Option 1: use helper
          static_assert(std::is_integral_v<T> && std::is_integral_v<U>, // Option 2: repeat
              "* functions require integral types.");
          if constexpr (std::is_signed_v<T> == std::is_signed_v<U>)
              return t < u;
          else if constexpr (std::is_signed_v<T>) // T is signed, U is unsigned
              // If t is negative, it's always less than an unsigned u.
              // Otherwise, convert t to its unsigned type for comparison.
              return t < 0 || std::make_unsigned_t<T>(t) < u;
          else // T is unsigned, U is signed
              // If u is negative, t (unsigned) cannot be less than u.
              // (i.e. t < u is false if u < 0)
              // If u is non-negative, convert u to its unsigned type for comparison.
              return u >= 0 && t < std::make_unsigned_t<U>(u);
      }

      template<class T, class U>
      constexpr bool greater(T t, U u) noexcept
      {
          return less(u, t);
      }

      template<class T, class U>
      constexpr bool less_equal(T t, U u) noexcept
      {
          // t <= u  is equivalent to !(u < t)
          return !less(u, t);
      }

      template<class T, class U>
      constexpr bool greater_equal(T t, U u) noexcept
      {
          // t >= u is equivalent to !(t < u)
          return !less(t, u);
      }

  }

#endif

#endif // COMPAT_LAYER_H