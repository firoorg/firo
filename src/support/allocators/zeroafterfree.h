// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SUPPORT_ALLOCATORS_ZEROAFTERFREE_H
#define BITCOIN_SUPPORT_ALLOCATORS_ZEROAFTERFREE_H

#include "../cleanse.h"

#include <memory>
#include <vector>

template <typename T>
struct zero_after_free_allocator : public std::allocator<T> {
    // MSVC8 default copy constructor is broken
    using base = std::allocator<T>;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;

    zero_after_free_allocator() throw() {}
    zero_after_free_allocator(const zero_after_free_allocator& a) throw() : base(a) {}
    template <typename U>
    zero_after_free_allocator(const zero_after_free_allocator<U>& a) throw() : base(a)
    {
    }
    ~zero_after_free_allocator() throw() {}
    template <typename _Other>
    struct rebind {
        typedef zero_after_free_allocator<_Other> other;
    };

    void deallocate(T* p, std::size_t n)
    {
        if (p != NULL)
            memory_cleanse(p, sizeof(T) * n);
        std::allocator<T>::deallocate(p, n);
    }
};

// Byte-vector that clears its contents before deletion.
typedef std::vector<char, zero_after_free_allocator<char> > CSerializeData;

#endif // BITCOIN_SUPPORT_ALLOCATORS_ZEROAFTERFREE_H
