//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_UTILS_LOCK_PROOF_HPP_INCLUDED
#define FIRO_UTILS_LOCK_PROOF_HPP_INCLUDED

#include <mutex>
#include <shared_mutex>
#include <stdexcept>

#include "traits.hpp"

namespace utils {

template < class M >
concept mutex = requires( M &m ) {
   m.lock();
   m.unlock();
};

template < auto MutexMemberPtr >
concept mutex_member_ptr = is_member_ptr< MutexMemberPtr >::value && mutex< typename is_member_ptr< MutexMemberPtr >::data_type >;

template < auto MutexMemberPtr >
   requires mutex_member_ptr< MutexMemberPtr >
class write_lock_proof {
   using class_type = typename is_member_ptr< MutexMemberPtr >::class_type;
   using mutex_type = typename is_member_ptr< MutexMemberPtr >::data_type;

public:
   // the lock parameter is a non-const reference so that temporary objects cannot be passed
   // ATTENTION: intentionally non-explicit
   write_lock_proof( class_type &c, std::unique_lock< mutex_type > &lock )
   {
      assert( lock.owns_lock() );
      assert( lock.mutex() == &(c.*MutexMemberPtr) );
      if ( !lock.owns_lock() )
         throw std::logic_error( "write_lock_proof: supplied unique_lock is not actually locked!" );
      if ( lock.mutex() != &(c.*MutexMemberPtr) )
         throw std::logic_error( "write_lock_proof: supplied unique_lock does not actually lock the expected mutex object!" );
   }
};

template < auto MutexMemberPtr >
   requires mutex_member_ptr< MutexMemberPtr >
class read_lock_proof {
   using class_type = typename is_member_ptr< MutexMemberPtr >::class_type;
   using mutex_type = typename is_member_ptr< MutexMemberPtr >::data_type;

public:
   // ATTENTION: all constructors are intentionally non-explicit

   // the lock parameter is a non-const reference so that temporary objects cannot be passed
   read_lock_proof( const class_type &c, std::shared_lock< mutex_type > &lock )
   {
      assert( lock.owns_lock() );
      assert( lock.mutex() == &(c.*MutexMemberPtr) );
      if ( !lock.owns_lock() )
         throw std::logic_error( "read_lock_proof: supplied shared_lock is not actually locked!" );
      if ( lock.mutex() != &(c.*MutexMemberPtr) )
         throw std::logic_error( "read_lock_proof: supplied shared_lock does not actually lock the expected mutex object!" );
   }

   // if one owns a unique (write) lock, then that is good for reading as well
   // the lock parameter is a non-const reference so that temporary objects cannot be passed
   read_lock_proof( const class_type &c, std::unique_lock< mutex_type > &lock )
   {
      assert( lock.owns_lock() );
      assert( lock.mutex() == &(c.*MutexMemberPtr) );
      if ( !lock.owns_lock() )
         throw std::logic_error( "read_lock_proof: supplied shared_lock is not actually locked!" );
      if ( lock.mutex() != &(c.*MutexMemberPtr) )
         throw std::logic_error( "read_lock_proof: supplied shared_lock does not actually lock the expected mutex object!" );
   }

   // again, if one can prove write lock ownership, then that is good for reading as well
   read_lock_proof( write_lock_proof< MutexMemberPtr > ) noexcept {}
};

}   // namespace utils

#endif   // FIRO_UTILS_LOCK_PROOF_HPP_INCLUDED
