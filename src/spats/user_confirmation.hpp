//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_USER_CONFIRMATION_HPP_INCLUDED
#define FIRO_SPATS_USER_CONFIRMATION_HPP_INCLUDED

#include <cstdint>
#include <utility>
#include <optional>
#include <functional>

#include "actions.hpp"

namespace spats {

template < concepts::Action A >
inline std::optional< std::pair< supply_amount_t, asset_symbol_t > > get_associated_burn_amount( const A & )
{
   return {};
}

inline std::optional< std::pair< supply_amount_t, asset_symbol_t > > get_associated_burn_amount( const CreateAssetAction &a )
{
   return std::pair( supply_amount_t( compute_new_spark_asset_fee( get_base( a.get() ).naming().symbol.get() ), base::precision ), base::naming().symbol );
}

inline std::optional< std::pair< supply_amount_t, asset_symbol_t > > get_associated_burn_amount( const BurnAction< BaseAssetBurnParameters > &a )
{
   return std::pair( a.get().burn_amount(), a.get().asset_symbol() );
}

inline std::optional< std::pair< supply_amount_t, asset_symbol_t > > get_associated_burn_amount( const BurnAction<> &a )
{
   assert( a.get().precision() && "Excepted precision to be specified when the action is in the phase of being confirmed by the user" );
   assert( a.get().asset_symbol() && "Excepted symbol to be specified when the action is in the phase of being confirmed by the user" );
   if ( a.get().precision() && a.get().asset_symbol() ) [[likely]]
      return std::pair( supply_amount_t{ a.get().raw_burn_amount(), *a.get().precision() }, *a.get().asset_symbol() );
   return {};
}

class BurnActionUserConfirmationCallback {
public:
   BurnActionUserConfirmationCallback() = default;

   // non-explicit
   BurnActionUserConfirmationCallback( auto callback )
      : spats_burn_callback_( callback )
      , base_burn_callback_( callback )
   {}

   explicit operator bool() const noexcept
   {
      return spats_burn_callback_ && base_burn_callback_;   // well, both will be present or both will be absent
   }

   bool operator()( const BurnAction< BurnParameters > &action, CAmount standard_fee, std::int64_t txsize ) const
   {
      return spats_burn_callback_( action, standard_fee, txsize );
   }

   bool operator()( const BurnAction< BaseAssetBurnParameters > &action, CAmount standard_fee, std::int64_t txsize ) const
   {
      return base_burn_callback_( action, standard_fee, txsize );
   }

private:
   std::function< bool( const BurnAction< BurnParameters > &action, CAmount standard_fee, std::int64_t txsize ) > spats_burn_callback_;
   std::function< bool( const BurnAction< BaseAssetBurnParameters > &action, CAmount standard_fee, std::int64_t txsize ) > base_burn_callback_;
};

}   // namespace spats

#endif   // FIRO_SPATS_USER_CONFIRMATION_HPP_INCLUDED
