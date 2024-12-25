//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_SPARK_ASSET_HPP_INCLUDED
#define FIRO_SPATS_SPARK_ASSET_HPP_INCLUDED

#include <locale>
#include <string>
#include <variant>
#include <algorithm>

#include "../serialize.h"
#include "../utils/constrained_value.hpp"
#include "../utils/scaled_amount.hpp"

#include "identification.hpp"

namespace spats {

using namespace std::literals;

inline bool is_nonempty_and_trimmed( const std::string_view s ) noexcept
{
   const auto is_space = []( char c ) { return std::isspace( c, std::locale::classic() ); };
   return !s.empty() && !is_space( s.front() ) && !is_space( s.back() );
}

inline bool is_nonempty_and_all_uppercase( const std::string_view s ) noexcept
{
   return !s.empty() && std::ranges::all_of( s, []( char c ) { return std::isupper( c, std::locale::classic() ); } );
}

using nonempty_trimmed_string = utils::constrained_value< std::string, is_nonempty_and_trimmed >;
using nonempty_trimmed_uppercase_string = utils::constrained_value< std::string, is_nonempty_and_all_uppercase >;
using public_address_t = std::string;   // TODO a constrained_value instead?

struct AssetNaming {
   nonempty_trimmed_string name;
   nonempty_trimmed_uppercase_string symbol;
   std::string description;

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << name.get() << symbol.get() << description;
   }

   template < typename Stream >
   void Unserialize( Stream &is )
   {
      std::string s;
      is >> s;
      name = std::move( s );
      is >> s;
      symbol = std::move( s );
      is >> description;
   }
};

using supply_amount_t = utils::scaled_amount<>;

class SparkAssetBase {
public:
   [[nodiscard]] asset_type_t asset_type() const noexcept { return asset_type_; }
   [[nodiscard]] const AssetNaming &naming() const noexcept { return asset_naming_; }
   [[nodiscard]] const std::string &metadata() const noexcept { return metadata_; }
   [[nodiscard]] const public_address_t &admin_public_address() const noexcept { return admin_public_address_; }

protected:
   // not meant to be constructed/destroyed by itself - only objects of derived classes are meant to be created
   SparkAssetBase( asset_type_t asset_type, AssetNaming asset_naming, std::string metadata, public_address_t admin_public_address )
      : asset_type_( asset_type )
      , asset_naming_( std::move( asset_naming ) )
      , metadata_( std::move( metadata ) )
      , admin_public_address_( std::move( admin_public_address ) )
   {
      if ( asset_type > max_allowed_asset_type_value )
         throw std::invalid_argument( "asset_type value unsupported: too big" );
   }

   template < typename Stream >
   SparkAssetBase( deserialize_type, Stream &is )
      : asset_naming_( "x"s, "X"s, "desc"s )   // dummy values that will soon get overwritten
   {
      is >> asset_type_ >> asset_naming_ >> metadata_ >> admin_public_address_;
   }

   ~SparkAssetBase() = default;

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << asset_type_ << asset_naming_ << metadata_ << admin_public_address_;
   }

private:
   asset_type_t asset_type_;   // TODO constrained, together with identifier
   AssetNaming asset_naming_;
   std::string metadata_;   // TODO do we need metadata at all for fungible assets? If not then move to NFT specifically.
   public_address_t admin_public_address_;
   // TODO? bool admin_control_transferable_;
};

template < bool Fungible >
class BasicSparkAsset : public SparkAssetBase {
   // fungible asset (currency)
   static_assert( Fungible, "Fungible should be true here, an explicit specialization should exist for 'false'" );

public:
   BasicSparkAsset(
     asset_type_t asset_type, AssetNaming asset_naming, std::string metadata, public_address_t admin_public_address, supply_amount_t total_supply, bool resupplyable )
      : SparkAssetBase( asset_type, std::move( asset_naming ), std::move( metadata ), std::move( admin_public_address ) )
      , total_supply_( total_supply )
      , resupplyable_( resupplyable )
   {
      if ( !is_fungible_asset_type( asset_type ) )
         throw std::runtime_error( "Invalid asset_type value specified for a fungible asset" );
   }

   template < typename Stream >
   BasicSparkAsset( deserialize_type, Stream &is )
      : SparkAssetBase( deserialize, is )
   {
      supply_amount_t::raw_amount_type total_supply_raw;
      is >> total_supply_raw;
      total_supply_ = total_supply_raw;
      is >> resupplyable_;
   }

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      SparkAssetBase::Serialize( os );
      os << total_supply_.raw() << resupplyable_;
   }

   [[nodiscard]] supply_amount_t total_supply() const noexcept { return total_supply_; }
   [[nodiscard]] bool resupplyable() const noexcept { return resupplyable_; }

private:
   supply_amount_t total_supply_;   // Precision of the asset is included within this too
   bool resupplyable_ = true;
};

template <>
class BasicSparkAsset< false > : public SparkAssetBase {
public:
   // non-fungible asset (NFT)

   BasicSparkAsset( asset_type_t asset_type, identifier_t identifier, AssetNaming asset_naming, std::string metadata, public_address_t admin_public_address )
      : SparkAssetBase( asset_type, std::move( asset_naming ), std::move( metadata ), std::move( admin_public_address ) )
      , identifier_( identifier )
   {
      if ( is_fungible_asset_type( asset_type ) )
         throw std::runtime_error( "Invalid asset_type value specified for a non-fungible asset" );
   }

   template < typename Stream >
   BasicSparkAsset( deserialize_type, Stream &is )
      : SparkAssetBase( deserialize, is )
   {
      is >> identifier_;
   }

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      SparkAssetBase::Serialize( os );
      os << identifier_;
   }

   [[nodiscard]] identifier_t identifier() const noexcept { return identifier_; }

private:
   identifier_t identifier_;
};

using FungibleSparkAsset = BasicSparkAsset< true >;
using NonfungibleSparkAsset = BasicSparkAsset< false >;
using Nft = NonfungibleSparkAsset;   // just another alias, for convenience

using SparkAsset = std::variant< FungibleSparkAsset, NonfungibleSparkAsset >;

// Function that returns the base of a SparkAsset
inline const SparkAssetBase &get_base( const SparkAsset &asset ) noexcept
{
   return std::visit( []( const auto &a ) -> const SparkAssetBase & { return a; }, asset );
}

}   // namespace spats

#endif   // FIRO_SPATS_SPARK_ASSET_HPP_INCLUDED
