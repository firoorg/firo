//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_SPARK_ASSET_HPP_INCLUDED
#define FIRO_SPATS_SPARK_ASSET_HPP_INCLUDED

#include <cstdint>
#include <locale>
#include <string>
#include <variant>
#include <algorithm>

#include <boost/lexical_cast.hpp>

#include "../serialize.h"
#include "../utils/constrained_value.hpp"
#include "../utils/scaled_amount.hpp"
#include "../utils/overloaded.hpp"

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

   AssetNaming( nonempty_trimmed_string n, nonempty_trimmed_uppercase_string s, std::string desc ) noexcept
      : name( std::move( n ) )
      , symbol( std::move( s ) )
      , description( std::move( desc ) )
   {}

   template < typename Stream >
   AssetNaming( deserialize_type d, Stream &is )
      : name( d, is )
      , symbol( d, is )
   {
      is >> description;
   }

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << name << symbol << description;
   }

   bool operator==( const AssetNaming &rhs ) const noexcept = default;
};

using supply_amount_t = utils::scaled_amount<>;

class SparkAssetBase {
public:
   // getters
   [[nodiscard]] asset_type_t asset_type() const noexcept { return asset_type_; }
   [[nodiscard]] const AssetNaming &naming() const noexcept { return asset_naming_; }
   [[nodiscard]] const std::string &metadata() const noexcept { return metadata_; }
   [[nodiscard]] const public_address_t &admin_public_address() const noexcept { return admin_public_address_; }

   // setters
   void naming( AssetNaming naming ) { asset_naming_ = std::move( naming ); }
   void metadata( std::string metadata ) { metadata_ = std::move( metadata ); }

   bool operator==( const SparkAssetBase &rhs ) const noexcept = default;

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
   SparkAssetBase( deserialize_type d, Stream &is )
      : asset_naming_( d, is )
   {
      is >> asset_type_ >> metadata_ >> admin_public_address_;
      if ( asset_type_ > max_allowed_asset_type_value )
         throw std::invalid_argument( "Serialized asset_type value unsupported: too big" );
   }

   ~SparkAssetBase() = default;

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << asset_naming_ << asset_type_ << metadata_ << admin_public_address_;
   }

private:
   asset_type_t asset_type_;   // TODO constrained, together with identifier
   AssetNaming asset_naming_;
   std::string metadata_;   // TODO do we need metadata at all for fungible assets? If not then move to NFT specifically.
   public_address_t admin_public_address_;
   // TODO? bool admin_control_transferable_;
};

struct SparkAssetDisplayAttributes;

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
      if ( !resupplyable && !total_supply )
         throw std::runtime_error( "Not allowing to create a non-resuppliable asset with 0 supply" );   // to avoid user frustration with pointless loss of money
   }

   template < typename Stream >
   BasicSparkAsset( deserialize_type, Stream &is )
      : SparkAssetBase( deserialize, is )
   {
      if ( !is_fungible_asset_type( asset_type() ) )
         throw std::runtime_error( "Invalid asset_type value serialized for a fungible asset" );
      supply_amount_t::precision_type precision;
      supply_amount_t::raw_amount_type total_supply_raw;
      is >> precision >> total_supply_raw;
      total_supply_ = { total_supply_raw, precision };
      is >> resupplyable_;
      if ( !resupplyable_ && !total_supply_ )
         throw std::runtime_error( "Rejecting a serialized non-resuppliable asset with 0 supply" );   // to avoid user frustration with pointless loss of money
   }

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      SparkAssetBase::Serialize( os );
      os << total_supply_.precision() << total_supply_.raw() << resupplyable_;
   }

   [[nodiscard]] supply_amount_t total_supply() const noexcept { return total_supply_; }
   [[nodiscard]] bool resupplyable() const noexcept { return resupplyable_; }

   [[nodiscard]] supply_amount_t::precision_type precision() const noexcept { return total_supply_.precision(); }

   bool operator==( const BasicSparkAsset &rhs ) const noexcept = default;

   explicit operator SparkAssetDisplayAttributes() const;
   explicit operator universal_asset_id_t() const noexcept { return { asset_type(), identifier_t{} }; }

   void add_new_supply( supply_amount_t new_supply )
   {
      assert( resupplyable_ );
      assert( new_supply.precision() == total_supply_.precision() );
      total_supply_ += new_supply;   // may throw due to overflow
   }

   void remove_supply( supply_amount_t new_supply )
   {
      assert( resupplyable_ );
      assert( new_supply.precision() == total_supply_.precision() );
      assert( new_supply <= total_supply_ );
      total_supply_ -= new_supply;   // may throw due to underflow, iff the assert above would fail but is eliminated due to NDEBUG
   }

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
      if ( is_fungible_asset_type( asset_type() ) )
         throw std::runtime_error( "Invalid asset_type value serialized for a non-fungible asset" );
      is >> identifier_;
   }

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      SparkAssetBase::Serialize( os );
      os << identifier_;
   }

   [[nodiscard]] identifier_t identifier() const noexcept { return identifier_; }

   bool operator==( const BasicSparkAsset &rhs ) const noexcept = default;

   explicit operator SparkAssetDisplayAttributes() const;
   explicit operator universal_asset_id_t() const noexcept { return { asset_type(), identifier() }; }

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

inline std::optional< identifier_t > get_identifier( const SparkAsset &asset ) noexcept
{
   return std::visit( utils::overloaded{ []( const FungibleSparkAsset & ) -> std::optional< identifier_t > { return std::nullopt; },
                                         []( const NonfungibleSparkAsset &a ) -> std::optional< identifier_t > { return a.identifier(); } },
                      asset );
}

inline supply_amount_t get_total_supply( const SparkAsset &a ) noexcept
{
   return std::visit( utils::overloaded{ []( const FungibleSparkAsset &x ) { return x.total_supply(); },
                                         []( const NonfungibleSparkAsset & ) { return supply_amount_t( 1, 0 ); } },
                      a );
}

struct SparkAssetDisplayAttributes {
   asset_type_underlying_type asset_type;
   identifier_underlying_type identifier = 0;
   std::string name;
   std::string symbol;
   std::string description;
   std::string metadata;
   std::string admin_public_address;
   std::string total_supply = "1";
   unsigned precision = 0;
   bool resupplyable = false;
   bool fungible = false;

   SparkAssetDisplayAttributes( const SparkAssetBase &b )
      : asset_type( utils::to_underlying( b.asset_type() ) )
      , name( b.naming().name )
      , symbol( b.naming().symbol )
      , description( b.naming().description )
      , metadata( b.metadata() )
      , admin_public_address( b.admin_public_address() )
   {}

   SparkAssetDisplayAttributes( const SparkAsset &asset )
   {
      *this = std::visit( []( const auto &a ) { return SparkAssetDisplayAttributes( a ); }, asset );
   }
};

template < bool Fungible >
BasicSparkAsset< Fungible >::operator SparkAssetDisplayAttributes() const
{
   static_assert( Fungible );
   const SparkAssetBase &b = *this;
   SparkAssetDisplayAttributes ret( b );
   ret.fungible = true;
   ret.total_supply = boost::lexical_cast< std::string >( total_supply() );
   ret.precision = precision();
   ret.resupplyable = resupplyable();
   return ret;
}

inline BasicSparkAsset< false >::operator SparkAssetDisplayAttributes() const
{
   const SparkAssetBase &b = *this;
   SparkAssetDisplayAttributes ret( b );
   ret.identifier = utils::to_underlying( identifier() );
   return ret;
}

// Compute the fee specifically for creating a new spark asset, based on the length of the asset's symbol.
// The shorter the symbol, the more expensive the fee.
// Right now mimicking the fee structure for Spark Names to get at concrete numbers.
// They don't necessarily have to match though, so these numbers here may change before going live...
// Returns the value as CAmount.
std::int64_t compute_new_spark_asset_fee( std::string_view asset_symbol ) noexcept;

}   // namespace spats

#endif   // FIRO_SPATS_SPARK_ASSET_HPP_INCLUDED