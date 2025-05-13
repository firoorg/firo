//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_ACTIONS_HPP_INCLUDED
#define FIRO_SPATS_ACTIONS_HPP_INCLUDED

#include <optional>
#include <variant>
#include <vector>

#include <boost/format.hpp>

#include "../serialize.h"
#include "../util.h"
#include "../streams.h"

#include "../utils/string.hpp"

#include "../libspark/coin.h"

#include "identification.hpp"
#include "base_asset.hpp"
#include "modification.hpp"
#include "spark_asset.hpp"

namespace spats {

namespace concepts {

template < class A >
concept Action = requires( A a ) {
   A( deserialize, std::declval< CDataStream & >() );
   a.Serialize( std::declval< CDataStream & >() );
   a.get();
   { a.name() } -> std::same_as< std::string >;
   { a.summary() } -> std::same_as< std::string >;
   { a.asset_id() } -> std::same_as< flexible_asset_id_t >;
};

}   // namespace concepts

class UnregisterAssetParameters {
public:
   UnregisterAssetParameters( asset_type_t assettype, std::optional< identifier_t > ident, public_address_t initiator_pubaddress )
      : asset_type_( assettype )
      , identifier_( ident )
      , initiator_public_address_( std::move( initiator_pubaddress ) )
   {
      validate();
   }

   template < typename Stream >
   UnregisterAssetParameters( deserialize_type, Stream &is )
   {
      is >> asset_type_ >> identifier_ >> initiator_public_address_;
      validate();
   }

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << asset_type_ << identifier_ << initiator_public_address_;
   }

   asset_type_t asset_type() const noexcept
   {
      assert( asset_type_ != base::asset_type );
      return asset_type_;
   }

   std::optional< identifier_t > identifier() const noexcept
   {
      assert( !identifier_ || !is_fungible_asset_type( asset_type_ ) );
      return identifier_;
   }

   const public_address_t &initiator_public_address() const noexcept { return initiator_public_address_; }

private:
   asset_type_t asset_type_;
   std::optional< identifier_t > identifier_;
   public_address_t initiator_public_address_;

   void validate()
   {
      if ( asset_type_ == base::asset_type )
         throw std::domain_error( "The base asset cannot be unregistered!" );

      if ( asset_type_ > max_allowed_asset_type_value )
         throw std::invalid_argument( "asset_type value for unregistration unsupported: too big" );

      if ( is_fungible_asset_type( asset_type_ ) ) {
         if ( identifier_ )
            if ( *identifier_ == identifier_t{ 0 } )
               identifier_ = std::nullopt;
            else
               throw std::invalid_argument( "No 'identifier' should be provided for identifying a fungible asset" );
         assert( !identifier_ );
      }
      else if ( identifier_ && *identifier_ > max_allowed_identifier_value )
         throw std::invalid_argument( "identifier value for unregistration unsupported: too big" );

      if ( initiator_public_address_.empty() )
         throw std::domain_error( "Initiator public address is required for a spark asset unregistration" );
   }
};

class CreateAssetAction {
public:
   explicit CreateAssetAction( SparkAsset asset )
      : asset_( std::move( asset ) )
   {}

   template < typename Stream >
   CreateAssetAction( deserialize_type, Stream &is )
      : asset_( Unserialize( is ) )
   {}

   template < typename Stream >
   void Serialize( Stream &os ) const;

   const SparkAsset &get() const & noexcept { return asset_; }
   SparkAsset &&get() && noexcept { return std::move( asset_ ); }

   static std::string name() { return _( "Spark Asset Create" ); }

   std::string summary() const
   {
      const SparkAssetDisplayAttributes a( get() );
      return str( boost::format( _( "Create %1% spark asset with type = %2%, identifier = %3%, symbol = %4% and name = %5%" ) ) %
                  ( a.fungible ? _( "fungible" ) : _( "non-fungible" ) ) % a.asset_type % a.identifier % a.symbol % a.name );
   }

   flexible_asset_id_t asset_id() const noexcept { return { get_base( get() ).asset_type(), get_identifier( get() ) }; }

   const std::optional< spark::Coin > &coin() const noexcept { return coin_; }
   void set_coin( spark::Coin &&coin ) noexcept { coin_ = std::move( coin ); }

private:
   SparkAsset asset_;
   // TODO flag for asset_type adjustability, for avoiding failure due to the asset_type getting taken away by someone else under one's feet
   std::optional< spark::Coin > coin_;   // the coin to be minted via this action. ATTENTION: not serialized, deliberately, will only be present in spark state processing
   static constexpr std::uint8_t serialization_version = 1;

   template < typename Stream >
   static SparkAsset Unserialize( Stream &is );
};

static_assert( concepts::Action< CreateAssetAction > );

template < typename Stream >
void CreateAssetAction::Serialize( Stream &os ) const
{
   os << serialization_version;
   ::Serialize( os, asset_ );
}

template < typename Stream >
SparkAsset CreateAssetAction::Unserialize( Stream &is )
{
   std::uint8_t version;
   is >> version;
   return UnserializeVariant< SparkAsset >( is );
}

class UnregisterAssetAction {
public:
   explicit UnregisterAssetAction( UnregisterAssetParameters parameters ) noexcept
      : parameters_( std::move( parameters ) )
   {}

   template < typename Stream >
   UnregisterAssetAction( deserialize_type, Stream &is )
      : parameters_( Unserialize( is ) )
   {}

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << serialization_version;
      os << parameters_;
   }

   const UnregisterAssetParameters &get() const & noexcept { return parameters_; }
   UnregisterAssetParameters &&get() && noexcept { return std::move( parameters_ ); }

   static std::string name() { return _( "Spark Asset Unregister" ); }

   std::string summary() const
   {
      std::ostringstream os;
      os << _( "unregister of spark asset type = " ) << parameters_.asset_type();
      if ( const auto p = parameters_.identifier() )
         os << _( " and identifier = " ) << *p;
      return os.str();
   }

   flexible_asset_id_t asset_id() const noexcept { return { get().asset_type(), get().identifier() }; }

private:
   UnregisterAssetParameters parameters_;
   static constexpr std::uint8_t serialization_version = 1;

   template < typename Stream >
   static UnregisterAssetParameters Unserialize( Stream &is )
   {
      std::uint8_t version;
      is >> version;
      return UnregisterAssetParameters( deserialize, is );
   }
};

static_assert( concepts::Action< UnregisterAssetAction > );

class ModifyAssetAction {
public:
   explicit ModifyAssetAction( AssetModification asset_modification )
      : asset_modification_( std::move( asset_modification ) )
   {}

   template < typename Stream >
   ModifyAssetAction( deserialize_type, Stream &is )
      : asset_modification_( Unserialize( is ) )
   {}

   template < typename Stream >
   void Serialize( Stream &os ) const;

   const AssetModification &get() const & noexcept { return asset_modification_; }
   AssetModification &&get() && noexcept { return std::move( asset_modification_ ); }

   static std::string name() { return _( "Spark Asset Modify" ); }

   std::string summary() const
   {
      std::ostringstream os;
      std::visit( utils::overloaded{
                    [ & ]( const FungibleAssetModification &m ) { os << _( "Modify of fungible spark asset with type = " ) << m.asset_type() << ": " << m; },
                    [ & ]( const NonfungibleAssetModification &m ) {
                       os << _( "Modify of non-fungible spark asset with type = " ) << m.asset_type() << _( " and identifier = " ) << m.identifier() << ": " << m;
                    } },
                  asset_modification_ );
      return os.str();
   }

   flexible_asset_id_t asset_id() const noexcept { return { get_base( get() ).asset_type(), get_identifier( get() ) }; }

private:
   AssetModification asset_modification_;
   static constexpr std::uint8_t serialization_version = 1;

   template < typename Stream >
   static AssetModification Unserialize( Stream &is );
};

static_assert( concepts::Action< ModifyAssetAction > );

template < typename Stream >
void ModifyAssetAction::Serialize( Stream &os ) const
{
   os << serialization_version;
   ::Serialize( os, asset_modification_ );
}

template < typename Stream >
AssetModification ModifyAssetAction::Unserialize( Stream &is )
{
   std::uint8_t version;
   is >> version;
   return UnserializeVariant< AssetModification >( is );
}

class MintParameters {
public:
   MintParameters( asset_type_t asset_type, supply_amount_t new_supply, public_address_t receiver_pubaddress, public_address_t initiator_pubaddress )
      : asset_type_( asset_type )
      , new_supply_( new_supply )
      , receiver_public_address_( std::move( receiver_pubaddress ) )
      , initiator_public_address_( std::move( initiator_pubaddress ) )
   {
      validate();
   }

   template < typename Stream >
   MintParameters( deserialize_type, Stream &is )
   {
      supply_amount_t::precision_type precision;
      supply_amount_t::raw_amount_type new_supply_raw;
      is >> asset_type_ >> precision >> new_supply_raw >> receiver_public_address_ >> initiator_public_address_;
      new_supply_ = { new_supply_raw, precision };
      validate();
   }

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << asset_type_ << new_supply_.precision() << new_supply_.raw() << receiver_public_address_ << initiator_public_address_;
   }

   asset_type_t asset_type() const noexcept
   {
      assert( asset_type_ != base::asset_type );
      assert( is_fungible_asset_type( asset_type_ ) );
      return asset_type_;
   }

   supply_amount_t new_supply() const noexcept { return new_supply_; }

   const public_address_t &initiator_public_address() const noexcept { return initiator_public_address_; }
   const public_address_t &receiver_public_address() const noexcept { return receiver_public_address_.empty() ? initiator_public_address_ : receiver_public_address_; }

private:
   asset_type_t asset_type_;
   supply_amount_t new_supply_;
   public_address_t receiver_public_address_;
   public_address_t initiator_public_address_;

   void validate() const
   {
      if ( asset_type_ > max_allowed_asset_type_value )
         throw std::invalid_argument( "asset_type value for mint unsupported: too big" );

      if ( !is_fungible_asset_type( asset_type_ ) )
         throw std::invalid_argument( "NFTs can never have their total supply changed by any means, including minting" );

      if ( !new_supply_ )
         throw std::invalid_argument( "Non-zero new supply is required for spats mint" );
      static_assert( std::is_unsigned_v< supply_amount_t::raw_amount_type > );
      assert( new_supply_ > supply_amount_t{} );

      if ( asset_type_ == base::asset_type )
         throw std::domain_error( "Spats mint cannot make new supply for the base asset" );

      if ( initiator_public_address_.empty() )
         throw std::domain_error( "Initiator public address is required for spats mint" );
   }
};

class MintAction {
public:
   explicit MintAction( MintParameters parameters ) noexcept
      : parameters_( std::move( parameters ) )
   {}

   template < typename Stream >
   MintAction( deserialize_type, Stream &is )
      : parameters_( Unserialize( is ) )
   {}

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << serialization_version;
      os << parameters_;
   }

   const MintParameters &get() const & noexcept { return parameters_; }
   MintParameters &&get() && noexcept { return std::move( parameters_ ); }

   static std::string name() { return _( "Spats Mint" ); }

   std::string summary() const
   {
      return str( boost::format( _( "Minting new %1% supply for spark asset type = %2% and crediting it to %3%" ) ) % get().new_supply() % get().asset_type() %
                  utils::abbreviate_for_display( get().receiver_public_address() ) );
   }

   flexible_asset_id_t asset_id() const noexcept { return { get().asset_type(), std::nullopt }; }

   const std::optional< spark::Coin > &coin() const noexcept { return coin_; }
   void set_coin( spark::Coin &&coin ) noexcept { coin_ = std::move( coin ); }

private:
   MintParameters parameters_;
   std::optional< spark::Coin > coin_;   // the coin to be minted via this action. ATTENTION: not serialized, deliberately, will only be present in spark state processing
   static constexpr std::uint8_t serialization_version = 1;

   template < typename Stream >
   static MintParameters Unserialize( Stream &is )
   {
      std::uint8_t version;
      is >> version;
      return MintParameters( deserialize, is );
   }
};

static_assert( concepts::Action< MintAction > );

class BurnParameters {
public:
   BurnParameters( asset_type_t asset_type, supply_amount_t burn_amount, public_address_t initiator_pubaddress, asset_symbol_t symbol )
      : asset_type_( asset_type )
      , burn_amount_( burn_amount )
      , initiator_public_address_( std::move( initiator_pubaddress ) )
      , asset_symbol_( std::move( symbol ) )
   {
      validate();
   }

   template < typename Stream >
   BurnParameters( deserialize_type d, Stream &is )
      : asset_symbol_( d, is )
   {
      supply_amount_t::precision_type precision;
      supply_amount_t::raw_amount_type burn_amount_raw;
      is >> asset_type_ >> precision >> burn_amount_raw >> initiator_public_address_;
      burn_amount_ = { burn_amount_raw, precision };
      validate();
   }

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << asset_symbol_ << asset_type_ << burn_amount_.precision() << burn_amount_.raw() << initiator_public_address_;
   }

   asset_type_t asset_type() const noexcept
   {
      assert( asset_type_ != base::asset_type );
      assert( is_fungible_asset_type( asset_type_ ) );
      return asset_type_;
   }

   supply_amount_t burn_amount() const noexcept { return burn_amount_; }

   const public_address_t &initiator_public_address() const noexcept { return initiator_public_address_; }

   const asset_symbol_t &asset_symbol() const noexcept { return asset_symbol_; }

private:
   asset_type_t asset_type_;
   supply_amount_t burn_amount_;
   public_address_t initiator_public_address_;
   asset_symbol_t asset_symbol_;   // just for display purposes

   void validate() const
   {
      if ( asset_type_ > max_allowed_asset_type_value )
         throw std::invalid_argument( "asset_type value for burn unsupported: too big" );

      if ( !is_fungible_asset_type( asset_type_ ) )
         throw std::invalid_argument( "Burning NFTs is not supported" );

      if ( !burn_amount_ )
         throw std::invalid_argument( "Non-zero burn amount is required" );

      static_assert( std::is_unsigned_v< supply_amount_t::raw_amount_type > );
      assert( burn_amount_ > supply_amount_t{} );

      if ( asset_type_ == base::asset_type )
         throw std::domain_error( "Base asset supply burns are not supported by spats Burn action. Just use a simple spark spend to firo burn address tx instead." );

      if ( initiator_public_address_.empty() )
         throw std::domain_error( "Initiator public address is required for spats burn" );
   }
};

class BaseAssetBurnParameters {
public:
   explicit BaseAssetBurnParameters( supply_amount_t burn_amount, public_address_t initiator_pubaddress )
      : burn_amount_( burn_amount )
      , initiator_public_address_( std::move( initiator_pubaddress ) )
   {
      validate();
   }

   template < typename Stream >
   BaseAssetBurnParameters( deserialize_type, Stream &is )
   {
      supply_amount_t::precision_type precision;
      supply_amount_t::raw_amount_type burn_amount_raw;
      is >> precision >> burn_amount_raw >> initiator_public_address_;
      burn_amount_ = { burn_amount_raw, precision };
      validate();
   }

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << burn_amount_.precision() << burn_amount_.raw() << initiator_public_address_;
   }

   static asset_type_t asset_type() noexcept { return base::asset_type; }

   supply_amount_t burn_amount() const noexcept { return burn_amount_; }

   const public_address_t &initiator_public_address() const noexcept { return initiator_public_address_; }

   static const asset_symbol_t &asset_symbol() noexcept { return base::naming().symbol; }

private:
   supply_amount_t burn_amount_;
   public_address_t initiator_public_address_;

   void validate() const
   {
      if ( !burn_amount_ )
         throw std::invalid_argument( "Non-zero burn amount is required" );

      static_assert( std::is_unsigned_v< supply_amount_t::raw_amount_type > );
      assert( burn_amount_ > supply_amount_t{} );

      if ( initiator_public_address_.empty() )
         throw std::domain_error( "Initiator public address is required for burn" );
   }
};

template < class Params = BurnParameters >
   requires( std::is_same_v< Params, BurnParameters > || std::is_same_v< Params, BaseAssetBurnParameters > )
class BurnAction {
public:
   using parameters_type = Params;

   explicit BurnAction( parameters_type parameters ) noexcept
      : parameters_( std::move( parameters ) )
   {}

   template < typename Stream >
   BurnAction( deserialize_type, Stream &is )
      : parameters_( Unserialize( is ) )
   {}

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << serialization_version;
      os << parameters_;
   }

   const parameters_type &get() const & noexcept { return parameters_; }
   parameters_type &&get() && noexcept { return std::move( parameters_ ); }

   static std::string name()
   {
      if constexpr ( std::is_same_v< parameters_type, BaseAssetBurnParameters > )
         return BaseAssetBurnParameters::asset_symbol().get() + ' ' + _( "Burn" );
      else
         return _( "Spats Burn" );
   }

   std::string summary() const
   {
      if constexpr ( std::is_same_v< parameters_type, BaseAssetBurnParameters > )
         return str( boost::format( _( "Burning %1% %2%" ) ) % get().burn_amount() % BaseAssetBurnParameters::asset_symbol().get() );
      else
         return str( boost::format( _( "Burning supply amounting to %1% for spark asset type = %2%" ) ) % get().burn_amount() % get().asset_type() );
   }

   flexible_asset_id_t asset_id() const noexcept { return { get().asset_type(), std::nullopt }; }

private:
   parameters_type parameters_;
   static constexpr std::uint8_t serialization_version = 1;

   template < typename Stream >
   static parameters_type Unserialize( Stream &is )
   {
      std::uint8_t version;
      is >> version;
      return parameters_type( deserialize, is );
   }
};

static_assert( concepts::Action< BurnAction< BurnParameters > > );
static_assert( concepts::Action< BurnAction< BaseAssetBurnParameters > > );

using Action = std::variant< CreateAssetAction, UnregisterAssetAction, ModifyAssetAction, MintAction, BurnAction<> >;   // TODO more
// no need to have BurnAction< BaseAssetBurnParameters > in `Action`. The former is needed just for user confirmation dialog purposes...

// ensuring that all types in Action satisfy concepts::Action indeed
static_assert( []< typename... Ts >( std::type_identity< std::variant< Ts... > > ) { return ( concepts::Action< Ts > && ... ); }( std::type_identity< Action >() ) );

// Even though this is a vector, it's not really a sequence in the sense that one action comes before the other. Transaction memory pool isn't a queue, and actions can
// come from different nodes at the same time, so the ordering at hand is just coincidental, with no deep meaning behind it...
// Hence, not (any longer) having 'sequence' in this type alias' name.
using Actions = std::vector< Action >;

inline std::vector< spark::Coin > get_coins( const Action &action )
{
   if ( const auto *const m = std::get_if< MintAction >( &action ) )
      if ( m->coin() )
         return { *m->coin() };
   if ( const auto *const c = std::get_if< CreateAssetAction >( &action ) )
      if ( c->coin() )
         return { *c->coin() };
   // TODO more, as needed
   return {};
}

inline const public_address_t &get_admin_public_address( const concepts::Action auto &action )
{
   // Any actions (except for Burn) that operate on a previously registered asset are able to be initiated by the admin only, anyone else attempting to do so will fail.
   // So if this function gets called only after successful processing of an action into the registry, we can be sure that the initiator address that we are returning
   // here is indeed the admin address.
   return action.get().initiator_public_address();
}

inline const public_address_t &get_admin_public_address( const CreateAssetAction &action )
{
   return get_base( action.get() ).admin_public_address();
}

inline const public_address_t &get_admin_public_address( const ModifyAssetAction &action )
{
   // This action is able to be initiated by the admin only, anyone else attempting to do so will fail.
   // So if this function gets called only after successful processing of an action into the registry, we can be sure that the initiator address that we are returning
   // here is indeed the admin address.
   return get_base( action.get() ).initiator_public_address();
}

// In order to return the actual admin address, we would need to consult the registry to obtain the admin address for the asset type that we are burning a supply of.
// We have the initiator address, but that may not necessarily be the admin address for a Burn action - anyone can burn as long as they have at least that much supply.
// Not bothering to consult the registry here, at least for now, instead returning empty address - indicating that the actual admin address is unknown for practical
// purposes, and hence any admin address should be considered as potentially being the admin of this asset, and hence considered as affected by this action for info
// refresh purposes.
inline const public_address_t &get_admin_public_address( const BurnAction<> &action )
{
   static const public_address_t empty{};
   return empty;
   // TODO consider actually consulting the registry here, and returning the actual admin address for the asset type that we are burning a supply of. Only if that doesn't
   //      work for some odd reason, return empty then.
}

inline const public_address_t &get_admin_public_address( const Action &action )
{
   return std::visit( []( const concepts::Action auto &a ) -> const public_address_t & { return get_admin_public_address( a ); }, action );
}

}   // namespace spats

#endif   // FIRO_SPATS_ACTIONS_HPP_INCLUDED
