//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_ACTIONS_HPP_INCLUDED
#define FIRO_SPATS_ACTIONS_HPP_INCLUDED

#include <optional>
#include <variant>
#include <vector>

#include "../serialize.h"

#include "identification.hpp"
#include "base_asset.hpp"
#include "modification.hpp"
#include "spark_asset.hpp"

namespace spats {

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

private:
   SparkAsset asset_;
   // TODO flag for asset_type adjustability, for avoiding failure due to the asset_type getting taken away by someone else under one's feet
   static constexpr std::uint8_t serialization_version = 1;

   template < typename Stream >
   static SparkAsset Unserialize( Stream &is );
};

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

private:
   AssetModification asset_modification_;
   static constexpr std::uint8_t serialization_version = 1;

   template < typename Stream >
   static AssetModification Unserialize( Stream &is );
};

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

private:
   MintParameters parameters_;
   static constexpr std::uint8_t serialization_version = 1;

   template < typename Stream >
   static MintParameters Unserialize( Stream &is )
   {
      std::uint8_t version;
      is >> version;
      return MintParameters( deserialize, is );
   }
};

class BurnParameters {
public:
   BurnParameters( asset_type_t asset_type, supply_amount_t burn_amount, public_address_t initiator_pubaddress )
      : asset_type_( asset_type )
      , burn_amount_( burn_amount )
      , initiator_public_address_( std::move( initiator_pubaddress ) )
   {
      validate();
   }

   template < typename Stream >
   BurnParameters( deserialize_type, Stream &is )
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
      os << asset_type_ << burn_amount_.precision() << burn_amount_.raw() << initiator_public_address_;
   }

   asset_type_t asset_type() const noexcept
   {
      assert( asset_type_ != base::asset_type );
      assert( is_fungible_asset_type( asset_type_ ) );
      return asset_type_;
   }

   supply_amount_t burn_amount() const noexcept { return burn_amount_; }

   const public_address_t &initiator_public_address() const noexcept { return initiator_public_address_; }

private:
   asset_type_t asset_type_;
   supply_amount_t burn_amount_;
   public_address_t initiator_public_address_;

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

class BurnAction {
public:
   explicit BurnAction( BurnParameters parameters ) noexcept
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

   const BurnParameters &get() const & noexcept { return parameters_; }
   BurnParameters &&get() && noexcept { return std::move( parameters_ ); }

private:
   BurnParameters parameters_;
   static constexpr std::uint8_t serialization_version = 1;

   template < typename Stream >
   static BurnParameters Unserialize( Stream &is )
   {
      std::uint8_t version;
      is >> version;
      return BurnParameters( deserialize, is );
   }
};

using Action = std::variant< CreateAssetAction, UnregisterAssetAction, ModifyAssetAction, MintAction, BurnAction >;   // TODO more

using ActionSequence = std::vector< Action >;

}   // namespace spats

#endif   // FIRO_SPATS_ACTIONS_HPP_INCLUDED
