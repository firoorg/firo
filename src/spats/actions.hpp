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

      if ( is_fungible_asset_type( asset_type_ ) ) {
         if ( identifier_ )
            if ( *identifier_ == identifier_t{ 0 } )
               identifier_ = std::nullopt;
            else
               throw std::invalid_argument( "No 'identifier' should be provided for identifying a fungible asset" );
         assert( !identifier_ );
      }

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
   explicit UnregisterAssetAction( UnregisterAssetParameters parameters )
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

using Action = std::variant< CreateAssetAction, UnregisterAssetAction, ModifyAssetAction >;   // TODO more

using ActionSequence = std::vector< Action >;

}   // namespace spats

#endif   // FIRO_SPATS_ACTIONS_HPP_INCLUDED
