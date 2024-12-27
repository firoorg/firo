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
#include "spark_asset.hpp"

namespace spats {

struct UnregisterAssetParameters {
   asset_type_t asset_type;
   std::optional< identifier_t > identifier;
   public_address_t initiator_public_address;

   ADD_SERIALIZE_METHODS;

   template < typename Stream, typename Operation >
   void SerializationOp( Stream &s, Operation ser_action )
   {
      READWRITE( asset_type );
      READWRITE( identifier );
      READWRITE( initiator_public_address );
   }
};

class CreateAssetAction {
public:
   explicit CreateAssetAction( SparkAsset asset )
      : asset_( std::move( asset ) )
   {}

   template < typename Stream >
   CreateAssetAction( deserialize_type, Stream &is );

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
CreateAssetAction::CreateAssetAction( deserialize_type, Stream &is )
   : asset_( Unserialize( is ) )
{}

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
   return [ & ]< typename... T >( std::type_identity< std::variant< T... > > ) { return UnserializeVariantOf< T... >( is ); }( std::type_identity< SparkAsset >() );
}

class UnregisterAssetAction {
public:
   ADD_SERIALIZE_METHODS;

   template < typename Stream, typename Operation >
   void SerializationOp( Stream &s, Operation ser_action )
   {
      auto version = serialization_version;
      READWRITE( version );
      READWRITE( parameters_ );
   }

   const UnregisterAssetParameters &get() const & noexcept { return parameters_; }
   UnregisterAssetParameters &&get() && noexcept { return std::move( parameters_ ); }

private:
   UnregisterAssetParameters parameters_;
   static constexpr std::uint8_t serialization_version = 1;
};

using Action = std::variant< CreateAssetAction, UnregisterAssetAction >;   // TODO more

using ActionSequence = std::vector< Action >;

}   // namespace spats

#endif   // FIRO_SPATS_ACTIONS_HPP_INCLUDED
