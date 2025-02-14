//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_MODIFICATION_HPP_INCLUDED
#define FIRO_SPATS_MODIFICATION_HPP_INCLUDED

#include "spark_asset.hpp"

namespace spats {

template < typename T >
void verify_modification_validity( const T & /*old_value*/, const T & /*new_value*/ ) noexcept
{
   // no-op by default, with any modifications considered OK
}

inline void verify_modification_validity( const AssetNaming &old_value, const AssetNaming &new_value )
{
   // TODO allow symbol length changes where the fee doesn't actually change
   if ( old_value.symbol.get().length() != new_value.symbol.get().length() )
      throw std::domain_error( "Spark asset's symbol length cannot be modified" );   // because the creation fee depended on that!
}

template < typename T >
class AttributeModification {
public:
   AttributeModification( T old_value, T new_value )
      : old_( std::move( old_value ) )
      , new_( std::move( new_value ) )
   {
      verify_modification_validity( old_, new_ );   // may throw
   }

   template < typename Stream >
      requires( std::is_default_constructible_v< T > )
   AttributeModification( deserialize_type, Stream &is )
   {
      is >> old_ >> new_;
   }

   template < typename Stream >
      requires( !std::is_default_constructible_v< T > )
   AttributeModification( deserialize_type d, Stream &is )
      : old_( d, is )
      , new_( d, is )
   {}

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << old_ << new_;
   }

   const T &old_value() const noexcept { return old_; }
   const T &new_value() const noexcept { return new_; }

   explicit operator bool() const noexcept( noexcept( old_ != new_ ) ) { return old_ != new_; }

private:
   T old_, new_;
};

class AssetModificationBase {
protected:
   AssetModificationBase( const SparkAssetBase &old_asset_base, const SparkAssetBase &new_asset_base, public_address_t initiator_public_address )
      : asset_type_( old_asset_base.asset_type() )
      , initiator_public_address_( std::move( initiator_public_address ) )
      , asset_naming_change_( old_asset_base.naming(), new_asset_base.naming() )
      , metadata_change_( old_asset_base.metadata(), new_asset_base.metadata() )
   {
      if ( old_asset_base.asset_type() != new_asset_base.asset_type() )
         throw std::domain_error( "Spats asset type cannot be modified" );
      if ( old_asset_base.admin_public_address() != new_asset_base.admin_public_address() )
         throw std::domain_error(
           "Spark asset's admin public address cannot be modified via a regular modification operation - use Admin Control Transfer operation instead" );   // TODO
   }

   template < typename Stream >
   AssetModificationBase( deserialize_type d, Stream &is )
      : asset_naming_change_( d, is )
      , metadata_change_( d, is )
   {
      is >> asset_type_ >> initiator_public_address_;
   }

   ~AssetModificationBase() = default;

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      os << asset_naming_change_ << metadata_change_ << asset_type_ << initiator_public_address_;
   }

public:
   asset_type_t asset_type() const noexcept { return asset_type_; }
   const public_address_t &initiator_public_address() const noexcept { return initiator_public_address_; }

protected:
   bool any_changes() const noexcept { return asset_naming_change_ || metadata_change_; }

   void apply_on( SparkAssetBase &b ) const
   {
      if ( b.naming() != asset_naming_change_.old_value() )
         throw std::domain_error( "Spark asset's naming modification no longer applicable" );
      if ( b.metadata() != metadata_change_.old_value() )
         throw std::domain_error( "Spark asset's metadata modification no longer applicable" );
      b.naming( asset_naming_change_.new_value() );
      b.metadata( metadata_change_.new_value() );
   }

private:
   asset_type_t asset_type_;
   public_address_t initiator_public_address_;
   AttributeModification< AssetNaming > asset_naming_change_;
   AttributeModification< std::string > metadata_change_;
};

template < bool Fungible >
class BasicAssetModification : public AssetModificationBase {
public:
   BasicAssetModification( const FungibleSparkAsset &old_asset, const FungibleSparkAsset &new_asset, public_address_t initiator_public_address )
      requires( Fungible )
      : AssetModificationBase( old_asset, new_asset, std::move( initiator_public_address ) )
      , old_asset_( old_asset )
   {
      if ( old_asset.total_supply().precision() != new_asset.total_supply().precision() )
         throw std::domain_error( "Spark asset's precision cannot be modified" );
      if ( old_asset.total_supply() != new_asset.total_supply() )
         throw std::domain_error( "Spark asset's total supply cannot be modified via a regular modification operation - use Mint or Burn operations instead" );
      if ( old_asset.resupplyable() != new_asset.resupplyable() )
         throw std::domain_error( "Spark asset's resuppliability cannot be modified" );
      assert( apply_on( FungibleSparkAsset( old_asset ) ) == new_asset );
      assert( this->new_asset() == new_asset );
   }

   BasicAssetModification( const NonfungibleSparkAsset &old_asset, const NonfungibleSparkAsset &new_asset, public_address_t initiator_public_address )
      requires( !Fungible )
      : AssetModificationBase( old_asset, new_asset, std::move( initiator_public_address ) )
      , old_asset_( old_asset )
   {
      if ( old_asset.identifier() != new_asset.identifier() )
         throw std::domain_error( "Spark asset's identifier cannot be modified" );
      assert( apply_on( NonfungibleSparkAsset( old_asset ) ) == new_asset );
      assert( this->new_asset() == new_asset );
   }

   template < typename Stream >
   BasicAssetModification( deserialize_type d, Stream &is )
      : AssetModificationBase( d, is )
      , old_asset_( d, is )
   {}

   template < typename Stream >
   void Serialize( Stream &os ) const
   {
      AssetModificationBase::Serialize( os );
      os << old_asset_;
   }

   const BasicSparkAsset< Fungible > &old_asset() const noexcept { return old_asset_; }

   BasicSparkAsset< Fungible > new_asset() const
   {
      auto a = old_asset_;
      apply_on( a );
      return a;
   }

   void apply_on( BasicSparkAsset< Fungible > &a ) const
   {
      this->AssetModificationBase::apply_on( a );
      // TODO apply Fungible-ity specific attribute changes from *this, if there ever are any
   }

   explicit operator bool() const noexcept
   {
      return AssetModificationBase::any_changes();   // TODO or any (Fungible-ity specific) data members in *this, if any ever
   }

private:
   BasicSparkAsset< Fungible > old_asset_;
   // ATTENTION: right now there are no fungibility-specific attributes that can be modified, but if there are in the future, add them here, as an object of a class that
   // is specialized based on Fungible-ity.

   BasicSparkAsset< Fungible > apply_on( BasicSparkAsset< Fungible > &&a ) const
   {
      apply_on( a );   // just calling the lvalue-ref overload
      return a;
   }
};

using FungibleAssetModification = BasicAssetModification< true >;
using NonfungibleAssetModification = BasicAssetModification< false >;
using AssetModification = std::variant< FungibleAssetModification, NonfungibleAssetModification >;

// Function that returns the base of an AssetModification
inline const AssetModificationBase &get_base( const AssetModification &modif ) noexcept
{
   return std::visit( []( const auto &m ) -> const AssetModificationBase & { return m; }, modif );
}

inline AssetModification make_asset_modification( const SparkAsset &old_asset, const SparkAsset &new_asset, public_address_t initiator_public_address )
{
   if ( old_asset.index() != new_asset.index() )
      throw std::domain_error( "Cannot modify the fungibility of an asset" );
   return std::visit(
     [ & ]< bool Fungible >( const BasicSparkAsset< Fungible > &old ) -> AssetModification {
        return BasicAssetModification< Fungible >( old, std::get< BasicSparkAsset< Fungible > >( new_asset ), std::move( initiator_public_address ) );
     },
     old_asset );
}

inline SparkAsset get_old_asset( const AssetModification &modif )
{
   return std::visit( []( const auto &m ) -> SparkAsset { return m.old_asset(); }, modif );
}

inline SparkAsset get_new_asset( const AssetModification &modif )
{
   return std::visit( []( const auto &m ) -> SparkAsset { return m.new_asset(); }, modif );
}

inline bool has_any_modifications( const AssetModification &modif ) noexcept
{
   return std::visit( []( const auto &m ) { return !!m; }, modif );
}

}   // namespace spats

#endif   // FIRO_SPATS_MODIFICATION_HPP_INCLUDED
