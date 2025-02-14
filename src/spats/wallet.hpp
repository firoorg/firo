//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_WALLET_HPP_INCLUDED
#define FIRO_SPATS_WALLET_HPP_INCLUDED

#include <string>
#include <unordered_map>
#include <optional>
#include <span>

#include "../utils/scaled_amount.hpp"

#include "identification.hpp"

class CSparkWallet;
class CWalletTx;

namespace spats {

class SparkAssetBase;
class UnregisterAssetParameters;
class Registry;

class Wallet {
   // using signed integer in wallet because the blocks on disk are traversed over in the reverse direction
   using amount_type = utils::scaled_amount< std::int64_t >;

public:
   explicit Wallet( CSparkWallet &spark_wallet ) noexcept;

   struct AssetAmount {
      amount_type available{}, pending{};
   };

   static CAmount compute_new_spark_asset_fee( std::string_view asset_symbol ) noexcept;

   static Scalar compute_new_spark_asset_serialization_scalar( const SparkAssetBase &b, std::span< const unsigned char > asset_serialization_bytes );
   static Scalar compute_unregister_spark_asset_serialization_scalar( const UnregisterAssetParameters &p,
                                                                      std::span< const unsigned char > unreg_asset_serialization_bytes );
   static Scalar compute_modify_spark_asset_serialization_scalar( const AssetModificationBase &b, std::span< const unsigned char > modification_serialization_bytes );

   const std::string &my_public_address_as_admin() const;

   CWalletTx create_new_spark_asset_transaction( const SparkAsset &a,
                                                 CAmount &standard_fee,
                                                 CAmount &new_asset_fee,
                                                 const public_address_t &destination_public_address = {} ) const;
   CWalletTx create_unregister_spark_asset_transaction( asset_type_t asset_type, std::optional< identifier_t > identifier, CAmount &standard_fee ) const;
   CWalletTx create_modify_spark_asset_transaction( const SparkAsset &old_asset, const SparkAsset &new_asset, CAmount &standard_fee ) const;

   void notify_registry_changed();

   // TODO s11n?
private:
   CSparkWallet &spark_wallet_;
   mutable std::string my_public_address_as_admin_;
   Registry &registry_;
   std::unordered_map< asset_type_t, AssetAmount > asset_balances_;
};

}   // namespace spats

#endif   // FIRO_SPATS_WALLET_HPP_INCLUDED
