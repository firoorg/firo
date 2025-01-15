//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_WALLET_HPP_INCLUDED
#define FIRO_SPATS_WALLET_HPP_INCLUDED

#include <unordered_map>

#include "../utils/scaled_amount.hpp"

#include "identification.hpp"

class CSparkWallet;
class CWalletTx;

namespace spats {

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

   const std::string &my_public_address_as_admin() const;

   CWalletTx create_new_spark_asset_transaction( const SparkAsset &a, CAmount &standard_fee, CAmount &new_asset_fee ) const;

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
