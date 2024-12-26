//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_WALLET_HPP_INCLUDED
#define FIRO_SPATS_WALLET_HPP_INCLUDED

#include <unordered_map>
#include <functional>

#include "../utils/scaled_amount.hpp"

#include "identification.hpp"

class CSparkWallet;

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

   const std::string &my_public_address_as_admin() const noexcept { return my_public_address_as_admin_; }

   void create_new_spark_asset( const SparkAsset &a,
                                const std::function< bool( const SparkAsset &a, CAmount standard_fee, CAmount asset_creation_fee ) > &user_confirmation_callback = {} );

   // TODO s11n?
private:
   CSparkWallet &spark_wallet_;
   const std::string my_public_address_as_admin_;
   Registry &registry_;
   std::unordered_map< asset_type_t, AssetAmount > asset_balances_;
};

}   // namespace spats

#endif   // FIRO_SPATS_WALLET_HPP_INCLUDED
