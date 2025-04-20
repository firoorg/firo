//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_WALLET_HPP_INCLUDED
#define FIRO_SPATS_WALLET_HPP_INCLUDED

#include <string>
#include <map>
#include <optional>
#include <span>

#include "../utils/scaled_amount.hpp"

#include "identification.hpp"
#include "user_confirmation.hpp"

class CSparkWallet;
class CWalletTx;
class CCoinControl;

namespace spats {

class SparkAssetBase;
class UnregisterAssetParameters;
class Registry;

class Wallet {
public:
   // using signed integer in wallet just in case there are out-of-order operations that are affecting the balance, to be on the safe side...
   using amount_type = utils::scaled_amount< std::int64_t >;

   explicit Wallet( CSparkWallet &spark_wallet ) noexcept;

   struct AssetAmount {
      amount_type available{}, pending{};

      AssetAmount() = default;

      // intentionally implicit
      AssetAmount( std::pair< CAmount, CAmount > base_asset_amounts ) noexcept
         : available( base_asset_amounts.first, 8 )
         , pending( base_asset_amounts.second, 8 )
      {}

      bool operator==( const AssetAmount &other ) const noexcept = default;
   };

   using asset_balances_t = std::map< universal_asset_id_t, AssetAmount >;

   asset_balances_t get_asset_balances() const;

   static Scalar compute_new_spark_asset_serialization_scalar( const SparkAssetBase &b, std::span< const unsigned char > asset_serialization_bytes );
   static Scalar compute_unregister_spark_asset_serialization_scalar( const UnregisterAssetParameters &p,
                                                                      std::span< const unsigned char > unreg_asset_serialization_bytes );
   static Scalar compute_modify_spark_asset_serialization_scalar( const AssetModificationBase &b, std::span< const unsigned char > modification_serialization_bytes );
   static Scalar compute_mint_asset_supply_serialization_scalar( const MintParameters &p, std::span< const unsigned char > mint_serialization_bytes );
   static Scalar compute_burn_asset_supply_serialization_scalar( const BurnParameters &p, std::span< const unsigned char > burn_serialization_bytes );

   const std::string &my_public_address_as_admin() const;

   std::optional< CWalletTx > create_new_spark_asset_transaction(
     const SparkAsset &a,
     CAmount &standard_fee,
     CAmount &new_asset_fee,
     const public_address_t &destination_public_address = {},
     const std::function< bool( const CreateAssetAction &action, CAmount standard_fee, std::int64_t txsize ) > &user_confirmation_callback = {} ) const;
   std::optional< CWalletTx > create_unregister_spark_asset_transaction(
     asset_type_t asset_type,
     std::optional< identifier_t > identifier,
     CAmount &standard_fee,
     const std::function< bool( const UnregisterAssetAction &action, CAmount standard_fee, std::int64_t txsize ) > &user_confirmation_callback = {} ) const;
   std::optional< CWalletTx > create_modify_spark_asset_transaction(
     const SparkAsset &old_asset,
     const SparkAsset &new_asset,
     CAmount &standard_fee,
     const std::function< bool( const ModifyAssetAction &action, CAmount standard_fee, std::int64_t txsize ) > &user_confirmation_callback = {} ) const;
   std::optional< CWalletTx > create_mint_asset_supply_transaction(
     asset_type_t asset_type,
     supply_amount_t new_supply,
     const public_address_t &receiver_pubaddress,
     CAmount &standard_fee,
     const CCoinControl *coin_control = nullptr,
     const std::function< bool( const MintAction &action, CAmount standard_fee, std::int64_t txsize ) > &user_confirmation_callback = {} ) const;
   std::optional< CWalletTx > create_burn_asset_supply_transaction( asset_type_t asset_type,
                                                                    const asset_symbol_t &asset_symbol,
                                                                    supply_amount_t burn_amount,
                                                                    CAmount &standard_fee,
                                                                    const BurnActionUserConfirmationCallback &user_confirmation_callback = {} ) const;

   void notify_registry_changed();

private:
   CSparkWallet &spark_wallet_;
   mutable std::string my_public_address_as_admin_;
   Registry &registry_;
   asset_balances_t asset_balances_;

   static spark::MintedCoinData create_minted_coin_data( const MintParameters &action_params );
};

}   // namespace spats

#endif   // FIRO_SPATS_WALLET_HPP_INCLUDED
