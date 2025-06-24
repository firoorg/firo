//
// Created by Gevorg Voskanyan
//

#include <boost/numeric/conversion/cast.hpp>
#include <boost/format.hpp>
#include <boost/exception/diagnostic_information.hpp>

#include "policy/policy.h"   // for GetVirtualTransactionSize

#include "../validation.h"
#include "../wallet/wallet.h"
#include "../spark/sparkwallet.h"
#include "../spark/state.h"
#include "../utils/scope_exit.hpp"

#include "registry.hpp"
#include "wallet.hpp"

namespace spats {

Scalar Wallet::compute_new_spark_asset_serialization_scalar( const SparkAssetBase &b, std::span< const unsigned char > asset_serialization_bytes )
{
   spark::Hash hash( tfm::format( "spatsnew_%u_from_%s", utils::to_underlying( b.asset_type() ), b.admin_public_address() ) );
   hash.include( asset_serialization_bytes );
   auto ret = hash.finalize_scalar();
   LogPrintf( "New spark asset serialization scalar (hex): %s\n", ret.GetHex() );
   return ret;
}

Scalar Wallet::compute_unregister_spark_asset_serialization_scalar( const UnregisterAssetParameters &p, std::span< const unsigned char > unreg_asset_serialization_bytes )
{
   auto identifier_absense_sentinel = max_allowed_identifier_value;
   ++identifier_absense_sentinel;
   spark::Hash hash( tfm::format( "spatsunreg_%u_%u_from_%s",
                                  utils::to_underlying( p.asset_type() ),
                                  utils::to_underlying( p.identifier().value_or( identifier_absense_sentinel ) ),
                                  p.initiator_public_address() ) );
   hash.include( unreg_asset_serialization_bytes );
   auto ret = hash.finalize_scalar();
   LogPrintf( "Unregister spark asset serialization scalar (hex): %s\n", ret.GetHex() );
   return ret;
}

Scalar Wallet::compute_modify_spark_asset_serialization_scalar( const AssetModificationBase &b, std::span< const unsigned char > modification_serialization_bytes )
{
   spark::Hash hash( tfm::format( "spatsmodify_%u_from_%s", utils::to_underlying( b.asset_type() ), b.initiator_public_address() ) );
   hash.include( modification_serialization_bytes );
   auto ret = hash.finalize_scalar();
   LogPrintf( "Modify spark asset serialization scalar (hex): %s\n", ret.GetHex() );
   return ret;
}

Scalar Wallet::compute_mint_asset_supply_serialization_scalar( const MintParameters &p, std::span< const unsigned char > mint_serialization_bytes )
{
   spark::Hash hash( tfm::format( "spatsmint_%u_for_%u_to_%s_from_%s",
                                  p.new_supply(),
                                  utils::to_underlying( p.asset_type() ),
                                  p.receiver_public_address(),
                                  p.initiator_public_address() ) );
   hash.include( mint_serialization_bytes );
   auto ret = hash.finalize_scalar();
   LogPrintf( "Spats mint serialization scalar (hex): %s\n", ret.GetHex() );
   return ret;
}

Scalar Wallet::compute_burn_asset_supply_serialization_scalar( const BurnParameters &p, std::span< const unsigned char > burn_serialization_bytes )
{
   spark::Hash hash( tfm::format( "spatsburn_%u_for_%u_from_%s", p.burn_amount(), utils::to_underlying( p.asset_type() ), p.initiator_public_address() ) );
   hash.include( burn_serialization_bytes );
   auto ret = hash.finalize_scalar();
   LogPrintf( "Spats burn serialization scalar (hex): %s\n", ret.GetHex() );
   return ret;
}

Wallet::Wallet( CSparkWallet &spark_wallet )
   : spark_wallet_( spark_wallet )
   , registry_( spark::CSparkState::GetState()->GetSpatsManager().registry() )
{
   // verifying a fundamental assumption about Scalar's default constructor, even though this might not be the best place for it, but it works for now...
   assert( Scalar().isZero() );
   assert( Scalar() == Scalar( std::uint64_t( 0 ) ) );
}

const std::string &Wallet::my_public_address_as_admin() const
{
   // Doing (thread-safe) lazy initialization, as in the constructor, spark_wallet isn't fully initialized yet!
   {
      std::shared_lock lock( my_public_address_as_admin_mutex_ );
      if ( !my_public_address_as_admin_.empty() )
         return my_public_address_as_admin_;
   }

   std::unique_lock lock( my_public_address_as_admin_mutex_ );
   if ( !my_public_address_as_admin_.empty() )   // some other thread already managed to init and return reference out!
      return my_public_address_as_admin_;   // so very important to not change this any further, ever!

   // init: compute and assign for the first and only time
   my_public_address_as_admin_ = spark_wallet_.getDefaultAddress().encode( spark::GetNetworkType() );
   assert( !my_public_address_as_admin_.empty() );
   LogPrintf( "my_public_address_as_admin: %s\n", my_public_address_as_admin_ );
   return my_public_address_as_admin_;
}

// TODO find out if we need to show the modifications on the GUI even before it has gone on a block that is now connected. I.e. right after being accepted to mempool,
// show it as an action is progress somehow... Ask Reuben if we need this.

// TODO for Levon to find out why no more than 1 spats action are picked to be placed on a block

static spark::MintedCoinData create_minted_coin_data( const CreateAssetAction &action, const public_address_t &destination_public_address )
{
   const auto &a = action.get();
   const auto initial_supply = get_total_supply( a );
   assert( initial_supply > supply_amount_t{} );
   const auto &b = get_base( a );
   spark::MintedCoinData coin;
   coin.address = CSparkWallet::decodeAddress( destination_public_address.empty() ? b.admin_public_address() : destination_public_address );
   coin.v = boost::numeric_cast< CAmount >( initial_supply.raw() );
   constexpr std::string_view memo = "new asset's initial supply mint";
   static_assert( memo.size() < 32 );   // Params::memo_bytes is commonly set to 31
   coin.memo = memo;
   coin.a = utils::to_underlying( b.asset_type() );
   coin.iota = utils::to_underlying( get_identifier( a ).value_or( identifier_t{} ) );
   return coin;
}

std::optional< CWalletTx > Wallet::create_new_spark_asset_transaction(
  const SparkAsset &a,
  CAmount &standard_fee,
  CAmount &new_asset_fee,
  const public_address_t &destination_public_address,
  const std::function< bool( const CreateAssetAction &action, CAmount standard_fee, std::int64_t txsize ) > &user_confirmation_callback ) const
{
   const auto &b = get_base( a );
   if ( b.admin_public_address() != my_public_address_as_admin() ) {
      assert( !"Only allowed to use own public address as admin's address when creating a new spark asset" );
      throw std::domain_error( "Only allowed to use own public address as admin's address when creating a new spark asset" );
   }
   const auto initial_supply = get_total_supply( a );
   if ( !initial_supply && !destination_public_address.empty() )
      throw std::domain_error( "Destination public address supplied, yet there is no initial supply of the new spark asset to credit it to" );

   CScript script;
   script << OP_SPATSCREATE;
   assert( script.IsSpatsCreate() );
   CDataStream serialized( SER_NETWORK, PROTOCOL_VERSION );
   const CreateAssetAction action( a );
   serialized << action;
   // TODO instead of how it is being done now, put ownership proof into script default-constructed first, then compute ownership proof from the whole tx, and overwrite
   //      the ownership proof in the script then
   const auto scalar_of_proof = compute_new_spark_asset_serialization_scalar( b, serialized.as_bytes_span() );
   const spark::OwnershipProof proof = spark_wallet_.makeDefaultAddressOwnershipProof( scalar_of_proof );
   LogPrintf( "Ownership proof for new spark asset (hex): %s\n", proof );
   CDataStream proof_serialized( SER_NETWORK, PROTOCOL_VERSION );
   proof_serialized << proof;
   script.insert( script.end(), serialized.begin(), serialized.end() );
   assert( script.IsSpatsCreate() );
   script.insert( script.end(), proof_serialized.begin(), proof_serialized.end() );
   assert( script.IsSpatsCreate() );
   new_asset_fee = compute_new_spark_asset_fee( b.naming().symbol.get() );
   const std::string burn_address( firo_burn_address );   // TODO the network-specific address from params, once Levon adds that
   CScript burn_script = GetScriptForDestination( CBitcoinAddress( burn_address ).Get() );
   CRecipient burn_recipient{ std::move( burn_script ), new_asset_fee, false, {}, "burning new asset fee" };
   auto tx = spark_wallet_.CreateSparkSpendTransaction( { CRecipient{ std::move( script ), {}, false, b.admin_public_address(), "new asset" }, burn_recipient },
                                                        {},
                                                        {},
                                                        standard_fee,
                                                        nullptr );   // may throw
   assert( tx.tx->IsSpatsCreate() );

   if ( initial_supply ) {
      CMutableTransaction mtx( *tx.tx );
      spark_wallet_.AppendSpatsMintTxData( mtx,
                                           { create_minted_coin_data( action, destination_public_address ), spark_wallet_.getDefaultAddress() },
                                           spark_wallet_.ensureSpendKey() );
      tx.tx = MakeTransactionRef( std::move( mtx ) );
      assert( tx.tx->IsSpatsCreate() );
   }

   if ( user_confirmation_callback )   // give the user a chance to confirm/cancel, if there are means to do so
      if ( const auto tx_size = ::GetVirtualTransactionSize( tx ); !user_confirmation_callback( action, standard_fee, tx_size ) ) {
         LogPrintf( "User cancelled %s, which would require creation fee = %d, standard fee = %d and txsize=%d\n",
                    action.summary(),
                    new_asset_fee,
                    standard_fee,
                    tx_size );
         return {};
      }

   return tx;
}

std::optional< CWalletTx > Wallet::create_unregister_spark_asset_transaction(
  asset_type_t asset_type,
  std::optional< identifier_t > identifier,
  CAmount &standard_fee,
  const std::function< bool( const UnregisterAssetAction &action, CAmount standard_fee, std::int64_t txsize ) > &user_confirmation_callback ) const
{
   const auto &admin_public_address = my_public_address_as_admin();
   const UnregisterAssetParameters action_params( asset_type, identifier, admin_public_address );
   CScript script;
   script << OP_SPATSUNREGISTER;
   assert( script.IsSpatsUnregister() );
   CDataStream serialized( SER_NETWORK, PROTOCOL_VERSION );
   const UnregisterAssetAction action( action_params );
   serialized << action;
   // TODO instead of how it is being done now, put ownership proof into script default-constructed first, then compute ownership proof from the whole tx, and overwrite
   //      the ownership proof in the script then
   const auto scalar_of_proof = compute_unregister_spark_asset_serialization_scalar( action_params, serialized.as_bytes_span() );
   const spark::OwnershipProof proof = spark_wallet_.makeDefaultAddressOwnershipProof( scalar_of_proof );
   LogPrintf( "Ownership proof for unregister spark asset (hex): %s\n", proof );
   CDataStream proof_serialized( SER_NETWORK, PROTOCOL_VERSION );
   proof_serialized << proof;
   script.insert( script.end(), serialized.begin(), serialized.end() );
   assert( script.IsSpatsUnregister() );
   script.insert( script.end(), proof_serialized.begin(), proof_serialized.end() );
   assert( script.IsSpatsUnregister() );
   auto tx = spark_wallet_.CreateSparkSpendTransaction( { CRecipient{ std::move( script ), {}, false, admin_public_address, "spats unregister" } },
                                                        {},
                                                        {},
                                                        standard_fee,
                                                        nullptr );   // may throw
   assert( tx.tx->IsSpatsUnregister() );

   if ( user_confirmation_callback )   // give the user a chance to confirm/cancel, if there are means to do so
      if ( const auto tx_size = ::GetVirtualTransactionSize( tx ); !user_confirmation_callback( action, standard_fee, tx_size ) ) {
         LogPrintf( "User cancelled %s, which would require fee=%d and txsize=%d\n", action.summary(), standard_fee, tx_size );
         return {};
      }

   return tx;
}

std::optional< CWalletTx > Wallet::create_modify_spark_asset_transaction(
  const SparkAsset &old_asset,
  const SparkAsset &new_asset,
  CAmount &standard_fee,
  const std::function< bool( const ModifyAssetAction &action, CAmount standard_fee, std::int64_t txsize ) > &user_confirmation_callback ) const
{
   const auto &admin_public_address = my_public_address_as_admin();
   const auto m = make_asset_modification( old_asset, new_asset, admin_public_address );
   const auto &b = get_base( m );
   CScript script;
   script << OP_SPATSMODIFY;
   assert( script.IsSpatsModify() );
   CDataStream serialized( SER_NETWORK, PROTOCOL_VERSION );
   const ModifyAssetAction action( m );
   serialized << action;
   // TODO instead of how it is being done now, put ownership proof into script default-constructed first, then compute ownership proof from the whole tx, and overwrite
   //      the ownership proof in the script then
   const auto scalar_of_proof = compute_modify_spark_asset_serialization_scalar( b, serialized.as_bytes_span() );
   const spark::OwnershipProof proof = spark_wallet_.makeDefaultAddressOwnershipProof( scalar_of_proof );
   LogPrintf( "Ownership proof for modify spark asset (hex): %s\n", proof );
   CDataStream proof_serialized( SER_NETWORK, PROTOCOL_VERSION );
   proof_serialized << proof;
   script.insert( script.end(), serialized.begin(), serialized.end() );
   assert( script.IsSpatsModify() );
   script.insert( script.end(), proof_serialized.begin(), proof_serialized.end() );
   assert( script.IsSpatsModify() );
   auto tx = spark_wallet_.CreateSparkSpendTransaction( { CRecipient{ std::move( script ), {}, false, admin_public_address, "spats modify" } },
                                                        {},
                                                        {},
                                                        standard_fee,
                                                        nullptr );   // may throw
   assert( tx.tx->IsSpatsModify() );

   if ( user_confirmation_callback )   // give the user a chance to confirm/cancel, if there are means to do so
      if ( const auto tx_size = ::GetVirtualTransactionSize( tx ); !user_confirmation_callback( action, standard_fee, tx_size ) ) {
         LogPrintf( "User cancelled %s, which would require fee=%d and txsize=%d\n", action.summary(), standard_fee, tx_size );
         return {};
      }

   return tx;
}

static spark::MintedCoinData create_minted_coin_data( const MintParameters &action_params )
{
   assert( action_params.new_supply() > supply_amount_t{} );
   spark::MintedCoinData coin;
   coin.address = CSparkWallet::decodeAddress( action_params.receiver_public_address() );
   coin.v = boost::numeric_cast< CAmount >( action_params.new_supply().raw() );
   coin.memo = "minting new supply";
   coin.a = utils::to_underlying( action_params.asset_type() );
   assert( coin.iota.isZero() );
   return coin;
}

std::optional< CWalletTx > Wallet::create_mint_asset_supply_transaction(
  asset_type_t asset_type,
  supply_amount_t new_supply,
  const public_address_t &receiver_pubaddress,
  CAmount &standard_fee,
  const CCoinControl *coin_control,
  const std::function< bool( const MintAction &action, CAmount standard_fee, std::int64_t txsize ) > &user_confirmation_callback ) const
{
   const auto &admin_public_address = my_public_address_as_admin();
   const MintParameters action_params( asset_type, new_supply, receiver_pubaddress, admin_public_address );
   CScript script;
   script << OP_SPATSMINT;
   assert( script.IsSpatsMint() );
   CDataStream serialized( SER_NETWORK, PROTOCOL_VERSION );
   const MintAction action( action_params );
   serialized << action;
   // TODO instead of how it is being done now, put ownership proof into script default-constructed first, then compute ownership proof from the whole tx, and overwrite
   //      the ownership proof in the script then
   const auto scalar_of_proof = compute_mint_asset_supply_serialization_scalar( action_params, serialized.as_bytes_span() );
   const spark::OwnershipProof proof = spark_wallet_.makeDefaultAddressOwnershipProof( scalar_of_proof );
   LogPrintf( "Ownership proof for mint asset supply (hex): %s\n", proof );
   CDataStream proof_serialized( SER_NETWORK, PROTOCOL_VERSION );
   proof_serialized << proof;
   script.insert( script.end(), serialized.begin(), serialized.end() );
   assert( script.IsSpatsMint() );
   script.insert( script.end(), proof_serialized.begin(), proof_serialized.end() );
   assert( script.IsSpatsMint() );
   auto tx = spark_wallet_.CreateSparkSpendTransaction( { CRecipient{ std::move( script ), {}, false, admin_public_address, "spats mint" } },
                                                        {},
                                                        {},
                                                        standard_fee,
                                                        coin_control );   // may throw
   assert( tx.tx->IsSpatsMint() );

   CMutableTransaction mtx( *tx.tx );
   spark_wallet_.AppendSpatsMintTxData( mtx, { create_minted_coin_data( action_params ), spark_wallet_.getDefaultAddress() }, spark_wallet_.ensureSpendKey() );
   tx.tx = MakeTransactionRef( std::move( mtx ) );
   assert( tx.tx->IsSpatsMint() );

   if ( user_confirmation_callback )   // give the user a chance to confirm/cancel, if there are means to do so
      if ( const auto tx_size = ::GetVirtualTransactionSize( tx ); !user_confirmation_callback( action, standard_fee, tx_size ) ) {
         LogPrintf( "User cancelled %s, which would require fee=%d and txsize=%d\n", action.summary(), standard_fee, tx_size );
         return {};
      }

   return tx;
}

std::optional< CWalletTx > Wallet::create_burn_asset_supply_transaction( asset_type_t const asset_type,
                                                                         const asset_symbol_t &asset_symbol,
                                                                         supply_amount_t const burn_amount,
                                                                         CAmount &standard_fee,
                                                                         const BurnActionUserConfirmationCallback &user_confirmation_callback ) const
{
   const auto &admin_public_address = my_public_address_as_admin();

   if ( asset_type == base::asset_type ) {
      const std::string burn_address( firo_burn_address );   // TODO the network-specific address from params, once Levon adds that
      CScript burn_script = GetScriptForDestination( CBitcoinAddress( burn_address ).Get() );
      CRecipient burn_recipient{ std::move( burn_script ), boost::numeric_cast< CAmount >( burn_amount.raw() ), false, {}, "burning a base asset amount" };
      auto tx = spark_wallet_.CreateSparkSpendTransaction( { burn_recipient }, {}, {}, standard_fee, nullptr );   // may throw

      if ( user_confirmation_callback ) {   // give the user a chance to confirm/cancel, if there are means to do so
         const BaseAssetBurnParameters action_params( burn_amount, admin_public_address );
         const BurnAction action( action_params );
         if ( const auto tx_size = ::GetVirtualTransactionSize( tx ); !user_confirmation_callback( action, standard_fee, tx_size ) ) {
            LogPrintf( "User cancelled %s, which would require fee=%d and txsize=%d\n", action.summary(), standard_fee, tx_size );
            return {};
         }
      }

      return tx;
   }

   const BurnParameters action_params( asset_type, burn_amount, admin_public_address, asset_symbol );
   CScript script;
   script << OP_SPATSBURN;
   assert( script.IsSpatsBurn() );
   CDataStream serialized( SER_NETWORK, PROTOCOL_VERSION );
   const BurnAction action( action_params );
   serialized << action;
   // TODO instead of how it is being done now, put ownership proof into script default-constructed first, then compute ownership proof from the whole tx, and overwrite
   //      the ownership proof in the script then
   const auto scalar_of_proof = compute_burn_asset_supply_serialization_scalar( action_params, serialized.as_bytes_span() );
   const spark::OwnershipProof proof = spark_wallet_.makeDefaultAddressOwnershipProof( scalar_of_proof );
   LogPrintf( "Ownership proof for burn asset supply (hex): %s\n", proof );
   CDataStream proof_serialized( SER_NETWORK, PROTOCOL_VERSION );
   proof_serialized << proof;
   script.insert( script.end(), serialized.begin(), serialized.end() );
   assert( script.IsSpatsBurn() );
   script.insert( script.end(), proof_serialized.begin(), proof_serialized.end() );
   assert( script.IsSpatsBurn() );
   // TODO add a recipient to firo_burn_address, for `burn_amount` of `asset_type`. It has to be done in such a way that the actual burning from the registry
   //      will NOT be actually performed if the sending to firo_burn_address fails (due to insufficient funds in this wallet).
   // TODO well, the below is just a demo code of how that could look like, with a fake 'burn' address. THIS IS NOT INTENDED TO BE FINAL PRODUCTION CODE.
   //      It will be rewritten before then. Until then, this is here just for demo & testing purposes.
   std::vector< spark::OutputCoinData > spats_recipients;
   spats_recipients.emplace_back( CSparkWallet::decodeAddress(
                                    "sr1yzjc2fmzfhchnve2wu5vqly6akgpntlsze47s6xf7x0m7zjv4dz7z2hr8hy93gj8fkp73p7gn4qf3mkhsress9tjafglspmd4yhj4mscvs52z3q5x2nt9dk4579cal6yp"
                                    "vax3cczwmund" ),   // just a fake 'burn' address, the burn will be done as a new output type eventually, before merging to master
                                  boost::numeric_cast< CAmount >( burn_amount.raw() ),
                                  "burning asset supply",
                                  utils::to_underlying( asset_type ),
                                  Scalar() );
   assert( spats_recipients.back().iota.isZero() );
   auto tx = spark_wallet_.CreateSparkSpendTransaction( { CRecipient{ std::move( script ), {}, false, admin_public_address, "spats burn" } },
                                                        {},
                                                        spats_recipients,
                                                        standard_fee,
                                                        nullptr );   // may throw
   assert( tx.tx->IsSpatsBurn() );

   if ( user_confirmation_callback )   // give the user a chance to confirm/cancel, if there are means to do so
      if ( const auto tx_size = ::GetVirtualTransactionSize( tx ); !user_confirmation_callback( action, standard_fee, tx_size ) ) {
         LogPrintf( "User cancelled %s, which would require fee=%d and txsize=%d\n", action.summary(), standard_fee, tx_size );
         return {};
      }

   return tx;
}

void Wallet::notify_registry_changed()
{
   // TODO
}

void Wallet::notify_coins_changed()
{
   all_coin_changes_processed_.clear();
}

Wallet::AssetAmount Wallet::AssetAmount::init_with_precision( unsigned precision )
{
   AssetAmount ret;
   ret.available = ret.pending = { 0, precision };
   return ret;
}

Wallet::asset_balances_t Wallet::get_asset_balances() const
{
   try {
      if ( all_coin_changes_processed_.test_and_set() ) {
         // the all_coin_changes_processed_ flag was true already even before
         std::shared_lock lock( asset_balances_mutex_ );
         // now under the lock, check the flag again, because we might have seen the prior value as 1 due to the map being filled right at that time by another thread,
         // but which failed with an exception, resetting the flag as a result
         if ( all_coin_changes_processed_.test() )
            return asset_balances_;
         // otherwise fall back to the more expensive processing (actual calculation) below
      }
   }
   catch ( ... ) {
      // There was an exception during either lock acquisition or return value copying. In either case, not much we can do except to return an empty map at this time...
      return {};
   }

   // The all_coin_changes_processed_ flag was false before this, so we need to regenerate the balances map

   bool flag_already_cleared = false;
   try {
      std::unique_lock lock( asset_balances_mutex_ );
      utils::on_exception_exit clear_flag_on_exception( [ & ] {
         // Failed to actually process this time, will retry the next time, perhaps more success then...
         // This is preferably done while holding the mutex lock, so that other threads won't accidentally think processing was successful and returning asset_balances_
         all_coin_changes_processed_.clear();
         flag_already_cleared = true;
         asset_balances_.clear();   // to avoid other threads seeing/using an inconsistent/incomplete balances map in some edge cases
      } );

      // set all existing balances to zero, while retaining the precisions (which can never change)
      for ( auto &balance : asset_balances_ ) {
         auto &b = balance.second;
         b.available.set_raw( 0 );
         b.pending.set_raw( 0 );
      }

      // compute the actual current balances off of spats coins present in spark_wallet_
      spark_wallet_
        .VisitUnusedCoinMetasWhere( []( const CSparkMintMeta &meta ) { return meta.IsSpats(); },
                                    std::bind( &Wallet::update_balances_given_coin, std::placeholders::_1, std::ref( asset_balances_ ), std::cref( registry_ ) ) );

      // Not excluding balances=0,0 entries from the result being returned. Don't see a need for that at this time...
      return asset_balances_;
   }
   catch ( ... ) {
      if ( !flag_already_cleared ) {
         // This means the exception was from unique_lock constructor. We still want to clear the flag, even if this wasn't the ideal place to do it, because it was
         // preferable to do it under the lock, but if the lock acquisition itself failed, then we obviously can't do any better than this...
         all_coin_changes_processed_.clear();   // Failed to actually process this time, will retry the next time, perhaps more success then...
         // Not sure whether to clear asset_balances_ here or not. There are arguments both in favor and against that. Very unlikely edge case anyway though...
      }
      LogPrintf( "Failed to compute spark asset balances: %s\n", boost::current_exception_diagnostic_information() );
      return {};
   }
}

static std::optional< supply_amount_t::precision_type > get_asset_precision( asset_type_t a, identifier_t i, const Registry &registry )
{
   if ( !is_fungible_asset_type( a ) )   // NFT
      return 0u;   // for performance, but also because if the asset is very new, it might not be in the registry yet, but here it doesn't matter (f. precision purposes)

   const auto located_asset = registry.get_asset( a, i );
   if ( located_asset )
      return get_precision( located_asset->asset );
   return {};
}

std::optional< supply_amount_t::precision_type > Wallet::get_asset_precision( asset_type_t a, identifier_t i ) const
{
   return spats::get_asset_precision( a, i, registry_ );
}

void Wallet::update_balances_given_coin( const CSparkMintMeta &coin_meta, asset_balances_t &asset_balances, const Registry &registry )
{
   assert( coin_meta.IsSpats() );
   // TODO Performance: consider a faster retrieval of uint64 from Scalar other than via .tostring(). Or even, why is Scalar used for these two in the first place?
   const auto asset_type = std::stoull( coin_meta.coin.a.tostring() );
   const auto identifier = std::stoull( coin_meta.coin.iota.tostring() );
   const universal_asset_id_t uid{ asset_type_t{ asset_type }, identifier_t{ identifier } };
   auto it = asset_balances.find( uid );
   if ( it == asset_balances.end() ) {
      // no entry, so we don't have the precision at hand yet, need to retrieve it from the registry
      const auto precision = spats::get_asset_precision( uid.first, uid.second, registry );
      if ( !precision ) {
         // Because we don't have the asset's precision yet, we will ignore this coin and won't calculate this specific asset's balance yet. However, we shouldn't let
         // that jeopardize the calculation of any other assets' balances, so we'll just return (effectively ignoring this coin), rather than throwing an exception and
         // suppressing the calculation/display of other spats balances as a result.
         LogPrintf( "%s: Spark asset %u,%u not found in the registry! Will omit it from the spats balances map, at least for now, ignoring coin %s\n",
                    coin_meta.IsUnconfirmed() ? "WARNING" : "ERROR",
                    asset_type,
                    identifier,
                    coin_meta.k );
         return;
      }
      it = asset_balances.emplace( uid, AssetAmount::init_with_precision( *precision ) ).first;
   }

   // the entry already existed or just got inserted here in this function - in either case we have the precision already inside there
   auto &balances = it->second;
   auto &b = coin_meta.IsUnconfirmed() ? balances.pending : balances.available;
   b.set_raw( b.raw() + coin_meta.GetValue() );
}

}   // namespace spats