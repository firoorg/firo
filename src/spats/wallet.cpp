//
// Created by Gevorg Voskanyan
//

#include "../validation.h"
#include "../wallet/wallet.h"
#include "../spark/sparkwallet.h"
#include "../spark/state.h"

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

Wallet::Wallet( CSparkWallet &spark_wallet ) noexcept
   : spark_wallet_( spark_wallet )
   , registry_( spark::CSparkState::GetState()->GetSpatsManager().registry() )
{}

const std::string &Wallet::my_public_address_as_admin() const
{
   if ( my_public_address_as_admin_.empty() ) {
      // Doing lazy initialization, as in the constructor, spark_wallet isn't fully initialized yet!
      my_public_address_as_admin_ = spark_wallet_.getDefaultAddress().encode( spark::GetNetworkType() );
      assert( !my_public_address_as_admin_.empty() );
      LogPrintf( "my_public_address_as_admin: %s\n", my_public_address_as_admin_ );
   }
   return my_public_address_as_admin_;
}

CWalletTx
Wallet::create_new_spark_asset_transaction( const SparkAsset &a, CAmount &standard_fee, CAmount &new_asset_fee, const public_address_t &destination_public_address ) const
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
   serialized << CreateAssetAction( a );
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
   std::string burn_address( firo_burn_address );
   CScript burn_script = GetScriptForDestination( CBitcoinAddress( burn_address ).Get() );
   CRecipient burn_recipient{ std::move( burn_script ), new_asset_fee, false, {}, "burning new asset fee" };
   if ( initial_supply ) {
      const auto initial_supply_raw = boost::numeric_cast< CAmount >( initial_supply.raw() );
      CRecipient initial_supply_recipient{ GetScriptForDestination(   // TODO or use mint, and thus a structure more appropriate for that?
                                             CBitcoinAddress( destination_public_address.empty() ? b.admin_public_address() : destination_public_address ).Get() ),
                                           initial_supply_raw,
                                           false,
                                           {},
                                           "crediting new asset's initial supply" };   // TODO include the asset's asset_type and identifier as new fields?
      // TODO include initial_supply_recipient into the tx being created (as a private recipient perhaps?), once spats sends/mints are implemented
   }
   auto tx = spark_wallet_.CreateSparkSpendTransaction( { CRecipient{ std::move( script ), {}, false, b.admin_public_address(), "new asset" }, burn_recipient },
                                                        {},
                                                        standard_fee,
                                                        nullptr );   // may throw
   assert( tx.tx->IsSpatsCreate() );
   return tx;
}

CWalletTx Wallet::create_unregister_spark_asset_transaction( asset_type_t asset_type, std::optional< identifier_t > identifier, CAmount &standard_fee ) const
{
   const auto &admin_public_address = my_public_address_as_admin();
   const UnregisterAssetParameters action_params( asset_type, identifier, admin_public_address );
   CScript script;
   script << OP_SPATSUNREGISTER;
   assert( script.IsSpatsUnregister() );
   CDataStream serialized( SER_NETWORK, PROTOCOL_VERSION );
   serialized << UnregisterAssetAction( action_params );
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
                                                        standard_fee,
                                                        nullptr );   // may throw
   assert( tx.tx->IsSpatsUnregister() );
   return tx;
}

CWalletTx Wallet::create_modify_spark_asset_transaction( const SparkAsset &old_asset, const SparkAsset &new_asset, CAmount &standard_fee ) const
{
   const auto &admin_public_address = my_public_address_as_admin();
   const auto m = make_asset_modification( old_asset, new_asset, admin_public_address );
   const auto &b = get_base( m );
   CScript script;
   script << OP_SPATSMODIFY;
   assert( script.IsSpatsModify() );
   CDataStream serialized( SER_NETWORK, PROTOCOL_VERSION );
   serialized << ModifyAssetAction( m );
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
                                                        standard_fee,
                                                        nullptr );   // may throw
   assert( tx.tx->IsSpatsModify() );
   return tx;
}

CWalletTx Wallet::create_mint_asset_supply_transaction( asset_type_t asset_type,
                                                        supply_amount_t new_supply,
                                                        const public_address_t &receiver_pubaddress,
                                                        CAmount &standard_fee ) const
{
   const auto &admin_public_address = my_public_address_as_admin();
   const MintParameters action_params( asset_type, new_supply, receiver_pubaddress, admin_public_address );
   CScript script;
   script << OP_SPATSMINT;
   assert( script.IsSpatsMint() );
   CDataStream serialized( SER_NETWORK, PROTOCOL_VERSION );
   serialized << MintAction( action_params );
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
   // TODO add a recipient to action_params.receiver_public_address(), for `new_supply` of `asset_type`. It has to be done in such a way that the actual crediting of
   //      `new_supply` will NOT be actually performed if the action validation by the registry fails.
   auto tx = spark_wallet_.CreateSparkSpendTransaction( { CRecipient{ std::move( script ), {}, false, admin_public_address, "spats mint" } },
                                                        {},
                                                        standard_fee,
                                                        nullptr );   // may throw
   assert( tx.tx->IsSpatsMint() );
   return tx;
}

CWalletTx Wallet::create_burn_asset_supply_transaction( asset_type_t asset_type, supply_amount_t burn_amount, CAmount &standard_fee ) const
{
   const auto &admin_public_address = my_public_address_as_admin();
   const BurnParameters action_params( asset_type, burn_amount, admin_public_address );
   CScript script;
   script << OP_SPATSBURN;
   assert( script.IsSpatsBurn() );
   CDataStream serialized( SER_NETWORK, PROTOCOL_VERSION );
   serialized << BurnAction( action_params );
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
   auto tx = spark_wallet_.CreateSparkSpendTransaction( { CRecipient{ std::move( script ), {}, false, admin_public_address, "spats burn" } },
                                                        {},
                                                        standard_fee,
                                                        nullptr );   // may throw
   assert( tx.tx->IsSpatsBurn() );
   return tx;
}

void Wallet::notify_registry_changed()
{
   // TODO
}

Wallet::asset_balances_t Wallet::get_asset_balances() const
{
   // TODO either fill this somehow (with locking), or compute on the fly in CSparkWallet and don't store here
   return asset_balances_;
}

}   // namespace spats