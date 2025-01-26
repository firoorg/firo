//
// Created by Gevorg Voskanyan
//

#include <format>

#include "../validation.h"
#include "../wallet/wallet.h"
#include "../spark/sparkwallet.h"
#include "../spark/state.h"

#include "registry.hpp"
#include "wallet.hpp"

namespace spats {

// Compute the fee specifically for creating a new spark asset, based on the length of the asset's symbol.
// The shorter the symbol, the more expensive the fee.
// Right now mimicking the fee structure for Spark Names to get at concrete numbers.
// They don't necessarily have to match though, so these numbers here may change before going live...
CAmount Wallet::compute_new_spark_asset_fee( const std::string_view asset_symbol ) noexcept
{
   const auto length = asset_symbol.length();
   assert( length > 0 );
   switch ( length ) {
      case 1:
         return 1000 * COIN;
      case 2:
         return 100 * COIN;
      case 3:
      case 4:
      case 5:
         return 10 * COIN;
      default:
         assert( length >= 6 );
         return COIN;   // 1 coin of the base asset, i.e. FIRO
   }
}

Scalar Wallet::compute_new_spark_asset_serialization_scalar( const SparkAssetBase &b, std::span< const unsigned char > asset_serialization_bytes )
{
   spark::Hash hash( std::format( "spatsnew_{}_from_{}", utils::to_underlying( b.asset_type() ), b.admin_public_address() ) );
   hash.include( asset_serialization_bytes );
   auto ret = hash.finalize_scalar();
   LogPrintf( "New spark asset serialization scalar (hex): %s\n", ret.GetHex() );
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
   serialized << a;
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
   CRecipient burn_recipient = { std::move( burn_script ), new_asset_fee, false, {} };
   if ( initial_supply ) {
      const auto initial_supply_raw = boost::numeric_cast< CAmount >( initial_supply.raw() );
      CRecipient initial_supply_recipient = { GetScriptForDestination(   // TODO or use mint, and thus a structure more appropriate for that?
                                                CBitcoinAddress( destination_public_address.empty() ? b.admin_public_address() : destination_public_address ).Get() ),
                                              initial_supply_raw,
                                              false,
                                              {} };   // TODO include the asset's asset_type and identifier as new fields?
      // TODO include initial_supply_recipient into the tx being created (as a private recipient perhaps?), once spats sends/mints are implemented
   }
   auto tx = spark_wallet_.CreateSparkSpendTransaction( { CRecipient( std::move( script ), {}, false, b.admin_public_address() ), burn_recipient },
                                                        {},
                                                        standard_fee,
                                                        nullptr );   // may throw
   assert( tx.tx->IsSpatsCreate() );   // TODO is this the right way to do the check?
   return tx;
}

void Wallet::notify_registry_changed()
{
   // TODO
}

}   // namespace spats