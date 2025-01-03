//
// Created by Gevorg Voskanyan
//

#include "net.h"   // for g_connman
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
         assert( length > 6 );
         return COIN;   // 1 coin of the base asset, i.e. FIRO
   }
}

Scalar Wallet::compute_new_spark_asset_serialization_scalar( const SparkAssetBase &b, std::span< const unsigned char > asset_serialization_bytes )
{
   spark::Hash hash( std::format( "spatsnew_{}_from_{}", utils::to_underlying( b.asset_type() ), b.admin_public_address() ) );
   hash.include( asset_serialization_bytes );
   return hash.finalize_scalar();
}

Wallet::Wallet( CSparkWallet &spark_wallet ) noexcept
   : spark_wallet_( spark_wallet )
   , my_public_address_as_admin_( spark_wallet.getDefaultAddress().encode( spark::GetNetworkType() ) )
   , registry_( spark::CSparkState::GetState()->GetSpatsManager().registry() )
{}

void Wallet::create_new_spark_asset( const SparkAsset &a,
                                     const std::function< bool( const SparkAsset &a, CAmount standard_fee, CAmount asset_creation_fee ) > &user_confirmation_callback )
{
   const auto &b = get_base( a );
   assert( b.admin_public_address() == my_public_address_as_admin() );
   CScript script;
   script << OP_SPATSCREATE;
   CDataStream serialized( SER_NETWORK, PROTOCOL_VERSION );
   serialized << a;
   // TODO instead of how it is being done now, put ownership proof into script default-constructed first, then compute ownership proof from the whole tx, and overwrite
   //      the ownership proof in the script then
   spark::OwnershipProof proof;
   spark::SpendKey spend_key( spark::Params::get_default() );
   spark::FullViewKey full_view_key( spend_key );
   spark::IncomingViewKey incoming_view_key( full_view_key );
   const auto scalar_of_proof = compute_new_spark_asset_serialization_scalar( b, serialized.as_bytes_span() );
   spark_wallet_.getDefaultAddress().prove_own( scalar_of_proof, spend_key, incoming_view_key, proof );
   CDataStream proof_serialized( SER_NETWORK, PROTOCOL_VERSION );
   proof_serialized << proof;
   script.insert( script.end(), serialized.begin(), serialized.end() );
   script.insert( script.end(), proof_serialized.begin(), proof_serialized.end() );
   const auto new_asset_fee = compute_new_spark_asset_fee( b.naming().symbol.get() );
   CScript burn_script = GetScriptForDestination( CBitcoinAddress( std::string( firo_burn_address ) ).Get() );
   CRecipient burn_recipient = { std::move( burn_script ), new_asset_fee, false, "" };   // TODO should .address stay empty or set to firo_burn_address too?
   CAmount standard_fee;
   CWalletTx tx = spark_wallet_.CreateSparkSpendTransaction( { CRecipient( std::move( script ), {}, false, b.admin_public_address() ), burn_recipient },
                                                             {},
                                                             standard_fee,
                                                             nullptr );   // may throw

   if ( user_confirmation_callback && !user_confirmation_callback( a, standard_fee, new_asset_fee ) ) {
      // TODO log cancellation by user
      return;
   }

   auto &main_wallet = spark_wallet_.getMainWallet();
   CReserveKey reserve_key( &main_wallet );   // TODO what is this for?
   CValidationState state;
   if ( !main_wallet.CommitTransaction( tx, reserve_key, g_connman.get(), state ) )
      throw std::runtime_error( "Failed to commit new spark asset transaction" );
}

void Wallet::notify_registry_changed()
{
   // TODO
}

}   // namespace spats