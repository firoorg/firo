//
// Created by Gevorg Voskanyan
//

#include "net.h"   // for g_connman
#include "../validation.h"
#include "../wallet/wallet.h"
#include "../spark/sparkwallet.h"

#include "wallet.hpp"

namespace spats {

// Compute the fee specifically for creating a new spark asset, based on the length of the asset's symbol.
// The shorter the symbol, the more expensive the fee.
// Right now mimicking the fee structure for Spark Names to get at concrete numbers.
// They don't necessarily have to match though, so these numbers here may change before going live...
static CAmount compute_new_spark_asset_fee( const std::string_view asset_symbol ) noexcept
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

void Wallet::create_new_spark_asset( const SparkAsset &a,
                                     const std::function< bool( const SparkAsset &a, CAmount standard_fee, CAmount asset_creation_fee ) > &user_confirmation_callback )
{
   const auto &b = get_base( a );
   CDataStream serialized( SER_NETWORK, PROTOCOL_VERSION );
   serialized << a;
   CScript script;
   script << OP_SPARKNEWASSET;
   script.insert( script.end(), serialized.begin(), serialized.end() );
   CAmount standard_fee;
   const auto new_asset_fee = compute_new_spark_asset_fee( b.naming().symbol.get() );
   const auto burn_address = "aFiroBurningAddressDoNotSendrPtjYA"s;
   CScript burn_script = GetScriptForDestination( CBitcoinAddress( burn_address ).Get() );
   CRecipient burn_recipient = { std::move( burn_script ), new_asset_fee, false, "" };   // TODO should .address stay empty or set to burn_address too?
   CWalletTx tx = wallet_.CreateSparkSpendTransaction( { CRecipient( std::move( script ), {}, false, b.admin_public_address() ), burn_recipient },
                                                       {},
                                                       standard_fee,
                                                       nullptr );   // may throw

   if ( user_confirmation_callback && !user_confirmation_callback( a, standard_fee, new_asset_fee ) ) {
      // TODO log cancellation by user
      return;
   }

   auto &main_wallet = wallet_.getMainWallet();
   CReserveKey reserve_key( &main_wallet );   // TODO what is this for?
   CValidationState state;
   if ( !main_wallet.CommitTransaction( tx, reserve_key, g_connman.get(), state ) )
      throw std::runtime_error( "Failed to commit new spark asset transaction" );
}

}   // namespace spats