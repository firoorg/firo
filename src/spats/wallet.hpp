//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATS_WALLET_HPP_INCLUDED
#define FIRO_SPATS_WALLET_HPP_INCLUDED

#include <unordered_map>

#include "identification.hpp"
#include "scaled_amount.hpp"

class CSparkWallet;

namespace spats {

class Wallet {
   // using signed integer in wallet because the blocks on disk are traversed over in the reverse direction
   using amount_type = scaled_amount< std::int64_t >;

public:
   explicit Wallet( CSparkWallet &wallet ) noexcept
      : wallet_( wallet )
   {}

   struct AssetAmount {
      amount_type available{}, pending{};
   };

   // TODO s11n?
private:
   CSparkWallet &wallet_;
   std::unordered_map< asset_type_t, AssetAmount > asset_balances_;
};

}   // namespace spats

#endif   // FIRO_SPATS_WALLET_HPP_INCLUDED
