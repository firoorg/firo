#ifndef ADDRESSTYPE_H
#define ADDRESSTYPE_H

enum struct AddressType
{
      unknown = 0
    , payToPubKeyHash = 1
    , payToScryptHash = 2
    , zeroMint = 3
    , zeroSpend = 4
};

#endif /* ADDRESSTYPE_H */

