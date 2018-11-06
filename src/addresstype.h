#ifndef ADDRESSTYPE_H
#define ADDRESSTYPE_H

enum struct AddressType
{
      unknown = 0
    , payToPubKeyHash = 1
    , payToScryptHash = 2
    , zerocoinMint = 3
    , zerocoinSpend = 4
};

#endif /* ADDRESSTYPE_H */

