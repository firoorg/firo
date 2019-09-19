    #include "Bip47ChannelAddress.h"
    Bip47ChannelAddress::Bip47ChannelAddress(){

    }
    Bip47ChannelAddress::Bip47ChannelAddress(CBaseChainParams *v_params, CExtPubKey &cKey, int child) {
        params = v_params;
        childNum = child;
        CExtPubKey dk ;
        if(!cKey.Derive(dk, childNum)){
            throw std::runtime_error("Bip47ChannelAddress::Bip47ChannelAddress(CBaseChainParams *v_params, CExtPubKey &cKey, int child) is failed.\n");
        }
        // if(dk.hasPrivKey()) {
        //     byte[] now = ArrayUtils.addAll(new byte[1], dk.getPrivKeyBytes());
        //     this.ecKey = ECKey.fromPrivate(new BigInteger(now), true);
        // } else {
        //     this.ecKey = ECKey.fromPublicOnly(dk.getPubKey());
        // }
        ecKey = dk ;

        // long now1 = Utils.now().getTime() / 1000L;
        // this.ecKey.setCreationTimeSeconds(now1);
        pubKey = std::vector<unsigned char>(ecKey.pubkey.begin(),ecKey.pubkey.end());
        // pubKeyHash = ecKey.getPubKeyHash();
        // strPath = dk.getPathAsString();
    }
  
    std::vector<unsigned char>& Bip47ChannelAddress::getPubKey() {
        return pubKey;
    }

    std::vector<unsigned char>& Bip47ChannelAddress::getPubKeyHash() {
        return pubKeyHash;
    }

    String Bip47ChannelAddress::getAddressString() {
//        return ecKey.toAddress(params).toString();
        return String("");
    }

    String Bip47ChannelAddress::getPrivateKeyString() {
//        return ecKey.hasPrivKey()?ecKey.getPrivateKeyEncoded(params).toString():null;
        return String("");

    }

    // Address getAddress() {
    //     return ecKey.toAddress(params);
    // }

    String Bip47ChannelAddress::getPath() {
        return strPath;
    }