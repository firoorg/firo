//
//  GKZerocoin.hpp
//  sigma
//
//  Created by David Gray on 25/01/2018.
//  Copyright © 2018 formal. All rights reserved.
//

#ifndef GKZerocoin_hpp
#define GKZerocoin_hpp

#include <stdio.h>
#include "GKSchema.hpp"

using namespace GK;

template <class Exponent, class GroupElement>
void mintCoin(Generators<Exponent,GroupElement>& generators,Exponent& r,Exponent& S,GroupElement& c) {
    r.random();
    S.random();
    generators.doCommit(S,r,c);
}

template <class Exponent, class GroupElement>
std::string encodeCoin(const Exponent& r,const Exponent& S,const GroupElement& c) {
    GKWriteBuffer<Exponent,GroupElement> buffer(5*1024);
    buffer.add(c);
    buffer.add(r);
    buffer.add(S);
    return buffer.base64EncodedData();
}

template <class Exponent, class GroupElement>
void decodeCoin(const std::string& encoding,Exponent& r,Exponent& S,GroupElement& c) {
    GKReadBuffer<Exponent,GroupElement> buffer(encoding);
    buffer.get(c);
    buffer.get(r);
    buffer.get(S);
}

template <class Exponent, class GroupElement>
void spendCoin(Generators<Exponent,GroupElement>& generators,
               const Exponent& r,
               const Exponent& S,
               const GroupElement& c,
               const std::string& M,
               // output arguments
               std::vector<GroupElement>& C,
               std::vector<CommitPackage<Exponent,GroupElement>>& cpackages,
               std::vector<ResponsePackage<Exponent,GroupElement>>& rpackages,
               Exponent& zd) {
    
    // add c to C at a random position
    size_t pos = GK::rand(C.size());
    C.insert(C.begin()+pos, c);
    
    GroupElement element;
    generators.doCommit(S,Exponent((int64_t)0),element).invm();

    std::vector<GroupElement> C1;
    for (int i = 0; i < C.size(); i++) {
        C1.push_back(GroupElement(C[i]).mult(element));
    }

    //
    std::vector<CommitDataPackage<Exponent,GroupElement>> dpackages;
    OneOutOfNCommit(generators,C1,pos,r,dpackages,cpackages);
    
    // Compute x
    GKWriteBuffer<Exponent,GroupElement> buffer;
    
    buffer.add(M);
    buffer.add(S);
    buffer.add(C);
    buffer.add(cpackages);
    Exponent x = buffer.hash().mod();
//    std::cerr << "Challenge: " << x << std::endl;

    OneOutOfNResponse(C1,dpackages,x,r,rpackages,zd);
}

template <class Exponent, class GroupElement>
std::string encodeSpend(const std::string& M,
                        const Exponent& S,
                        const std::vector<GroupElement>& C,
                        const std::vector<CommitPackage<Exponent,GroupElement>>& cpackages,
                        const std::vector<ResponsePackage<Exponent,GroupElement>>& rpackages,
                        const Exponent& zd) {
    GKWriteBuffer<Exponent,GroupElement> buffer;
    buffer.add(M);
    buffer.add(S);
    buffer.add(C);
    buffer.add(cpackages);
    buffer.add(rpackages);
    buffer.add(zd);
    return buffer.base64EncodedData();
    
}


template <class Exponent, class GroupElement>
void decodeSpend(const std::string& encoding,
                 std::string& M,
                 Exponent& S,
                 std::vector<GroupElement>& C,
                 std::vector<CommitPackage<Exponent,GroupElement>>& cpackages,
                 std::vector<ResponsePackage<Exponent,GroupElement>>& rpackages,
                 Exponent& zd) {
    GKReadBuffer<Exponent,GroupElement> buffer(encoding);
    buffer.get(M);
    buffer.get(S);
    buffer.get(C);
    buffer.get(cpackages);
    buffer.get(rpackages);
    buffer.get(zd);
}

template <class Exponent, class GroupElement>
bool verifyCoin(Generators<Exponent,GroupElement>& generators,const std::string& M,
                const Exponent& S,
                const std::vector<GroupElement>& C,
                const std::vector<CommitPackage<Exponent,GroupElement>>& cpackages,
                const std::vector<ResponsePackage<Exponent,GroupElement>>& rpackages,
                const Exponent& zd) {
    //
    GroupElement element;
    generators.doCommit(S,Exponent((int64_t)0),element).invm();
    std::vector<GroupElement> C1;
    for (int i = 0; i < C.size(); i++) {
        C1.push_back(GroupElement(C[i]).mult(element));
    }

    // Compute x
    GKWriteBuffer<Exponent,GroupElement> buffer;
    
    buffer.add(M);
    buffer.add(S);
    buffer.add(C);
    buffer.add(cpackages);
    Exponent x = buffer.hash().mod();
//    std::cerr << "Challenge: " << x << std::endl;

    try {
        OneOutOfNVerify(generators,C1,cpackages,rpackages,zd,x);
        return true;
    } catch (std::string error) {
        std::cerr << "Exception: " << error << std::endl;
        return false;
    }

}

#endif /* GKZerocoin_hpp */
