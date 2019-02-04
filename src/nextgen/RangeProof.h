#ifndef ZCOIN_SIGMA_RANGEPROOF_H
#define ZCOIN_SIGMA_RANGEPROOF_H

namespace nextgen{

template<class Exponent, class GroupElement>
class RangeProof{
public:

    inline int memoryRequired(int n) {
        int size = (int)(log(n) / log(2));
        return A.memoryRequired() * 4
                + T_x.memoryRequired() * 2
                + innerProductProof.memoryRequired(size);
    }

    inline unsigned char* serialize(unsigned char* buffer) const {
        unsigned char* current = A.serialize(buffer);
        current = S.serialize(current);
        current = T1.serialize(current);
        current = T2.serialize(current);
        current = T_x.serialize(current);
        current = u.serialize(current);
        /// for linear size proof
//        current = t_.serialize(current);
//        for(int i = 0; i < l.size(); ++i)
//            current = l[i].serialize(current);
//        for(int i = 0; i < r.size(); ++i)
//            current = r[i].serialize(current);
        /// for inner product proof
        current = innerProductProof.serialize(current);
        return current;
    }
    inline unsigned char* deserialize(unsigned char* buffer, int size) {
        unsigned char* current = A.deserialize(buffer);
        current = S.deserialize(current);
        current = T1.deserialize(current);
        current = T2.deserialize(current);
        current = T_x.deserialize(current);
        current = u.deserialize(current);
        /// for linear size proof
//        current = t_.deserialize(current);
//        for(int i = 0; i < l.size(); ++i)
//            current = l[i].deserialize(current);
//        for(int i = 0; i < r.size(); ++i)
//            current = r[i].deserialize(current);
        /// for inner product proof
        current = innerProductProof.deserialize(current);
        return current;
    }

    GroupElement A;
    GroupElement S;
    GroupElement T1;
    GroupElement T2;
    Exponent T_x;
    Exponent u;
/// for linear prof size
//    Exponent t_; //t is inside innerProductProof with name c;
//    std::vector<Exponent> l;
//    std::vector<Exponent> r;
/// inner product proof
    InnerProductProof<Exponent, GroupElement> innerProductProof;

};
}//namespace nextgen

#endif //ZCOIN_SIGMA_RANGEPROOF_H
