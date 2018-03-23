//
//  MKGroups.hpp
//  sigma
//
//  Created by David Gray on 04/02/2018.
//  Copyright © 2018 formal. All rights reserved.
//

#ifndef GKGroups_hpp
#define  GKGroups_hpp

#include <stdio.h>
#include <iostream>
#include "GKInteger.hpp"
#include "GKEllipticCurve.hpp"

namespace GK {
    
    template <class Exponent, class GroupElement>
    class Generators {
    private:
        GroupElement _G;
        GroupElement _H;
        
    public:
        Generators(GroupElement G,GroupElement H) : _G(G), _H(H) {
        }
        
        Generators(const Generators& generators) : _G(generators._G), _H(generators._H) {
        }
        
        GroupElement& doCommit(const Exponent& m,const Exponent& r, GroupElement& result) const {
            result.set(_G);
            result.expm(m).mult(GroupElement(_H).expm(r));
            return result;
        }
        
        friend std::ostream& operator<< ( std::ostream& os, const Generators& s ) {
            os << "   " << s._G << "\n   " << s._H ;
            return os;
        }
        
    };
    
    
    typedef ModuloInteger<Q> Number;
    typedef IntegerGroupElement<P,GK::Q> Element;

    extern const GK::Generators<Number,Element> one;
    extern const GK::Generators<Number,Element> two;
    extern const GK::Generators<ECScalar,ECGroupElement> three;
    void displayGenerators();

}
#endif /*  GKGroups_hpp */
