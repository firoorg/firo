#include "bignum.h"
#include "semiOrderedMap.h"

namespace bts {
	bool momentum_search( uint256 midHash ,std::vector< std::pair<uint32_t,uint32_t> > &results);
	bool momentum_verify( uint256 midHash, uint32_t a, uint32_t b );
}

