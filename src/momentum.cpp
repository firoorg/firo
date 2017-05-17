#include <boost/unordered_map.hpp>
#include <iostream>
#include <openssl/sha.h>
#include "momentum.h"
#include "hashblock.h"
namespace bts 
{
	#define MAX_MOMENTUM_NONCE  (1<<22)
	#define SEARCH_SPACE_BITS 42
	#define BIRTHDAYS_PER_HASH 8
	
	bool momentum_search( uint256 midHash ,std::vector< std::pair<uint32_t,uint32_t> > &results)
  {
			semiOrderedMap somap;
			if(!somap.allocate(4))
			{
				return false;
			}

      char  hash_tmp[sizeof(midHash)+4];
      memcpy((char*)&hash_tmp[4], (char*)&midHash, sizeof(midHash) );
      uint32_t* index = (uint32_t*)hash_tmp;

      for( uint32_t i = 0; i < MAX_MOMENTUM_NONCE;  )
      {
	      if(i%1048576==0){
		boost::this_thread::interruption_point();
	      }
          *index = i;
          uint64_t  result_hash[8];
          HashGroestl((unsigned char*)hash_tmp, sizeof(hash_tmp), (unsigned char*)result_hash);
        
	      
          for( uint32_t x = 0; x < 8; ++x )
          {
              uint64_t birthday = result_hash[x] >> (64-SEARCH_SPACE_BITS);
              uint32_t nonce = i+x;
              //boost::unordered_map<uint64_t,uint32_t>::const_iterator itr = found.find( birthday );

              uint64_t foundMatch=somap.checkAdd( birthday, nonce );
              if( foundMatch != 0 ){
                  results.push_back( std::make_pair( foundMatch, nonce ) );
              }
          }
          i += BIRTHDAYS_PER_HASH;
      }
      //for( auto itr = results.begin(); itr != results.end(); ++itr )
      //{
      //   assert( momentum_verify( midHash, itr->first, itr->second ) );
     // }
      //somap.destroy();
      return true;
   }


	uint64_t getBirthdayHash(const uint256& midHash, uint32_t a)
  {
    uint32_t index = a - (a%8);
    char  hash_tmp[sizeof(midHash)+4];
  //  std::cerr<<"midHash size:" <<sizeof(midHash)<<"\n";
    memcpy(&hash_tmp[4], (char*)&midHash, sizeof(midHash) );
    memcpy(&hash_tmp[0], (char*)&index, sizeof(index) );

    uint64_t  result_hash[8];
//      for( uint32_t i = 0; i < sizeof(hash_tmp); ++i )
 //     {
  //       std::cerr<<" "<<uint16_t((((unsigned char*)hash_tmp)[i]));
   //   }
//      std::cerr<<"\n";
		HashGroestl((unsigned char*)hash_tmp, sizeof(hash_tmp), (unsigned char*)&result_hash);
//    std::cerr<<"result_hash "<<a<<"  "<<a%8<<"  --- ";
 //   for( uint32_t i = 0; i < 8; ++i ) std::cerr<<result_hash[i]<<" ";
  //  std::cerr<<"\n";

    uint64_t r = result_hash[a%BIRTHDAYS_PER_HASH]>>(64-SEARCH_SPACE_BITS);
  //  std::cerr<<"bdayresult: "<<r<<"\n";
    return r;
	}

	bool momentum_verify( uint256 head, uint32_t a, uint32_t b ){
 //   std::cerr<<"verify  "<<a<<"  and "<<b<<"  mid: "<<head.ToString()<<"\n";
 //   std::cerr<<"    "<<getBirthdayHash(head,a)<<"   "<<getBirthdayHash(head,b)<<"\n";
		if( a == b ) return false;
		if( a > MAX_MOMENTUM_NONCE ) return false;
		if( b > MAX_MOMENTUM_NONCE ) return false;		

     bool r = (getBirthdayHash(head,a) == getBirthdayHash(head,b));
  //   std::cerr<< "####### Verified "<<int(r)<<"\n";
     return r;
	}

}
