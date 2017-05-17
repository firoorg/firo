#ifndef HASHBLOCK_H
#define HASHBLOCK_H

#include "uint256.h"
#include "sph_groestl.h"
#include "sph_keccak.h"

#ifndef QT_NO_DEBUG
#include <string>
#endif

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_groestl512_context   z_groestl;
GLOBAL sph_keccak512_context    z_keccak;

#define fillz() do { \
    sph_groestl512_init(&z_groestl); \
    sph_keccak512_init(&z_keccak); \
} while (0) 

#define ZGROESTL (memcpy(&ctx_groestl, &z_groestl, sizeof(z_groestl)))
#define ZKECCAK (memcpy(&ctx_keccak, &z_keccak, sizeof(z_keccak)))

template<typename T1>
void HashGroestl(const T1 pbegin, uint32_t size,const T1 result)
{
    sph_groestl512_context   ctx_groestl;
    static unsigned char pblank[1];
    sph_groestl512_init(&ctx_groestl);
        // ZGROESTL;
    sph_groestl512 (&ctx_groestl, static_cast<const void*>(&pbegin[0]), size);
        sph_groestl512_close(&ctx_groestl, static_cast<void*>(result));
		
}

template<typename T1>
uint256 Hashkeccak2(const T1 pbegin, uint32_t size)

{
    sph_keccak512_context    ctx_keccak;
    static unsigned char pblank[1];


    uint512 mask = 8;
    uint512 zero = 0;
    
    uint512 hash[2];

    sph_keccak512_init(&ctx_keccak);
    // ZKECCAK;
    sph_keccak512 (&ctx_keccak, static_cast<const void*>(&pbegin[0]), size);
    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[0]));

    sph_keccak512_init(&ctx_keccak);
        // ZKECCAK;
        sph_keccak512 (&ctx_keccak, static_cast<const void*>(&hash[0]), 64);
        sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[1]));
		

    return hash[1].trim256();
}






#endif // HASHBLOCK_H
