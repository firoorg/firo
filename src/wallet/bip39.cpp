/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "bip39.h"
#include "bip39_english.h"
#include "crypto/sha256.h"
#include "random.h"

#include <openssl/evp.h>

SecureString Mnemonic::mnemonic_generate(int strength)
{
    if (strength % 32 || strength < 128 || strength > 256) {
        return SecureString();
    }
    SecureVector data(32);
    GetRandBytes(&data[0], 32);
    SecureString mnemonic = mnemonic_from_data(data, strength / 8);
    return mnemonic;
}

SecureString Mnemonic::mnemonic_from_data(const SecureVector& data, int len)
{
    if (len % 4) {
        return SecureString();
    }

    SecureVector checksum(32);
    CSHA256().Write(&data[0], len).Finalize(&checksum[0]);

    // data
    SecureVector bits(len);
    memcpy(&bits[0], &data[0], len);
    // checksum
    bits.push_back(checksum[0]);

    int mlen = len * 3 / 4;
    SecureString mnemonic;

    int i, j, idx;
    for (i = 0; i < mlen; i++) {
        idx = 0;
        for (j = 0; j < 11; j++) {
            idx <<= 1;
            idx += (bits[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
        }
        mnemonic.append(wordlist[idx]);
        if (i < mlen - 1) {
            mnemonic += ' ';
        }
    }

    return mnemonic;
}

bool Mnemonic::mnemonic_check(const SecureString& mnemonic)
{
    if (mnemonic.empty()) {
        return false;
    }

    uint32_t n = 0;

    for (size_t i = 0; i < mnemonic.size(); ++i) {
        if (mnemonic[i] == ' ') {
            n++;
        }
    }
    n++;
    // check number of words
    if (n != 12 && n != 18 && n != 24) {
        return false;
    }

    SecureString ssCurrentWord;
    SecureVector bits(32 + 1);

    uint32_t nWordIndex, ki, nBitsCount{};

    for (size_t i = 0; i < mnemonic.size(); ++i)
    {
        ssCurrentWord = "";
        while (i + ssCurrentWord.size() < mnemonic.size() && mnemonic[i + ssCurrentWord.size()] != ' ') {
            if (ssCurrentWord.size() >= 9) {
                return false;
            }
            ssCurrentWord += mnemonic[i + ssCurrentWord.size()];
        }
        i += ssCurrentWord.size();
        nWordIndex = 0;
        for (;;) {
            if (!wordlist[nWordIndex]) { // word not found
                return false;
            }
            if (ssCurrentWord == wordlist[nWordIndex]) { // word found on index nWordIndex
                for (ki = 0; ki < 11; ki++) {
                    if (nWordIndex & (1 << (10 - ki))) {
                        bits[nBitsCount / 8] |= 1 << (7 - (nBitsCount % 8));
                    }
                    nBitsCount++;
                }
                break;
            }
            nWordIndex++;
        }
    }
    if (nBitsCount != n * 11) {
        return false;
    }
    bits[32] = bits[n * 4 / 3];
    CSHA256().Write(&bits[0], n * 4 / 3).Finalize(&bits[0]);

    bool fResult = 0;
    if (n == 12) {
        fResult = (bits[0] & 0xF0) == (bits[32] & 0xF0); // compare first 4 bits
    } else
    if (n == 18) {
        fResult = (bits[0] & 0xFC) == (bits[32] & 0xFC); // compare first 6 bits
    } else
    if (n == 24) {
        fResult = bits[0] == bits[32]; // compare 8 bits
    }

    return fResult;
}

// passphrase must be at most 256 characters or code may crash
void Mnemonic::mnemonic_to_seed(const SecureString& mnemonic, const SecureString& passPhrase, SecureVector& seed_out)
{
    SecureString ssSalt = SecureString("mnemonic") + passPhrase;
    SecureVector vchSalt(ssSalt.begin(), ssSalt.end());
    seed_out.resize(64);
    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.size(), &vchSalt[0], vchSalt.size(), 2048, EVP_sha512(), 64, &seed_out[0]);
}
