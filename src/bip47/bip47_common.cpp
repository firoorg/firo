#include "bip47_common.h"
unsigned char* Bip47_common::arraycopy(const unsigned char *source_arr, int sourcePos, unsigned char* dest_arr, int destPos, int len){
    return (unsigned char*)memcpy(dest_arr + destPos,source_arr + sourcePos , len);
}
unsigned char* Bip47_common::arraycopy(const std::vector<unsigned char> &source_arr,int sourcePos,unsigned char* dest_arr, int destPos, int len){
    if(source_arr.size() < sourcePos + len)
    {
        throw std::runtime_error("arraycopy error, source_arr has invalid size");
    }
    return (unsigned char*)memcpy(dest_arr + destPos,source_arr.data() + sourcePos , len);
}
unsigned char* Bip47_common::arraycopy(const unsigned char *source_arr,int sourcePos,std::vector<unsigned char> &dest_arr, int destPos, int len){
    if(dest_arr.size() < destPos + len)
    {
        throw std::runtime_error("arraycopy error, dest_arr has invalid size");
    }
    return (unsigned char*)memcpy(dest_arr.data() + destPos, source_arr + sourcePos , len);
}
unsigned char* Bip47_common::arraycopy(const std::vector<unsigned char> &source_arr,int sourcePos,std::vector<unsigned char> &dest_arr, int destPos, int len){
    if(dest_arr.size() < destPos + len)
    {
        throw std::runtime_error("arraycopy error, dest_arr has invalid size");
    }
    if(source_arr.size() < sourcePos + len)
    {
        throw std::runtime_error("arraycopy error, source_arr has invalid size");
    }
    return (unsigned char*)memcpy(dest_arr.data() + destPos, source_arr.data() + sourcePos , len);
}
unsigned char* Bip47_common::copyOfRange(const std::vector<unsigned char> &original, int from, int to,std::vector<unsigned char> &result) {
    int newLength = to - from;
    if (newLength < 0)
        throw std::runtime_error(from + " > " + to);
    result = std::vector<unsigned char>(newLength);
    int len = original.size() - from ;
    if(len > newLength) len = newLength ;
    arraycopy(original, from, result, 0, len);
    return result.data();
}
bool Bip47_common::doublehash(const std::vector<unsigned char> &input,std::vector<unsigned char> &result)
{
    try{
        SHA256_CTX shaCtx;
        SHA256_Init(&shaCtx);
        SHA256_Update(&shaCtx, input.data(), input.size());
        uint256 hash1;
        SHA256_Final((unsigned char*)&hash1, &shaCtx);
        uint256 hash2;
        SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
        result = std::vector<unsigned char>(hash2.begin(),hash2.end());
        return true;
    }
    catch(std::exception &e)
    {
        printf("bool Bip47_common::doublehash is failed ...\n");
        return false;
    }
    
}
    
    

