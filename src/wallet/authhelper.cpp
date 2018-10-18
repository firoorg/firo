#include <random>
#include <string>
#include <map>

#include "base58.h"
#include "authhelper.h"
#include "wallet.h"
#include "main.h"

struct AuthorizationHelper::Impl
{
    using rnd_type = size_t;
    using code_type = std::string;
    Impl()
    : rnd_dist(std::numeric_limits<rnd_type>::min(), std::numeric_limits<rnd_type>::max())
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        generator.seed(pwalletMain->GetHDChain().masterKeyID.GetUint64(0) ^ time(NULL));
    }

    bool authorize(code_type const & functionName, code_type code)
    {
        auto const fn_key_iter = key_store.find(functionName);
        if(fn_key_iter == key_store.end())
        {
            generateAuthorizationCode(functionName);
            return false;
        }

        if(code == toCode(fn_key_iter->second))
        {
            generateAuthorizationCode(functionName);
            return true;
        }

        return false;
    }

    code_type generateAuthorizationCode(code_type const & functionName)
    {
        rnd_type key = rnd_dist(generator);
        key_store[functionName] = key;
        return toCode(key);
    }

private:
    std::mt19937 generator;
    std::uniform_int_distribution<rnd_type> rnd_dist;
    std::map<code_type, rnd_type> key_store;

    code_type toCode(rnd_type code)
    {
        static_assert(true == std::is_standard_layout<rnd_type>::value, "This method can only work with standard_layout data.");
        std::string temp = EncodeBase58(reinterpret_cast<const unsigned char*>(&code), reinterpret_cast<const unsigned char*>(&code) + sizeof(code));

        static std::vector<size_t> const pick_positions = {13, 17, 19, 23};

        code_type result;

        size_t position = 0;

        for(auto pick_position : pick_positions)
        {
            position += pick_position;
            position %= temp.size();
            result.push_back(temp[position]);
        }

        return result;
    }
};


AuthorizationHelper & AuthorizationHelper::inst()
{
    static AuthorizationHelper inst;
    return inst;
}


AuthorizationHelper::AuthorizationHelper() 
: pImpl(*new Impl)
{
}


AuthorizationHelper::~AuthorizationHelper()
{
    delete &pImpl;
}


bool AuthorizationHelper::authorize(std::string const & function_name, std::string const & auth_code)
{
    return pImpl.authorize(function_name, auth_code);
}


std::string AuthorizationHelper::generateAuthorizationCode(std::string const & function_name)
{
    return pImpl.generateAuthorizationCode(function_name);
}

