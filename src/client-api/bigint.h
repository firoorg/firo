#ifndef ELYSIUM_CPP_BIGINT_H
#define ELYSIUM_CPP_BIGINT_H

UniValue BigInt(std::string s);
UniValue BigInt(uint64_t n);

int64_t get_bigint(const UniValue& u);

#endif //ELYSIUM_CPP_BIGINT_H
