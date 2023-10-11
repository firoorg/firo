#include "params.h"
#include "chainparams.h"
#include "util.h"

namespace spark {

    CCriticalSection Params::cs_instance;
    std::unique_ptr<Params> Params::instance;

// Protocol parameters for deployment
Params const* Params::get_default() {
    if (instance) {
        return instance.get();
    } else {
        LOCK(cs_instance);
        if (instance) {
            return instance.get();
        }

        std::size_t memo_bytes = 32;
        std::size_t max_M_range = 16;
        std::size_t n_grootle = 8;
        std::size_t m_grootle = 5;

        instance.reset(new Params(memo_bytes, max_M_range, n_grootle, m_grootle));
        return instance.get();
    }
}

// Protocol parameters for testing
Params const* Params::get_test() {
    if (instance) {
        return instance.get();
    } else {
        LOCK(cs_instance);
        if (instance) {
            return instance.get();
        }

        std::size_t memo_bytes = 32;
        std::size_t max_M_range = 16;
        std::size_t n_grootle = 2;
        std::size_t m_grootle = 4;

        instance.reset(new Params(memo_bytes, max_M_range, n_grootle, m_grootle));
        return instance.get();
    }
}

Params::Params(
    const std::size_t memo_bytes,
    const std::size_t max_M_range,
    const std::size_t n_grootle,
    const std::size_t m_grootle
)
{
    // Global generators
    this->F = SparkUtils::hash_generator(LABEL_GENERATOR_F);
    this->G.set_base_g();
    this->H = SparkUtils::hash_generator(LABEL_GENERATOR_H);
    this->U = SparkUtils::hash_generator(LABEL_GENERATOR_U);

    // Coin parameters
    this->memo_bytes = memo_bytes;

    // Range proof parameters
    this->max_M_range = max_M_range;
    this->G_range.resize(64*max_M_range);
    this->H_range.resize(64*max_M_range);
    for (std::size_t i = 0; i < 64*max_M_range; i++) {
        this->G_range[i] = SparkUtils::hash_generator(LABEL_GENERATOR_G_RANGE + " " + std::to_string(i));
        this->H_range[i] = SparkUtils::hash_generator(LABEL_GENERATOR_H_RANGE + " " + std::to_string(i));
    }

    // One-of-many parameters
    if (n_grootle < 2 || m_grootle < 3) {
        throw std::invalid_argument("Bad Grootle parameteres");
    }
    this->n_grootle = n_grootle;
    this->m_grootle = m_grootle;
    this->G_grootle.resize(n_grootle * m_grootle);
    this->H_grootle.resize(n_grootle * m_grootle);
    for (std::size_t i = 0; i < n_grootle * m_grootle; i++) {
        this->G_grootle[i] = SparkUtils::hash_generator(LABEL_GENERATOR_G_GROOTLE + " " + std::to_string(i));
        this->H_grootle[i] = SparkUtils::hash_generator(LABEL_GENERATOR_H_GROOTLE + " " + std::to_string(i));
    }
}

const GroupElement& Params::get_F() const {
    return this->F;
}

const GroupElement& Params::get_G() const {
    return this->G;
}

const GroupElement& Params::get_H() const {
    return this->H;
}

const GroupElement& Params::get_U() const {
    return this->U;
}

const std::size_t Params::get_memo_bytes() const {
    return this->memo_bytes;
}

const std::vector<GroupElement>& Params::get_G_range() const {
    return this->G_range;
}

const std::vector<GroupElement>& Params::get_H_range() const {
    return this->H_range;
}

const std::vector<GroupElement>& Params::get_G_grootle() const {
    return this->G_grootle;
}

const std::vector<GroupElement>& Params::get_H_grootle() const {
    return this->H_grootle;
}

std::size_t Params::get_max_M_range() const {
    return this->max_M_range;
}

std::size_t Params::get_n_grootle() const {
    return this->n_grootle;
}

std::size_t Params::get_m_grootle() const {
    return this->m_grootle;
}

}
