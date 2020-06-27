#include "ecmult.hpp"

#include "group.hpp"
#include "scalar.hpp"
#include "secp256k1.hpp"

#include "../scalar_impl.h"
#include "../field_impl.h"
#include "../group_impl.h"
#include "../ecmult_impl.h"
#include "../scratch_impl.h"
#include "../util.h"

#include <new>
#include <stdexcept>
#include <string>

#include <stddef.h>

namespace {

void error_handler(const char *text, void *data) {
    try {
        reinterpret_cast<::std::string *>(data)->assign(text);
    } catch (...) {
        // this is called by C so we don't want C++ exception to go upper
    }
}

int multi_handler(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    auto d = reinterpret_cast<const ::secp_primitives::MultiExponent::Data *>(data);
    auto ge = d->pt[idx]; // make a copy due to secp256k1_ge_set_gej need to modify it

    *sc = d->sc[idx];
    secp256k1_ge_set_gej(pt, &ge);

    return 1;
}

} // unnamed namespace

namespace secp_primitives {

MultiExponent::MultiExponent(const std::vector<GroupElement>& generators, const std::vector<Scalar>& powers) : data(new Data()) {
    if (generators.size() != powers.size()) {
        throw std::invalid_argument("Number of generators and powers is mismatched");
    }

    data->sc.reserve(generators.size());
    data->pt.reserve(generators.size());

    for (size_t i = 0; i < generators.size(); i++) {
        data->sc.push_back(powers[i].get_data().value);
        data->pt.push_back(generators[i].get_data().value);
    }
}

MultiExponent::MultiExponent(const MultiExponent& other) : data(new Data(*other.data)) {
}

MultiExponent::~MultiExponent() {
    // don't remove this destructor otherwise it will inlined on the outside and cause linking error due to
    // MultiExponent::Data is incomplete type
}

MultiExponent& MultiExponent::operator=(const MultiExponent& other) {
    *data = *other.data;
    return *this;
}

GroupElement MultiExponent::get_multiple() {
    std::string err;
    auto eh = secp256k1_callback{.fn = error_handler, .data = &err};
    secp256k1_scratch *scratch;
    GroupElement::Data r;
    int status;

    if (data->sc.size() > ECMULT_PIPPENGER_THRESHOLD) {
        auto bucket_window = secp256k1_pippenger_bucket_window(data->sc.size());
        auto scratch_size = secp256k1_pippenger_scratch_size(data->sc.size(), bucket_window);
        scratch = secp256k1_scratch_create(&eh, scratch_size + PIPPENGER_SCRATCH_OBJECTS * ALIGNMENT);
    } else {
        auto scratch_size = secp256k1_strauss_scratch_size(data->sc.size());
        scratch = secp256k1_scratch_create(&eh, scratch_size + STRAUSS_SCRATCH_OBJECTS * ALIGNMENT);
    }

    if (!scratch) {
        // no need to grab the reason from err due to it is always out of memory, also bad_alloc does not accept the message
        throw std::bad_alloc();
    }

    status = secp256k1_ecmult_multi_var(&eh, &secp256k1::default_context->ecmult_ctx, scratch, &r.value, nullptr, multi_handler, data.get(), data->sc.size());
    secp256k1_scratch_destroy(&eh, scratch);

    if (!status) {
        // we can safely use err as the reason due to the only case secp256k1_scratch_destroy will fail is we pass invalid scratch
        throw std::runtime_error(err);
    }

    return r;
}

} // namespace secp_primitives