#include "../include/MultiExponent.h"

#include "../include/secp256k1.h"
#include "../field.h"
#include "../field_impl.h"
#include "../group.h"
#include "../group_impl.h"
#include "../scalar.h"
#include "../scalar_impl.h"
#include "../ecmult.h"
#include "../ecmult_impl.h"
#include "../src/scratch_impl.h"
#include "../src/ecmult_impl.h"


typedef struct {
    secp256k1_scalar *sc;
    secp256k1_gej *pt;
} ecmult_multi_data;

int ecmult_multi_callback(secp256k1_scalar *sc, secp256k1_gej *pt, size_t idx, void *cbdata) {
    ecmult_multi_data *data = (ecmult_multi_data*) cbdata;
    *sc = data->sc[idx];
    *pt = data->pt[idx];
    return 1;
}

namespace secp_primitives {

MultiExponent::MultiExponent(const MultiExponent& other)
        : sc_(new secp256k1_scalar[other.n_points])
        , pt_(new secp256k1_gej[other.n_points])
        , n_points(other.n_points)
{
    for(int i = 0; i < n_points; ++i)
    {
        (reinterpret_cast<secp256k1_scalar *>(sc_))[i] = (reinterpret_cast<secp256k1_scalar *>(other.sc_))[i];
        (reinterpret_cast<secp256k1_gej *>(pt_))[i] = (reinterpret_cast<secp256k1_gej *>(other.pt_))[i];
    }
}

MultiExponent::MultiExponent(const std::vector<GroupElement>& generators, const std::vector<Scalar>& powers){
    sc_ = new secp256k1_scalar[powers.size()];
    pt_ = new secp256k1_gej[generators.size()];
    n_points = generators.size();
    for(int i = 0; i < n_points; ++i)
    {
        (reinterpret_cast<secp256k1_scalar *>(sc_))[i] = *reinterpret_cast<const secp256k1_scalar *>(powers[i].get_value());
        (reinterpret_cast<secp256k1_gej *>(pt_))[i] = *reinterpret_cast<const secp256k1_gej *>(generators[i].get_value());
    }
}

MultiExponent::~MultiExponent(){
    delete []reinterpret_cast<secp256k1_scalar *>(sc_);
    delete []reinterpret_cast<secp256k1_gej *>(pt_);
}

GroupElement MultiExponent::get_multiple(){
    secp256k1_gej r;

    ecmult_multi_data data;
    data.sc = reinterpret_cast<secp256k1_scalar *>(sc_);
    data.pt = reinterpret_cast<secp256k1_gej *>(pt_);

    secp256k1_scratch *scratch;
    if (n_points > ECMULT_PIPPENGER_THRESHOLD) {
        int bucket_window = secp256k1_pippenger_bucket_window(n_points);
        size_t scratch_size = secp256k1_pippenger_scratch_size(n_points, bucket_window);
        scratch = secp256k1_scratch_create(NULL, scratch_size + PIPPENGER_SCRATCH_OBJECTS*ALIGNMENT);
    } else {
        size_t scratch_size = secp256k1_strauss_scratch_size(n_points);
        scratch = secp256k1_scratch_create(NULL, scratch_size + STRAUSS_SCRATCH_OBJECTS*ALIGNMENT);
    }

    secp256k1_ecmult_context ctx;

    secp256k1_ecmult_multi_var(&ctx, scratch, &r, NULL, ecmult_multi_callback, &data, n_points);

    secp256k1_scratch_destroy(scratch);

    return  reinterpret_cast<secp256k1_scalar *>(&r);
}

}// namespace secp_primitives
