#ifndef LIBRUSTZCASH_INCLUDE_H_
#define LIBRUSTZCASH_INCLUDE_H_

#include <stdint.h>

struct librustzcash_params {
};

extern "C" {
    uint64_t librustzcash_xor(uint64_t a, uint64_t b);

    /// Initializes some parameters for sapling-crypto,
    /// returning a pointer to the parameters. You should
    /// free this when you're done with 
    /// `librustzcash_init_params()`.
    librustzcash_params* librustzcash_init_params();

    /// Frees some parameters that were previously returned
    /// from `librustzcash_init_params()`. Only call this
    /// once.
    void librustzcash_free_params(librustzcash_params* params);

    /// Computes a merkle tree hash for a given depth.
    /// The `depth` parameter should not be larger than
    /// 62.
    ///
    /// Params must be a valid pointer that was returned
    /// from `librustzcash_init_params()`.
    ///
    /// `a` and `b` each must be of length 32, and must each
    /// be scalars of BLS12-381.
    ///
    /// The result of the merkle tree hash is placed in
    /// `result`, which must also be of length 32.
    void librustzcash_merkle_hash(
        const librustzcash_params* params,
        size_t depth,
        const unsigned char *a,
        const unsigned char *b,
        unsigned char *result
    );
}

#endif // LIBRUSTZCASH_INCLUDE_H_
