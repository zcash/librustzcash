#ifndef LIBRUSTZCASH_INCLUDE_H_
#define LIBRUSTZCASH_INCLUDE_H_

#include <stdint.h>

extern "C" {
    void librustzcash_to_scalar(const unsigned char *input, unsigned char *result);

    void librustzcash_ask_to_ak(const unsigned char *ask, unsigned char *result);

    void librustzcash_nsk_to_nk(const unsigned char *nsk, unsigned char *result);

    void librustzcash_crh_ivk(const unsigned char *ak, const unsigned char *nk, unsigned char *result);

    bool librustzcash_check_diversifier(const unsigned char *diversifier);

    bool librustzcash_ivk_to_pkd(const unsigned char *ivk, const unsigned char *diversifier, unsigned char *result);

    /// Loads the zk-SNARK parameters into memory and saves
    /// paths as necessary. Only called once.
    void librustzcash_init_zksnark_params(
        const char* spend_path,
        const char* output_path,
        const char* sprout_path
    );

    /// Validates the provided Equihash solution against
    /// the given parameters, input and nonce.
    bool librustzcash_eh_isvalid(
        uint32_t n,
        uint32_t k,
        const unsigned char* input,
        size_t input_len,
        const unsigned char* nonce,
        size_t nonce_len,
        const unsigned char* soln,
        size_t soln_len
    );

    /// Writes the "uncommitted" note value for empty leaves
    /// of the merkle tree. `result` must be a valid pointer
    /// to 32 bytes which will be written.
    void librustzcash_tree_uncommitted(
        unsigned char *result
    );

    /// Computes a merkle tree hash for a given depth.
    /// The `depth` parameter should not be larger than
    /// 62.
    ///
    /// `a` and `b` each must be of length 32, and must each
    /// be scalars of BLS12-381.
    ///
    /// The result of the merkle tree hash is placed in
    /// `result`, which must also be of length 32.
    void librustzcash_merkle_hash(
        size_t depth,
        const unsigned char *a,
        const unsigned char *b,
        unsigned char *result
    );

    /// Creates a Sapling verification context. Please free this
    /// when you're done.
    void * librustzcash_sapling_verification_ctx_init();

    /// Check the validity of a Sapling Spend description,
    /// accumulating the value commitment into the context.
    bool librustzcash_sapling_check_spend(
        void *ctx,
        const unsigned char *cv,
        const unsigned char *anchor,
        const unsigned char *nullifier,
        const unsigned char *rk,
        const unsigned char *zkproof,
        const unsigned char *spendAuthSig,
        const unsigned char *sighashValue
    );

    /// Check the validity of a Sapling Output description,
    /// accumulating the value commitment into the context.
    bool librustzcash_sapling_check_output(
        void *ctx,
        const unsigned char *cv,
        const unsigned char *cm,
        const unsigned char *ephemeralKey,
        const unsigned char *zkproof
    );

    /// Finally checks the validity of the entire Sapling
    /// transaction given valueBalance and the binding signature.
    bool librustzcash_sapling_final_check(
        void *ctx,
        int64_t valueBalance,
        const unsigned char *bindingSig,
        const unsigned char *sighashValue
    );

    /// Frees a Sapling verification context returned from
    /// `librustzcash_sapling_verification_ctx_init`.
    void librustzcash_sapling_verification_ctx_free(void *);

    /// Compute a Sapling nullifier.
    ///
    /// The `diversifier` parameter must be 11 bytes in length.
    /// The `pk_d`, `r`, `ak` and `nk` parameters must be of length 32.
    /// The result is also of length 32 and placed in `result`.
    /// Returns false if the diversifier or pk_d is not valid
    bool librustzcash_sapling_compute_nf(
        const unsigned char *diversifier,
        const unsigned char *pk_d,
        const uint64_t value,
        const unsigned char *r,
        const unsigned char *ak,
        const unsigned char *nk,
        const uint64_t position,
        unsigned char *result
    );

    /// Compute a Sapling commitment.
    ///
    /// The `diversifier` parameter must be 11 bytes in length.
    /// The `pk_d` and `r` parameters must be of length 32.
    /// The result is also of length 32 and placed in `result`.
    /// Returns false if the diversifier or pk_d is not valid
    bool librustzcash_sapling_compute_cm(
        const unsigned char *diversifier,
        const unsigned char *pk_d,
        const uint64_t value,
        const unsigned char *r,
        unsigned char *result
    );

    /// Generate uniform Sapling commitment randomness `r`.
    /// The result is of length 32.
    void librustzcash_sapling_generate_r(
        unsigned char *result
    );

    /// Sprout JoinSplit proof generation.
    void librustzcash_sprout_prove(
        unsigned char *proof_out,

        const unsigned char *phi,
        const unsigned char *rt,
        const unsigned char *h_sig,

        const unsigned char *in_sk1,
        uint64_t in_value1,
        const unsigned char *in_rho1,
        const unsigned char *in_r1,
        const unsigned char *in_auth1,

        const unsigned char *in_sk2,
        uint64_t in_value2,
        const unsigned char *in_rho2,
        const unsigned char *in_r2,
        const unsigned char *in_auth2,

        const unsigned char *out_pk1,
        uint64_t out_value1,
        const unsigned char *out_r1,

        const unsigned char *out_pk2,
        uint64_t out_value2,
        const unsigned char *out_r2,

        uint64_t vpub_old,
        uint64_t vpub_new
    );

    /// Sprout JoinSplit proof verification.
    bool librustzcash_sprout_verify(
        const unsigned char *proof,
        const unsigned char *rt,
        const unsigned char *h_sig,
        const unsigned char *mac1,
        const unsigned char *mac2,
        const unsigned char *nf1,
        const unsigned char *nf2,
        const unsigned char *cm1,
        const unsigned char *cm2,
        uint64_t vpub_old,
        uint64_t vpub_new
    );
}

#endif // LIBRUSTZCASH_INCLUDE_H_
