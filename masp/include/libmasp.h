#ifndef LIBMASP_INCLUDE_H_
#define LIBMASP_INCLUDE_H_

#include <stdint.h>

#ifdef WIN32
typedef uint16_t codeunit;
#else
typedef uint8_t codeunit;
#endif

#include <stddef.h>

#ifndef __cplusplus
  #include <assert.h>
  #include <stdalign.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

    /// Derives an asset identifier without a starting nonce
    /// Not constant-time as it uses rejection sampling
    bool libmasp_new_asset_identifier(const unsigned char *name, size_t name_length, unsigned char *identifier_result, uint8_t* nonce_result);

    /// Derives an asset identifier
    /// Not yet constant-time; assume not constant-time
    bool libmasp_asset_from_name_and_nonce(const unsigned char *name, size_t name_length, uint8_t nonce, unsigned char *result);

    void libmasp_to_scalar(const unsigned char *input, unsigned char *result);

    void libmasp_ask_to_ak(const unsigned char *ask, unsigned char *result);

    void libmasp_nsk_to_nk(const unsigned char *nsk, unsigned char *result);

    void libmasp_crh_ivk(const unsigned char *ak, const unsigned char *nk, unsigned char *result);

    bool libmasp_check_diversifier(const unsigned char *diversifier);

    bool libmasp_ivk_to_pkd(const unsigned char *ivk, const unsigned char *diversifier, unsigned char *result);

    /// Loads the zk-SNARK parameters into memory and saves
    /// paths as necessary. Only called once.
    void libmasp_init_zksnark_params(
        const codeunit* spend_path,
        size_t spend_path_len,
        const codeunit* output_path,
        size_t output_path_len,
    );

    /// Writes the "uncommitted" note value for empty leaves
    /// of the merkle tree. `result` must be a valid pointer
    /// to 32 bytes which will be written.
    void libmasp_tree_uncommitted(
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
    void libmasp_merkle_hash(
        size_t depth,
        const unsigned char *a,
        const unsigned char *b,
        unsigned char *result
    );

    /// Computes the signature for each Spend description, given the key
    /// `ask`, the re-randomization `ar`, the 32-byte sighash `sighash`,
    /// and an output `result` buffer of 64-bytes for the signature.
    ///
    /// This function will fail if the provided `ask` or `ar` are invalid.
    bool libmasp_sapling_spend_sig(
        const unsigned char *ask,
        const unsigned char *ar,
        const unsigned char *sighash,
        unsigned char *result
    );

    /// Creates a Sapling proving context. Please free this when you're done.
    void * libmasp_sapling_proving_ctx_init();

    /// This function (using the proving context) constructs a Spend proof
    /// given the necessary witness information. It outputs `cv` (the value
    /// commitment) and `rk` (so that you don't have to compute it) along
    /// with the proof.
    bool libmasp_sapling_spend_proof(
        void *ctx,
        const unsigned char *ak,
        const unsigned char *nsk,
        const unsigned char *diversifier,
        const unsigned char *rcm,
        const unsigned char *ar,
        const unsigned char *asset_identifier,
        const uint64_t value,
        const unsigned char *anchor,
        const unsigned char *witness,
        unsigned char *cv,
        unsigned char *rk,
        unsigned char *zkproof
    );

    /// This function (using the proving context) constructs an Output
    /// proof given the necessary witness information. It outputs `cv`
    /// and the `zkproof`.
    bool libmasp_sapling_output_proof(
        void *ctx,
        const unsigned char *esk,
        const unsigned char *payment_address,
        const unsigned char *rcm,
        const unsigned char *asset_identifier,
        const uint64_t value,
        unsigned char *cv,
        unsigned char *zkproof
    );

    /// This function (using the proving context) constructs a binding
    /// signature. You must provide the intended valueBalance so that
    /// we can internally check consistency.
    bool libmasp_sapling_binding_sig(
        const void *ctx,
        const unsigned char *asset_identifiers,
        int64_t *value_balances,
        size_t asset_count,
        const unsigned char *sighash,
        unsigned char *result
    );

    /// Frees a Sapling proving context returned from
    /// `libmasp_sapling_proving_ctx_init`.
    void libmasp_sapling_proving_ctx_free(void *);

    /// Creates a Sapling verification context. Please free this
    /// when you're done.
    void * libmasp_sapling_verification_ctx_init();

    /// Check the validity of a Sapling Spend description,
    /// accumulating the value commitment into the context.
    bool libmasp_sapling_check_spend(
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
    bool libmasp_sapling_check_output(
        void *ctx,
        const unsigned char *cv,
        const unsigned char *cm,
        const unsigned char *ephemeralKey,
        const unsigned char *zkproof
    );

    /// Finally checks the validity of the entire Sapling
    /// transaction given valueBalance and the binding signature.
    bool libmasp_sapling_final_check(
        void *ctx,
        const unsigned char *asset_identifiers,
        int64_t *value_balances,
        size_t asset_count,
        const unsigned char *bindingSig,
        const unsigned char *sighashValue
    );

    /// Frees a Sapling verification context returned from
    /// `libmasp_sapling_verification_ctx_init`.
    void libmasp_sapling_verification_ctx_free(void *);

    /// Compute a Sapling nullifier.
    ///
    /// The `diversifier` parameter must be 11 bytes in length.
    /// The `pk_d`, `r`, `ak` and `nk` parameters must be of length 32.
    /// The result is also of length 32 and placed in `result`.
    /// Returns false if the diversifier or pk_d is not valid
    bool libmasp_sapling_compute_nf(
        const unsigned char *diversifier,
        const unsigned char *pk_d,
        const unsigned char *asset_identifier,
        const uint64_t value,
        const unsigned char *rcm,
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
    bool libmasp_sapling_compute_cmu(
        const unsigned char *diversifier,
        const unsigned char *pk_d,
        const unsigned char *asset_identifier,
        const uint64_t value,
        const unsigned char *rcm,
        unsigned char *result
    );

    /// Compute [sk] [8] P for some 32-byte
    /// point P, and 32-byte Fs. If P or sk
    /// are invalid, returns false. Otherwise,
    /// the result is written to the 32-byte
    /// `result` buffer.
    bool libmasp_sapling_ka_agree(
        const unsigned char *p,
        const unsigned char *sk,
        unsigned char *result
    );

    /// Compute g_d = GH(diversifier) and returns
    /// false if the diversifier is invalid.
    /// Computes [esk] g_d and writes the result
    /// to the 32-byte `result` buffer. Returns
    /// false if `esk` is not a valid scalar.
    bool libmasp_sapling_ka_derivepublic(
        const unsigned char *diversifier,
        const unsigned char *esk,
        unsigned char *result
    );

    /// Generate uniformly random scalar in Jubjub.
    /// The result is of length 32.
    void libmasp_sapling_generate_r(
        unsigned char *result
    );

    /// Derive the master ExtendedSpendingKey from a seed.
    void libmasp_zip32_xsk_master(
        const unsigned char *seed,
        size_t seedlen,
        unsigned char *xsk_master
    );

    /// Derive a child ExtendedSpendingKey from a parent.
    void libmasp_zip32_xsk_derive(
        const unsigned char *xsk_parent,
        uint32_t i,
        unsigned char *xsk_i
    );

    /// Derive a child ExtendedFullViewingKey from a parent.
    bool libmasp_zip32_xfvk_derive(
        const unsigned char *xfvk_parent,
        uint32_t i,
        unsigned char *xfvk_i
    );

    /// Derive a PaymentAddress from an ExtendedFullViewingKey.
    bool libmasp_zip32_xfvk_address(
        const unsigned char *xfvk,
        const unsigned char *j,
        unsigned char *j_ret,
        unsigned char *addr_ret
    );

#ifdef __cplusplus
}
#endif

#endif // LIBMASP_INCLUDE_H_
