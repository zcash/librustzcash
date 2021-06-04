use bellman::gadgets::boolean::Boolean;
use bellman::gadgets::sha256::sha256_block_no_padding;
use bellman::{ConstraintSystem, SynthesisError};
use group::ff::PrimeField;

#[allow(clippy::many_single_char_names)]
fn prf<Scalar, CS>(
    cs: CS,
    a: bool,
    b: bool,
    c: bool,
    d: bool,
    x: &[Boolean],
    y: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(x.len(), 252);
    assert_eq!(y.len(), 256);

    let mut image = vec![
        Boolean::constant(a),
        Boolean::constant(b),
        Boolean::constant(c),
        Boolean::constant(d),
    ];
    image.extend(x.iter().cloned());
    image.extend(y.iter().cloned());

    assert_eq!(image.len(), 512);

    sha256_block_no_padding(cs, &image)
}

pub fn prf_a_pk<Scalar, CS>(cs: CS, a_sk: &[Boolean]) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    prf(
        cs,
        true,
        true,
        false,
        false,
        a_sk,
        &(0..256)
            .map(|_| Boolean::constant(false))
            .collect::<Vec<_>>(),
    )
}

pub fn prf_nf<Scalar, CS>(
    cs: CS,
    a_sk: &[Boolean],
    rho: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    prf(cs, true, true, true, false, a_sk, rho)
}

pub fn prf_pk<Scalar, CS>(
    cs: CS,
    a_sk: &[Boolean],
    h_sig: &[Boolean],
    nonce: bool,
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    prf(cs, false, nonce, false, false, a_sk, h_sig)
}

pub fn prf_rho<Scalar, CS>(
    cs: CS,
    phi: &[Boolean],
    h_sig: &[Boolean],
    nonce: bool,
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    prf(cs, false, nonce, true, false, phi, h_sig)
}
