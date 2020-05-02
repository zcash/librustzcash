#![recursion_limit = "1024"]

extern crate proc_macro;
extern crate proc_macro2;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use quote::quote;
use quote::TokenStreamExt;
use std::iter;
use std::str::FromStr;

mod pow_fixed;

enum ReprEndianness {
    Big,
    Little,
}

impl FromStr for ReprEndianness {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "big" => Ok(ReprEndianness::Big),
            "little" => Ok(ReprEndianness::Little),
            _ => Err(()),
        }
    }
}

impl ReprEndianness {
    fn repr_endianness(&self) -> proc_macro2::TokenStream {
        match self {
            ReprEndianness::Big => quote! {::byteorder::BigEndian},
            ReprEndianness::Little => quote! {::byteorder::LittleEndian},
        }
    }

    fn modulus_repr(&self, modulus: &BigUint, bytes: usize) -> Vec<u8> {
        match self {
            ReprEndianness::Big => {
                let buf = modulus.to_bytes_be();
                iter::repeat(0)
                    .take(bytes - buf.len())
                    .chain(buf.into_iter())
                    .collect()
            }
            ReprEndianness::Little => {
                let mut buf = modulus.to_bytes_le();
                buf.extend(iter::repeat(0).take(bytes - buf.len()));
                buf
            }
        }
    }

    fn from_repr(&self, name: &syn::Ident, limbs: usize) -> proc_macro2::TokenStream {
        let read_repr = match self {
            ReprEndianness::Big => quote! {
                ::byteorder::BigEndian::read_u64_into(r.as_ref(), &mut inner[..]);
                inner.reverse();
            },
            ReprEndianness::Little => quote! {
                ::byteorder::LittleEndian::read_u64_into(r.as_ref(), &mut inner[..]);
            },
        };

        quote! {
            use ::byteorder::ByteOrder;

            let r = {
                let mut inner = [0u64; #limbs];
                #read_repr
                #name(inner)
            };

            if r.is_valid() {
                Some(r * R2)
            } else {
                None
            }
        }
    }

    fn to_repr(
        &self,
        repr: &syn::Ident,
        mont_reduce_self_params: &proc_macro2::TokenStream,
        limbs: usize,
    ) -> proc_macro2::TokenStream {
        let bytes = limbs * 8;

        let write_repr = match self {
            ReprEndianness::Big => quote! {
                r.0.reverse();
                ::byteorder::BigEndian::write_u64_into(&r.0, &mut repr[..]);
            },
            ReprEndianness::Little => quote! {
                ::byteorder::LittleEndian::write_u64_into(&r.0, &mut repr[..]);
            },
        };

        quote! {
            use ::byteorder::ByteOrder;

            let mut r = *self;
            r.mont_reduce(
                #mont_reduce_self_params
            );

            let mut repr = [0u8; #bytes];
            #write_repr
            #repr(repr)
        }
    }

    fn iter_be(&self) -> proc_macro2::TokenStream {
        match self {
            ReprEndianness::Big => quote! {self.0.iter()},
            ReprEndianness::Little => quote! {self.0.iter().rev()},
        }
    }
}

#[proc_macro_derive(
    PrimeField,
    attributes(PrimeFieldModulus, PrimeFieldGenerator, PrimeFieldReprEndianness)
)]
pub fn prime_field(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Parse the type definition
    let ast: syn::DeriveInput = syn::parse(input).unwrap();

    // We're given the modulus p of the prime field
    let modulus: BigUint = fetch_attr("PrimeFieldModulus", &ast.attrs)
        .expect("Please supply a PrimeFieldModulus attribute")
        .parse()
        .expect("PrimeFieldModulus should be a number");

    // We may be provided with a generator of p - 1 order. It is required that this generator be quadratic
    // nonresidue.
    // TODO: Compute this ourselves.
    let generator: BigUint = fetch_attr("PrimeFieldGenerator", &ast.attrs)
        .expect("Please supply a PrimeFieldGenerator attribute")
        .parse()
        .expect("PrimeFieldGenerator should be a number");

    // Field element representations may be in little-endian or big-endian.
    let endianness = fetch_attr("PrimeFieldReprEndianness", &ast.attrs)
        .expect("Please supply a PrimeFieldReprEndianness attribute")
        .parse()
        .expect("PrimeFieldReprEndianness should be 'big' or 'little'");

    // The arithmetic in this library only works if the modulus*2 is smaller than the backing
    // representation. Compute the number of limbs we need.
    let mut limbs = 1;
    {
        let mod2 = (&modulus) << 1; // modulus * 2
        let mut cur = BigUint::one() << 64; // always 64-bit limbs for now
        while cur < mod2 {
            limbs += 1;
            cur <<= 64;
        }
    }

    // The struct we're deriving for must be a wrapper around `pub [u64; limbs]`.
    if let Some(err) = validate_struct(&ast, limbs) {
        return err.into();
    }

    // Generate the identifier for the "Repr" type we must construct.
    let repr_ident = syn::Ident::new(
        &format!("{}Repr", ast.ident),
        proc_macro2::Span::call_site(),
    );

    let mut gen = proc_macro2::TokenStream::new();

    let (constants_impl, sqrt_impl) = prime_field_constants_and_sqrt(
        &ast.ident,
        &repr_ident,
        &modulus,
        &endianness,
        limbs,
        generator,
    );

    gen.extend(constants_impl);
    gen.extend(prime_field_repr_impl(&repr_ident, &endianness, limbs * 8));
    gen.extend(prime_field_impl(
        &ast.ident,
        &repr_ident,
        &modulus,
        &endianness,
        limbs,
        sqrt_impl,
    ));

    // Return the generated impl
    gen.into()
}

/// Checks that `body` contains `pub [u64; limbs]`.
fn validate_struct(ast: &syn::DeriveInput, limbs: usize) -> Option<proc_macro2::TokenStream> {
    // The body should be a struct.
    let variant_data = match &ast.data {
        syn::Data::Struct(x) => x,
        _ => {
            return Some(
                syn::Error::new_spanned(ast, "PrimeField derive only works for structs.")
                    .to_compile_error(),
            )
        }
    };

    // The struct should contain a single unnamed field.
    let fields = match &variant_data.fields {
        syn::Fields::Unnamed(x) if x.unnamed.len() == 1 => x,
        _ => {
            return Some(
                syn::Error::new_spanned(
                    &ast.ident,
                    format!(
                        "The struct must contain an array of limbs. Change this to `{}([u64; {}])`",
                        ast.ident, limbs,
                    ),
                )
                .to_compile_error(),
            )
        }
    };
    let field = &fields.unnamed[0];

    // The field should be an array.
    let arr = match &field.ty {
        syn::Type::Array(x) => x,
        _ => {
            return Some(
                syn::Error::new_spanned(
                    field,
                    format!(
                        "The inner field must be an array of limbs. Change this to `[u64; {}]`",
                        limbs,
                    ),
                )
                .to_compile_error(),
            )
        }
    };

    // The array's element type should be `u64`.
    if match arr.elem.as_ref() {
        syn::Type::Path(path) => path
            .path
            .get_ident()
            .map(|x| x.to_string() != "u64")
            .unwrap_or(true),
        _ => true,
    } {
        return Some(
            syn::Error::new_spanned(
                arr,
                format!(
                    "PrimeField derive requires 64-bit limbs. Change this to `[u64; {}]",
                    limbs
                ),
            )
            .to_compile_error(),
        );
    }

    // The array's length should be a literal int equal to `limbs`.
    let lit_int = match match &arr.len {
        syn::Expr::Lit(expr_lit) => match &expr_lit.lit {
            syn::Lit::Int(lit_int) => Some(lit_int),
            _ => None,
        },
        _ => None,
    } {
        Some(x) => x,
        _ => {
            return Some(
                syn::Error::new_spanned(
                    arr,
                    format!("To derive PrimeField, change this to `[u64; {}]`.", limbs),
                )
                .to_compile_error(),
            )
        }
    };
    if lit_int.base10_digits() != limbs.to_string() {
        return Some(
            syn::Error::new_spanned(
                lit_int,
                format!("The given modulus requires {} limbs.", limbs),
            )
            .to_compile_error(),
        );
    }

    // The field should not be public.
    match &field.vis {
        syn::Visibility::Inherited => (),
        _ => {
            return Some(
                syn::Error::new_spanned(&field.vis, "Field must not be public.").to_compile_error(),
            )
        }
    }

    // Valid!
    None
}

/// Fetch an attribute string from the derived struct.
fn fetch_attr(name: &str, attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if let Ok(meta) = attr.parse_meta() {
            match meta {
                syn::Meta::NameValue(nv) => {
                    if nv.path.get_ident().map(|i| i.to_string()) == Some(name.to_string()) {
                        match nv.lit {
                            syn::Lit::Str(ref s) => return Some(s.value()),
                            _ => {
                                panic!("attribute {} should be a string", name);
                            }
                        }
                    }
                }
                _ => {
                    panic!("attribute {} should be a string", name);
                }
            }
        }
    }

    None
}

// Implement the wrapped ident `repr` with `bytes` bytes.
fn prime_field_repr_impl(
    repr: &syn::Ident,
    endianness: &ReprEndianness,
    bytes: usize,
) -> proc_macro2::TokenStream {
    let repr_iter_be = endianness.iter_be();

    quote! {
        #[derive(Copy, Clone)]
        pub struct #repr(pub [u8; #bytes]);

        impl ::subtle::ConstantTimeEq for #repr {
            fn ct_eq(&self, other: &#repr) -> ::subtle::Choice {
                self.0
                    .iter()
                    .zip(other.0.iter())
                    .map(|(a, b)| a.ct_eq(b))
                    .fold(1.into(), |acc, x| acc & x)
            }
        }

        impl ::core::cmp::PartialEq for #repr {
            fn eq(&self, other: &#repr) -> bool {
                use ::subtle::ConstantTimeEq;
                self.ct_eq(other).into()
            }
        }

        impl ::core::cmp::Eq for #repr { }

        impl ::core::default::Default for #repr {
            fn default() -> #repr {
                #repr([0u8; #bytes])
            }
        }

        impl ::core::fmt::Debug for #repr
        {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "0x")?;
                for i in #repr_iter_be {
                    write!(f, "{:02x}", *i)?;
                }

                Ok(())
            }
        }

        impl ::core::fmt::Display for #repr {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "0x")?;
                for i in #repr_iter_be {
                    write!(f, "{:02x}", *i)?;
                }

                Ok(())
            }
        }

        impl AsRef<[u8]> for #repr {
            #[inline(always)]
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsMut<[u8]> for #repr {
            #[inline(always)]
            fn as_mut(&mut self) -> &mut [u8] {
                &mut self.0
            }
        }
    }
}

/// Convert BigUint into a vector of 64-bit limbs.
fn biguint_to_real_u64_vec(mut v: BigUint, limbs: usize) -> Vec<u64> {
    let m = BigUint::one() << 64;
    let mut ret = vec![];

    while v > BigUint::zero() {
        ret.push((&v % &m).to_u64().unwrap());
        v >>= 64;
    }

    while ret.len() < limbs {
        ret.push(0);
    }

    assert!(ret.len() == limbs);

    ret
}

/// Convert BigUint into a tokenized vector of 64-bit limbs.
fn biguint_to_u64_vec(v: BigUint, limbs: usize) -> proc_macro2::TokenStream {
    let ret = biguint_to_real_u64_vec(v, limbs);
    quote!([#(#ret,)*])
}

fn biguint_num_bits(mut v: BigUint) -> u32 {
    let mut bits = 0;

    while v != BigUint::zero() {
        v >>= 1;
        bits += 1;
    }

    bits
}

/// BigUint modular exponentiation by square-and-multiply.
fn exp(base: BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    let mut ret = BigUint::one();

    for i in exp
        .to_bytes_be()
        .into_iter()
        .flat_map(|x| (0..8).rev().map(move |i| (x >> i).is_odd()))
    {
        ret = (&ret * &ret) % modulus;
        if i {
            ret = (ret * &base) % modulus;
        }
    }

    ret
}

#[test]
fn test_exp() {
    assert_eq!(
        exp(
            BigUint::from_str("4398572349857239485729348572983472345").unwrap(),
            &BigUint::from_str("5489673498567349856734895").unwrap(),
            &BigUint::from_str(
                "52435875175126190479447740508185965837690552500527637822603658699938581184513"
            )
            .unwrap()
        ),
        BigUint::from_str(
            "4371221214068404307866768905142520595925044802278091865033317963560480051536"
        )
        .unwrap()
    );
}

fn prime_field_constants_and_sqrt(
    name: &syn::Ident,
    repr: &syn::Ident,
    modulus: &BigUint,
    endianness: &ReprEndianness,
    limbs: usize,
    generator: BigUint,
) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
    let modulus_num_bits = biguint_num_bits(modulus.clone());

    // The number of bits we should "shave" from a randomly sampled reputation, i.e.,
    // if our modulus is 381 bits and our representation is 384 bits, we should shave
    // 3 bits from the beginning of a randomly sampled 384 bit representation to
    // reduce the cost of rejection sampling.
    let repr_shave_bits = (64 * limbs as u32) - biguint_num_bits(modulus.clone());

    // Compute R = 2**(64 * limbs) mod m
    let r = (BigUint::one() << (limbs * 64)) % modulus;

    // modulus - 1 = 2^s * t
    let mut s: u32 = 0;
    let mut t = modulus - BigUint::from_str("1").unwrap();
    while t.is_even() {
        t >>= 1;
        s += 1;
    }

    // Compute 2^s root of unity given the generator
    let root_of_unity =
        biguint_to_u64_vec((exp(generator.clone(), &t, &modulus) * &r) % modulus, limbs);
    let generator = biguint_to_u64_vec((generator.clone() * &r) % modulus, limbs);

    let sqrt_impl =
        if (modulus % BigUint::from_str("4").unwrap()) == BigUint::from_str("3").unwrap() {
            // Addition chain for (r + 1) // 4
            let mod_plus_1_over_4 = pow_fixed::generate(
                &quote! {self},
                (modulus + BigUint::from_str("1").unwrap()) >> 2,
            );

            quote! {
                use ::subtle::ConstantTimeEq;

                // Because r = 3 (mod 4)
                // sqrt can be done with only one exponentiation,
                // via the computation of  self^((r + 1) // 4) (mod r)
                let sqrt = {
                    #mod_plus_1_over_4
                };

                ::subtle::CtOption::new(
                    sqrt,
                    (sqrt * &sqrt).ct_eq(self), // Only return Some if it's the square root.
                )
            }
        } else if (modulus % BigUint::from_str("16").unwrap()) == BigUint::from_str("1").unwrap() {
            // Addition chain for (t - 1) // 2
            let t_minus_1_over_2 = pow_fixed::generate(&quote! {self}, (&t - BigUint::one()) >> 1);

            quote! {
                // Tonelli-Shank's algorithm for q mod 16 = 1
                // https://eprint.iacr.org/2012/685.pdf (page 12, algorithm 5)
                use ::subtle::{ConditionallySelectable, ConstantTimeEq};

                // w = self^((t - 1) // 2)
                let w = {
                    #t_minus_1_over_2
                };

                let mut v = S;
                let mut x = *self * &w;
                let mut b = x * &w;

                // Initialize z as the 2^S root of unity.
                let mut z = ROOT_OF_UNITY;

                for max_v in (1..=S).rev() {
                    let mut k = 1;
                    let mut tmp = b.square();
                    let mut j_less_than_v: ::subtle::Choice = 1.into();

                    for j in 2..max_v {
                        let tmp_is_one = tmp.ct_eq(&#name::one());
                        let squared = #name::conditional_select(&tmp, &z, tmp_is_one).square();
                        tmp = #name::conditional_select(&squared, &tmp, tmp_is_one);
                        let new_z = #name::conditional_select(&z, &squared, tmp_is_one);
                        j_less_than_v &= !j.ct_eq(&v);
                        k = u32::conditional_select(&j, &k, tmp_is_one);
                        z = #name::conditional_select(&z, &new_z, j_less_than_v);
                    }

                    let result = x * &z;
                    x = #name::conditional_select(&result, &x, b.ct_eq(&#name::one()));
                    z = z.square();
                    b *= &z;
                    v = k;
                }

                ::subtle::CtOption::new(
                    x,
                    (x * &x).ct_eq(self), // Only return Some if it's the square root.
                )
            }
        } else {
            syn::Error::new_spanned(
                &name,
                "ff_derive can't generate a square root function for this field.",
            )
            .to_compile_error()
        };

    // Compute R^2 mod m
    let r2 = biguint_to_u64_vec((&r * &r) % modulus, limbs);

    let r = biguint_to_u64_vec(r, limbs);
    let modulus_repr = endianness.modulus_repr(modulus, limbs * 8);
    let modulus = biguint_to_real_u64_vec(modulus.clone(), limbs);

    // Compute -m^-1 mod 2**64 by exponentiating by totient(2**64) - 1
    let mut inv = 1u64;
    for _ in 0..63 {
        inv = inv.wrapping_mul(inv);
        inv = inv.wrapping_mul(modulus[0]);
    }
    inv = inv.wrapping_neg();

    (
        quote! {
            /// This is the modulus m of the prime field
            const MODULUS: #repr = #repr([#(#modulus_repr,)*]);

            /// This is the modulus m of the prime field in limb form
            const MODULUS_LIMBS: #name = #name([#(#modulus,)*]);

            /// The number of bits needed to represent the modulus.
            const MODULUS_BITS: u32 = #modulus_num_bits;

            /// The number of bits that must be shaved from the beginning of
            /// the representation when randomly sampling.
            const REPR_SHAVE_BITS: u32 = #repr_shave_bits;

            /// 2^{limbs*64} mod m
            const R: #name = #name(#r);

            /// 2^{limbs*64*2} mod m
            const R2: #name = #name(#r2);

            /// -(m^{-1} mod m) mod m
            const INV: u64 = #inv;

            /// Multiplicative generator of `MODULUS` - 1 order, also quadratic
            /// nonresidue.
            const GENERATOR: #name = #name(#generator);

            /// 2^s * t = MODULUS - 1 with t odd
            const S: u32 = #s;

            /// 2^s root of unity computed by GENERATOR^t
            const ROOT_OF_UNITY: #name = #name(#root_of_unity);
        },
        sqrt_impl,
    )
}

/// Implement PrimeField for the derived type.
fn prime_field_impl(
    name: &syn::Ident,
    repr: &syn::Ident,
    modulus: &BigUint,
    endianness: &ReprEndianness,
    limbs: usize,
    sqrt_impl: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    // Returns r{n} as an ident.
    fn get_temp(n: usize) -> syn::Ident {
        syn::Ident::new(&format!("r{}", n), proc_macro2::Span::call_site())
    }

    // The parameter list for the mont_reduce() internal method.
    // r0: u64, mut r1: u64, mut r2: u64, ...
    let mut mont_paramlist = proc_macro2::TokenStream::new();
    mont_paramlist.append_separated(
        (0..(limbs * 2)).map(|i| (i, get_temp(i))).map(|(i, x)| {
            if i != 0 {
                quote! {mut #x: u64}
            } else {
                quote! {#x: u64}
            }
        }),
        proc_macro2::Punct::new(',', proc_macro2::Spacing::Alone),
    );

    // Implement montgomery reduction for some number of limbs
    fn mont_impl(limbs: usize) -> proc_macro2::TokenStream {
        let mut gen = proc_macro2::TokenStream::new();

        for i in 0..limbs {
            {
                let temp = get_temp(i);
                gen.extend(quote! {
                    let k = #temp.wrapping_mul(INV);
                    let mut carry = 0;
                    ::ff::mac_with_carry(#temp, k, MODULUS_LIMBS.0[0], &mut carry);
                });
            }

            for j in 1..limbs {
                let temp = get_temp(i + j);
                gen.extend(quote! {
                    #temp = ::ff::mac_with_carry(#temp, k, MODULUS_LIMBS.0[#j], &mut carry);
                });
            }

            let temp = get_temp(i + limbs);

            if i == 0 {
                gen.extend(quote! {
                    #temp = ::ff::adc(#temp, 0, &mut carry);
                });
            } else {
                gen.extend(quote! {
                    #temp = ::ff::adc(#temp, carry2, &mut carry);
                });
            }

            if i != (limbs - 1) {
                gen.extend(quote! {
                    let carry2 = carry;
                });
            }
        }

        for i in 0..limbs {
            let temp = get_temp(limbs + i);

            gen.extend(quote! {
                self.0[#i] = #temp;
            });
        }

        gen
    }

    fn sqr_impl(a: proc_macro2::TokenStream, limbs: usize) -> proc_macro2::TokenStream {
        let mut gen = proc_macro2::TokenStream::new();

        for i in 0..(limbs - 1) {
            gen.extend(quote! {
                let mut carry = 0;
            });

            for j in (i + 1)..limbs {
                let temp = get_temp(i + j);
                if i == 0 {
                    gen.extend(quote! {
                        let #temp = ::ff::mac_with_carry(0, #a.0[#i], #a.0[#j], &mut carry);
                    });
                } else {
                    gen.extend(quote! {
                        let #temp = ::ff::mac_with_carry(#temp, #a.0[#i], #a.0[#j], &mut carry);
                    });
                }
            }

            let temp = get_temp(i + limbs);

            gen.extend(quote! {
                let #temp = carry;
            });
        }

        for i in 1..(limbs * 2) {
            let temp0 = get_temp(limbs * 2 - i);
            let temp1 = get_temp(limbs * 2 - i - 1);

            if i == 1 {
                gen.extend(quote! {
                    let #temp0 = #temp1 >> 63;
                });
            } else if i == (limbs * 2 - 1) {
                gen.extend(quote! {
                    let #temp0 = #temp0 << 1;
                });
            } else {
                gen.extend(quote! {
                    let #temp0 = (#temp0 << 1) | (#temp1 >> 63);
                });
            }
        }

        gen.extend(quote! {
            let mut carry = 0;
        });

        for i in 0..limbs {
            let temp0 = get_temp(i * 2);
            let temp1 = get_temp(i * 2 + 1);
            if i == 0 {
                gen.extend(quote! {
                    let #temp0 = ::ff::mac_with_carry(0, #a.0[#i], #a.0[#i], &mut carry);
                });
            } else {
                gen.extend(quote! {
                    let #temp0 = ::ff::mac_with_carry(#temp0, #a.0[#i], #a.0[#i], &mut carry);
                });
            }

            gen.extend(quote! {
                let #temp1 = ::ff::adc(#temp1, 0, &mut carry);
            });
        }

        let mut mont_calling = proc_macro2::TokenStream::new();
        mont_calling.append_separated(
            (0..(limbs * 2)).map(get_temp),
            proc_macro2::Punct::new(',', proc_macro2::Spacing::Alone),
        );

        gen.extend(quote! {
            let mut ret = *self;
            ret.mont_reduce(#mont_calling);
            ret
        });

        gen
    }

    fn mul_impl(
        a: proc_macro2::TokenStream,
        b: proc_macro2::TokenStream,
        limbs: usize,
    ) -> proc_macro2::TokenStream {
        let mut gen = proc_macro2::TokenStream::new();

        for i in 0..limbs {
            gen.extend(quote! {
                let mut carry = 0;
            });

            for j in 0..limbs {
                let temp = get_temp(i + j);

                if i == 0 {
                    gen.extend(quote! {
                        let #temp = ::ff::mac_with_carry(0, #a.0[#i], #b.0[#j], &mut carry);
                    });
                } else {
                    gen.extend(quote! {
                        let #temp = ::ff::mac_with_carry(#temp, #a.0[#i], #b.0[#j], &mut carry);
                    });
                }
            }

            let temp = get_temp(i + limbs);

            gen.extend(quote! {
                let #temp = carry;
            });
        }

        let mut mont_calling = proc_macro2::TokenStream::new();
        mont_calling.append_separated(
            (0..(limbs * 2)).map(get_temp),
            proc_macro2::Punct::new(',', proc_macro2::Spacing::Alone),
        );

        gen.extend(quote! {
            self.mont_reduce(#mont_calling);
        });

        gen
    }

    /// Generates an implementation of multiplicative inversion within the target prime
    /// field.
    fn inv_impl(
        a: proc_macro2::TokenStream,
        name: &syn::Ident,
        modulus: &BigUint,
    ) -> proc_macro2::TokenStream {
        // Addition chain for p - 2
        let mod_minus_2 = pow_fixed::generate(&a, modulus - BigUint::from(2u64));

        quote! {
            use ::subtle::ConstantTimeEq;

            // By Euler's theorem, if `a` is coprime to `p` (i.e. `gcd(a, p) = 1`), then:
            //     a^-1 ≡ a^(phi(p) - 1) mod p
            //
            // `ff_derive` requires that `p` is prime; in this case, `phi(p) = p - 1`, and
            // thus:
            //     a^-1 ≡ a^(p - 2) mod p
            let inv = {
                #mod_minus_2
            };

            ::subtle::CtOption::new(inv, !#a.ct_eq(&#name::zero()))
        }
    }

    let squaring_impl = sqr_impl(quote! {self}, limbs);
    let multiply_impl = mul_impl(quote! {self}, quote! {other}, limbs);
    let invert_impl = inv_impl(quote! {self}, name, modulus);
    let montgomery_impl = mont_impl(limbs);

    // self.0[0].ct_eq(&other.0[0]) & self.0[1].ct_eq(&other.0[1]) & ...
    let mut ct_eq_impl = proc_macro2::TokenStream::new();
    ct_eq_impl.append_separated(
        (0..limbs).map(|i| quote! { self.0[#i].ct_eq(&other.0[#i]) }),
        proc_macro2::Punct::new('&', proc_macro2::Spacing::Alone),
    );

    fn mont_reduce_params(a: proc_macro2::TokenStream, limbs: usize) -> proc_macro2::TokenStream {
        // a.0[0], a.0[1], ..., 0, 0, 0, 0, ...
        let mut mont_reduce_params = proc_macro2::TokenStream::new();
        mont_reduce_params.append_separated(
            (0..limbs)
                .map(|i| quote! { #a.0[#i] })
                .chain((0..limbs).map(|_| quote! {0})),
            proc_macro2::Punct::new(',', proc_macro2::Spacing::Alone),
        );
        mont_reduce_params
    }

    let mont_reduce_self_params = mont_reduce_params(quote! {self}, limbs);
    let mont_reduce_other_params = mont_reduce_params(quote! {other}, limbs);

    let repr_endianness = endianness.repr_endianness();
    let from_repr_impl = endianness.from_repr(name, limbs);
    let to_repr_impl = endianness.to_repr(repr, &mont_reduce_self_params, limbs);

    let top_limb_index = limbs - 1;

    quote! {
        impl ::core::marker::Copy for #name { }

        impl ::core::clone::Clone for #name {
            fn clone(&self) -> #name {
                *self
            }
        }

        impl ::core::default::Default for #name {
            fn default() -> #name {
                #name::zero()
            }
        }

        impl ::subtle::ConstantTimeEq for #name {
            fn ct_eq(&self, other: &#name) -> ::subtle::Choice {
                self.to_repr().ct_eq(&other.to_repr())
            }
        }

        impl ::core::cmp::PartialEq for #name {
            fn eq(&self, other: &#name) -> bool {
                use ::subtle::ConstantTimeEq;
                self.ct_eq(other).into()
            }
        }

        impl ::core::cmp::Eq for #name { }

        impl ::core::fmt::Debug for #name
        {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "{}({:?})", stringify!(#name), self.to_repr())
            }
        }

        /// Elements are ordered lexicographically.
        impl Ord for #name {
            #[inline(always)]
            fn cmp(&self, other: &#name) -> ::core::cmp::Ordering {
                let mut a = *self;
                a.mont_reduce(
                    #mont_reduce_self_params
                );

                let mut b = *other;
                b.mont_reduce(
                    #mont_reduce_other_params
                );

                a.cmp_native(&b)
            }
        }

        impl PartialOrd for #name {
            #[inline(always)]
            fn partial_cmp(&self, other: &#name) -> Option<::core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl ::core::fmt::Display for #name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "{}({})", stringify!(#name), self.to_repr())
            }
        }

        impl From<u64> for #name {
            #[inline(always)]
            fn from(val: u64) -> #name {
                let mut raw = [0u64; #limbs];
                raw[0] = val;
                #name(raw) * R2
            }
        }

        impl From<#name> for #repr {
            fn from(e: #name) -> #repr {
                e.to_repr()
            }
        }

        impl<'a> From<&'a #name> for #repr {
            fn from(e: &'a #name) -> #repr {
                e.to_repr()
            }
        }

        impl ::subtle::ConditionallySelectable for #name {
            fn conditional_select(a: &#name, b: &#name, choice: ::subtle::Choice) -> #name {
                let mut res = [0u64; #limbs];
                for i in 0..#limbs {
                    res[i] = u64::conditional_select(&a.0[i], &b.0[i], choice);
                }
                #name(res)
            }
        }

        impl ::core::ops::Neg for #name {
            type Output = #name;

            #[inline]
            fn neg(self) -> #name {
                let mut ret = self;
                if !ret.is_zero() {
                    let mut tmp = MODULUS_LIMBS;
                    tmp.sub_noborrow(&ret);
                    ret = tmp;
                }
                ret
            }
        }

        impl<'r> ::core::ops::Add<&'r #name> for #name {
            type Output = #name;

            #[inline]
            fn add(self, other: &#name) -> #name {
                let mut ret = self;
                ret.add_assign(other);
                ret
            }
        }

        impl ::core::ops::Add for #name {
            type Output = #name;

            #[inline]
            fn add(self, other: #name) -> Self {
                self + &other
            }
        }

        impl<'r> ::core::ops::AddAssign<&'r #name> for #name {
            #[inline]
            fn add_assign(&mut self, other: &#name) {
                // This cannot exceed the backing capacity.
                self.add_nocarry(other);

                // However, it may need to be reduced.
                self.reduce();
            }
        }

        impl ::core::ops::AddAssign for #name {
            #[inline]
            fn add_assign(&mut self, other: #name) {
                self.add_assign(&other);
            }
        }

        impl<'r> ::core::ops::Sub<&'r #name> for #name {
            type Output = #name;

            #[inline]
            fn sub(self, other: &#name) -> Self {
                let mut ret = self;
                ret.sub_assign(other);
                ret
            }
        }

        impl ::core::ops::Sub for #name {
            type Output = #name;

            #[inline]
            fn sub(self, other: #name) -> Self {
                self - &other
            }
        }

        impl<'r> ::core::ops::SubAssign<&'r #name> for #name {
            #[inline]
            fn sub_assign(&mut self, other: &#name) {
                // If `other` is larger than `self`, we'll need to add the modulus to self first.
                if other.cmp_native(self) == ::core::cmp::Ordering::Greater {
                    self.add_nocarry(&MODULUS_LIMBS);
                }

                self.sub_noborrow(other);
            }
        }

        impl ::core::ops::SubAssign for #name {
            #[inline]
            fn sub_assign(&mut self, other: #name) {
                self.sub_assign(&other);
            }
        }

        impl<'r> ::core::ops::Mul<&'r #name> for #name {
            type Output = #name;

            #[inline]
            fn mul(self, other: &#name) -> Self {
                let mut ret = self;
                ret.mul_assign(other);
                ret
            }
        }

        impl ::core::ops::Mul for #name {
            type Output = #name;

            #[inline]
            fn mul(self, other: #name) -> Self {
                self * &other
            }
        }

        impl<'r> ::core::ops::MulAssign<&'r #name> for #name {
            #[inline]
            fn mul_assign(&mut self, other: &#name)
            {
                #multiply_impl
            }
        }

        impl ::core::ops::MulAssign for #name {
            #[inline]
            fn mul_assign(&mut self, other: #name)
            {
                self.mul_assign(&other);
            }
        }

        impl ::ff::PrimeField for #name {
            type Repr = #repr;
            type ReprEndianness = #repr_endianness;

            fn from_repr(r: #repr) -> Option<#name> {
                #from_repr_impl
            }

            fn to_repr(&self) -> #repr {
                #to_repr_impl
            }

            #[inline(always)]
            fn is_odd(&self) -> bool {
                let mut r = *self;
                r.mont_reduce(
                    #mont_reduce_self_params
                );

                r.0[0] & 1 == 1
            }

            fn char() -> Self::Repr {
                MODULUS
            }

            const NUM_BITS: u32 = MODULUS_BITS;

            const CAPACITY: u32 = Self::NUM_BITS - 1;

            fn multiplicative_generator() -> Self {
                GENERATOR
            }

            const S: u32 = S;

            fn root_of_unity() -> Self {
                ROOT_OF_UNITY
            }
        }

        impl ::ff::Field for #name {
            /// Computes a uniformly random element using rejection sampling.
            fn random<R: ::rand_core::RngCore + ?std::marker::Sized>(rng: &mut R) -> Self {
                loop {
                    let mut tmp = {
                        let mut repr = [0u64; #limbs];
                        for i in 0..#limbs {
                            repr[i] = rng.next_u64();
                        }
                        #name(repr)
                    };

                    // Mask away the unused most-significant bits.
                    tmp.0.as_mut()[#top_limb_index] &= 0xffffffffffffffff >> REPR_SHAVE_BITS;

                    if tmp.is_valid() {
                        return tmp
                    }
                }
            }

            #[inline]
            fn zero() -> Self {
                #name([0; #limbs])
            }

            #[inline]
            fn one() -> Self {
                R
            }

            #[inline]
            fn is_zero(&self) -> bool {
                self.0.iter().all(|&e| e == 0)
            }

            #[inline]
            fn double(&self) -> Self {
                let mut ret = *self;

                // This cannot exceed the backing capacity.
                let mut last = 0;
                for i in &mut ret.0 {
                    let tmp = *i >> 63;
                    *i <<= 1;
                    *i |= last;
                    last = tmp;
                }

                // However, it may need to be reduced.
                ret.reduce();

                ret
            }

            fn invert(&self) -> ::subtle::CtOption<Self> {
                #invert_impl
            }

            #[inline]
            fn square(&self) -> Self
            {
                #squaring_impl
            }

            fn sqrt(&self) -> ::subtle::CtOption<Self> {
                #sqrt_impl
            }
        }

        impl #name {
            /// Compares two elements in native representation. This is only used
            /// internally.
            #[inline(always)]
            fn cmp_native(&self, other: &#name) -> ::core::cmp::Ordering {
                for (a, b) in self.0.iter().rev().zip(other.0.iter().rev()) {
                    if a < b {
                        return ::core::cmp::Ordering::Less
                    } else if a > b {
                        return ::core::cmp::Ordering::Greater
                    }
                }

                ::core::cmp::Ordering::Equal
            }

            /// Determines if the element is really in the field. This is only used
            /// internally.
            #[inline(always)]
            fn is_valid(&self) -> bool {
                // The Ord impl calls `reduce`, which in turn calls `is_valid`, so we use
                // this internal function to eliminate the cycle.
                self.cmp_native(&MODULUS_LIMBS) == ::core::cmp::Ordering::Less
            }

            #[inline(always)]
            fn add_nocarry(&mut self, other: &#name) {
                let mut carry = 0;

                for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
                    *a = ::ff::adc(*a, *b, &mut carry);
                }
            }

            #[inline(always)]
            fn sub_noborrow(&mut self, other: &#name) {
                let mut borrow = 0;

                for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
                    *a = ::ff::sbb(*a, *b, &mut borrow);
                }
            }

            /// Subtracts the modulus from this element if this element is not in the
            /// field. Only used interally.
            #[inline(always)]
            fn reduce(&mut self) {
                if !self.is_valid() {
                    self.sub_noborrow(&MODULUS_LIMBS);
                }
            }

            #[inline(always)]
            fn mont_reduce(
                &mut self,
                #mont_paramlist
            )
            {
                // The Montgomery reduction here is based on Algorithm 14.32 in
                // Handbook of Applied Cryptography
                // <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

                #montgomery_impl

                self.reduce();
            }
        }
    }
}
