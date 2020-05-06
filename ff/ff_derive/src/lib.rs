#![recursion_limit = "1024"]

extern crate proc_macro;
extern crate proc_macro2;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use quote::quote;
use quote::TokenStreamExt;
use std::str::FromStr;

mod pow_fixed;

#[proc_macro_derive(PrimeField, attributes(PrimeFieldModulus, PrimeFieldGenerator))]
pub fn prime_field(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Parse the type definition
    let ast: syn::DeriveInput = syn::parse(input).unwrap();

    // The struct we're deriving for is a wrapper around a "Repr" type we must construct.
    let repr_ident = fetch_wrapped_ident(&ast.data)
        .expect("PrimeField derive only operates over tuple structs of a single item");

    // We're given the modulus p of the prime field
    let modulus: BigUint = fetch_attr("PrimeFieldModulus", &ast.attrs)
        .expect("Please supply a PrimeFieldModulus attribute")
        .parse()
        .expect("PrimeFieldModulus should be a number");

    // We may be provided with a generator of p - 1 order. It is required that this generator be quadratic
    // nonresidue.
    let generator: BigUint = fetch_attr("PrimeFieldGenerator", &ast.attrs)
        .expect("Please supply a PrimeFieldGenerator attribute")
        .parse()
        .expect("PrimeFieldGenerator should be a number");

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

    let mut gen = proc_macro2::TokenStream::new();

    let (constants_impl, sqrt_impl) =
        prime_field_constants_and_sqrt(&ast.ident, &repr_ident, &modulus, limbs, generator);

    gen.extend(constants_impl);
    gen.extend(prime_field_repr_impl(&repr_ident, limbs));
    gen.extend(prime_field_impl(&ast.ident, &repr_ident, &modulus, limbs));
    gen.extend(sqrt_impl);

    // Return the generated impl
    gen.into()
}

/// Fetches the ident being wrapped by the type we're deriving.
fn fetch_wrapped_ident(body: &syn::Data) -> Option<syn::Ident> {
    if let syn::Data::Struct(ref variant_data) = body {
        if let syn::Fields::Unnamed(ref fields) = variant_data.fields {
            if fields.unnamed.len() == 1 {
                if let syn::Type::Path(ref path) = fields.unnamed[0].ty {
                    if path.path.segments.len() == 1 {
                        return Some(path.path.segments[0].ident.clone());
                    }
                }
            }
        }
    };

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

// Implement PrimeFieldRepr for the wrapped ident `repr` with `limbs` limbs.
fn prime_field_repr_impl(repr: &syn::Ident, limbs: usize) -> proc_macro2::TokenStream {
    quote! {
        #[derive(Copy, Clone, PartialEq, Eq, Default)]
        pub struct #repr(pub [u64; #limbs]);

        impl ::core::fmt::Debug for #repr
        {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "0x")?;
                for i in self.0.iter().rev() {
                    write!(f, "{:016x}", *i)?;
                }

                Ok(())
            }
        }

        impl ::core::fmt::Display for #repr {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "0x")?;
                for i in self.0.iter().rev() {
                    write!(f, "{:016x}", *i)?;
                }

                Ok(())
            }
        }

        impl AsRef<[u64]> for #repr {
            #[inline(always)]
            fn as_ref(&self) -> &[u64] {
                &self.0
            }
        }

        impl AsMut<[u64]> for #repr {
            #[inline(always)]
            fn as_mut(&mut self) -> &mut [u64] {
                &mut self.0
            }
        }

        impl From<u64> for #repr {
            #[inline(always)]
            fn from(val: u64) -> #repr {
                use core::default::Default;

                let mut repr = Self::default();
                repr.0[0] = val;
                repr
            }
        }

        impl Ord for #repr {
            #[inline(always)]
            fn cmp(&self, other: &#repr) -> ::core::cmp::Ordering {
                for (a, b) in self.0.iter().rev().zip(other.0.iter().rev()) {
                    if a < b {
                        return ::core::cmp::Ordering::Less
                    } else if a > b {
                        return ::core::cmp::Ordering::Greater
                    }
                }

                ::core::cmp::Ordering::Equal
            }
        }

        impl PartialOrd for #repr {
            #[inline(always)]
            fn partial_cmp(&self, other: &#repr) -> Option<::core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl ::ff::PrimeFieldRepr for #repr {
            #[inline(always)]
            fn is_odd(&self) -> bool {
                self.0[0] & 1 == 1
            }

            #[inline(always)]
            fn is_even(&self) -> bool {
                !self.is_odd()
            }

            #[inline(always)]
            fn is_zero(&self) -> bool {
                self.0.iter().all(|&e| e == 0)
            }

            #[inline(always)]
            fn shr(&mut self, mut n: u32) {
                if n as usize >= 64 * #limbs {
                    *self = Self::from(0);
                    return;
                }

                while n >= 64 {
                    let mut t = 0;
                    for i in self.0.iter_mut().rev() {
                        ::core::mem::swap(&mut t, i);
                    }
                    n -= 64;
                }

                if n > 0 {
                    let mut t = 0;
                    for i in self.0.iter_mut().rev() {
                        let t2 = *i << (64 - n);
                        *i >>= n;
                        *i |= t;
                        t = t2;
                    }
                }
            }

            #[inline(always)]
            fn div2(&mut self) {
                let mut t = 0;
                for i in self.0.iter_mut().rev() {
                    let t2 = *i << 63;
                    *i >>= 1;
                    *i |= t;
                    t = t2;
                }
            }

            #[inline(always)]
            fn mul2(&mut self) {
                let mut last = 0;
                for i in &mut self.0 {
                    let tmp = *i >> 63;
                    *i <<= 1;
                    *i |= last;
                    last = tmp;
                }
            }

            #[inline(always)]
            fn shl(&mut self, mut n: u32) {
                if n as usize >= 64 * #limbs {
                    *self = Self::from(0);
                    return;
                }

                while n >= 64 {
                    let mut t = 0;
                    for i in &mut self.0 {
                        ::core::mem::swap(&mut t, i);
                    }
                    n -= 64;
                }

                if n > 0 {
                    let mut t = 0;
                    for i in &mut self.0 {
                        let t2 = *i >> (64 - n);
                        *i <<= n;
                        *i |= t;
                        t = t2;
                    }
                }
            }

            #[inline(always)]
            fn num_bits(&self) -> u32 {
                let mut ret = (#limbs as u32) * 64;
                for i in self.0.iter().rev() {
                    let leading = i.leading_zeros();
                    ret -= leading;
                    if leading != 64 {
                        break;
                    }
                }

                ret
            }

            #[inline(always)]
            fn add_nocarry(&mut self, other: &#repr) {
                let mut carry = 0;

                for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
                    *a = ::ff::adc(*a, *b, &mut carry);
                }
            }

            #[inline(always)]
            fn sub_noborrow(&mut self, other: &#repr) {
                let mut borrow = 0;

                for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
                    *a = ::ff::sbb(*a, *b, &mut borrow);
                }
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

    let sqrt_impl = if (modulus % BigUint::from_str("4").unwrap())
        == BigUint::from_str("3").unwrap()
    {
        // Addition chain for (r + 1) // 4
        let mod_plus_1_over_4 = pow_fixed::generate(
            &quote! {self},
            (modulus + BigUint::from_str("1").unwrap()) >> 2,
        );

        quote! {
            impl ::ff::SqrtField for #name {
                fn sqrt(&self) -> ::subtle::CtOption<Self> {
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
            }
        }
    } else if (modulus % BigUint::from_str("16").unwrap()) == BigUint::from_str("1").unwrap() {
        // Addition chain for (t - 1) // 2
        let t_minus_1_over_2 = pow_fixed::generate(&quote! {self}, (&t - BigUint::one()) >> 1);

        quote! {
            impl ::ff::SqrtField for #name {
                fn sqrt(&self) -> ::subtle::CtOption<Self> {
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
                    let mut z = #name(ROOT_OF_UNITY);

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
            }
        }
    } else {
        quote! {}
    };

    // Compute R^2 mod m
    let r2 = biguint_to_u64_vec((&r * &r) % modulus, limbs);

    let r = biguint_to_u64_vec(r, limbs);
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
            const MODULUS: #repr = #repr([#(#modulus,)*]);

            /// The number of bits needed to represent the modulus.
            const MODULUS_BITS: u32 = #modulus_num_bits;

            /// The number of bits that must be shaved from the beginning of
            /// the representation when randomly sampling.
            const REPR_SHAVE_BITS: u32 = #repr_shave_bits;

            /// 2^{limbs*64} mod m
            const R: #repr = #repr(#r);

            /// 2^{limbs*64*2} mod m
            const R2: #repr = #repr(#r2);

            /// -(m^{-1} mod m) mod m
            const INV: u64 = #inv;

            /// Multiplicative generator of `MODULUS` - 1 order, also quadratic
            /// nonresidue.
            const GENERATOR: #repr = #repr(#generator);

            /// 2^s * t = MODULUS - 1 with t odd
            const S: u32 = #s;

            /// 2^s root of unity computed by GENERATOR^t
            const ROOT_OF_UNITY: #repr = #repr(#root_of_unity);
        },
        sqrt_impl,
    )
}

/// Implement PrimeField for the derived type.
fn prime_field_impl(
    name: &syn::Ident,
    repr: &syn::Ident,
    modulus: &BigUint,
    limbs: usize,
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
                    ::ff::mac_with_carry(#temp, k, MODULUS.0[0], &mut carry);
                });
            }

            for j in 1..limbs {
                let temp = get_temp(i + j);
                gen.extend(quote! {
                    #temp = ::ff::mac_with_carry(#temp, k, MODULUS.0[#j], &mut carry);
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
                (self.0).0[#i] = #temp;
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
                        let #temp = ::ff::mac_with_carry(0, (#a.0).0[#i], (#a.0).0[#j], &mut carry);
                    });
                } else {
                    gen.extend(quote!{
                        let #temp = ::ff::mac_with_carry(#temp, (#a.0).0[#i], (#a.0).0[#j], &mut carry);
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
                    let #temp0 = ::ff::mac_with_carry(0, (#a.0).0[#i], (#a.0).0[#i], &mut carry);
                });
            } else {
                gen.extend(quote!{
                    let #temp0 = ::ff::mac_with_carry(#temp0, (#a.0).0[#i], (#a.0).0[#i], &mut carry);
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
                        let #temp = ::ff::mac_with_carry(0, (#a.0).0[#i], (#b.0).0[#j], &mut carry);
                    });
                } else {
                    gen.extend(quote!{
                        let #temp = ::ff::mac_with_carry(#temp, (#a.0).0[#i], (#b.0).0[#j], &mut carry);
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

    // (self.0).0[0].ct_eq(&(other.0).0[0]) & (self.0).0[1].ct_eq(&(other.0).0[1]) & ...
    let mut ct_eq_impl = proc_macro2::TokenStream::new();
    ct_eq_impl.append_separated(
        (0..limbs).map(|i| quote! { (self.0).0[#i].ct_eq(&(other.0).0[#i]) }),
        proc_macro2::Punct::new('&', proc_macro2::Spacing::Alone),
    );

    // (self.0).0[0], (self.0).0[1], ..., 0, 0, 0, 0, ...
    let mut into_repr_params = proc_macro2::TokenStream::new();
    into_repr_params.append_separated(
        (0..limbs)
            .map(|i| quote! { (self.0).0[#i] })
            .chain((0..limbs).map(|_| quote! {0})),
        proc_macro2::Punct::new(',', proc_macro2::Spacing::Alone),
    );

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
                #ct_eq_impl
            }
        }

        impl ::core::cmp::PartialEq for #name {
            fn eq(&self, other: &#name) -> bool {
                self.0 == other.0
            }
        }

        impl ::core::cmp::Eq for #name { }

        impl ::core::fmt::Debug for #name
        {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "{}({:?})", stringify!(#name), self.into_repr())
            }
        }

        /// Elements are ordered lexicographically.
        impl Ord for #name {
            #[inline(always)]
            fn cmp(&self, other: &#name) -> ::core::cmp::Ordering {
                self.into_repr().cmp(&other.into_repr())
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
                write!(f, "{}({})", stringify!(#name), self.into_repr())
            }
        }

        impl From<#name> for #repr {
            fn from(e: #name) -> #repr {
                e.into_repr()
            }
        }

        impl ::subtle::ConditionallySelectable for #name {
            fn conditional_select(a: &#name, b: &#name, choice: ::subtle::Choice) -> #name {
                let mut res = [0u64; #limbs];
                for i in 0..#limbs {
                    res[i] = u64::conditional_select(&(a.0).0[i], &(b.0).0[i], choice);
                }
                #name(#repr(res))
            }
        }

        impl ::core::ops::Neg for #name {
            type Output = #name;

            #[inline]
            fn neg(self) -> #name {
                let mut ret = self;
                if !ret.is_zero() {
                    let mut tmp = MODULUS;
                    tmp.sub_noborrow(&ret.0);
                    ret.0 = tmp;
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
                self.0.add_nocarry(&other.0);

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
                if other.0 > self.0 {
                    self.0.add_nocarry(&MODULUS);
                }

                self.0.sub_noborrow(&other.0);
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

            fn from_repr(r: #repr) -> Result<#name, PrimeFieldDecodingError> {
                let mut r = #name(r);
                if r.is_valid() {
                    r.mul_assign(&#name(R2));

                    Ok(r)
                } else {
                    Err(PrimeFieldDecodingError::NotInField)
                }
            }

            fn into_repr(&self) -> #repr {
                let mut r = *self;
                r.mont_reduce(
                    #into_repr_params
                );

                r.0
            }

            fn char() -> #repr {
                MODULUS
            }

            const NUM_BITS: u32 = MODULUS_BITS;

            const CAPACITY: u32 = Self::NUM_BITS - 1;

            fn multiplicative_generator() -> Self {
                #name(GENERATOR)
            }

            const S: u32 = S;

            fn root_of_unity() -> Self {
                #name(ROOT_OF_UNITY)
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
                        #name(#repr(repr))
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
                #name(#repr::from(0))
            }

            #[inline]
            fn one() -> Self {
                #name(R)
            }

            #[inline]
            fn is_zero(&self) -> bool {
                self.0.is_zero()
            }

            #[inline]
            fn double(&self) -> Self {
                let mut ret = *self;

                // This cannot exceed the backing capacity.
                ret.0.mul2();

                // However, it may need to be reduced.
                ret.reduce();

                ret
            }

            fn invert(&self) -> ::subtle::CtOption<Self> {
                #invert_impl
            }

            #[inline(always)]
            fn frobenius_map(&mut self, _: usize) {
                // This has no effect in a prime field.
            }

            #[inline]
            fn square(&self) -> Self
            {
                #squaring_impl
            }
        }

        impl #name {
            /// Determines if the element is really in the field. This is only used
            /// internally.
            #[inline(always)]
            fn is_valid(&self) -> bool {
                self.0 < MODULUS
            }

            /// Subtracts the modulus from this element if this element is not in the
            /// field. Only used interally.
            #[inline(always)]
            fn reduce(&mut self) {
                if !self.is_valid() {
                    self.0.sub_noborrow(&MODULUS);
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
