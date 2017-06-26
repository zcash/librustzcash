#![recursion_limit="1024"]

extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

extern crate num_bigint;
extern crate num_traits;

use num_traits::{Zero, One, ToPrimitive};
use num_bigint::BigUint;
use std::str::FromStr;

#[proc_macro_derive(PrimeField, attributes(PrimeFieldModulus))]
pub fn prime_field(
    input: proc_macro::TokenStream
) -> proc_macro::TokenStream
{
    // Construct a string representation of the type definition
    let s = input.to_string();
    
    // Parse the string representation
    let ast = syn::parse_derive_input(&s).unwrap();

    // The struct we're deriving for is a wrapper around a "Repr" type we must construct.
    let repr_ident = fetch_wrapped_ident(&ast.body)
                     .expect("PrimeField derive only operates over tuple structs of a single item");

    // We're given the modulus p of the prime field
    let modulus: BigUint = fetch_attr("PrimeFieldModulus", &ast.attrs)
                           .expect("Please supply a PrimeFieldModulus attribute")
                           .parse().expect("PrimeFieldModulus should be a number");

    // The arithmetic in this library only works if the modulus*2 is smaller than the backing
    // representation. Compute the number of limbs we need.
    let mut limbs = 1;
    {
        let mod2 = (&modulus) << 1; // modulus * 2
        let mut cur = BigUint::one() << 64;
        while cur < mod2 {
            limbs += 1;
            cur = cur << 64;
        }
    }

    let mut gen = quote::Tokens::new();

    gen.append(prime_field_repr_impl(&repr_ident, limbs));
    gen.append(prime_field_constants_and_sqrt(&ast.ident, &repr_ident, modulus, limbs));
    gen.append(prime_field_impl(&ast.ident, &repr_ident, limbs));
    
    // Return the generated impl
    gen.parse().unwrap()
}

fn fetch_wrapped_ident(
    body: &syn::Body
) -> Option<syn::Ident>
{
    match body {
        &syn::Body::Struct(ref variant_data) => {
            let fields = variant_data.fields();
            if fields.len() == 1 {
                match fields[0].ty {
                    syn::Ty::Path(_, ref path) => {
                        if path.segments.len() == 1 {
                            return Some(path.segments[0].ident.clone());
                        }
                    },
                    _ => {}
                }
            }
        },
        _ => {}
    };

    None
}

/// Fetch an attribute string from the derived struct.
fn fetch_attr(
    name: &str,
    attrs: &[syn::Attribute]
) -> Option<String>
{
    for attr in attrs {
        if attr.name() == name {
            match attr.value {
                syn::MetaItem::NameValue(_, ref val) => {
                    match val {
                        &syn::Lit::Str(ref s, _) => {
                            return Some(s.clone())
                        },
                        _ => {
                            panic!("attribute {} should be a string", name);
                        }
                    }
                },
                _ => {
                    panic!("attribute {} should be a string", name);
                }
            }
        }
    }

    None
}

fn prime_field_repr_impl(
    repr: &syn::Ident,
    limbs: usize
) -> quote::Tokens
{
    quote! {
        #[derive(Copy, Clone, PartialEq, Eq, Default)]
        pub struct #repr(pub [u64; #limbs]);

        impl ::rand::Rand for #repr {
            fn rand<R: ::rand::Rng>(rng: &mut R) -> Self {
                #repr(rng.gen())
            }
        }

        impl ::std::fmt::Debug for #repr
        {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                try!(write!(f, "0x"));
                for i in self.0.iter().rev() {
                    try!(write!(f, "{:016x}", *i));
                }

                Ok(())
            }
        }

        impl AsRef<[u64]> for #repr {
            fn as_ref(&self) -> &[u64] {
                &self.0
            }
        }

        impl From<u64> for #repr {
            #[inline(always)]
            fn from(val: u64) -> #repr {
                use std::default::Default;

                let mut repr = Self::default();
                repr.0[0] = val;
                repr
            }
        }

        impl Ord for #repr {
            fn cmp(&self, other: &#repr) -> ::std::cmp::Ordering {
                for (a, b) in self.0.iter().rev().zip(other.0.iter().rev()) {
                    if a < b {
                        return ::std::cmp::Ordering::Less
                    } else if a > b {
                        return ::std::cmp::Ordering::Greater
                    }
                }

                ::std::cmp::Ordering::Equal
            }
        }

        impl PartialOrd for #repr {
            fn partial_cmp(&self, other: &#repr) -> Option<::std::cmp::Ordering> {
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
                for i in self.0.iter_mut() {
                    let tmp = *i >> 63;
                    *i <<= 1;
                    *i |= last;
                    last = tmp;
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
            fn add_nocarry(&mut self, other: &#repr) -> bool {
                let mut carry = 0;

                for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
                    *a = ::ff::adc(*a, *b, &mut carry);
                }

                carry != 0
            }

            #[inline(always)]
            fn sub_noborrow(&mut self, other: &#repr) -> bool {
                let mut borrow = 0;

                for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
                    *a = ::ff::sbb(*a, *b, &mut borrow);
                }

                borrow != 0
            }
        }
    }
}

fn biguint_to_u64_vec(
    mut v: BigUint
) -> Vec<u64>
{
    let m = BigUint::one() << 64;
    let mut ret = vec![];

    while v > BigUint::zero() {
        ret.push((&v % &m).to_u64().unwrap());
        v = v >> 64;
    }

    ret
}

fn biguint_num_bits(
    mut v: BigUint
) -> u32
{
    let mut bits = 0;

    while v != BigUint::zero() {
        v = v >> 1;
        bits += 1;
    }

    bits
}

fn prime_field_constants_and_sqrt(
    name: &syn::Ident,
    repr: &syn::Ident,
    modulus: BigUint,
    limbs: usize
) -> quote::Tokens
{
    let modulus_num_bits = biguint_num_bits(modulus.clone());
    let repr_shave_bits = (64 * limbs as u32) - biguint_num_bits(modulus.clone());

    // Compute R = 2**(64 * limbs) mod m
    let r = (BigUint::one() << (limbs * 64)) % &modulus;

    let sqrt_impl =
    if (&modulus % BigUint::from_str("4").unwrap()) == BigUint::from_str("3").unwrap() {
        let mod_minus_3_over_4 = biguint_to_u64_vec((&modulus - BigUint::from_str("3").unwrap()) >> 2);

        // Compute -R as (m - r)
        let rneg = biguint_to_u64_vec(&modulus - &r);

        quote!{
            impl ::ff::SqrtField for #name {
                fn sqrt(&self) -> Option<Self> {
                    // Shank's algorithm for q mod 4 = 3
                    // https://eprint.iacr.org/2012/685.pdf (page 9, algorithm 2)

                    let mut a1 = self.pow(#mod_minus_3_over_4);

                    let mut a0 = a1;
                    a0.square();
                    a0.mul_assign(self);

                    if a0.0 == #repr(#rneg) {
                        None
                    } else {
                        a1.mul_assign(self);
                        Some(a1)
                    }
                }
            }
        }
    } else {
        quote!{}
    };

    // Compute R^2 mod m
    let r2 = biguint_to_u64_vec((&r * &r) % &modulus);

    let r = biguint_to_u64_vec(r);
    let modulus = biguint_to_u64_vec(modulus);

    // Compute -m^-1 mod 2**64 by exponentiating by totient(2**64) - 1
    let mut inv = 1u64;
    for _ in 0..63 {
        inv = inv.wrapping_mul(inv);
        inv = inv.wrapping_mul(modulus[0]);
    }
    inv = inv.wrapping_neg();

    quote! {
        /// This is the modulus m of the prime field
        const MODULUS: #repr = #repr(#modulus);

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

        #sqrt_impl
    }
}

fn prime_field_impl(
    name: &syn::Ident,
    repr: &syn::Ident,
    limbs: usize
) -> quote::Tokens
{
    fn get_temp(n: usize) -> syn::Ident {
        syn::Ident::from(format!("r{}", n))
    }

    let mut mont_paramlist = quote::Tokens::new();
    mont_paramlist.append_separated(
        (0..(limbs*2)).map(|i| (i, get_temp(i)))
               .map(|(i, x)| {
                    if i != 0 {
                        quote!{mut #x: u64}
                    } else {
                        quote!{#x: u64}
                    }
                }),
        ","
    ); // r0: u64, mut r1: u64, mut r2: u64, ...

    let mut mont_impl = quote::Tokens::new();
    for i in 0..limbs {
        {
            let temp = get_temp(i);
            mont_impl.append(quote!{
                let k = #temp.wrapping_mul(INV);
                let mut carry = 0;
                ::ff::mac_with_carry(#temp, k, MODULUS.0[0], &mut carry);
            });
        }

        for j in 1..limbs {
            let temp = get_temp(i + j);
            mont_impl.append(quote!{
                #temp = ::ff::mac_with_carry(#temp, k, MODULUS.0[#j], &mut carry);
            });
        }

        let temp = get_temp(i + limbs);

        if i == 0 {
            mont_impl.append(quote!{
                #temp = ::ff::adc(#temp, 0, &mut carry);
            });
        } else {
            mont_impl.append(quote!{
                #temp = ::ff::adc(#temp, carry2, &mut carry);
            });
        }

        if i != (limbs - 1) {
            mont_impl.append(quote!{
                let carry2 = carry;
            });
        }
    }

    for i in 0..limbs {
        let temp = get_temp(limbs + i);

        mont_impl.append(quote!{
            (self.0).0[#i] = #temp;
        });
    }

    fn mul_impl(a: quote::Tokens, b: quote::Tokens, limbs: usize) -> quote::Tokens
    {
        let mut gen = quote::Tokens::new();

        for i in 0..limbs {
            gen.append(quote!{
                let mut carry = 0;
            });

            for j in 0..limbs {
                let temp = get_temp(i + j);

                if i == 0 {
                    gen.append(quote!{
                        let #temp = ::ff::mac_with_carry(0, (#a.0).0[#i], (#b.0).0[#j], &mut carry);
                    });
                } else {
                    gen.append(quote!{
                        let #temp = ::ff::mac_with_carry(#temp, (#a.0).0[#i], (#b.0).0[#j], &mut carry);
                    });
                }
            }

            let temp = get_temp(i + limbs);

            gen.append(quote!{
                let #temp = carry;
            });
        }

        let mut mont_calling = quote::Tokens::new();
        mont_calling.append_separated((0..(limbs*2)).map(|i| get_temp(i)), ",");

        gen.append(quote!{
            self.mont_reduce(#mont_calling);
        });

        gen
    }

    let squaring_impl = mul_impl(quote!{self}, quote!{self}, limbs);
    let multiply_impl = mul_impl(quote!{self}, quote!{other}, limbs);

    let mut into_repr_params = quote::Tokens::new();
    into_repr_params.append_separated(
        (0..limbs).map(|i| quote!{ (self.0).0[#i] })
                  .chain((0..limbs).map(|_| quote!{0})),
        ","
    );

    quote!{
        impl Copy for #name { }

        impl Clone for #name {
            fn clone(&self) -> #name {
                *self
            }
        }

        impl PartialEq for #name {
            fn eq(&self, other: &#name) -> bool {
                self.0 == other.0
            }
        }

        impl Eq for #name { }

        impl ::std::fmt::Debug for #name
        {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "{}({:?})", stringify!(#name), self.into_repr())
            }
        }

        impl ::rand::Rand for #name {
            /// Computes a uniformly random element using rejection sampling.
            fn rand<R: ::rand::Rng>(rng: &mut R) -> Self {
                loop {
                    let mut tmp = #name(#repr::rand(rng));
                    for _ in 0..REPR_SHAVE_BITS {
                        tmp.0.div2();
                    }
                    if tmp.is_valid() {
                        return tmp
                    }
                }
            }
        }

        impl ::ff::PrimeField for #name {
            type Repr = #repr;

            fn from_repr(r: #repr) -> Result<#name, ()> {
                let mut r = #name(r);
                if r.is_valid() {
                    r.mul_assign(&#name(R2));

                    Ok(r)
                } else {
                    Err(())
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

            fn num_bits() -> u32 {
                MODULUS_BITS
            }

            fn capacity() -> u32 {
                Self::num_bits() - 1
            }
        }

        impl ::ff::Field for #name {
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
            fn add_assign(&mut self, other: &#name) {
                // This cannot exceed the backing capacity.
                self.0.add_nocarry(&other.0);

                // However, it may need to be reduced.
                self.reduce();
            }

            #[inline]
            fn double(&mut self) {
                // This cannot exceed the backing capacity.
                self.0.mul2();

                // However, it may need to be reduced.
                self.reduce();
            }

            #[inline]
            fn sub_assign(&mut self, other: &#name) {
                // If `other` is larger than `self`, we'll need to add the modulus to self first.
                if other.0 > self.0 {
                    self.0.add_nocarry(&MODULUS);
                }

                self.0.sub_noborrow(&other.0);
            }

            #[inline]
            fn negate(&mut self) {
                if !self.is_zero() {
                    let mut tmp = MODULUS;
                    tmp.sub_noborrow(&self.0);
                    self.0 = tmp;
                }
            }

            fn inverse(&self) -> Option<Self> {
                if self.is_zero() {
                    None
                } else {
                    // Guajardo Kumar Paar Pelzl
                    // Efficient Software-Implementation of Finite Fields with Applications to Cryptography
                    // Algorithm 16 (BEA for Inversion in Fp)

                    let one = #repr::from(1);

                    let mut u = self.0;
                    let mut v = MODULUS;
                    let mut b = #name(R2); // Avoids unnecessary reduction step.
                    let mut c = Self::zero();

                    while u != one && v != one {
                        while u.is_even() {
                            u.div2();

                            if b.0.is_even() {
                                b.0.div2();
                            } else {
                                b.0.add_nocarry(&MODULUS);
                                b.0.div2();
                            }
                        }

                        while v.is_even() {
                            v.div2();

                            if c.0.is_even() {
                                c.0.div2();
                            } else {
                                c.0.add_nocarry(&MODULUS);
                                c.0.div2();
                            }
                        }

                        if v < u {
                            u.sub_noborrow(&v);
                            b.sub_assign(&c);
                        } else {
                            v.sub_noborrow(&u);
                            c.sub_assign(&b);
                        }
                    }

                    if u == one {
                        Some(b)
                    } else {
                        Some(c)
                    }
                }
            }

            #[inline(always)]
            fn frobenius_map(&mut self, _: usize) {
                // This has no effect in a prime field.
            }

            #[inline]
            fn mul_assign(&mut self, other: &#name)
            {
                #multiply_impl
            }

            #[inline]
            fn square(&mut self)
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

                #mont_impl

                self.reduce();
            }
        }
    }
}
