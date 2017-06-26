extern crate proc_macro;
//extern crate syn;
//#[macro_use]
extern crate quote;

//extern crate num_bigint;
//extern crate num_traits;

//use num_traits::{Zero, One, ToPrimitive};
//use num_bigint::BigUint;

#[proc_macro_derive(PrimeField, attributes(PrimeFieldModulus))]
pub fn prime_field(
    _: proc_macro::TokenStream
) -> proc_macro::TokenStream
{
	/*
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
    */

    let gen = quote::Tokens::new();

    //gen.append(prime_field_repr_impl(&repr_ident, limbs));
    //gen.append(prime_field_constants(&repr_ident, modulus, limbs));
    //gen.append(prime_field_impl(&ast.ident, &repr_ident));
    //gen.append(prime_field_arith_impl(&ast.ident, &repr_ident, limbs));
    
    // Return the generated impl
    gen.parse().unwrap()
}

/*
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
*/
