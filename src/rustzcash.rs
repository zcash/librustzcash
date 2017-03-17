extern crate libc;
use libc::uint64_t;

/// XOR two uint64_t values and return the result, used
/// as a temporary mechanism for introducing Rust into
/// Zcash.
#[no_mangle]
pub extern "system" fn librustzcash_xor(a: uint64_t, b: uint64_t) -> uint64_t
{
    a ^ b
}

#[test]
fn test_xor() {
	assert_eq!(librustzcash_xor(0x0f0f0f0f0f0f0f0f, 0x1111111111111111), 0x1e1e1e1e1e1e1e1e);
}
