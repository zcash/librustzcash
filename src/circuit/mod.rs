#[cfg(test)]
pub mod test;

pub mod boolean;
pub mod uint32;
pub mod blake2s;
pub mod num;
pub mod lookup;
pub mod ecc;
pub mod pedersen_hash;

use bellman::SynthesisError;

trait Assignment<T> {
    fn get(&self) -> Result<&T, SynthesisError>;
}

impl<T> Assignment<T> for Option<T> {
    fn get(&self) -> Result<&T, SynthesisError> {
        match *self {
            Some(ref v) => Ok(v),
            None => Err(SynthesisError::AssignmentMissing)
        }
    }
}
