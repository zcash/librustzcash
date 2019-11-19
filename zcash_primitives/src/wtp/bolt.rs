//! Bolt parsing logic for WTPs.
//!
//! See [the demo program's consensus rules][demo-rules] for details about the demo
//! protocol. All the parser cares about is the lengths and types of the predicates and
//! witnesses, which in this demo protocol are all 32-byte arrays.
//!
//! [demo-rules]: crate::consensus::wtp::demo

use std::convert::{TryFrom, TryInto};

use super::ToPayload;

mod open {
    pub const MODE: usize = 0;

    #[derive(Debug, PartialEq)]
    pub struct Predicate(pub [u8; 32]);

    #[derive(Debug, PartialEq)]
    pub struct Witness(pub [u8; 32]);
}

mod close {
    pub const MODE: usize = 1;

    #[derive(Debug, PartialEq)]
    pub struct Predicate(pub [u8; 32]);

    #[derive(Debug, PartialEq)]
    pub struct Witness(pub [u8; 32]);
}

#[derive(Debug, PartialEq)]
pub enum Predicate {
    Open(open::Predicate),
    Close(close::Predicate),
}

impl Predicate {
    pub fn open(hash: [u8; 32]) -> Self {
        Predicate::Open(open::Predicate(hash))
    }

    pub fn close(hash: [u8; 32]) -> Self {
        Predicate::Close(close::Predicate(hash))
    }
}

impl TryFrom<(usize, &[u8])> for Predicate {
    type Error = &'static str;

    fn try_from((mode, payload): (usize, &[u8])) -> Result<Self, Self::Error> {
        match mode {
            open::MODE => {
                if payload.len() == 32 {
                    let mut hash = [0; 32];
                    hash.copy_from_slice(&payload);
                    Ok(Predicate::Open(open::Predicate(hash)))
                } else {
                    Err("Payload is not 32 bytes")
                }
            }
            close::MODE => {
                if payload.len() == 32 {
                    let mut hash = [0; 32];
                    hash.copy_from_slice(&payload);
                    Ok(Predicate::Close(close::Predicate(hash)))
                } else {
                    Err("Payload is not 32 bytes")
                }
            }
            _ => Err("Invalid mode"),
        }
    }
}

impl TryFrom<(usize, &Vec<u8>)> for Predicate {
    type Error = &'static str;

    fn try_from((mode, payload): (usize, &Vec<u8>)) -> Result<Self, Self::Error> {
        (mode, &payload[..]).try_into()
    }
}

impl TryFrom<(usize, Predicate)> for Predicate {
    type Error = &'static str;

    fn try_from(from: (usize, Self)) -> Result<Self, Self::Error> {
        match from {
            (open::MODE, Predicate::Open(p)) => Ok(Predicate::Open(p)),
            (close::MODE, Predicate::Close(p)) => Ok(Predicate::Close(p)),
            _ => Err("Invalid mode for predicate"),
        }
    }
}

impl ToPayload for Predicate {
    fn to_payload(&self) -> (usize, Vec<u8>) {
        match self {
            Predicate::Open(p) => (open::MODE, p.0.to_vec()),
            Predicate::Close(p) => (close::MODE, p.0.to_vec()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Witness {
    Open(open::Witness),
    Close(close::Witness),
}

impl Witness {
    pub fn open(preimage: [u8; 32]) -> Self {
        Witness::Open(open::Witness(preimage))
    }

    pub fn close(preimage: [u8; 32]) -> Self {
        Witness::Close(close::Witness(preimage))
    }
}

impl TryFrom<(usize, &[u8])> for Witness {
    type Error = &'static str;

    fn try_from((mode, payload): (usize, &[u8])) -> Result<Self, Self::Error> {
        match mode {
            open::MODE => {
                if payload.len() == 32 {
                    let mut preimage = [0; 32];
                    preimage.copy_from_slice(&payload);
                    Ok(Witness::Open(open::Witness(preimage)))
                } else {
                    Err("Payload is not 32 bytes")
                }
            }
            close::MODE => {
                if payload.len() == 32 {
                    let mut preimage = [0; 32];
                    preimage.copy_from_slice(&payload);
                    Ok(Witness::Close(close::Witness(preimage)))
                } else {
                    Err("Payload is not 32 bytes")
                }
            }
            _ => Err("Invalid mode"),
        }
    }
}

impl TryFrom<(usize, &Vec<u8>)> for Witness {
    type Error = &'static str;

    fn try_from((mode, payload): (usize, &Vec<u8>)) -> Result<Self, Self::Error> {
        (mode, &payload[..]).try_into()
    }
}

impl TryFrom<(usize, Witness)> for Witness {
    type Error = &'static str;

    fn try_from(from: (usize, Self)) -> Result<Self, Self::Error> {
        match from {
            (open::MODE, Witness::Open(p)) => Ok(Witness::Open(p)),
            (close::MODE, Witness::Close(p)) => Ok(Witness::Close(p)),
            _ => Err("Invalid mode for witness"),
        }
    }
}

impl ToPayload for Witness {
    fn to_payload(&self) -> (usize, Vec<u8>) {
        match self {
            Witness::Open(w) => (open::MODE, w.0.to_vec()),
            Witness::Close(w) => (close::MODE, w.0.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use super::{close, open, Predicate, Witness};
    use crate::wtp::ToPayload;

    #[test]
    fn predicate_open_round_trip() {
        let data = vec![7; 32];
        let p: Predicate = (open::MODE, &data[..]).try_into().unwrap();
        assert_eq!(p, Predicate::Open(open::Predicate([7; 32])));
        assert_eq!(p.to_payload(), (open::MODE, data));
    }

    #[test]
    fn predicate_close_round_trip() {
        let data = vec![7; 32];
        let p: Predicate = (close::MODE, &data[..]).try_into().unwrap();
        assert_eq!(p, Predicate::Close(close::Predicate([7; 32])));
        assert_eq!(p.to_payload(), (close::MODE, data));
    }

    #[test]
    fn predicate_rejects_invalid_mode_or_length() {
        for mode in 0..3 {
            for len in &[31, 33] {
                let p: Result<Predicate, _> = (mode, &vec![7; *len]).try_into();
                assert!(p.is_err());
            }
        }
    }

    #[test]
    fn witness_open_round_trip() {
        let data = vec![7; 32];
        let w: Witness = (open::MODE, &data[..]).try_into().unwrap();
        assert_eq!(w, Witness::Open(open::Witness([7; 32])));
        assert_eq!(w.to_payload(), (open::MODE, data));
    }

    #[test]
    fn witness_close_round_trip() {
        let data = vec![7; 32];
        let p: Witness = (close::MODE, &data[..]).try_into().unwrap();
        assert_eq!(p, Witness::Close(close::Witness([7; 32])));
        assert_eq!(p.to_payload(), (close::MODE, data));
    }

    #[test]
    fn witness_rejects_invalid_mode_or_length() {
        for mode in 0..3 {
            for len in &[31, 33] {
                let p: Result<Witness, _> = (mode, &vec![7; *len]).try_into();
                assert!(p.is_err());
            }
        }
    }
}
