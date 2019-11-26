//! Bolt parsing logic for WTPs.
//!
//! See [the demo program's consensus rules][demo-rules] for details about the demo
//! protocol. All the parser cares about is the lengths and types of the predicates and
//! witnesses, which in this demo protocol are all 32-byte arrays.
//!
//! [bolt-rules]: crate::consensus::wtp::bolt

use std::convert::{TryFrom, TryInto};

use super::ToPayload;
use crate::transaction::builder::Error::InvalidWitness;
use crate::wtp::bolt::open::get_witness_payload;

mod open {
    use std::convert::TryInto;
    use super::convert_u32_to_bytes;

    pub const MODE: usize = 0;

    #[derive(Debug, PartialEq)]
    pub struct Predicate {
        pub address: [u8; 32], // merch-close-address
        pub channel_token: Vec<u8> // (pkc, pkm, pkM, mpk)
    }

    #[derive(Debug, PartialEq)]
    pub struct Witness {     // 210 bytes
        pub witness_type: u8,
        pub cust_bal: u32,
        pub merch_bal: u32,
        pub cust_sig: Vec<u8>,
        pub merch_sig: Vec<u8>,
        pub wpk: [u8; 32]
    }

    pub fn get_predicate_payload(p: &Predicate) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend(p.address.iter());
        output.extend(p.channel_token.iter());
        return output;
    }

    pub fn get_witness_payload(w: &Witness) -> Vec<u8> {
        let mut output = Vec::new();
        output.push(w.witness_type);
        output.extend(convert_u32_to_bytes(w.cust_bal).iter());
        output.extend(convert_u32_to_bytes(w.merch_bal).iter());
        output.extend(w.cust_sig.iter());
        output.extend(w.merch_sig.iter());
        if w.witness_type == 0x1 {
            output.extend(w.wpk.iter())
        }
        output.push(0x0); // add null as last byte
        return output;
    }

}

mod close {
    pub const MODE: usize = 1;

    #[derive(Debug, PartialEq)]
    pub struct Predicate {
        pub hash: [u8; 32]
    }

    #[derive(Debug, PartialEq)]
    pub struct Witness(pub [u8; 32]);
}

#[derive(Debug, PartialEq)]
pub enum Predicate {
    Open(open::Predicate),
    Close(close::Predicate),
}

impl Predicate {
    pub fn open(input: [u8; 1024]) -> Self {
        let mut channel_token = Vec::new();
        let mut address = [0; 32];
        address.copy_from_slice(&input[0..32]);
        channel_token.extend(input[32..].iter());
        Predicate::Open(open::Predicate { address, channel_token })
    }

    pub fn close(hash: [u8; 32]) -> Self {
        Predicate::Close(close::Predicate { hash })
    }
}

impl TryFrom<(usize, &[u8])> for Predicate {
    type Error = &'static str;

    fn try_from((mode, payload): (usize, &[u8])) -> Result<Self, Self::Error> {
        match mode {
            open::MODE => {
                if payload.len() == 1024 {
                    let mut address = [0; 32];
                    let mut channel_token = Vec::new();
                    address.copy_from_slice(&payload[0..32]);
                    channel_token.extend(payload[32..].iter());

                    let op = open::Predicate { address, channel_token };
                    Ok(Predicate::Open(op))
                } else {
                    Err("Payload is not 33 bytes")
                }
            }
            close::MODE => {
                if payload.len() == 32 {
                    let mut hash = [0; 32];
                    hash.copy_from_slice(&payload);
                    let cl = close::Predicate { hash };
                    Ok(Predicate::Close(cl))
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
            Predicate::Open(p) => (open::MODE, open::get_predicate_payload(p)),
            Predicate::Close(p) => (close::MODE, p.hash.to_vec()),
        }
    }
}

fn convert_u32_to_bytes(x: u32) -> [u8; 4] {
    let b1 : u8 = ((x >> 24) & 0xff) as u8;
    let b2 : u8 = ((x >> 16) & 0xff) as u8;
    let b3 : u8 = ((x >> 8) & 0xff) as u8;
    let b4 : u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4]
}

fn convert_bytes_to_u32(x: Vec<u8>) -> u32 {
    let mut u: u32 = 0;
    let len = x.len() - 1;
    for i in 0 .. 4 {
        let t: u32 = (x[len - i] as u32) << (i * 8);
        u += t;
    }
    return u;
}

#[derive(Debug, PartialEq)]
pub enum Witness {
    Open(open::Witness),
    Close(close::Witness),
}

fn parse_witness_input(input: [u8; 210]) -> open::Witness {
    let witness_type = input[0];
    let cust_bal = convert_bytes_to_u32(input[1..5].to_vec());
    let merch_bal = convert_bytes_to_u32(input[5..9].to_vec());
    let mut cust_sig = Vec::new();
    let mut merch_sig = Vec::new();
    cust_sig.extend_from_slice(&input[9..81].to_vec()); // customer signature

    let mut wpk = [0u8; 32];
    if witness_type == 0x0 { // merchant initiated (merch_sig : 72 bytes)
        merch_sig.extend_from_slice(&input[81..153].to_vec());
    } else if witness_type == 0x1 { // customer initiated (merch_sig : close-token = 96 bytes)
        merch_sig.extend_from_slice(&input[81..177].to_vec());
        wpk.copy_from_slice(&input[177..209]);
    }

    return open::Witness {
        witness_type,
        cust_bal,
        merch_bal,
        cust_sig,
        merch_sig,
        wpk
    };
}

impl Witness {
    pub fn open(input: [u8; 210]) -> Self {
        Witness::Open(parse_witness_input(input))
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
                if payload.len() == 210 {
                    let witness_type = payload[0];
                    if witness_type != 0x0 && witness_type != 0x1 {
                        return Err("Invalid witness for open channel mode");
                    }
                    let mut witness_input = [0; 210];
                    witness_input.copy_from_slice(payload);
                    let witness = parse_witness_input(witness_input);
                    Ok(Witness::Open(witness))
                } else {
                    Err("Payload is not 210 bytes")
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
            Witness::Open(w) => (open::MODE, open::get_witness_payload(w)),
            Witness::Close(w) => (close::MODE, w.0.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use super::{close, open, Predicate, Witness};
    use crate::wtp::ToPayload;
    use crate::wtp::bolt::parse_witness_input;

    #[test]
    fn predicate_open_round_trip() {
        let data = vec![7; 1024];
        let p: Predicate = (open::MODE, &data[..]).try_into().unwrap();
        let mut channel_token = Vec::new();

        let mut address = [0; 32];
        address.copy_from_slice(&data[0..32]);
        channel_token.extend(data[32..].iter());

        assert_eq!(p, Predicate::Open(open::Predicate { address, channel_token }));
        assert_eq!(p.to_payload(), (open::MODE, data));
    }

//    #[test]
//    fn predicate_close_round_trip() {
//        let data = vec![7; 32];
//        let p: Predicate = (close::MODE, &data[..]).try_into().unwrap();
//        let hash = [7; 32];
//        assert_eq!(p, Predicate::Close(close::Predicate { hash }));
//        assert_eq!(p.to_payload(), (close::MODE, data));
//    }
//
    #[test]
    fn predicate_rejects_invalid_mode_or_length() {
        for mode in 0..3 {
            for len in &[32, 32] {
                let p: Result<Predicate, _> = (mode, &vec![7; *len * 2]).try_into();
                assert!(p.is_err());
            }
        }
    }

    #[test]
    fn witness_open_round_trip() {
        let mut data = vec![7; 208];
        data.insert(0, 0x1);
        data.push(0x0);

        let w: Witness = (open::MODE, &data[..]).try_into().unwrap();
        let mut witness_input = [0; 210];
        witness_input.copy_from_slice(&data);
        let witness = parse_witness_input(witness_input);

        assert_eq!(w, Witness::Open(witness));
        assert_eq!(w.to_payload(), (open::MODE, data));
    }

//    #[test]
//    fn witness_close_round_trip() {
//        let data = vec![7; 32];
//        let p: Witness = (close::MODE, &data[..]).try_into().unwrap();
//        assert_eq!(p, Witness::Close(close::Witness([7; 32])));
//        assert_eq!(p.to_payload(), (close::MODE, data));
//    }
//
//    #[test]
//    fn witness_rejects_invalid_mode_or_length() {
//        for mode in 0..3 {
//            for len in &[32, 32] {
//                let p: Result<Witness, _> = (mode, &vec![7; *len]).try_into();
//                assert!(p.is_err());
//            }
//        }
//    }
}
