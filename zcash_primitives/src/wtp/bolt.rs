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

use bolt::wtp_utils::{reconstruct_channel_token_bls12, reconstruct_close_wallet_bls12, reconstruct_secp_public_key,
                      reconstruct_signature_bls12, wtp_verify_cust_close_message};

mod open {
    use std::convert::TryInto;
    use super::convert_u32_to_bytes;

    pub const MODE: usize = 0;

    #[derive(Debug, PartialEq)]
    pub struct Predicate {
        pub address: [u8; 32], // merch-close-address
        pub channel_token: Vec<u8> // (pkc, pkm, pkM, mpk, comparams) => 1074 bytes
    }

    #[derive(Debug, PartialEq)]
    pub struct Witness {     // 210 bytes
        pub witness_type: u8,
        pub cust_bal: u32,
        pub merch_bal: u32,
        pub cust_sig: Vec<u8>,
        pub merch_sig: Vec<u8>,
        pub wpk: Vec<u8> // 33 bytes
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
        return output;
    }

}

mod close {
    use super::convert_u32_to_bytes;

    pub const MODE: usize = 1;

    #[derive(Debug, PartialEq)]
    pub struct Predicate {
        pub pubkey: Vec<u8>, // 33 bytes
        pub balance: u32, // merch-bal or cust-bal
        pub channel_token: Vec<u8> // (pkc, pkm, pkM, mpk, comparams) => 1074 bytes
    }

    #[derive(Debug, PartialEq)]
    pub struct Witness {  // (pub [u8; 32]);
        pub witness_type: u8, // 1 byte
        pub address: [u8; 32], // 32 bytes
        pub signature: Vec<u8>, // 72 bytes (cust-sig or merch-sig)
        pub revoke_token: Vec<u8>, // 104 (wpk + rev-sig)
    }

    pub fn get_predicate_payload(p: &Predicate) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend(p.pubkey.iter());
        output.extend(convert_u32_to_bytes(p.balance).iter());
        output.extend(p.channel_token.iter());
        return output;
    }

    pub fn get_witness_payload(w: &Witness) -> Vec<u8> {
        let mut output = Vec::new();
        output.push(w.witness_type);
        output.extend(w.address.iter());
        output.extend(w.signature.iter());
        if w.witness_type == 0x1 {
            output.extend(w.revoke_token.iter());
        }
        // output.push(0x0); // add null as last byte
        return output;
    }
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

    pub fn close(input: [u8; 1024]) -> Self {
        let mut channel_token = Vec::new();
        let mut pubkey = Vec::new();
        pubkey.extend(input[0..33].iter());

        let balance = convert_bytes_to_u32(input[33..37].to_vec());

        channel_token.extend(input[37..].iter());

        Predicate::Close(close::Predicate { pubkey, balance, channel_token })
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
                    Err("Payload is not 1024 bytes")
                }
            }
            close::MODE => {
                if payload.len() == 1024 { // should be 1111
                    let mut pubkey = Vec::new();
                    pubkey.extend(payload[0..33].iter());
                    let balance = convert_bytes_to_u32(payload[33..37].to_vec());
                    let mut channel_token = Vec::new();
                    channel_token.extend(payload[37..].iter());

                    let cl = close::Predicate { pubkey, balance, channel_token };
                    Ok(Predicate::Close(cl))
                } else {
                    Err("Payload is not 1024 bytes")
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
            Predicate::Close(p) => (close::MODE, close::get_predicate_payload(p)),
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

fn parse_open_witness_input(input: [u8; 210]) -> open::Witness {
    let witness_type = input[0];
    let cust_bal = convert_bytes_to_u32(input[1..5].to_vec());
    let merch_bal = convert_bytes_to_u32(input[5..9].to_vec());
    let mut cust_sig = Vec::new();
    let mut merch_sig = Vec::new();
    cust_sig.extend_from_slice(&input[9..81].to_vec()); // customer signature

    let mut wpk = Vec::new(); // [0u8; 33];
    if witness_type == 0x0 { // merchant initiated (merch_sig : 72 bytes)
        merch_sig.extend_from_slice(&input[81..153].to_vec());
    } else if witness_type == 0x1 { // customer initiated (merch_sig : close-token = 96 bytes)
        merch_sig.extend_from_slice(&input[81..177].to_vec());
        wpk.extend(input[177..210].iter());
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

fn parse_close_witness_input(input: [u8; 210]) -> close::Witness {
    let witness_type = input[0];
    let mut address= [0u8; 32];
    let mut signature = Vec::new();
    let mut revoke_token = Vec::new();

    address.copy_from_slice(&input[1..33]);
    // cust-sig or merch-sig (depending on witness type)
    signature.extend_from_slice(&input[33..72].to_vec());

    if witness_type == 0x1 {
        revoke_token.extend_from_slice(&input[72..210].to_vec());
    }
    return close::Witness {
        witness_type,
        address,
        signature,
        revoke_token
    };
}

impl Witness {
    pub fn open(input: [u8; 210]) -> Self {
        Witness::Open(parse_open_witness_input(input))
    }

    pub fn close(input: [u8; 210]) -> Self {
        Witness::Close(parse_close_witness_input(input))
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
                    let witness = parse_open_witness_input(witness_input);
                    Ok(Witness::Open(witness))
                } else {
                    Err("Payload is not 210 bytes")
                }
            }
            close::MODE => {
                if payload.len() == 210 {
                    let witness_type = payload[0];
                    if witness_type != 0x0 && witness_type != 0x1 {
                        return Err("Invalid witness for close channel mode");
                    }
                    let mut witness_input = [0; 210];
                    witness_input.copy_from_slice(payload);
                    let witness = parse_close_witness_input(witness_input);
                    Ok(Witness::Close(witness))
                } else {
                    Err("Payload is not 210 bytes")
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
            Witness::Close(w) => (close::MODE, close::get_witness_payload(w)),
        }
    }
}

// open-channel program description
// If witness is of type 0x0, check that 2 new outputs are created, with the specified balances (unless one of the balances is zero), and that the signatures verify.

// If witness is of type 0x1, check that 2 new outputs are created (unless one of the balances is zero), with the specified balances:

// -- one paying <balance-merch> to <merch-close-address>
// -- one paying a cust-close WTP containing <channel-token> and <wallet> = <<wpk> || <balance-cust> || <balance-merch>>
//
// Also check that <cust-sig> is a valid signature and that <closing-token> contains a valid signature under <MERCH-PK> on <<cust-pk> || <wpk> || <balance-cust> || <balance-merch> || CLOSE>.

pub fn verify_channel_opening(escrow_pred: &open::Predicate, close_tx_witness: &open::Witness) -> bool {
    println!("Predicate: {:?}", open::get_predicate_payload(escrow_pred));
    println!("Witness: {:?}", open::get_witness_payload(close_tx_witness));

    if close_tx_witness.witness_type == 0x0 {
        // merchant-initiated
    } else if close_tx_witness.witness_type == 0x1 {
        // customer-initiated
        let _channel_token = &escrow_pred.channel_token;
        let cust_bal = close_tx_witness.cust_bal;
        let merch_bal = close_tx_witness.merch_bal;

        // reconstruct the close wallet
        let option_channel_token = reconstruct_channel_token_bls12(&_channel_token);
        let channel_token = match option_channel_token {
            Ok(n) => n.unwrap(),
            Err(e) => return false
        };

        let mut wpk_bytes = [0u8; 33];
        wpk_bytes.copy_from_slice(close_tx_witness.wpk.as_slice());
        let wpk = reconstruct_secp_public_key(&wpk_bytes);

        let close_wallet = reconstruct_close_wallet_bls12(&channel_token, &wpk, cust_bal, merch_bal);

        // TODO:
        let is_cust_sig_valid = true; // wtp_verify_secp_signature(close_tx_witness.cust_sig);

        let option_close_token = reconstruct_signature_bls12(&close_tx_witness.merch_sig);
        let close_token = match option_close_token {
            Ok(n) => n.unwrap(),
            Err(e) => return false
        };

        // check whether close token is valid
        let is_close_token_valid = wtp_verify_cust_close_message(&channel_token, &wpk, &close_wallet, &close_token);
        return is_cust_sig_valid && is_close_token_valid;
    }

    return false;
}


#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use super::{close, open, Predicate, Witness};
    use crate::wtp::ToPayload;
    use crate::wtp::bolt::{parse_open_witness_input, parse_close_witness_input, convert_bytes_to_u32};

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

    #[test]
    fn predicate_close_round_trip() {
        let data = vec![7; 1024];
        let p: Predicate = (close::MODE, &data[..]).try_into().unwrap();

        let mut pubkey = Vec::new(); // [0; 33];
        pubkey.extend(data[0..33].iter());
        let balance = convert_bytes_to_u32(data[33..37].to_vec());

        let mut channel_token: Vec<u8> = Vec::new();
        channel_token.extend(data[37..].iter());

        assert_eq!(p, Predicate::Close(close::Predicate { pubkey, balance, channel_token }));
        assert_eq!(p.to_payload(), (close::MODE, data));
    }

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
        let mut data = vec![7; 209];
        data.insert(0, 0x1);

        let w: Witness = (open::MODE, &data[..]).try_into().unwrap();
        let mut witness_input = [0; 210];
        witness_input.copy_from_slice(&data);
        let witness = parse_open_witness_input(witness_input);

        assert_eq!(w, Witness::Open(witness));
        assert_eq!(w.to_payload(), (open::MODE, data));
    }

    #[test]
    fn witness_close_round_trip() {
        let mut data = vec![7; 209];
        data.insert(0, 0x1);

        let w: Witness = (close::MODE, &data[..]).try_into().unwrap();
        let mut witness_input = [0; 210];
        witness_input.copy_from_slice(&data);
        let witness = parse_close_witness_input(witness_input);

        assert_eq!(w, Witness::Close(witness));
        assert_eq!(w.to_payload(), (close::MODE, data));
    }

    #[test]
    fn witness_rejects_invalid_mode_or_length() {
        for mode in 0..3 {
            for len in &[32, 32] {
                let p: Result<Witness, _> = (mode, &vec![7; *len * 2]).try_into();
                assert!(p.is_err());
            }
        }
    }
}
