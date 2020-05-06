//! Bolt implementation of WTP consensus rules.
//!
//! See `README.md` for a description of the three Bolt programs. Here's one scenario covered by the programs:
//!
//! - `tx_a`: `[ [any input types...] ----> TzeOut(channel_token, merch-close-pk) ]` funding tx
//! - `tx_b`: `[ TzeIn(tx_a, (wallet || cust-sig || close-token)) -> { TzeOut(cust-bal, (wpk || block-height)), TxOut(merch-bal, merch-close-pk) } ]` cust-close-tx
//! - `tx_c`: `[ TzeIn(tx_b, (0x0 || cust-sig)) -> [any output types...] ]` cust-spending-tx after time delay
//!
//! For all the cases, see tests below

use std::convert::{TryFrom, TryInto};

use zcash_extensions_api::transparent::{ToPayload, FromPayload, Extension};
use crate::consensus::{BranchId};
use crate::transaction::{Transaction, signature_hash, SIGHASH_ALL};
use crate::transaction::components::{Amount, TzeOut};

use bolt::tze_utils::{reconstruct_channel_token_bls12, reconstruct_close_wallet_bls12,
                      reconstruct_secp_public_key, reconstruct_signature_bls12,
                      verify_secp_signature, verify_cust_close_message,
                      reconstruct_secp_channel_close_m, reconstruct_secp_signature,
                      generate_secp_signature};
use bolt::bidirectional::{wtp_verify_revoke_message, wtp_verify_merch_close_message};

mod open {
    pub const MODE: usize = 0;

    #[derive(Debug, PartialEq)]
    pub struct Predicate {
        pub pubkey: Vec<u8>,
        pub channel_token: Vec<u8> // (pkc, pkm, pkM, mpk, comparams) => 1074 bytes
    }

    #[derive(Debug, PartialEq)]
    pub struct Witness {     // 210 bytes
        pub witness_type: u8,
        pub cust_bal: u64,
        pub merch_bal: u64,
        pub cust_sig: Vec<u8>,
        pub merch_sig: Vec<u8>,
        pub wpk: Vec<u8> // 33 bytes
    }

    pub fn get_predicate_payload(p: &Predicate) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend(p.pubkey.iter());
        output.extend(p.channel_token.iter());
        return output;
    }

    pub fn get_witness_payload(w: &Witness) -> Vec<u8> {
        let mut output = Vec::new();
        output.push(w.witness_type);
        output.extend(w.cust_bal.to_be_bytes().iter());
        output.extend(w.merch_bal.to_be_bytes().iter());
        output.push(w.cust_sig.len() as u8);
        output.extend(w.cust_sig.iter());
        output.push(w.merch_sig.len() as u8);
        output.extend(w.merch_sig.iter());
        if w.witness_type == 0x1 {
            output.extend(w.wpk.iter())
        }
        return output;
    }

}

mod close {
    pub const MODE: usize = 1;

    #[derive(Debug, PartialEq)]
    pub struct Predicate {
        pub pubkey: Vec<u8>, // 33 bytes
        pub amount: u64, // merch-bal or cust-bal
        pub block_height: i32,
        pub channel_token: Vec<u8> // (pkc, pkm, pkM, mpk, comparams) => 1074 bytes
    }

    #[derive(Debug, PartialEq)]
    pub struct Witness {
        pub witness_type: u8, // 1 byte
        pub address: Vec<u8>, // 33 bytes
        pub signature: Vec<u8>, // x bytes (cust-sig or merch-sig)
        pub revoke_token: Vec<u8>, // 33 + x (wpk + rev-sig)
    }

    pub fn get_predicate_payload(p: &Predicate) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend(p.pubkey.iter());
        output.extend(p.amount.to_be_bytes().iter());
        output.extend(p.block_height.to_be_bytes().iter());
        output.extend(p.channel_token.iter());
        return output;
    }

    pub fn get_witness_payload(w: &Witness) -> Vec<u8> {
        let mut output = Vec::new();
        output.push(w.witness_type);
        output.extend(w.address.iter());
        output.push(w.signature.len() as u8);
        output.extend(w.signature.iter());
        if w.witness_type == 0x1 {
            output.push(w.revoke_token.len() as u8);
            output.extend(w.revoke_token.iter());
        }
        return output;
    }
}

mod merch_close {
    pub const MODE: usize = 2;

    #[derive(Debug, PartialEq)]
    pub struct Predicate {
        pub pubkey: Vec<u8>, // 33 bytes
        pub block_height: i32,
        pub channel_token: Vec<u8> // (pkc, pkm, pkM, mpk, comparams) => 1074 bytes
    }

    #[derive(Debug, PartialEq)]
    pub struct Witness {
        pub witness_type: u8, // 1 byte
        pub cust_bal: u64, // 4 bytes
        pub merch_bal: u64, // 4 bytes
        pub sig: Vec<u8>, // 73 bytes
        pub close_token: Vec<u8>, // 73 or 96 bytes
        pub wpk: Vec<u8> // 33 bytes
    }

    pub fn get_predicate_payload(p: &Predicate) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend(p.pubkey.iter());
        output.extend(p.block_height.to_be_bytes().iter());
        output.extend(p.channel_token.iter());
        return output;
    }

    pub fn get_witness_payload(w: &Witness) -> Vec<u8> {
        let mut output = Vec::new();
        output.push(w.witness_type);
        output.push(w.sig.len() as u8);
        output.extend(w.sig.iter());
        output.extend(w.cust_bal.to_be_bytes().iter());
        output.extend(w.merch_bal.to_be_bytes().iter());
        if w.witness_type == 0x1 {
            output.push(w.close_token.len() as u8);
            output.extend(w.close_token.iter());
            output.extend(w.wpk.iter())
        }
        return output;
    }
}


#[derive(Debug, PartialEq)]
pub enum Predicate {
    Open(open::Predicate),
    Close(close::Predicate),
    MerchClose(merch_close::Predicate)
}

impl Predicate {
    pub fn open(input: [u8; 1107]) -> Self {
        let mut channel_token = Vec::new();
        let mut pubkey = Vec::new();
        pubkey.extend(input[0..33].iter());

        channel_token.extend(input[33..].iter());
        Predicate::Open(open::Predicate { pubkey, channel_token })
    }

    pub fn close(input: [u8; 1119]) -> Self {
        let mut channel_token = Vec::new();
        let mut pubkey = Vec::new();
        pubkey.extend(input[0..33].iter());

        let amount = convert_bytes_to_u64(&input[33..41]);
        let block_height = convert_bytes_to_i32(&input[41..45]);

        channel_token.extend(input[45..].iter());

        Predicate::Close(close::Predicate { pubkey, amount, block_height, channel_token })
    }

    pub fn merch_close(input: [u8; 1111]) -> Self {
        let mut channel_token = Vec::new();
        let mut pubkey = Vec::new();
        pubkey.extend(input[0..33].iter());
        let block_height = convert_bytes_to_i32(&input[33..37]);

        channel_token.extend(input[37..].iter());

        Predicate::MerchClose(merch_close::Predicate { pubkey, block_height, channel_token })
    }
}

impl TryFrom<(usize, &[u8])> for Predicate {
    type Error = &'static str;

    fn try_from((mode, payload): (usize, &[u8])) -> Result<Self, Self::Error> {
        match mode {
            open::MODE => {
                if payload.len() == 1107 {
                    let mut pubkey = Vec::new();
                    pubkey.extend(payload[0..33].iter());

                    let mut channel_token = Vec::new();
                    channel_token.extend(payload[33..].iter());

                    let op = open::Predicate { pubkey, channel_token };
                    Ok(Predicate::Open(op))
                } else {
                    Err("Payload is not 1107 bytes")
                }
            }
            close::MODE => {
                if payload.len() == 1119 {
                    let mut pubkey = Vec::new();
                    pubkey.extend(payload[0..33].iter());
                    let amount = convert_bytes_to_u64(&payload[33..41]);
                    let block_height = convert_bytes_to_i32(&payload[41..45]);
                    let mut channel_token = Vec::new();
                    channel_token.extend(payload[45..].iter());

                    let cl = close::Predicate { pubkey, amount, block_height, channel_token };
                    Ok(Predicate::Close(cl))
                } else {
                    Err("Payload is not 1119 bytes")
                }
            }
            merch_close::MODE => {
                if payload.len() == 1111 {
                    let mut pubkey = Vec::new();
                    pubkey.extend(payload[0..33].iter());
                    let block_height = convert_bytes_to_i32(&payload[33..37]);
                    let mut channel_token = Vec::new();
                    channel_token.extend(payload[37..].iter());

                    let cl = merch_close::Predicate { pubkey, block_height, channel_token };
                    Ok(Predicate::MerchClose(cl))
                } else {
                    Err("Payload is not 1111 bytes")
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
            (merch_close::MODE, Predicate::MerchClose(p)) => Ok(Predicate::MerchClose(p)),
            _ => Err("Invalid mode for predicate"),
        }
    }
}

impl FromPayload for Predicate {
    type Error = &'static str;

    fn from_payload(mode: usize, payload: &[u8]) -> Result<Self, Self::Error> {
        (mode, payload).try_into()
    }
}

impl ToPayload for Predicate {
    fn to_payload(&self) -> (usize, Vec<u8>) {
        match self {
            Predicate::Open(p) => (open::MODE, open::get_predicate_payload(p)),
            Predicate::Close(p) => (close::MODE, close::get_predicate_payload(p)),
            Predicate::MerchClose(p) => (merch_close::MODE, merch_close::get_predicate_payload(p)),
        }
    }
}

fn convert_bytes_to_i32(x: &[u8]) -> i32 {
    let mut x_array = [0; 4];
    x_array.copy_from_slice(x);
    return i32::from_be_bytes(x_array);
}

//fn convert_bytes_to_u32(x: &[u8]) -> u32 {
//    let mut x_array = [0; 4];
//    x_array.copy_from_slice(x);
//    return u32::from_be_bytes(x_array);
//}

fn convert_bytes_to_u64(x: &[u8]) -> u64 {
    let mut x_array = [0; 8];
    x_array.copy_from_slice(x);
    return u64::from_be_bytes(x_array);
}

#[derive(Debug, PartialEq)]
pub enum Witness {
    Open(open::Witness),
    Close(close::Witness),
    MerchClose(merch_close::Witness)
}

fn parse_witness_struct(input: [u8; 220]) -> (u8, u64, u64, Vec<u8>, Vec<u8>, Vec<u8>) {
    let witness_type = input[0];
    let cust_bal = convert_bytes_to_u64(&input[1..9]);
    let merch_bal = convert_bytes_to_u64(&input[9..17]);

    let mut cust_sig = Vec::new();
    let mut merch_sig = Vec::new();
    let mut wpk = Vec::new();

    let start_index = 18;
    let end_index = (18 + input[17]) as usize;

    // customer signature
    cust_sig.extend_from_slice(&input[start_index .. end_index].to_vec());

    let start_merch_sig = end_index + 1;
    let end_merch_sig = start_merch_sig + input[end_index] as usize;

    // merchant signature
    merch_sig.extend_from_slice(&input[start_merch_sig .. end_merch_sig].to_vec());

    if witness_type == 0x1 { // customer initiated (merch_sig : close-token = 96 bytes)
        let end_wpk = end_merch_sig + 33;
        wpk.extend(input[end_merch_sig .. end_wpk].iter());
    }

    return (witness_type, cust_bal, merch_bal, cust_sig, merch_sig, wpk);
}

fn parse_open_witness_input(input: [u8; 220]) -> open::Witness {
    let (witness_type, cust_bal, merch_bal, cust_sig, merch_sig, wpk) = parse_witness_struct(input);

    return open::Witness {
        witness_type,
        cust_bal,
        merch_bal,
        cust_sig,
        merch_sig,
        wpk
    };
}

fn parse_close_witness_input(input: [u8; 180]) -> close::Witness {
    let witness_type = input[0];
    let mut address= Vec::new();
    let mut signature = Vec::new();
    let mut revoke_token = Vec::new();

    address.extend_from_slice(&input[1..34]);
    // cust-sig or merch-sig (depending on witness type)
    let end_first_sig = (35 + input[34]) as usize;
    signature.extend_from_slice(&input[35..end_first_sig]);

    if witness_type == 0x1 {
        let start_second_sig = (end_first_sig + 1) as usize;
        let end_second_sig = start_second_sig + input[end_first_sig] as usize;
        revoke_token.extend_from_slice(&input[start_second_sig..end_second_sig]);
    }
    return close::Witness {
        witness_type,
        address,
        signature,
        revoke_token
    };
}

fn parse_merch_close_witness_input(input: [u8; 220]) -> merch_close::Witness {
    let witness_type = input[0];
    let mut cust_sig = Vec::new();
    let mut merch_sig = Vec::new();
    let mut wpk = Vec::new();

    let end_first_sig = (2 + input[1]) as usize;
    cust_sig.extend_from_slice(&input[2..end_first_sig].to_vec()); // customer signature

    let end_cust_balance = end_first_sig + 8;
    let cust_bal = convert_bytes_to_u64(&input[end_first_sig..end_cust_balance]);
    let end_merch_balance = end_cust_balance + 8;
    let merch_bal = convert_bytes_to_u64(&input[end_cust_balance..end_merch_balance]);

    if witness_type == 0x1 { // customer initiated (merch_sig : close-token = 96 bytes)
        let start_second_sig = end_merch_balance + 1;
        let end_second_sig = start_second_sig + input[end_merch_balance] as usize;
        merch_sig.extend_from_slice(&input[start_second_sig..end_second_sig].to_vec());
        let end_wpk = end_second_sig + 33;
        wpk.extend(input[end_second_sig..end_wpk].iter());
    }

    return merch_close::Witness {
        witness_type,
        cust_bal,
        merch_bal,
        sig: cust_sig,
        close_token: merch_sig, wpk
    };
}


impl Witness {
    pub fn open(input: [u8; 220]) -> Self {
        Witness::Open(parse_open_witness_input(input))
    }

    pub fn close(input: [u8; 180]) -> Self {
        Witness::Close(parse_close_witness_input(input))
    }

    pub fn merch_close(input: [u8; 220]) -> Self {
        Witness::MerchClose(parse_merch_close_witness_input(input))
    }
}

impl TryFrom<(usize, &[u8])> for Witness {
    type Error = &'static str;

    fn try_from((mode, payload): (usize, &[u8])) -> Result<Self, Self::Error> {
        match mode {
            open::MODE => {
                if payload.len() == 220 {
                    let witness_type = payload[0];
                    if witness_type != 0x0 && witness_type != 0x1 {
                        return Err("Invalid witness for open channel mode");
                    }
                    let mut witness_input = [0; 220];
                    witness_input.copy_from_slice(payload);
                    let witness = parse_open_witness_input(witness_input);
                    Ok(Witness::Open(witness))
                } else {
                    Err("Payload is not 220 bytes")
                }
            }
            close::MODE => {
                if payload.len() == 180 {
                    let witness_type = payload[0];
                    if witness_type != 0x0 && witness_type != 0x1 {
                        return Err("Invalid witness for close channel mode");
                    }
                    let mut witness_input = [0; 180];
                    witness_input.copy_from_slice(payload);
                    let witness = parse_close_witness_input(witness_input);
                    Ok(Witness::Close(witness))
                } else {
                    Err("Payload is not 180 bytes")
                }
            }
            merch_close::MODE => {
                if payload.len() == 220 {
                    let witness_type = payload[0];
                    if witness_type != 0x0 && witness_type != 0x1 {
                        return Err("Invalid witness for merch close channel mode");
                    }
                    let mut witness_input = [0; 220];
                    witness_input.copy_from_slice(payload);
                    let witness = parse_merch_close_witness_input(witness_input);
                    Ok(Witness::MerchClose(witness))
                } else {
                    Err("Payload is not 220 bytes")
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
            (merch_close::MODE, Witness::MerchClose(p)) => Ok(Witness::MerchClose(p)),
            _ => Err("Invalid mode for witness"),
        }
    }
}

impl FromPayload for Witness {
    type Error = &'static str;

    fn from_payload(mode: usize, payload: &[u8]) -> Result<Self, Self::Error> {
        (mode, payload).try_into()
    }
}

impl ToPayload for Witness {
    fn to_payload(&self) -> (usize, Vec<u8>) {
        match self {
            Witness::Open(w) => (open::MODE, open::get_witness_payload(w)),
            Witness::Close(w) => (close::MODE, close::get_witness_payload(w)),
            Witness::MerchClose(w) => (merch_close::MODE, merch_close::get_witness_payload(w)),
        }
    }
}

pub fn compute_tx_signature(sk: &Vec<u8>, txhash: &Vec<u8>) -> Vec<u8> {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&txhash.as_slice());

    let mut seckey = [0u8; 32];
    seckey.copy_from_slice(sk.as_slice());

    return generate_secp_signature(&seckey, &hash);
}

pub fn convert_to_amount(value: u64) -> Amount {
    return Amount::from_u64(value).unwrap();
}

// open-channel program
// If witness is of type 0x0, check that 2 new outputs are created, with the specified amounts (unless one of the amounts is zero), and that the signatures verify.

// If witness is of type 0x1, check that 2 new outputs are created (unless one of the amounts is zero), with the specified amounts:

// -- one paying <amount-merch> to <merch-close-address>
// -- one paying a cust-close WTP containing <channel-token> and <wallet> = <<wpk> || <amount-cust> || <amount-merch>>
//
// Also check that <cust-sig> is a valid signature and that <closing-token> contains a valid signature under <MERCH-PK> on <<cust-pk> || <wpk> || <amount-cust> || <amount-merch> || CLOSE>

pub fn verify_channel_opening(escrow_pred: &open::Predicate, close_tx_witness: &open::Witness, tx_hash: &Vec<u8>, tx2_pubkey: Vec<u8>) -> bool {
    let _channel_token = &escrow_pred.channel_token;
    let option_channel_token = reconstruct_channel_token_bls12(&_channel_token);
    let channel_token = match option_channel_token {
        Ok(n) => n.unwrap(),
        Err(_e) => return false
    };

    //println!("debug: verify_channel_opening - tx_hash: {:?}", &tx_hash);
    let pkc = channel_token.pk_c.unwrap();
    let pkm = channel_token.pk_m;

    let cust_bal = close_tx_witness.cust_bal;
    let merch_bal = close_tx_witness.merch_bal;

    if close_tx_witness.witness_type == 0x0 {
        // merchant-initiated
        let cust_sig = reconstruct_secp_signature(close_tx_witness.cust_sig.as_slice());
        let merch_sig = reconstruct_secp_signature(close_tx_witness.merch_sig.as_slice());

        let is_cust_sig_valid = verify_secp_signature(&pkc, tx_hash, &cust_sig);
        let is_merch_sig_valid = verify_secp_signature(&pkm, tx_hash, &merch_sig);

        return is_cust_sig_valid && is_merch_sig_valid;
    } else if close_tx_witness.witness_type == 0x1 {
        // customer-initiated
        let is_merch_pk_thesame= tx2_pubkey == escrow_pred.pubkey;

        let mut wpk_bytes = [0u8; 33];
        wpk_bytes.copy_from_slice(close_tx_witness.wpk.as_slice());
        let wpk = reconstruct_secp_public_key(&wpk_bytes);

        let close_wallet = reconstruct_close_wallet_bls12(&channel_token, &wpk, cust_bal, merch_bal);

        let cust_sig = reconstruct_secp_signature(close_tx_witness.cust_sig.as_slice());

        let is_cust_sig_valid = verify_secp_signature(&pkc, tx_hash, &cust_sig);

        let option_close_token = reconstruct_signature_bls12(&close_tx_witness.merch_sig);
        let close_token = match option_close_token {
            Ok(n) => n.unwrap(),
            Err(_e) => return false
        };

        // check whether close token is valid
        let is_close_token_valid = verify_cust_close_message(&channel_token, &wpk, &close_wallet, &close_token);
        return is_cust_sig_valid && is_close_token_valid && is_merch_pk_thesame;
    }

    return false;
}

// close-channel program
// If witness is of type 0x0, verify customer signature and relative timeout met

// If witness is of type 0x1, check that 1 output is created paying <amount-merch + amount-cust> to <address>.
// Also check that <merch-sig> is a valid signature on <<address> || <revocation-token>>
// and that <revocation-token> contains a valid signature under <wpk> on <<wpk> || REVOKED>

pub fn verify_channel_closing(close_tx_pred: &close::Predicate, spend_tx_witness: &close::Witness, tx_hash: &Vec<u8>) -> bool {
    let option_channel_token = reconstruct_channel_token_bls12(&close_tx_pred.channel_token);
    let channel_token = match option_channel_token {
        Ok(n) => n.unwrap(),
        Err(_e) => return false
    };

    if spend_tx_witness.witness_type == 0x0 {
        // customer-initiated
        let pkc = channel_token.pk_c.unwrap();
        let cust_sig = reconstruct_secp_signature(spend_tx_witness.signature.as_slice());
        let is_cust_sig_valid = verify_secp_signature(&pkc, tx_hash, &cust_sig);
        return is_cust_sig_valid;
    } else if spend_tx_witness.witness_type == 0x1 {
        // merchant-initiated
        let mut address_bytes = [0u8; 33];
        address_bytes.copy_from_slice(spend_tx_witness.address.as_slice());
        let channel_close = reconstruct_secp_channel_close_m(&address_bytes, &spend_tx_witness.revoke_token, &spend_tx_witness.signature);
        let mut wpk_bytes = [0u8; 33];
        wpk_bytes.copy_from_slice(close_tx_pred.pubkey.as_slice());
        let wpk = reconstruct_secp_public_key(&wpk_bytes);
        let revoke_token = reconstruct_secp_signature(spend_tx_witness.revoke_token.as_slice());
        return wtp_verify_revoke_message(&wpk, &revoke_token) &&  wtp_verify_merch_close_message(&channel_token, &channel_close);
    }

    return false;
}

// merch-close program
pub fn verify_channel_merch_closing(merch_tx_pred: &merch_close::Predicate, close_tx_witness: &merch_close::Witness, tx_hash: &Vec<u8>, tx2_pubkey: Vec<u8>) -> bool {
    let option_channel_token = reconstruct_channel_token_bls12(&merch_tx_pred.channel_token);
    let channel_token = match option_channel_token {
        Ok(n) => n.unwrap(),
        Err(_e) => return false
    };

    let pkc = channel_token.pk_c.unwrap();
    let cust_bal = close_tx_witness.cust_bal;
    let merch_bal = close_tx_witness.merch_bal;
    // println!("debug: verify_channel_merch_closing - tx_hash: {:?}", &tx_hash);

    if close_tx_witness.witness_type == 0x0 {
        let merch_sig = reconstruct_secp_signature(close_tx_witness.sig.as_slice());
        let is_merch_sig_valid = verify_secp_signature(&channel_token.pk_m, tx_hash, &merch_sig);
        return is_merch_sig_valid;
    } else if close_tx_witness.witness_type == 0x1 {
        // customer spending from merchant-initiated close tx
        let is_merch_pk_thesame= tx2_pubkey != merch_tx_pred.pubkey;

        let mut wpk_bytes = [0u8; 33];
        wpk_bytes.copy_from_slice(close_tx_witness.wpk.as_slice());
        let wpk = reconstruct_secp_public_key(&wpk_bytes);

        let close_wallet = reconstruct_close_wallet_bls12(&channel_token, &wpk, cust_bal, merch_bal);

        let cust_sig = reconstruct_secp_signature(close_tx_witness.sig.as_slice());

        let is_cust_sig_valid = verify_secp_signature(&pkc, tx_hash, &cust_sig);

        let option_close_token = reconstruct_signature_bls12(&close_tx_witness.close_token);
        let close_token = match option_close_token {
            Ok(n) => n.unwrap(),
            Err(_e) => return false
        };

        // check whether close token is valid
        let is_close_token_valid = verify_cust_close_message(&channel_token, &wpk, &close_wallet, &close_token);
        return is_cust_sig_valid && is_close_token_valid && is_merch_pk_thesame;
    }

    return false;
}

pub struct BoltOut {
    pub value: Amount,
    pub predicate: Predicate,
}

pub trait Context {
    fn block_height(&self) -> i32;
    fn tx(&self) -> &Transaction;

    fn is_tze_and_vout_only(&self) -> bool {
        self.tx().vin.is_empty()
            && self.tx().tze_outputs.len() == 1
            && self.tx().vout.len() <= 1
            && self.tx().shielded_spends.is_empty()
            && self.tx().shielded_outputs.is_empty()
            && self.tx().joinsplits.is_empty()
    }

    fn get_tx_hash(&self) -> Vec<u8> {
        signature_hash(&self.tx(), BranchId::Heartwood, SIGHASH_ALL, None)
    }

    fn get_tx_tze_output_value(&self) -> Result<Amount, ()> {
        if self.tx().tze_outputs.len() == 1 {
            Ok(self.tx().tze_outputs[0].value)
        } else {
            Err(())
        }
    }

    fn get_tx_output_value(&self) -> Result<Amount, ()> {
        if self.tx().vout.len() == 1 {
            Ok(self.tx().vout[0].value)
        } else {
            Err(())
        }
    }

    fn get_tx_output_pk(&self) -> Result<Vec<u8>, ()> {
        if self.tx().vout.len() == 1 {
            Ok(self.tx().vout[0].script_pubkey.0.clone())
        } else {
            Err(())
        }
    }

    fn is_vout_only(&self) -> bool {
        self.tx().vin.is_empty()
            && self.tx().vout.len() <= 1
            && self.tx().tze_outputs.is_empty()
            && self.tx().shielded_spends.is_empty()
            && self.tx().shielded_outputs.is_empty()
            && self.tx().joinsplits.is_empty()
    }

    fn tx_tze_outputs(&self) -> &[TzeOut] {
        &self.tx().tze_outputs
    }

    //fn is_tze_and_vout_only(&self) -> bool;
    //fn tx_tze_outputs(&self) -> &[TzeOut];
    //fn get_tx_output_pk(&self) -> Result<Vec<u8>, ()>;
    //fn get_tx_output_value(&self) -> Result<Amount, ()>;
    //fn get_tx_tze_output_value(&self) -> Result<Amount, ()>;
    //fn block_height(&self) -> i32;
    //fn get_tx_hash(&self) -> Vec<u8>;
    //fn is_vout_only(&self) -> bool;
}

pub struct Program;

impl<C: Context> Extension<C> for Program {
    type P = Predicate;
    type W = Witness;
    type Error = &'static str;

    /// Runs the program against the given predicate, witness, and context.
    ///
    /// At this point the predicate and witness have been parsed and validated
    /// non-contextually, and are guaranteed to both be for this program. All subsequent
    /// validation is this function's responsibility.
    fn verify_inner(
        &self,
        predicate: &Predicate,
        witness: &Witness,
        ctx: &C,
    ) -> Result<(), &'static str> {
        // This match statement is selecting the mode that the program is operating in,
        // based on the enums defined in the parser.
        match (predicate, witness) {
            (Predicate::Open(p_open), Witness::Open(w_open)) => {
                // In OPEN mode, we enforce that the transaction must only contain inputs
                // and outputs from this program. The consensus rules enforce that if a
                // transaction contains both WTP inputs and WTP outputs, they must all be
                // of the same program type. Therefore we only need to check that the
                // transaction does not contain any other type of input or output.
                if !ctx.is_tze_and_vout_only() {
                    return Err(
                        "Bolt WTP cannot be closed in a transaction with multiple non-WTP inputs or outputs",
                    );
                }

                // (1) p_open.address == close tx output with this address
                // (2) check that the two outputs for the close tx for the pks
                match &ctx.tx_tze_outputs() {
                    [tze_out] => match &tze_out.precondition.try_to::<Predicate>() {
                        Ok(Predicate::Close(p_close)) => {
                            // to merchant output address and value
                            let tx2_pubkey = ctx.get_tx_output_pk().unwrap(); // TODO: handle safely
                            let tx2_output_value = ctx.get_tx_output_value().unwrap();

                            // to customer WTP output value
                            let tx1_value = tze_out.value;

                            // Check if block_height is more than 24h away.
                            if p_close.block_height < 0 || p_close.block_height - ctx.block_height() < 144 {
                                return Err("The block height should be more than 24h in the future");
                            }

                            // Check that witness type set correctly
                            if w_open.witness_type != 0x1 {
                                return Err("Invalid witness type specified for this Bolt WTP mode")
                            }

                            // Check that tx outputs have the correct balances
                            let is_tx_output1_correct = convert_to_amount(w_open.cust_bal) == tx1_value;
                            let is_tx_output2_correct = convert_to_amount(w_open.merch_bal) == tx2_output_value;
                            let is_tx_output_correct= is_tx_output1_correct && is_tx_output2_correct;

                            // Get the tx hash for the transaction (signatures in witness are supposed to be valid w.r.t this hash)
                            let tx_hash = ctx.get_tx_hash();
                            // Verify channel opening against the witness info provided
                            let is_channel_valid = verify_channel_opening(p_open, w_open, &tx_hash, tx2_pubkey);

                            if is_channel_valid && is_tx_output_correct {
                                Ok(())
                            } else {
                                Err("could not validate channel opening - cust close")
                            }
                        }
                        Ok(Predicate::MerchClose(p_close)) => {
                            // Check if block_height is more than 24h away.
                            if p_close.block_height < 0 || p_close.block_height - ctx.block_height() < 144 {
                                return Err("The block height should be more than 24h in the future");
                            }

                            let tx1_value = tze_out.value;
                            let is_tx_output_correct = convert_to_amount(w_open.cust_bal + w_open.merch_bal) == tx1_value;
                            // check_merchant_output(w_open, tx1_value, p_close);

                            let tx_hash = ctx.get_tx_hash();
                            let tx2_pubkey = p_close.pubkey.clone();
                            let is_valid = verify_channel_opening(p_open, w_open, &tx_hash, tx2_pubkey);

                            if is_valid && is_tx_output_correct {
                                Ok(())
                            } else {
                                Err("could not validate channel opening - merch close")
                            }
                        }
                        _ => Err("Could not parse to a BOLT predicate"),
                    },
                    _ => Err("Invalid number of BOLT outputs"),
                }
            }
            (Predicate::Close(p_close), Witness::Close(w_close)) => {
                if !ctx.is_vout_only() {
                    return Err(
                        "Bolt WTP cannot be closed in a transaction with multiple outputs or WTP outputs",
                    );
                }
                if w_close.witness_type == 0x0 && p_close.block_height > ctx.block_height() {
                    return Err("Timelock has not been met")
                }
                if Amount::from_u64(p_close.amount as u64).unwrap() != ctx.get_tx_output_value().unwrap() {
                    return Err("The outgoing amount is not correct.")
                }

                let tx_hash = ctx.get_tx_hash();
                let is_valid = verify_channel_closing(p_close, w_close, &tx_hash);
                if is_valid {
                    Ok(())
                } else {
                    Err("could not validate channel closing initiated by customer")
                }
            }
            (Predicate::MerchClose(p_close), Witness::MerchClose(w_close)) => {
                if w_close.witness_type == 0x0 {
                    if !ctx.is_vout_only() {
                        return Err(
                            "Bolt WTP cannot be closed in a transaction with multiple outputs or WTP outputs",
                        );
                    }
                    if p_close.block_height > ctx.block_height() {
                        return Err("Timelock has not been met")
                    }
                    if ctx.get_tx_output_value().unwrap() != Amount::from_u64((w_close.merch_bal + w_close.cust_bal) as u64).unwrap() {
                        return Err("The outgoing amount is not correct.");
                    }
                }

                let mut tx2_pk = vec![];
                if w_close.witness_type == 0x1 {
                    if !ctx.is_tze_and_vout_only() {
                        return Err(
                            "Bolt WTP cannot be closed in a transaction with multiple non-WTP inputs or outputs",
                        );
                    }
                    let tx2_pubkey = match &ctx.tx_tze_outputs() {
                        [tze_out] => match &tze_out.precondition.try_to::<Predicate>() {
                            Ok(Predicate::Close(out)) => Ok(out.pubkey.clone()),
                            _ => Err("Invalid BOLT output type"),
                        }
                        _ => Err("Invalid number of BOLT outputs"),
                    };

                    tx2_pk = tx2_pubkey.unwrap();

                    if ctx.get_tx_output_value().unwrap() != Amount::from_u64(w_close.merch_bal as u64).unwrap() {
                        return Err("The outgoing amount to merchant is not correct.");
                    }
                    if ctx.get_tx_tze_output_value().unwrap() != Amount::from_u64(w_close.cust_bal as u64).unwrap() {
                        return Err("The outgoing amount to customer is not correct.");
                    }
                }

                let tx_hash = ctx.get_tx_hash();
                let is_valid = verify_channel_merch_closing(p_close, w_close, &tx_hash, tx2_pk);
                if is_valid {
                    Ok(())
                } else {
                    Err("could not validate channel closing initiated by merchant")
                }

            }
            _ => Err("Mode mismatch"),
        }
    }

}


#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use blake2b_simd::Params;
    use std::fs::File;
    use std::io::Read;

    use zcash_extensions_api::transparent::{self as tze, Extension, ToPayload, FromPayload};
    use crate::{
        transaction::{
            components::{Amount, OutPoint, TzeIn, TzeOut},
            Transaction, TxId,
            TransactionData,
        },
        extensions::transparent::{
            bolt,
        }
    };

    use super::{
        parse_open_witness_input, 
        parse_close_witness_input, 
        convert_bytes_to_u64, 
        convert_bytes_to_i32, 
        parse_merch_close_witness_input,
        compute_tx_signature,
        merch_close, close, open, Predicate, Witness, Program
    };

    use crate::transaction::components::TxOut;
    use crate::legacy::Script;

    #[test]
    fn predicate_open_round_trip() {
        let data = vec![7; 1107];
        let p: Predicate = (open::MODE, &data[..]).try_into().unwrap();
        let mut channel_token = Vec::new();

        let mut pubkey = Vec::new(); // [0; 33];
        pubkey.extend(data[0..33].iter());

        channel_token.extend(data[33..].iter());

        assert_eq!(p, Predicate::Open(open::Predicate { pubkey, channel_token }));
        assert_eq!(p.to_payload(), (open::MODE, data));
    }

    #[test]
    fn predicate_close_round_trip() {
        let data = vec![7; 1119];
        let p: Predicate = (close::MODE, &data[..]).try_into().unwrap();

        let mut pubkey = Vec::new(); // [0; 33];
        pubkey.extend(data[0..33].iter());
        let amount = convert_bytes_to_u64(&data[33..41]);
        let block_height = convert_bytes_to_i32(&data[41..45]);

        let mut channel_token: Vec<u8> = Vec::new();
        channel_token.extend(data[45..].iter());

        assert_eq!(p, Predicate::Close(close::Predicate { pubkey, amount, block_height, channel_token }));
        assert_eq!(p.to_payload(), (close::MODE, data));
    }

    #[test]
    fn predicate_merch_close_round_trip() {
        let data = vec![7; 1111];
        let p: Predicate = (merch_close::MODE, &data[..]).try_into().unwrap();

        let mut pubkey = Vec::new();
        pubkey.extend(data[0..33].iter());
        let block_height = convert_bytes_to_i32(&data[33..37]);

        let mut channel_token: Vec<u8> = Vec::new();
        channel_token.extend(data[37..].iter());

        assert_eq!(p, Predicate::MerchClose(merch_close::Predicate { pubkey, block_height, channel_token }));
        assert_eq!(p.to_payload(), (merch_close::MODE, data));
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
        let mut data = vec![7; 219];
        data.insert(0, 0x1);
        data[17] = 72;
        data[90] = 96;

        let w: Witness = (open::MODE, &data[..]).try_into().unwrap();
        let mut witness_input = [0; 220];
        witness_input.copy_from_slice(&data);
        let witness = parse_open_witness_input(witness_input);

        assert_eq!(w, Witness::Open(witness));
        assert_eq!(w.to_payload(), (open::MODE, data));
    }

    #[test]
    fn witness_close_round_trip_mode0() {
        let mut data = vec![7; 179];
        data.insert(0, 0x0);
        data[34] = 0x48;

        let w: Witness = (close::MODE, &data[..]).try_into().unwrap();
        let mut witness_input = [0; 180];
        witness_input.copy_from_slice(&data);
        let witness = parse_close_witness_input(witness_input);

        assert_eq!(w, Witness::Close(witness));
        assert_eq!(w.to_payload(), (close::MODE, data[0..107].to_vec()));
    }

    #[test]
    fn witness_close_round_trip_mode1() {
        let mut data = vec![7; 179];
        data.insert(0, 0x1);
        data[34] = 0x48;
        data[107] = 0x48;

        let w: Witness = (close::MODE, &data[..]).try_into().unwrap();
        let mut witness_input = [0; 180];
        witness_input.copy_from_slice(&data);
        let witness = parse_close_witness_input(witness_input);

        assert_eq!(w, Witness::Close(witness));
        assert_eq!(w.to_payload(), (close::MODE, data));
    }

    #[test]
    fn witness_merch_close_round_trip_mode0() {
        let mut data = vec![7; 219];
        data.insert(0, 0x0);
        data[1] = 72;

        let w: Witness = (merch_close::MODE, &data[..]).try_into().unwrap();
        let mut witness_input = [0; 220];
        witness_input.copy_from_slice(&data);
        let witness = parse_merch_close_witness_input(witness_input);

        assert_eq!(w, Witness::MerchClose(witness));
        assert_eq!(w.to_payload(), (merch_close::MODE, data[0..90].to_vec()));
    }

    #[test]
    fn witness_merch_close_round_trip_mode1() {
        let mut data = vec![7; 219];
        data.insert(0, 0x1);
        data[1] = 72;
        data[90] = 96;

        let w: Witness = (merch_close::MODE, &data[..]).try_into().unwrap();
        let mut witness_input = [0; 220];
        witness_input.copy_from_slice(&data);
        let witness = parse_merch_close_witness_input(witness_input);

        assert_eq!(w, Witness::MerchClose(witness));
        assert_eq!(w.to_payload(), (merch_close::MODE, data));
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

    const OPEN_WITNESS_LEN: usize = 220;
    const MERCH_CLOSE_WITNESS_LEN: usize = 220;
    const CLOSE_WITNESS_LEN: usize = 180;
    const CLOSE_PREDICATE_LEN: usize = 1119;
    const OPEN_PREDICATE_LEN: usize = 1107;
    const MERCH_CLOSE_PREDICATE_LEN: usize = 1111;

    fn read_file<'a>(name: &'a str) -> std::io::Result<Vec<u8>> {
        let mut file = File::open(name).unwrap();

        let mut data = Vec::new();
        file.read_to_end(&mut data);

        return Ok(data);
    }

    fn generate_customer_close_witness(cust_bal: [u8; 8], merch_bal: [u8; 8], cust_sig: &Vec<u8>, close_token: &Vec<u8>, wpk: &Vec<u8>) -> [u8; OPEN_WITNESS_LEN] {
        let mut close_witness_input = [0u8; OPEN_WITNESS_LEN];
        let mut close_witness_vec: Vec<u8> = Vec::new();
        close_witness_vec.push(0x1);
        close_witness_vec.extend(cust_bal.iter());
        close_witness_vec.extend(merch_bal.iter());
        close_witness_vec.push(cust_sig.len() as u8);
        close_witness_vec.extend(cust_sig.iter());
        close_witness_vec.push(close_token.len() as u8);
        close_witness_vec.extend(close_token.iter());
        close_witness_vec.extend(wpk.iter());
        let pad = OPEN_WITNESS_LEN - close_witness_vec.len();
        for i in 0 .. pad {
            close_witness_vec.push(0x0);
        }
        close_witness_input.copy_from_slice(close_witness_vec.as_slice());

        return close_witness_input;
    }

    fn generate_customer_merch_close_witness(cust_bal: [u8; 8], merch_bal: [u8; 8], cust_sig: &Vec<u8>, close_token: &Vec<u8>, wpk: &Vec<u8>) -> [u8; MERCH_CLOSE_WITNESS_LEN] {
        let mut close_witness_input = [0u8; MERCH_CLOSE_WITNESS_LEN];
        let mut close_witness_vec: Vec<u8> = Vec::new();
        close_witness_vec.push(0x1);
        close_witness_vec.push(cust_sig.len() as u8);
        close_witness_vec.extend(cust_sig.iter());
        close_witness_vec.extend(cust_bal.iter());
        close_witness_vec.extend(merch_bal.iter());
        close_witness_vec.push(close_token.len() as u8);
        close_witness_vec.extend(close_token.iter());
        close_witness_vec.extend(wpk.iter());
        let pad = MERCH_CLOSE_WITNESS_LEN - close_witness_vec.len();
        for i in 0 .. pad {
            close_witness_vec.push(0x0);
        }
        close_witness_input.copy_from_slice(close_witness_vec.as_slice());

        return close_witness_input;
    }

    fn generate_merchant_unilateral_close_witness(cust_bal: [u8; 8], merch_bal: [u8; 8], sig: &Vec<u8>) -> [u8; MERCH_CLOSE_WITNESS_LEN] {
        let mut close_witness_input = [0u8; MERCH_CLOSE_WITNESS_LEN];
        let mut close_witness_vec: Vec<u8> = Vec::new();
        close_witness_vec.push(0x0);
        close_witness_vec.push(sig.len() as u8);
        close_witness_vec.extend(sig.iter());
        close_witness_vec.extend(cust_bal.iter());
        close_witness_vec.extend(merch_bal.iter());
        let pad = MERCH_CLOSE_WITNESS_LEN - close_witness_vec.len();
        for i in 0 .. pad {
            close_witness_vec.push(0x0);
        }
        close_witness_input.copy_from_slice(close_witness_vec.as_slice());
        return close_witness_input;
    }

    fn generate_merchant_close_witness(cust_bal: [u8; 8], merch_bal: [u8; 8], cust_sig: &Vec<u8>, merch_sig: &Vec<u8>) -> [u8; OPEN_WITNESS_LEN] {
        let mut close_witness_input = [0u8; OPEN_WITNESS_LEN];
        let mut close_witness_vec: Vec<u8> = Vec::new();
        close_witness_vec.push(0x0);
        close_witness_vec.extend(cust_bal.iter());
        close_witness_vec.extend(merch_bal.iter());
        close_witness_vec.push(cust_sig.len() as u8);
        close_witness_vec.extend(cust_sig.iter());
        close_witness_vec.push(merch_sig.len() as u8);
        close_witness_vec.extend(merch_sig.iter());
        let pad = OPEN_WITNESS_LEN - close_witness_vec.len();
        for i in 0 .. pad {
            close_witness_vec.push(0x0);
        }
        close_witness_input.copy_from_slice(close_witness_vec.as_slice());
        return close_witness_input;
    }

    fn generate_merchant_revoke_witness(address: &Vec<u8>, sig: &Vec<u8>, revoke_token: &Vec<u8>) -> [u8; CLOSE_WITNESS_LEN] {
        let mut revoke_witness_input = [0u8; CLOSE_WITNESS_LEN];
        let mut revoke_witness_vec: Vec<u8> = Vec::new();
        revoke_witness_vec.push(0x1);
        revoke_witness_vec.extend(address.iter());
        revoke_witness_vec.push(sig.len() as u8);
        revoke_witness_vec.extend(sig.iter());
        revoke_witness_vec.push(revoke_token.len() as u8);
        revoke_witness_vec.extend(revoke_token.iter());
        let pad = CLOSE_WITNESS_LEN - revoke_witness_vec.len();
        for i in 0 .. pad {
            revoke_witness_vec.push(0x0);
        }
        revoke_witness_input.copy_from_slice(revoke_witness_vec.as_slice());
        return revoke_witness_input;
    }

    fn generate_spend_tx_witness(address: &Vec<u8>, sig: &Vec<u8>) -> [u8; CLOSE_WITNESS_LEN] {
        let mut spend_witness_input = [0u8; CLOSE_WITNESS_LEN];
        let mut spend_witness_vec: Vec<u8> = Vec::new();
        spend_witness_vec.push(0x0);
        spend_witness_vec.extend(address.iter());
        spend_witness_vec.push(sig.len() as u8);
        spend_witness_vec.extend(sig.iter());
        let pad = CLOSE_WITNESS_LEN - spend_witness_vec.len();
        for i in 0 .. pad {
            spend_witness_vec.push(0x0);
        }
        spend_witness_input.copy_from_slice(spend_witness_vec.as_slice());
        return spend_witness_input;
    }

    fn generate_predicate(pubkey: &Vec<u8>, amount: [u8; 8], block_height: [u8; 4], channel_token: &Vec<u8>) -> [u8; CLOSE_PREDICATE_LEN] {
        let mut tx_predicate = [0u8; CLOSE_PREDICATE_LEN];
        let mut tx_pred: Vec<u8> = Vec::new();
        tx_pred.extend(pubkey.iter());
        tx_pred.extend(amount.iter());
        tx_pred.extend(block_height.iter());
        tx_pred.extend(channel_token.iter());
        tx_predicate.copy_from_slice(tx_pred.as_slice());
        return tx_predicate;
    }

    fn generate_open_predicate(pubkey: &Vec<u8>, channel_token: &Vec<u8>) -> [u8; OPEN_PREDICATE_LEN] {
        let mut tx_predicate = [0u8; OPEN_PREDICATE_LEN];
        let mut tx_pred: Vec<u8> = Vec::new();
        tx_pred.extend(pubkey.iter());
        tx_pred.extend(channel_token.iter());
        tx_predicate.copy_from_slice(tx_pred.as_slice());
        return tx_predicate;
    }

    fn generate_merch_close_predicate(pubkey: &Vec<u8>, block_height: [u8; 4], channel_token: &Vec<u8>) -> [u8; MERCH_CLOSE_PREDICATE_LEN] {
        let mut tx_predicate = [0u8; MERCH_CLOSE_PREDICATE_LEN];
        let mut tx_pred: Vec<u8> = Vec::new();
        tx_pred.extend(pubkey.iter());
        tx_pred.extend(block_height.iter());
        tx_pred.extend(channel_token.iter());
        tx_predicate.copy_from_slice(tx_pred.as_slice());
        return tx_predicate;
    }

    fn tzeOut<P: ToPayload>(amount: u64, value: &P) -> TzeOut {
        TzeOut {
            value: Amount::from_u64(amount).unwrap(),
            precondition: tze::Precondition::from(1, value),
        }
    }

    fn tzeIn<W: ToPayload>(txid: TxId, value: &W) -> TzeIn {
        TzeIn {
            prevout: OutPoint::new(txid.0, 0),
            witness: tze::Witness::from(1, value),
        }
    }

    // this is 
    pub struct Ctx<'a> {
        pub height: i32,
        pub tx: &'a Transaction,
    }

    impl<'a> Ctx<'a> {
        /// Generates a version 1 WTP context.
        pub fn v1(height: i32, tx: &'a Transaction) -> Self {
            Ctx {
                height: height,
                tx: tx,
            }
        }
    }

    impl<'a> bolt::Context for Ctx<'a> {
        fn block_height(&self) -> i32 {
            self.height
        }

        fn tx(&self) -> &Transaction {
            &self.tx
        }
    }

    #[test]
    fn bolt_program_open_and_close() {

        let _ser_channel_token = hex::decode(read_file("bolt_testdata/channel.token").unwrap()).unwrap();

        let escrow_tx_hash= vec![218, 142, 74, 74, 236, 37, 47, 120, 241, 20, 203, 94, 78, 126, 131, 174, 4, 3, 75, 81, 194, 90, 203, 24, 16, 158, 53, 237, 241, 57, 97, 137];

        let pk_c = hex::decode("0398cb634c1bf97559dfcc47b6c8cc3cce8be2219e571ff721b95130efe065991a").unwrap();
        let sk_c = hex::decode("ee3c802d34a1359b9d3b2a81773730325f7634e2991336c534cbd180980ec581").unwrap();

        let pk_m = hex::decode("03504d8f01942e63cde2caa0c741f8e651a0d339afa9ad5a854bc41e9240492ac2").unwrap();
        let sk_m = hex::decode("4a86f3d5a1edc4ae633216db6efe07d8f358626d595de288816619a10c61e98c").unwrap();

        let cust_sig1 = compute_tx_signature(&sk_c, &escrow_tx_hash);
        // println!("cust sig: {:?}, len: {}", cust_sig, cust_sig.len());

        let merch_tx_hash = vec![161, 57, 186, 255, 37, 146, 146, 208, 208, 38, 1, 222, 7, 151, 43, 160, 164, 115, 162, 54, 211, 138, 190, 1, 179, 131, 22, 210, 56, 163, 143, 113];
        let cust_sig2 = compute_tx_signature(&sk_c, &merch_tx_hash);
        let merch_sig = compute_tx_signature(&sk_m, &merch_tx_hash);

        let wpk = hex::decode("02b4395f62fc0b786902b37924c2773195ad707ef07dd5ec7e31f2b3cda4804d8c").unwrap();

        let mut _merch_close_addr = hex::decode("0a1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let _merch_close_addr2 = hex::decode("0b2222222222222222222222222222222222222222222222222222222222222222").unwrap();

        let merch_close_address = Script(_merch_close_addr.clone());
        let merch_close_address_dup = Script(_merch_close_addr.clone());
        let merch_close_address_dup2 = Script(_merch_close_addr.clone());
        let merch_close_address_dup3 = Script(_merch_close_addr.clone());
        let merch_close_address_dup4 = Script(_merch_close_addr.clone());

        let escrow_tx_predicate= generate_open_predicate(&_merch_close_addr, &_ser_channel_token);

        // 1 byte mode + 4 bytes cust_bal + 4 bytes merch_bal + 72 bytes cust_sig + 96 bytes close token
        let close_token = hex::decode("8d4ff4d96f17760cabdd9728e667596c2c6d238427dd0529f2b6b60140fc71efc890e03502bdae679ca09236fbb11d9d832b9fc275bf44bad06fd9d0b0296722140273f6cba23859b48c3aaa5ed25455e70bd665165169956be25708026478b6").unwrap();

        let cust_close_witness_input = generate_customer_close_witness([0,0,0,0,0,0,0,140], [0,0,0,0,0,0,0,70], &cust_sig1, &close_token, &wpk);
        let merch_close_witness_input = generate_merchant_close_witness([0,0,0,0,0,0,0,200], [0,0,0,0,0,0,0,10], &cust_sig2, &merch_sig);

        let cust_close_tx_predicate = generate_predicate(&wpk, [0,0,0,0,0,0,0,140], [0,0,0,146], &_ser_channel_token);
        let cust_close_tx_predicate_too_early = generate_predicate(&wpk, [0,0,0,0,0,0,0,140], [0,0,0,110], &_ser_channel_token);
        let merch_close_tx_predicate = generate_merch_close_predicate(&_merch_close_addr2, [0,0,0,146], &_ser_channel_token);

        let merch_tx_hash2= vec![218, 142, 74, 74, 236, 37, 47, 120, 241, 20, 203, 94, 78, 126, 131, 174, 4, 3, 75, 81, 194, 90, 203, 24, 16, 158, 53, 237, 241, 57, 97, 137];
        let cust_sig3 = compute_tx_signature(&sk_c, &merch_tx_hash2);
        let cust_close_witness_input2 = generate_customer_merch_close_witness([0,0,0,0,0,0,0,140], [0,0,0,0,0,0,0,70], &cust_sig3, &close_token, &wpk);

        let extId = 1;

        // escrow-tx (lock up 210 zats)
        let mut mtx_a = TransactionData::nu4();
        mtx_a.tze_outputs.push(tzeOut(210, &Predicate::open(escrow_tx_predicate)));
        let tx_a = mtx_a.freeze().unwrap();
        // println!("debug: Escrow transaction: {:?}", tx_a);

        // begin - customer-close-tx
        let mut mtx_b = TransactionData::nu4();
        mtx_b.tze_inputs.push(tzeIn(tx_a.txid(), &Witness::open(cust_close_witness_input)));
        // to_customer
        mtx_b.tze_outputs.push(tzeOut(140, &Predicate::close(cust_close_tx_predicate)));
        // to_merchant
        mtx_b.vout.push(TxOut {
            value: Amount::from_u64(70).unwrap(),
            script_pubkey: merch_close_address,
        });
        let tx_b = mtx_b.freeze().unwrap();
        // end - customer-close-tx
        // println!("debug: Customer close transaction: {:?}", tx_b);

        // begin - merchant-close-tx
        let mut mtx_c = TransactionData::nu4();
        mtx_c.tze_inputs.push(tzeIn(tx_a.txid(), &Witness::open(merch_close_witness_input)));
        // to_merchant
        mtx_c.tze_outputs.push(tzeOut(210, &Predicate::merch_close(merch_close_tx_predicate)));
        let tx_c = mtx_c.freeze().unwrap();
        // end - merchant-close-tx
        // println!("debug: Merchant close transaction: {:?}", tx_c);

        // begin - customer-close-tx (spending from merchant-close-tx)
        let mut mtx_d = TransactionData::nu4();
        mtx_d.tze_inputs.push(tzeIn(tx_c.txid(), &Witness::merch_close(cust_close_witness_input2)));
        // to_customer
        mtx_d.tze_outputs.push(tzeOut(140, &Predicate::close(cust_close_tx_predicate)));
        // to_merchant
        mtx_d.vout.push(TxOut {
            value: Amount::from_u64(70).unwrap(),
            script_pubkey: merch_close_address_dup,
        });
        let tx_d = mtx_d.freeze().unwrap();
        // end - customer-close-tx (spending from merchant-close-tx)
        // println!("debug: Customer close transaction spending from merchant-close tx: {:?}", tx_d);

        // begin - customer-close-tx
        let mut mtx_e = TransactionData::nu4();
        mtx_e.tze_inputs.push(tzeIn(tx_a.txid(), &Witness::open(cust_close_witness_input)));
        // to_customer
        mtx_e.tze_outputs.push(tzeOut(140, &Predicate::close(cust_close_tx_predicate_too_early)));
        // to_merchant
        mtx_e.vout.push(TxOut {
            value: Amount::from_u64(70).unwrap(),
            script_pubkey: merch_close_address_dup2,
        });
        let tx_e = mtx_e.freeze().unwrap();

        // begin - customer-close-tx (spending from merchant-close-tx)
        let mut mtx_f = TransactionData::nu4();
        mtx_f.tze_inputs.push(tzeIn(tx_c.txid(), &Witness::merch_close(cust_close_witness_input2)));
        // to_customer
        mtx_f.tze_outputs.push(tzeOut(130, &Predicate::close(cust_close_tx_predicate)));
        // to_merchant
        mtx_f.vout.push(TxOut {
            value: Amount::from_u64(70).unwrap(),
            script_pubkey: merch_close_address_dup3,
        });
        let tx_f = mtx_f.freeze().unwrap();
        // end - customer-close-tx (spending from merchant-close-tx)

        // begin - customer-close-tx (spending from merchant-close-tx)
        let mut mtx_g = TransactionData::nu4();
        mtx_g.tze_inputs.push(tzeIn(tx_c.txid(), &Witness::merch_close(cust_close_witness_input2)));
        // to_customer
        mtx_g.tze_outputs.push(tzeOut(140, &Predicate::close(cust_close_tx_predicate)));
        // to_merchant
        mtx_g.vout.push(TxOut {
            value: Amount::from_u64(60).unwrap(),
            script_pubkey: merch_close_address_dup4,
        });
        let tx_g = mtx_g.freeze().unwrap();
        // end - customer-close-tx (spending from merchant-close-tx)

        let program = Program { };

        // Verify tx_b
        {
            let ctx = Ctx::v1(1, &tx_b);
            assert_eq!(
                program.verify(
                    &tx_a.tze_outputs[0].precondition, // escrow
                    &tx_b.tze_inputs[0].witness, // customer-close-tx
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_e time lock block height is too short
        {
            let ctx = Ctx::v1(1, &tx_e);
            assert_eq!(
                program.verify(
                    &tx_a.tze_outputs[0].precondition, // escrow
                    &tx_e.tze_inputs[0].witness, // customer-close-tx
                    &ctx
                ),
                Err("The block height should be more than 24h in the future")
            );
        }

        // Verify tx_c
        {
            let ctx = Ctx::v1(1, &tx_c);
            assert_eq!(
                program.verify(
                    &tx_a.tze_outputs[0].precondition, // escrow
                    &tx_c.tze_inputs[0].witness, // merchant-close-tx (initiating closing)
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_d (customer-close-tx spending from merch-close-tx)
        {
            let ctx = Ctx::v1(2, &tx_d);
            assert_eq!(
                program.verify(
                    &tx_c.tze_outputs[0].precondition, // merchant-close-tx
                    &tx_d.tze_inputs[0].witness, // customer-close-tx
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_f (customer-close-tx spending from merch-close-tx)
        {
            let ctx = Ctx::v1(2, &tx_f);
            assert_eq!(
                program.verify(
                    &tx_c.tze_outputs[0].precondition, // merchant-close-tx
                    &tx_f.tze_inputs[0].witness, // customer-close-tx
                    &ctx
                ),
                Err("The outgoing amount to customer is not correct.")
            );
        }

        // Verify tx_g (customer-close-tx spending from merch-close-tx)
        {
            let ctx = Ctx::v1(2, &tx_g);
            assert_eq!(
                program.verify(
                    &tx_c.tze_outputs[0].precondition, // merchant-close-tx
                    &tx_g.tze_inputs[0].witness, // customer-close-tx
                    &ctx
                ),
                Err("The outgoing amount to merchant is not correct.")
            );
        }

    }

    #[test]
    fn bolt_program_unilateral_merch() {

        let _ser_channel_token = hex::decode(read_file("bolt_testdata/channel.token").unwrap()).unwrap();

        let escrow_tx_hash= vec![218, 142, 74, 74, 236, 37, 47, 120, 241, 20, 203, 94, 78, 126, 131, 174, 4, 3, 75, 81, 194, 90, 203, 24, 16, 158, 53, 237, 241, 57, 97, 137];

        let pk_c = hex::decode("0398cb634c1bf97559dfcc47b6c8cc3cce8be2219e571ff721b95130efe065991a").unwrap();
        let sk_c = hex::decode("ee3c802d34a1359b9d3b2a81773730325f7634e2991336c534cbd180980ec581").unwrap();

        let pk_m = hex::decode("03504d8f01942e63cde2caa0c741f8e651a0d339afa9ad5a854bc41e9240492ac2").unwrap();
        let sk_m = hex::decode("4a86f3d5a1edc4ae633216db6efe07d8f358626d595de288816619a10c61e98c").unwrap();

        let cust_sig1 = compute_tx_signature(&sk_c, &escrow_tx_hash);
        // println!("cust sig: {:?}, len: {}", cust_sig, cust_sig.len());

        let merch_tx_hash = vec![161, 57, 186, 255, 37, 146, 146, 208, 208, 38, 1, 222, 7, 151, 43, 160, 164, 115, 162, 54, 211, 138, 190, 1, 179, 131, 22, 210, 56, 163, 143, 113];
        let cust_sig2 = compute_tx_signature(&sk_c, &merch_tx_hash);
        let merch_sig = compute_tx_signature(&sk_m, &merch_tx_hash);

        let wpk = hex::decode("02b4395f62fc0b786902b37924c2773195ad707ef07dd5ec7e31f2b3cda4804d8c").unwrap();

        let mut _merch_close_addr = hex::decode("0a1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let _merch_close_addr2 = hex::decode("0b2222222222222222222222222222222222222222222222222222222222222222").unwrap();

        let merch_close_address = Script(_merch_close_addr.clone());
        let merch_close_address_dup = Script(_merch_close_addr.clone());
        let merch_close_address_dup2 = Script(_merch_close_addr.clone());

        let escrow_tx_predicate= generate_open_predicate(&_merch_close_addr, &_ser_channel_token);

        // 1 byte mode + 4 bytes cust_bal + 4 bytes merch_bal + 72 bytes cust_sig + 96 bytes close token
        let close_token = hex::decode("8d4ff4d96f17760cabdd9728e667596c2c6d238427dd0529f2b6b60140fc71efc890e03502bdae679ca09236fbb11d9d832b9fc275bf44bad06fd9d0b0296722140273f6cba23859b48c3aaa5ed25455e70bd665165169956be25708026478b6").unwrap();

        let merch_close_witness_input = generate_merchant_close_witness([0,0,0,0,0,0,0,200], [0,0,0,0,0,0,0,10], &cust_sig2, &merch_sig);

        let merch_close_tx_predicate = generate_merch_close_predicate(&_merch_close_addr2, [0,0,0,146], &_ser_channel_token);
        let merch_close_tx_predicate_too_early = generate_merch_close_predicate(&_merch_close_addr2, [0,0,0,110], &_ser_channel_token);

        let merch_tx_hash2= vec![175, 134, 188, 203, 129, 93, 74, 219, 67, 195, 80, 143, 144, 87, 109, 169, 129, 138, 65, 71, 66, 23, 117, 101, 91, 204, 217, 196, 36, 124, 91, 87];
        let merch_sig = compute_tx_signature(&sk_m, &merch_tx_hash2);
        let merch_close_witness = generate_merchant_unilateral_close_witness([0,0,0,0,0,0,0,140], [0,0,0,0,0,0,0,70], &merch_sig);

        // escrow-tx (lock up 210 zats)
        let mut mtx_a = TransactionData::nu4();
        mtx_a.tze_outputs.push(tzeOut(210, &Predicate::open(escrow_tx_predicate)));
        let tx_a = mtx_a.freeze().unwrap();
        // println!("debug: Escrow transaction: {:?}", tx_a);

        // begin - merchant-close-tx
        let mut mtx_b = TransactionData::nu4();
        mtx_b.tze_inputs.push(tzeIn(tx_a.txid(), &Witness::open(merch_close_witness_input)));
        // to_merchant
        mtx_b.tze_outputs.push(tzeOut(210, &Predicate::merch_close(merch_close_tx_predicate_too_early)));
        let tx_b = mtx_b.freeze().unwrap();
        // end - merchant-close-tx

        // begin - merchant-close-tx
        let mut mtx_c = TransactionData::nu4();
        mtx_c.tze_inputs.push(tzeIn(tx_a.txid(), &Witness::open(merch_close_witness_input)));
        // to_merchant
        mtx_c.tze_outputs.push(tzeOut(210, &Predicate::merch_close(merch_close_tx_predicate)));
        let tx_c = mtx_c.freeze().unwrap();
        // end - merchant-close-tx

        // begin - merchant-spending-tx (spending from merchant-close-tx)
        let mut mtx_d = TransactionData::nu4();
        mtx_d.tze_inputs.push(tzeIn(tx_c.txid(), &Witness::merch_close(merch_close_witness)));
        // to_merchant
        mtx_d.vout.push(TxOut {
            value: Amount::from_u64(210).unwrap(),
            script_pubkey: merch_close_address_dup,
        });
        let tx_d = mtx_d.freeze().unwrap();
        // end - customer-close-tx (spending from merchant-close-tx)
        // println!("debug: Customer close transaction spending from merchant-close tx: {:?}", tx_d);

        // begin - merchant-spending-tx (spending from merchant-close-tx)
        let mut mtx_e = TransactionData::nu4();
        mtx_e.tze_inputs.push(tzeIn(tx_c.txid(), &Witness::merch_close(merch_close_witness)));
        // to_merchant
        mtx_e.vout.push(TxOut {
            value: Amount::from_u64(200).unwrap(),
            script_pubkey: merch_close_address_dup2,
        });
        let tx_e = mtx_e.freeze().unwrap();
        // end - customer-close-tx (spending from merchant-close-tx)

        let program = Program { };

        // Verify tx_b
        {
            let ctx = Ctx::v1(1, &tx_b);
            assert_eq!(
                program.verify(
                    &tx_a.tze_outputs[0].precondition, // escrow
                    &tx_b.tze_inputs[0].witness, // merchant-close-tx (initiating closing)
                    &ctx
                ),
                Err("The block height should be more than 24h in the future")
            );
        }

        // Verify tx_c
        {
            let ctx = Ctx::v1(1, &tx_c);
            assert_eq!(
                program.verify(
                    &tx_a.tze_outputs[0].precondition, // escrow
                    &tx_c.tze_inputs[0].witness, // merchant-close-tx (initiating closing)
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_d (merch-spend-tx spending from merch-close-tx)
        {
            let ctx = Ctx::v1(110, &tx_d);
            assert_eq!(
                program.verify(
                    &tx_c.tze_outputs[0].precondition, // merchant-close-tx
                    &tx_d.tze_inputs[0].witness, // customer-close-tx
                    &ctx
                ),
                Err("Timelock has not been met")
            );
        }

        // Verify tx_d (merch-spend-tx spending from merch-close-tx)
        {
            let ctx = Ctx::v1(150, &tx_d);
            assert_eq!(
                program.verify(
                    &tx_c.tze_outputs[0].precondition, // merchant-close-tx
                    &tx_d.tze_inputs[0].witness, // customer-close-tx
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_e (merch-spend-tx spending from merch-close-tx)
        {
            let ctx = Ctx::v1(150, &tx_e);
            assert_eq!(
                program.verify(
                    &tx_c.tze_outputs[0].precondition, // merchant-close-tx
                    &tx_e.tze_inputs[0].witness, // customer-close-tx
                    &ctx
                ),
                Err("The outgoing amount is not correct.")
            );
        }

    }

    #[test]
    fn bolt_merch_revoke_program() {

        let _ser_channel_token = hex::decode(read_file("bolt_testdata/channel.token").unwrap()).unwrap();

        let escrow_tx_hash= vec![218, 142, 74, 74, 236, 37, 47, 120, 241, 20, 203, 94, 78, 126, 131, 174, 4, 3, 75, 81, 194, 90, 203, 24, 16, 158, 53, 237, 241, 57, 97, 137];

        let pk_c = hex::decode("0398cb634c1bf97559dfcc47b6c8cc3cce8be2219e571ff721b95130efe065991a").unwrap();
        let sk_c = hex::decode("ee3c802d34a1359b9d3b2a81773730325f7634e2991336c534cbd180980ec581").unwrap();

        let pk_m = hex::decode("03504d8f01942e63cde2caa0c741f8e651a0d339afa9ad5a854bc41e9240492ac2").unwrap();
        let sk_m = hex::decode("4a86f3d5a1edc4ae633216db6efe07d8f358626d595de288816619a10c61e98c").unwrap();

        let cust_sig1 = compute_tx_signature(&sk_c, &escrow_tx_hash);
        // println!("cust sig: {:?}, len: {}", cust_sig, cust_sig.len());

        let merch_tx_hash = vec![161, 57, 186, 255, 37, 146, 146, 208, 208, 38, 1, 222, 7, 151, 43, 160, 164, 115, 162, 54, 211, 138, 190, 1, 179, 131, 22, 210, 56, 163, 143, 113];
        let cust_sig2 = compute_tx_signature(&sk_c, &merch_tx_hash);
        let merch_sig = compute_tx_signature(&sk_m, &merch_tx_hash);

        let wpk = hex::decode("02b4395f62fc0b786902b37924c2773195ad707ef07dd5ec7e31f2b3cda4804d8c").unwrap();

        let mut _merch_close_addr = hex::decode("0a1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let _merch_close_addr2 = hex::decode("0b2222222222222222222222222222222222222222222222222222222222222222").unwrap();
        let _cust_close_addr = hex::decode("0c3333333333333333333333333333333333333333333333333333333333333333").unwrap();

        let merch_close_address = Script(_merch_close_addr.clone());
        let merch_close_address_dup = Script(_merch_close_addr.clone());
        let merch_close_address2 = Script(_merch_close_addr2.clone());
        let cust_close_addr = Script(_cust_close_addr.clone());
        let cust_close_addr_dup = Script(_cust_close_addr.clone());
        let cust_close_addr_dup2 = Script(_cust_close_addr.clone());

        let escrow_tx_predicate= generate_open_predicate(&_merch_close_addr, &_ser_channel_token);

        // 1 byte mode + 4 bytes cust_bal + 4 bytes merch_bal + 72 bytes cust_sig + 96 bytes close token
        let close_token = hex::decode("8d4ff4d96f17760cabdd9728e667596c2c6d238427dd0529f2b6b60140fc71efc890e03502bdae679ca09236fbb11d9d832b9fc275bf44bad06fd9d0b0296722140273f6cba23859b48c3aaa5ed25455e70bd665165169956be25708026478b6").unwrap();

        let cust_close_witness_input = generate_customer_close_witness([0,0,0,0,0,0,0,140], [0,0,0,0,0,0,0,70], &cust_sig1, &close_token, &wpk);

        let cust_close_tx_predicate = generate_predicate(&wpk, [0,0,0,0,0,0,0,140], [0,0,0,146], &_ser_channel_token);
        let merch_close_tx_predicate = generate_open_predicate(&_merch_close_addr2, &_ser_channel_token);

        let merch_sig = hex::decode("3045022100e171be9eb5ffc799eb944e87762116ddff9ae77de58f63175ca354b9d93922390220601aed54bc60d03012f7d1b76d2caa78f9d461b83f014d40ec33ea233de2246e").unwrap();
        let revoke_token = hex::decode("3045022100d4421207f4698bd93b0fd7de19a52f2cf90022c80261c4ff7423c6a5ae2c22e0022043eac6981cf37d873036cd5544dcf9a95cfe8271abc0d66f6c3db031307c2e52").unwrap();
        let merch_revoke_witness_input = generate_merchant_revoke_witness(&_merch_close_addr2, &merch_sig, &revoke_token);

        let cust_spend_tx_hash = vec![162, 216, 70, 64, 240, 17, 105, 190, 59, 6, 128, 231, 90, 96, 241, 201, 184, 90, 28, 9, 3, 175, 79, 250, 236, 33, 159, 103, 66, 16, 181, 207];
        let cust_sig = compute_tx_signature(&sk_c, &cust_spend_tx_hash);
        let cust_spend_tx_witness = generate_spend_tx_witness(&_cust_close_addr, &cust_sig);

        let mut mtx_a = TransactionData::nu4();
        mtx_a.tze_outputs.push(tzeOut(210, &Predicate::open(escrow_tx_predicate)));
        let tx_a = mtx_a.freeze().unwrap();
        // println!("Escrow transaction: {:?}", tx_a);

        // construct customer-close-tx
        let mut mtx_b = TransactionData::nu4();
        mtx_b.tze_inputs.push(tzeIn(tx_a.txid(), &Witness::open(cust_close_witness_input)));
        // to_customer
        mtx_b.tze_outputs.push(tzeOut(140, &Predicate::close(cust_close_tx_predicate)));
        // to_merchant
        mtx_b.vout.push(TxOut {
            value: Amount::from_u64(70).unwrap(),
            script_pubkey: merch_close_address,
        });

        let tx_b = mtx_b.freeze().unwrap();

        let mut mtx_c = TransactionData::nu4();
        mtx_c.tze_inputs.push(tzeIn(tx_b.txid(), &Witness::close(merch_revoke_witness_input)));
        // to_merchant
        mtx_c.vout.push(TxOut {
            value: Amount::from_u64(140).unwrap(),
            script_pubkey: merch_close_address2,
        });

        let tx_c = mtx_c.freeze().unwrap();

        let mut mtx_d = TransactionData::nu4();
        mtx_d.tze_inputs.push(tzeIn(tx_b.txid(), &Witness::close(cust_spend_tx_witness)));
        // to_merchant
        mtx_d.vout.push(TxOut {
            value: Amount::from_u64(140).unwrap(),
            script_pubkey: cust_close_addr,
        });

        let tx_d = mtx_d.freeze().unwrap();

        let mut mtx_e = TransactionData::nu4();
        mtx_e.tze_inputs.push(tzeIn(tx_b.txid(), &Witness::close(cust_spend_tx_witness)));
        // to_merchant
        mtx_e.vout.push(TxOut {
            value: Amount::from_u64(140).unwrap(),
            script_pubkey: cust_close_addr_dup,
        });

        let tx_e = mtx_e.freeze().unwrap();

        let mut mtx_f = TransactionData::nu4();
        mtx_f.tze_inputs.push(tzeIn(tx_b.txid(), &Witness::close(cust_spend_tx_witness)));
        // to_merchant
        mtx_f.vout.push(TxOut {
            value: Amount::from_u64(110).unwrap(),
            script_pubkey: cust_close_addr_dup2,
        });

        let tx_f = mtx_f.freeze().unwrap();

        let program = Program { };

        // Verify tx_b
        {
            let ctx = Ctx::v1(1, &tx_b);
            assert_eq!(
                program.verify(
                    &tx_a.tze_outputs[0].precondition, // escrow
                    &tx_b.tze_inputs[0].witness, // customer-close-tx
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_c
        {
            let ctx = Ctx::v1(1, &tx_c);
            assert_eq!(
                program.verify(
                    &tx_b.tze_outputs[0].precondition, // customer-close-tx
                    &tx_c.tze_inputs[0].witness, // merchant-revoke-tx
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_d
        {
            let ctx = Ctx::v1(150, &tx_d);
            assert_eq!(
                program.verify(
                    &tx_b.tze_outputs[0].precondition, // customer-close-tx
                    &tx_d.tze_inputs[0].witness, // customer-spending-tx
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_e
        {
            let ctx = Ctx::v1(120, &tx_e);
            assert_eq!(
                program.verify(
                    &tx_b.tze_outputs[0].precondition, // customer-close-tx
                    &tx_e.tze_inputs[0].witness, // customer-spending-tx
                    &ctx
                ),
                Err("Timelock has not been met")
            );
        }

        // Verify tx_f
        {
            let ctx = Ctx::v1(150, &tx_f);
            assert_eq!(
                program.verify(
                    &tx_b.tze_outputs[0].precondition, // customer-close-tx
                    &tx_f.tze_inputs[0].witness, // customer-spending-tx
                    &ctx
                ),
                Err("The outgoing amount is not correct.")
            );
        }
    }
}
