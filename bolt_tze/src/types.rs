//! Bolt parsing logic for WTPs.
//!
//! [bolt-rules]: crate::consensus::wtp::bolt

use std::convert::{TryFrom, TryInto};

use zcash_primitives::{
    extensions::transparent::{FromPayload, ToPayload},
    transaction::components::Amount,
};

use bolt::tze_utils::{
    generate_secp_signature, reconstruct_channel_token_bls12, reconstruct_close_wallet_bls12,
    reconstruct_secp_channel_close_m, reconstruct_secp_public_key, reconstruct_secp_signature,
    reconstruct_signature_bls12, verify_cust_close_message, verify_secp_signature,
};

use bolt::bidirectional::{wtp_verify_merch_close_message, wtp_verify_revoke_message};

mod open {
    pub const MODE: u32 = 0;

    #[derive(Debug, PartialEq)]
    pub struct Predicate {
        pub pubkey: Vec<u8>,
        pub channel_token: Vec<u8>, // (pkc, pkm, pkM, mpk, comparams) => 1074 bytes
    }

    #[derive(Debug, PartialEq)]
    pub struct Witness {
        // 210 bytes
        pub witness_type: u8,
        pub cust_bal: u64,
        pub merch_bal: u64,
        pub cust_sig: Vec<u8>,
        pub merch_sig: Vec<u8>,
        pub wpk: Vec<u8>, // 33 bytes
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
    pub const MODE: u32 = 1;

    #[derive(Debug, PartialEq)]
    pub struct Predicate {
        pub pubkey: Vec<u8>, // 33 bytes
        pub amount: u64,     // merch-bal or cust-bal
        pub block_height: i32,
        pub channel_token: Vec<u8>, // (pkc, pkm, pkM, mpk, comparams) => 1074 bytes
    }

    #[derive(Debug, PartialEq)]
    pub struct Witness {
        pub witness_type: u8,      // 1 byte
        pub address: Vec<u8>,      // 33 bytes
        pub signature: Vec<u8>,    // x bytes (cust-sig or merch-sig)
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
    pub const MODE: u32 = 2;

    #[derive(Debug, PartialEq)]
    pub struct Predicate {
        pub pubkey: Vec<u8>, // 33 bytes
        pub block_height: i32,
        pub channel_token: Vec<u8>, // (pkc, pkm, pkM, mpk, comparams) => 1074 bytes
    }

    #[derive(Debug, PartialEq)]
    pub struct Witness {
        pub witness_type: u8,     // 1 byte
        pub cust_bal: u64,        // 4 bytes
        pub merch_bal: u64,       // 4 bytes
        pub sig: Vec<u8>,         // 73 bytes
        pub close_token: Vec<u8>, // 73 or 96 bytes
        pub wpk: Vec<u8>,         // 33 bytes
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
    MerchClose(merch_close::Predicate),
}

impl Predicate {
    pub fn open(input: [u8; 1107]) -> Self {
        let mut channel_token = Vec::new();
        let mut pubkey = Vec::new();
        pubkey.extend(input[0..33].iter());

        channel_token.extend(input[33..].iter());
        Predicate::Open(open::Predicate {
            pubkey,
            channel_token,
        })
    }

    pub fn close(input: [u8; 1119]) -> Self {
        let mut channel_token = Vec::new();
        let mut pubkey = Vec::new();
        pubkey.extend(input[0..33].iter());

        let amount = convert_bytes_to_u64(&input[33..41]);
        let block_height = convert_bytes_to_i32(&input[41..45]);

        channel_token.extend(input[45..].iter());

        Predicate::Close(close::Predicate {
            pubkey,
            amount,
            block_height,
            channel_token,
        })
    }

    pub fn merch_close(input: [u8; 1111]) -> Self {
        let mut channel_token = Vec::new();
        let mut pubkey = Vec::new();
        pubkey.extend(input[0..33].iter());
        let block_height = convert_bytes_to_i32(&input[33..37]);

        channel_token.extend(input[37..].iter());

        Predicate::MerchClose(merch_close::Predicate {
            pubkey,
            block_height,
            channel_token,
        })
    }
}

impl TryFrom<(u32, &[u8])> for Predicate {
    type Error = &'static str;

    fn try_from((mode, payload): (u32, &[u8])) -> Result<Self, Self::Error> {
        match mode {
            open::MODE => {
                if payload.len() == 1107 {
                    let mut pubkey = Vec::new();
                    pubkey.extend(payload[0..33].iter());

                    let mut channel_token = Vec::new();
                    channel_token.extend(payload[33..].iter());

                    let op = open::Predicate {
                        pubkey,
                        channel_token,
                    };
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

                    let cl = close::Predicate {
                        pubkey,
                        amount,
                        block_height,
                        channel_token,
                    };
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

                    let cl = merch_close::Predicate {
                        pubkey,
                        block_height,
                        channel_token,
                    };
                    Ok(Predicate::MerchClose(cl))
                } else {
                    Err("Payload is not 1111 bytes")
                }
            }
            _ => Err("Invalid mode"),
        }
    }
}

impl TryFrom<(u32, &Vec<u8>)> for Predicate {
    type Error = &'static str;

    fn try_from((mode, payload): (u32, &Vec<u8>)) -> Result<Self, Self::Error> {
        (mode, &payload[..]).try_into()
    }
}

impl TryFrom<(u32, Predicate)> for Predicate {
    type Error = &'static str;

    fn try_from(from: (u32, Self)) -> Result<Self, Self::Error> {
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

    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error> {
        (mode, payload).try_into()
    }
}

impl ToPayload for Predicate {
    fn to_payload(&self) -> (u32, Vec<u8>) {
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
    MerchClose(merch_close::Witness),
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
    cust_sig.extend_from_slice(&input[start_index..end_index].to_vec());

    let start_merch_sig = end_index + 1;
    let end_merch_sig = start_merch_sig + input[end_index] as usize;

    // merchant signature
    merch_sig.extend_from_slice(&input[start_merch_sig..end_merch_sig].to_vec());

    if witness_type == 0x1 {
        // customer initiated (merch_sig : close-token = 96 bytes)
        let end_wpk = end_merch_sig + 33;
        wpk.extend(input[end_merch_sig..end_wpk].iter());
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
        wpk,
    };
}

fn parse_close_witness_input(input: [u8; 180]) -> close::Witness {
    let witness_type = input[0];
    let mut address = Vec::new();
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
        revoke_token,
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

    if witness_type == 0x1 {
        // customer initiated (merch_sig : close-token = 96 bytes)
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
        close_token: merch_sig,
        wpk,
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

impl TryFrom<(u32, &[u8])> for Witness {
    type Error = &'static str;

    fn try_from((mode, payload): (u32, &[u8])) -> Result<Self, Self::Error> {
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

impl TryFrom<(u32, &Vec<u8>)> for Witness {
    type Error = &'static str;

    fn try_from((mode, payload): (u32, &Vec<u8>)) -> Result<Self, Self::Error> {
        (mode, &payload[..]).try_into()
    }
}

impl TryFrom<(u32, Witness)> for Witness {
    type Error = &'static str;

    fn try_from(from: (u32, Self)) -> Result<Self, Self::Error> {
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

    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error> {
        (mode, payload).try_into()
    }
}

impl ToPayload for Witness {
    fn to_payload(&self) -> (u32, Vec<u8>) {
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

pub fn verify_channel_opening(
    escrow_pred: &open::Predicate,
    close_tx_witness: &open::Witness,
    tx_hash: &Vec<u8>,
    tx2_pubkey: Vec<u8>,
) -> bool {
    let _channel_token = &escrow_pred.channel_token;
    let option_channel_token = reconstruct_channel_token_bls12(&_channel_token);
    let channel_token = match option_channel_token {
        Ok(n) => n.unwrap(),
        Err(_e) => return false,
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
        let is_merch_pk_thesame = tx2_pubkey == escrow_pred.pubkey;

        let mut wpk_bytes = [0u8; 33];
        wpk_bytes.copy_from_slice(close_tx_witness.wpk.as_slice());
        let wpk = reconstruct_secp_public_key(&wpk_bytes);

        let close_wallet =
            reconstruct_close_wallet_bls12(&channel_token, &wpk, cust_bal, merch_bal);

        let cust_sig = reconstruct_secp_signature(close_tx_witness.cust_sig.as_slice());

        let is_cust_sig_valid = verify_secp_signature(&pkc, tx_hash, &cust_sig);

        let option_close_token = reconstruct_signature_bls12(&close_tx_witness.merch_sig);
        let close_token = match option_close_token {
            Ok(n) => n.unwrap(),
            Err(_e) => return false,
        };

        // check whether close token is valid
        let is_close_token_valid =
            verify_cust_close_message(&channel_token, &wpk, &close_wallet, &close_token);
        return is_cust_sig_valid && is_close_token_valid && is_merch_pk_thesame;
    }

    return false;
}

// close-channel program
// If witness is of type 0x0, verify customer signature and relative timeout met

// If witness is of type 0x1, check that 1 output is created paying <amount-merch + amount-cust> to <address>.
// Also check that <merch-sig> is a valid signature on <<address> || <revocation-token>>
// and that <revocation-token> contains a valid signature under <wpk> on <<wpk> || REVOKED>

pub fn verify_channel_closing(
    close_tx_pred: &close::Predicate,
    spend_tx_witness: &close::Witness,
    tx_hash: &Vec<u8>,
) -> bool {
    let option_channel_token = reconstruct_channel_token_bls12(&close_tx_pred.channel_token);
    let channel_token = match option_channel_token {
        Ok(n) => n.unwrap(),
        Err(_e) => return false,
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
        let channel_close = reconstruct_secp_channel_close_m(
            &address_bytes,
            &spend_tx_witness.revoke_token,
            &spend_tx_witness.signature,
        );
        let mut wpk_bytes = [0u8; 33];
        wpk_bytes.copy_from_slice(close_tx_pred.pubkey.as_slice());
        let wpk = reconstruct_secp_public_key(&wpk_bytes);
        let revoke_token = reconstruct_secp_signature(spend_tx_witness.revoke_token.as_slice());
        return wtp_verify_revoke_message(&wpk, &revoke_token)
            && wtp_verify_merch_close_message(&channel_token, &channel_close);
    }

    return false;
}

// merch-close program
pub fn verify_channel_merch_closing(
    merch_tx_pred: &merch_close::Predicate,
    close_tx_witness: &merch_close::Witness,
    tx_hash: &Vec<u8>,
    tx2_pubkey: Vec<u8>,
) -> bool {
    let option_channel_token = reconstruct_channel_token_bls12(&merch_tx_pred.channel_token);
    let channel_token = match option_channel_token {
        Ok(n) => n.unwrap(),
        Err(_e) => return false,
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
        let is_merch_pk_thesame = tx2_pubkey != merch_tx_pred.pubkey;

        let mut wpk_bytes = [0u8; 33];
        wpk_bytes.copy_from_slice(close_tx_witness.wpk.as_slice());
        let wpk = reconstruct_secp_public_key(&wpk_bytes);

        let close_wallet =
            reconstruct_close_wallet_bls12(&channel_token, &wpk, cust_bal, merch_bal);

        let cust_sig = reconstruct_secp_signature(close_tx_witness.sig.as_slice());

        let is_cust_sig_valid = verify_secp_signature(&pkc, tx_hash, &cust_sig);

        let option_close_token = reconstruct_signature_bls12(&close_tx_witness.close_token);
        let close_token = match option_close_token {
            Ok(n) => n.unwrap(),
            Err(_e) => return false,
        };

        // check whether close token is valid
        let is_close_token_valid =
            verify_cust_close_message(&channel_token, &wpk, &close_wallet, &close_token);
        return is_cust_sig_valid && is_close_token_valid && is_merch_pk_thesame;
    }

    return false;
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use zcash_primitives::extensions::transparent::ToPayload;

    use super::{
        close, convert_bytes_to_i32, convert_bytes_to_u64, merch_close, open,
        parse_close_witness_input, parse_merch_close_witness_input, parse_open_witness_input,
        Predicate, Witness,
    };

    #[test]
    fn predicate_open_round_trip() {
        let data = vec![7; 1107];
        let p: Predicate = (open::MODE, &data[..]).try_into().unwrap();
        let mut channel_token = Vec::new();

        let mut pubkey = Vec::new(); // [0; 33];
        pubkey.extend(data[0..33].iter());

        channel_token.extend(data[33..].iter());

        assert_eq!(
            p,
            Predicate::Open(open::Predicate {
                pubkey,
                channel_token
            })
        );
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

        assert_eq!(
            p,
            Predicate::Close(close::Predicate {
                pubkey,
                amount,
                block_height,
                channel_token
            })
        );
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

        assert_eq!(
            p,
            Predicate::MerchClose(merch_close::Predicate {
                pubkey,
                block_height,
                channel_token
            })
        );
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
}
