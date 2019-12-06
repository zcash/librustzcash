//! Bolt implementation of WTP consensus rules.
//!
//! The bolt program implements a dual-hash-lock encumbrance with the following form:
//!
//! > `hash = BLAKE2b_256(preimage_1 || BLAKE2b_256(preimage_2))`
//!
//! The two preimages are revealed in sequential transactions, demonstrating how WTPs can
//! impose constraints on how program modes are chained together.
//!
//! The bolt program has two modes:
//!
//! - Mode 0: `hash_1 = BLAKE2b_256(preimage_1 || hash_2)`
//! - Mode 1: `hash_2 = BLAKE2b_256(preimage_2)`
//!
//! and uses the following transaction formats:
//!
//! - `tx_a`: `[ [any input types...] ----> WtpOut(value, hash_1) ]`
//! - `tx_b`: `[ WtpIn(tx_a, preimage_1) -> WtpOut(value, hash_2) ]`
//! - `tx_c`: `[ WtpIn(tx_b, preimage_2) -> [any output types...] ]`

use blake2b_simd::Params;

use super::context;
use crate::wtp::{bolt, Predicate};
use crate::transaction::components::Amount;

pub struct Program;

impl Program {
    /// Runs the program against the given predicate, witness, and context.
    ///
    /// At this point the predicate and witness have been parsed and validated
    /// non-contextually, and are guaranteed to both be for this program. All subsequent
    /// validation is this function's responsibility.
    pub(super) fn verify<'a>(
        predicate: &bolt::Predicate,
        witness: &bolt::Witness,
        ctx: &context::V1<'a>,
    ) -> Result<(), &'static str> {
        // This match statement is selecting the mode that the program is operating in,
        // based on the enums defined in the parser.
        match (predicate, witness) {
            (bolt::Predicate::Open(p_open), bolt::Witness::Open(w_open)) => {
                // In OPEN mode, we enforce that the transaction must only contain inputs
                // and outputs from this program. The consensus rules enforce that if a
                // transaction contains both WTP inputs and WTP outputs, they must all be
                // of the same program type. Therefore we only need to check that the
                // transaction does not contain any other type of input or output.
                if !ctx.is_wtp_and_vout_only() {
                    return Err(
                        "Bolt WTP cannot be closed in a transaction with multiple non-WTP inputs or outputs",
                    );
                }

                // (1) p_open.address == close tx output with this address
                // (2) check that the two outputs for the close tx for the pks
                match &ctx.tx_wtp_outputs() {
                    [wtp_out] => match &wtp_out.predicate {
                        Predicate::Bolt(bolt::Predicate::Close(p_close)) => {
                            // retrieve the two outputs here
                            // to merchant output
                            let tx2_pubkey = ctx.get_tx_output_pk().unwrap(); // TODO: handle safely

                            let tx1_value = wtp_out.value;
                            let tx2_output_value= ctx.get_tx_output_value().unwrap();

                            // Check if block_height is more than 24h away.
                            println!("{}", p_close.block_height);
                            println!("{}", ctx.block_height());
                            if p_close.block_height < 0 || p_close.block_height - ctx.block_height() < 144 {
                                return Err("The block height should be more than 24h in the future");
                            }

                            let is_tx_output_correct = bolt::check_customer_output(w_open, tx1_value, p_close,tx2_output_value);

                            let tx_hash = ctx.get_tx_hash();
                            let is_valid = bolt::verify_channel_opening(p_open, w_open, &tx_hash, tx2_pubkey);

                            if is_valid && is_tx_output_correct {
                                Ok(())
                            } else {
                                Err("could not validate channel opening - cust close")
                            }
                        }
                        Predicate::Bolt(bolt::Predicate::MerchClose(p_close)) => {

                            let tx1_value = wtp_out.value;
                            let is_tx_output_correct = bolt::check_merchant_output(w_open, tx1_value, p_close);

                            let tx_hash = ctx.get_tx_hash();
                            let tx2_pubkey = p_close.pubkey.clone();
                            let is_valid = bolt::verify_channel_opening(p_open, w_open, &tx_hash, tx2_pubkey);

                            if is_valid && is_tx_output_correct {
                                Ok(())
                            } else {
                                Err("could not validate channel opening - merch close")
                            }
                        }
                        Predicate::Bolt(_) => Err("Invalid WTP output mode"),
                        _ => Err("Invalid WTP output type"),
                    },
                    _ => Err("Invalid number of WTP outputs"),
                }
            }
            (bolt::Predicate::Close(p_close), bolt::Witness::Close(w_close)) => {
                if !ctx.is_vout_only() {
                    return Err(
                        "Bolt WTP cannot be closed in a transaction with multiple outputs or WTP outputs",
                    );
                }
                if w_close.witness_type == 0x0 {
                    // TODO: validate timelock
                }
                let tx_hash = ctx.get_tx_hash();
                let is_valid = bolt::verify_channel_closing(p_close, w_close, &tx_hash);
                if is_valid {
                    Ok(())
                } else {
                    Err("could not validate channel closing initiated by customer")
                }
            }
            (bolt::Predicate::MerchClose(p_close), bolt::Witness::MerchClose(w_close)) => {

                if !ctx.is_wtp_and_vout_only() {
                    return Err(
                        "Bolt WTP cannot be closed in a transaction with multiple non-WTP inputs or outputs",
                    );
                }
                let tx2_pubkey = match &ctx.tx_wtp_outputs() {
                    [wtp_out] => match &wtp_out.predicate {
                        Predicate::Bolt(bolt::Predicate::Close(out)) => Ok(out.pubkey.clone()),
                        Predicate::Bolt(_) => Err("Invalid WTP output mode"),
                        _ => Err("Invalid WTP output type"),
                    }
                    _ => Err("Invalid number of WTP outputs"),
                };

                let tx2_pk = tx2_pubkey.unwrap();

                let tx_hash = ctx.get_tx_hash();
                let is_valid = bolt::verify_channel_merch_closing(p_close, w_close, &tx_hash, tx2_pk);
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
    use crate::{
        consensus::wtp::{Context, Programs},
        transaction::{
            components::{Amount, OutPoint, WtpIn, WtpOut},
            TransactionData,
        },
        wtp::{self, bolt},
    };
    use blake2b_simd::Params;
    use std::fs::File;
    use std::io::Read;
    use crate::transaction::components::TxOut;
    use crate::legacy::Script;

    const OPEN_WITNESS_LEN: usize = 212;
    const CLOSE_WITNESS_LEN: usize = 180;
    const CLOSE_PREDICATE_LEN: usize = 1115;
    const OPEN_PREDICATE_LEN: usize = 1107;

    fn read_file<'a>(name: &'a str) -> std::io::Result<Vec<u8>> {
        let mut file = File::open(name).unwrap();

        let mut data = Vec::new();
        file.read_to_end(&mut data);

        return Ok(data);
    }

    fn generate_customer_close_witness(cust_bal: [u8; 4], merch_bal: [u8; 4], cust_sig: &Vec<u8>, close_token: &Vec<u8>, wpk: &Vec<u8>) -> [u8; OPEN_WITNESS_LEN] {
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

    fn generate_merchant_close_witness(cust_bal: [u8; 4], merch_bal: [u8; 4], cust_sig: &Vec<u8>, merch_sig: &Vec<u8>) -> [u8; OPEN_WITNESS_LEN] {
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

    fn generate_predicate(pubkey: &Vec<u8>, amount: [u8; 4], block_height: [u8; 4], channel_token: &Vec<u8>) -> [u8; CLOSE_PREDICATE_LEN] {
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

    #[test]
    fn bolt_program_open_and_close() {

        let _ser_channel_token = hex::decode(read_file("bolt_testdata/channel.token").unwrap()).unwrap();

        let escrow_tx_hash= vec![218, 142, 74, 74, 236, 37, 47, 120, 241, 20, 203, 94, 78, 126, 131, 174, 4, 3, 75, 81, 194, 90, 203, 24, 16, 158, 53, 237, 241, 57, 97, 137];

        let pk_c = hex::decode("0398cb634c1bf97559dfcc47b6c8cc3cce8be2219e571ff721b95130efe065991a").unwrap();
        let sk_c = hex::decode("ee3c802d34a1359b9d3b2a81773730325f7634e2991336c534cbd180980ec581").unwrap();

        let pk_m = hex::decode("03504d8f01942e63cde2caa0c741f8e651a0d339afa9ad5a854bc41e9240492ac2").unwrap();
        let sk_m = hex::decode("4a86f3d5a1edc4ae633216db6efe07d8f358626d595de288816619a10c61e98c").unwrap();

        let cust_sig1 = bolt::compute_tx_signature(&sk_c, &escrow_tx_hash);
        // println!("cust sig: {:?}, len: {}", cust_sig, cust_sig.len());

        let merch_tx_hash = vec![161, 57, 186, 255, 37, 146, 146, 208, 208, 38, 1, 222, 7, 151, 43, 160, 164, 115, 162, 54, 211, 138, 190, 1, 179, 131, 22, 210, 56, 163, 143, 113];
        let cust_sig2 = bolt::compute_tx_signature(&sk_c, &merch_tx_hash);
        let merch_sig = bolt::compute_tx_signature(&sk_m, &merch_tx_hash);

        let wpk = hex::decode("02b4395f62fc0b786902b37924c2773195ad707ef07dd5ec7e31f2b3cda4804d8c").unwrap();

        let mut _merch_close_addr = hex::decode("0a1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let _merch_close_addr2 = hex::decode("0b2222222222222222222222222222222222222222222222222222222222222222").unwrap();

        let merch_close_address = Script(_merch_close_addr.clone());
        let merch_close_address_dup = Script(_merch_close_addr.clone());
        let merch_close_address_dup2 = Script(_merch_close_addr.clone());

        let escrow_tx_predicate= generate_open_predicate(&_merch_close_addr, &_ser_channel_token);

        // 1 byte mode + 4 bytes cust_bal + 4 bytes merch_bal + 72 bytes cust_sig + 96 bytes close token
        let close_token = hex::decode("8d4ff4d96f17760cabdd9728e667596c2c6d238427dd0529f2b6b60140fc71efc890e03502bdae679ca09236fbb11d9d832b9fc275bf44bad06fd9d0b0296722140273f6cba23859b48c3aaa5ed25455e70bd665165169956be25708026478b6").unwrap();

        let cust_close_witness_input = generate_customer_close_witness([0,0,0,140], [0,0,0,70], &cust_sig1, &close_token, &wpk);
        let merch_close_witness_input = generate_merchant_close_witness([0,0,0,200], [0,0,0,10], &cust_sig2, &merch_sig);

        let cust_close_tx_predicate = generate_predicate(&wpk, [0,0,0,140], [0,0,0,146], &_ser_channel_token);
        let cust_close_tx_predicate_too_early = generate_predicate(&wpk, [0,0,0,140], [0,0,0,110], &_ser_channel_token);
        let merch_close_tx_predicate = generate_open_predicate(&_merch_close_addr2, &_ser_channel_token);

        let merch_tx_hash2= vec![218, 142, 74, 74, 236, 37, 47, 120, 241, 20, 203, 94, 78, 126, 131, 174, 4, 3, 75, 81, 194, 90, 203, 24, 16, 158, 53, 237, 241, 57, 97, 137];
        let cust_sig3 = bolt::compute_tx_signature(&sk_c, &merch_tx_hash2);
        let cust_close_witness_input2 = generate_customer_close_witness([0,0,0,140], [0,0,0,70], &cust_sig3, &close_token, &wpk);

        // escrow-tx (lock up 210 zats)
        let mut mtx_a = TransactionData::nu4();
        mtx_a.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(210).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::open(escrow_tx_predicate)),
        });
        let tx_a = mtx_a.freeze().unwrap();
        // println!("debug: Escrow transaction: {:?}", tx_a);

        // begin - customer-close-tx
        let mut mtx_b = TransactionData::nu4();
        mtx_b.wtp_inputs.push(WtpIn {
            prevout: OutPoint::new(tx_a.txid().0, 0),
            witness: wtp::Witness::Bolt(bolt::Witness::open(cust_close_witness_input)),
        });
        // to_customer
        mtx_b.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(140).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::close(cust_close_tx_predicate)),
        });
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
        mtx_c.wtp_inputs.push(WtpIn {
            prevout: OutPoint::new(tx_a.txid().0, 0),
            witness: wtp::Witness::Bolt(bolt::Witness::open(merch_close_witness_input)),
        });
        // to_merchant
        mtx_c.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(210).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::merch_close(merch_close_tx_predicate)),
        });
        let tx_c = mtx_c.freeze().unwrap();
        // end - merchant-close-tx
        // println!("debug: Merchant close transaction: {:?}", tx_c);

        // begin - customer-close-tx (spending from merchant-close-tx)
        let mut mtx_d = TransactionData::nu4();
        mtx_d.wtp_inputs.push(WtpIn {
            prevout: OutPoint::new(tx_c.txid().0, 0),
            witness: wtp::Witness::Bolt(bolt::Witness::merch_close(cust_close_witness_input2)),
        });
        // to_customer
        mtx_d.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(140).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::close(cust_close_tx_predicate)),
        });
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
        mtx_e.wtp_inputs.push(WtpIn {
            prevout: OutPoint::new(tx_a.txid().0, 0),
            witness: wtp::Witness::Bolt(bolt::Witness::open(cust_close_witness_input)),
        });
        // to_customer
        mtx_e.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(140).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::close(cust_close_tx_predicate_too_early)),
        });
        // to_merchant
        mtx_e.vout.push(TxOut {
            value: Amount::from_u64(70).unwrap(),
            script_pubkey: merch_close_address_dup2,
        });
        let tx_e = mtx_e.freeze().unwrap();

        let programs = Programs::for_epoch(0x7473_6554).unwrap();

        // Verify tx_b
        {
            let ctx = Context::v1(1, &tx_b);
            assert_eq!(
                programs.verify(
                    &tx_a.wtp_outputs[0].predicate, // escrow
                    &tx_b.wtp_inputs[0].witness, // customer-close-tx
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_e time lock block height is too short
        {
            let ctx = Context::v1(1, &tx_e);
            assert!(
                programs.verify(
                    &tx_a.wtp_outputs[0].predicate, // escrow
                    &tx_e.wtp_inputs[0].witness, // customer-close-tx
                    &ctx
                ).is_err()
            );
        }

        // Verify tx_c
        {
            let ctx = Context::v1(1, &tx_c);
            assert_eq!(
                programs.verify(
                    &tx_a.wtp_outputs[0].predicate, // escrow
                    &tx_c.wtp_inputs[0].witness, // merchant-close-tx (initiating closing)
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_d (customer-close-tx spending from merch-close-tx)
        {
            let ctx = Context::v1(2, &tx_d);
            assert_eq!(
                programs.verify(
                    &tx_c.wtp_outputs[0].predicate, // merchant-close-tx
                    &tx_d.wtp_inputs[0].witness, // customer-close-tx
                    &ctx
                ),
                Ok(())
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

        let cust_sig1 = bolt::compute_tx_signature(&sk_c, &escrow_tx_hash);
        // println!("cust sig: {:?}, len: {}", cust_sig, cust_sig.len());

        let merch_tx_hash = vec![161, 57, 186, 255, 37, 146, 146, 208, 208, 38, 1, 222, 7, 151, 43, 160, 164, 115, 162, 54, 211, 138, 190, 1, 179, 131, 22, 210, 56, 163, 143, 113];
        let cust_sig2 = bolt::compute_tx_signature(&sk_c, &merch_tx_hash);
        let merch_sig = bolt::compute_tx_signature(&sk_m, &merch_tx_hash);

        let wpk = hex::decode("02b4395f62fc0b786902b37924c2773195ad707ef07dd5ec7e31f2b3cda4804d8c").unwrap();

        let mut _merch_close_addr = hex::decode("0a1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let _merch_close_addr2 = hex::decode("0b2222222222222222222222222222222222222222222222222222222222222222").unwrap();

        let merch_close_address = Script(_merch_close_addr.clone());
        let merch_close_address2 = Script(_merch_close_addr2.clone());

        let escrow_tx_predicate= generate_open_predicate(&_merch_close_addr, &_ser_channel_token);

        // 1 byte mode + 4 bytes cust_bal + 4 bytes merch_bal + 72 bytes cust_sig + 96 bytes close token
        let close_token = hex::decode("8d4ff4d96f17760cabdd9728e667596c2c6d238427dd0529f2b6b60140fc71efc890e03502bdae679ca09236fbb11d9d832b9fc275bf44bad06fd9d0b0296722140273f6cba23859b48c3aaa5ed25455e70bd665165169956be25708026478b6").unwrap();

        let cust_close_witness_input = generate_customer_close_witness([0,0,0,140], [0,0,0,70], &cust_sig1, &close_token, &wpk);
        let merch_close_witness_input = generate_merchant_close_witness([0,0,0,200], [0,0,0,10], &cust_sig2, &merch_sig);


        let cust_close_tx_predicate = generate_predicate(&wpk, [0,0,0,140], [0,0,0,146], &_ser_channel_token);
        let merch_close_tx_predicate = generate_open_predicate(&_merch_close_addr2, &_ser_channel_token);

        let sig = hex::decode("3045022100e171be9eb5ffc799eb944e87762116ddff9ae77de58f63175ca354b9d93922390220601aed54bc60d03012f7d1b76d2caa78f9d461b83f014d40ec33ea233de2246e").unwrap();
        let revoke_token = hex::decode("3045022100d4421207f4698bd93b0fd7de19a52f2cf90022c80261c4ff7423c6a5ae2c22e0022043eac6981cf37d873036cd5544dcf9a95cfe8271abc0d66f6c3db031307c2e52").unwrap();
        let merch_revoke_witness_input = generate_merchant_revoke_witness(&_merch_close_addr2, &sig, &revoke_token);

        let mut mtx_a = TransactionData::nu4();
        mtx_a.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(210).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::open(escrow_tx_predicate)),
        });
        let tx_a = mtx_a.freeze().unwrap();
        // println!("Escrow transaction: {:?}", tx_a);

        // construct customer-close-tx
        let mut mtx_b = TransactionData::nu4();
        mtx_b.wtp_inputs.push(WtpIn {
            prevout: OutPoint::new(tx_a.txid().0, 0),
            witness: wtp::Witness::Bolt(bolt::Witness::open(cust_close_witness_input)),
        });
        // to_customer
        mtx_b.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(140).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::close(cust_close_tx_predicate)),
        });
        // to_merchant
        mtx_b.vout.push(TxOut {
            value: Amount::from_u64(70).unwrap(),
            script_pubkey: merch_close_address,
        });

        let tx_b = mtx_b.freeze().unwrap();

        let mut mtx_c = TransactionData::nu4();
        mtx_c.wtp_inputs.push(WtpIn {
            prevout: OutPoint::new(tx_b.txid().0, 0),
            witness: wtp::Witness::Bolt(bolt::Witness::close(merch_revoke_witness_input)),
        });
        // to_merchant
        mtx_c.vout.push(TxOut {
            value: Amount::from_u64(140).unwrap(),
            script_pubkey: merch_close_address2,
        });

        let tx_c = mtx_c.freeze().unwrap();

        let programs = Programs::for_epoch(0x7473_6554).unwrap();

        // Verify tx_b
        {
            let ctx = Context::v1(1, &tx_b);
            assert_eq!(
                programs.verify(
                    &tx_a.wtp_outputs[0].predicate, // escrow
                    &tx_b.wtp_inputs[0].witness, // customer-close-tx
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_c
        {
            let ctx = Context::v1(1, &tx_c);
            assert_eq!(
                programs.verify(
                    &tx_b.wtp_outputs[0].predicate, // customer-close-tx
                    &tx_c.wtp_inputs[0].witness, // merchant-revoke-tx
                    &ctx
                ),
                Ok(())
            );
        }
    }
}
