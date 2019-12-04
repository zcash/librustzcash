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
                            let is_tx_output_correct = bolt::check_customer_output(w_open, p_close);

                            let tx_hash = ctx.get_tx_hash();
                            let is_valid = bolt::verify_channel_opening(p_open, w_open, &tx_hash);

                            if is_valid && is_tx_output_correct {
                                Ok(())
                            } else {
                                Err("could not validate channel opening - cust close")
                            }
                        }
                        Predicate::Bolt(bolt::Predicate::MerchClose(p_close)) => {

                            let is_tx_output_correct = bolt::check_merchant_output(w_open, p_close);

                            let tx_hash = ctx.get_tx_hash();
                            let is_valid = bolt::verify_channel_opening(p_open, w_open, &tx_hash);

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
                // In CLOSE mode, we only require that the predicate is satisfied:
                // TODO: validate timelock
                let tx_hash = ctx.get_tx_hash();
                let is_valid = bolt::verify_channel_closing(p_close, w_close, &tx_hash);
                if is_valid {
                    Ok(())
                } else {
                    Err("could not validate channel closing")
                }
            }
            (bolt::Predicate::MerchClose(p_close), bolt::Witness::MerchClose(w_close)) => {
                let tx_hash = ctx.get_tx_hash();
                let is_valid = true; // bolt::verify_channel_closing(p_close, w_close, &tx_hash);
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
    const CLOSE_PREDICATE_LEN: usize = 1111;
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

    fn generate_predicate(pubkey: &Vec<u8>, amount: [u8; 4], channel_token: &Vec<u8>) -> [u8; CLOSE_PREDICATE_LEN] {
        let mut tx_predicate = [0u8; CLOSE_PREDICATE_LEN];
        let mut tx_pred: Vec<u8> = Vec::new();
        tx_pred.extend(pubkey.iter());
        tx_pred.extend(amount.iter());
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
    fn bolt_program() {

        let mut new_ser_channel_token = read_file("bolt_testdata/channel.token").unwrap();
        let mut _ser_channel_token = hex::decode(new_ser_channel_token.clone()).unwrap();

        let escrow_tx_hash= vec![218, 142, 74, 74, 236, 37, 47, 120, 241, 20, 203, 94, 78, 126, 131, 174, 4, 3, 75, 81, 194, 90, 203, 24, 16, 158, 53, 237, 241, 57, 97, 137]; // [ 2, 58, 234, 150, 17, 53, 50, 221, 73, 222, 95, 248, 177, 62, 130, 21, 96, 30, 229, 126, 61, 117, 47, 136, 140, 28, 202, 147, 169, 176, 215, 1];
        println!("Escrow tx hash: {:?}", escrow_tx_hash);

        let pk_c = hex::decode("0288b05faa5b9b1c600830052790ce40b1356c983869e92f6de181ce9e0b0fbbcf").unwrap();
        let sk_c = hex::decode("81361b9bc2f67524dcc59b980dc8b06aadb77db54f6968d2af76ecdb612e07e4").unwrap();

        let pk_m = hex::decode("0361e1d6f4820eeb26c94aaeec9cfa7f6eb3bb3fa3b4aa149a9ef85e72da1da8c1").unwrap();
        let sk_m = hex::decode("952c2565eb1325d497dcf556b0fa963719b0579b4bc6b15064b2936303f59da7").unwrap();

        let cust_sig1 = bolt::compute_tx_signature(&sk_c, &escrow_tx_hash);
        // println!("cust sig: {:?}, len: {}", cust_sig, cust_sig.len());

        let merch_tx_hash = vec![161, 57, 186, 255, 37, 146, 146, 208, 208, 38, 1, 222, 7, 151, 43, 160, 164, 115, 162, 54, 211, 138, 190, 1, 179, 131, 22, 210, 56, 163, 143, 113];
        let cust_sig2 = bolt::compute_tx_signature(&sk_c, &merch_tx_hash);
        let merch_sig = bolt::compute_tx_signature(&sk_m, &merch_tx_hash);

        let wpk = hex::decode("032ea8d5c660a8eed5ab973b09636e171863a0762bcc351def7c941be91818a232").unwrap();

        let mut _merch_close_addr = hex::decode("0a1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let _merch_close_addr2 = hex::decode("0b2222222222222222222222222222222222222222222222222222222222222222").unwrap();

        let merch_close_address = Script(_merch_close_addr.clone());

        let escrow_tx_predicate= generate_open_predicate(&_merch_close_addr, &_ser_channel_token);

        // 1 byte mode + 4 bytes cust_bal + 4 bytes merch_bal + 72 bytes cust_sig + 96 bytes close token
        let close_token = hex::decode("a823bc8be5e3176ef63f2671de7004e5a14cb174d008040413303fd7b7b9b68bcdfefc4e4cfa189d0a7dfa496dd6ce3397ad18ce0d3c89463c8e02de3f0a9435bd53160a725851fb312771a272289ad170cd3f9b52915fa9b6050590cec1d118").unwrap();

        let cust_close_witness_input = generate_customer_close_witness([0,0,0,140], [0,0,0,70], &cust_sig1, &close_token, &wpk);
        let merch_close_witness_input = generate_merchant_close_witness([0,0,0,200], [0,0,0,10], &cust_sig2, &merch_sig);


        let cust_close_tx_predicate = generate_predicate(&wpk, [0,0,0,140], &_ser_channel_token);
        let merch_close_tx_predicate = generate_predicate(&_merch_close_addr2, [0,0,0,210], &_ser_channel_token);

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

        // println!("Customer close transaction: {:?}", tx_b);

//        let mut mtx_c = TransactionData::nu4();
//        mtx_c.wtp_inputs.push(WtpIn {
//            prevout: OutPoint::new(tx_b.txid().0, 0),
//            witness: wtp::Witness::Bolt(bolt::Witness::close(preimage_2)),
//        });
//        let tx_c = mtx_c.freeze().unwrap();

        let mut mtx_c = TransactionData::nu4();
        mtx_c.wtp_inputs.push(WtpIn {
            prevout: OutPoint::new(tx_a.txid().0, 0),
            witness: wtp::Witness::Bolt(bolt::Witness::open(merch_close_witness_input)),
        });
        // to_merchant
        mtx_c.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(140).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::merch_close(merch_close_tx_predicate)),
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
                    &tx_a.wtp_outputs[0].predicate, // escrow
                    &tx_c.wtp_inputs[0].witness, // merchant-close-tx
                    &ctx
                ),
                Ok(())
            );
        }


//
//        // Verify tx_c
//        {
//            let ctx = Context::v1(2, &tx_c);
//            assert_eq!(
//                programs.verify(
//                    &tx_b.wtp_outputs[0].predicate,
//                    &tx_c.wtp_inputs[0].witness,
//                    &ctx
//                ),
//                Ok(())
//            );
//        }
    }
}
