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
                if !ctx.is_wtp_only() {
                    return Err(
                        "Bolt WTP cannot be closed in a transaction with non-WTP inputs or outputs",
                    );
                }

                // (1) p_open.address == close tx output with this address
                // (2) check that there are two outputs for the close tx
                let wtx_output_len = ctx.tx_wtp_outputs().len();
                if wtx_output_len != 2 {
                    return Err("Invalid number of WTP outputs: close transaction does not have 2 outputs!");
                }

                // retrieve the two outputs here
                let tx_hash = ctx.get_tx_hash();
                let is_valid = bolt::verify_channel_opening(p_open, w_open, &tx_hash);

                if is_valid {
                    Ok(())
                } else {
                    Err("could not validate channel opening")
                }
            }
            (bolt::Predicate::Close(p_close), bolt::Witness::Close(w_close)) => {
                // NOTE: call the close-channel-verify program here
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

    fn read_file<'a>(name: &'a str) -> std::io::Result<Vec<u8>> {
        let mut file = File::open(name).unwrap();

        let mut data = Vec::new();
        file.read_to_end(&mut data);

        return Ok(data);
    }

    #[test]
    fn bolt_program() {

        let mut new_ser_channel_token = read_file("bolt_testdata/channel.token").unwrap();
        let mut _ser_channel_token = hex::decode(new_ser_channel_token).unwrap();

        let escrow_tx_hash= vec![161, 57, 186, 255, 37, 146, 146, 208, 208, 38, 1, 222, 7, 151, 43, 160, 164, 115, 162, 54, 211, 138, 190, 1, 179, 131, 22, 210, 56, 163, 143, 113];
        println!("Escrow tx hash: {:?}", escrow_tx_hash);

        let pk = hex::decode("0288b05faa5b9b1c600830052790ce40b1356c983869e92f6de181ce9e0b0fbbcf").unwrap();
        let sk = hex::decode("81361b9bc2f67524dcc59b980dc8b06aadb77db54f6968d2af76ecdb612e07e4").unwrap();

        let cust_sig = bolt::compute_tx_signature(&sk, &escrow_tx_hash);
        let cust_sig_len = cust_sig.len();
        println!("cust sig: {:?}", cust_sig);
        println!("cust sig len: {}", cust_sig_len);

        let wpk = hex::decode("032ea8d5c660a8eed5ab973b09636e171863a0762bcc351def7c941be91818a232").unwrap();

        let mut _merch_close_addr = hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        _merch_close_addr.append(&mut _ser_channel_token);
        let mut escrow_tx_predicate = [0u8; 1106]; // channel token + merch-close-address
        escrow_tx_predicate.copy_from_slice(_merch_close_addr.as_slice());

        // 1 byte mode + 4 bytes cust_bal + 4 bytes merch_bal + 72 bytes cust_sig + 96 bytes close token
        let mut close_witness_input = [0u8; 212];
        let mut close_witness_vec: Vec<u8> = Vec::new();
        close_witness_vec.push(0x1);
        close_witness_vec.extend([0,0,0,140].iter()); // cust-bal
        close_witness_vec.extend([0,0,0,70].iter()); // merch-bal
        close_witness_vec.push(cust_sig_len as u8);
        close_witness_vec.extend(cust_sig.iter());
        close_witness_vec.push(96);
        close_witness_vec.extend(hex::decode("a823bc8be5e3176ef63f2671de7004e5a14cb174d008040413303fd7b7b9b68bcdfefc4e4cfa189d0a7dfa496dd6ce3397ad18ce0d3c89463c8e02de3f0a9435bd53160a725851fb312771a272289ad170cd3f9b52915fa9b6050590cec1d118").unwrap());
        close_witness_vec.extend(wpk);
        close_witness_vec.extend([0].iter()); // pad extra byte to 212
        close_witness_input.copy_from_slice(close_witness_vec.as_slice());

        let cust_close_tx_predicate = [0u8; 1024];
        let merch_close_tx_predicate = [0u8; 1024];


        let mut mtx_a = TransactionData::nu4();
        mtx_a.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(210).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::open(escrow_tx_predicate)),
        });
        let tx_a = mtx_a.freeze().unwrap();
        println!("Escrow transaction: {:?}", tx_a);

        // construct customer-close-tx
        let mut mtx_b = TransactionData::nu4();
        mtx_b.wtp_inputs.push(WtpIn {
            prevout: OutPoint::new(tx_a.txid().0, 0),
            witness: wtp::Witness::Bolt(bolt::Witness::open(close_witness_input)),
        });
        // to_customer
        mtx_b.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(140).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::close(cust_close_tx_predicate)),
        });
        // to_merchant
        mtx_b.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(70).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::close(merch_close_tx_predicate)),
        });

        let tx_b = mtx_b.freeze().unwrap();

        // println!("Customer close transaction: {:?}", tx_b);

//        let mut mtx_c = TransactionData::nu4();
//        mtx_c.wtp_inputs.push(WtpIn {
//            prevout: OutPoint::new(tx_b.txid().0, 0),
//            witness: wtp::Witness::Bolt(bolt::Witness::close(preimage_2)),
//        });
//        let tx_c = mtx_c.freeze().unwrap();

        let programs = Programs::for_epoch(0x7473_6554).unwrap();

        // Verify tx_b
        {
            let ctx = Context::v1(1, &tx_b);
            assert_eq!(
                programs.verify(
                    &tx_a.wtp_outputs[0].predicate,
                    &tx_b.wtp_inputs[0].witness,
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
