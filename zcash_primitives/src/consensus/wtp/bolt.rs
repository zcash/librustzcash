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
                println!("Now we can process the two outputs!");
                let is_valid = bolt::verify_channel_opening(p_open, w_open);

                if is_valid {
                    Ok(())
                } else {
                    Err("could not validate channel opening")
                }
            }
            (bolt::Predicate::Close(p), bolt::Witness::Close(w)) => {
                // NOTE: call the close-channel-verify program here
                // In CLOSE mode, we only require that the predicate is satisfied:
                // predicate_close = BLAKE2b_256(witness_close)
                println!("BOLT: close valid for now!");
                Ok(())
//                let hash = Params::new().hash_length(32).hash(&w.0);
//                if hash.as_bytes() == p.0 {
//                    Ok(())
//                } else {
//                    Err("hash mismatch")
//                }
            }
            _ => Err("Mode mismatch"),
        }
    }
}


//// Next, check that there is only a single WTP output of the correct type.
//match &ctx.tx_wtp_outputs() {
//    [wtp_out] => match &wtp_out.predicate {
//        Predicate::Bolt(bolt::Predicate::Close(p_close)) => {
//            // NOTE: call the close-channel-verify program here
//            // Finally, check the predicate:
//            // predicate_open = BLAKE2b_256(witness_open || predicate_close)
////                            let mut h = Params::new().hash_length(32).to_state();
////                            h.update(&w_open.0);
////                            h.update(&p_close.0);
////                            let hash = h.finalize();
////                            if hash.as_bytes() == p_open.0 {
////                                Ok(())
////                            } else {
////                                Err("hash mismatch")
////                            }
//
//            let is_valid = bolt::verify_channel_opening(p_open, w_open, p_close);
//            if is_valid {
//                Ok(())
//            } else {
//                Err("signatures or close-token invalid")
//            }
//        }
//        Predicate::Bolt(_) => Err("Invalid WTP output mode"),
//        _ => Err("Invalid WTP output type"),
//    },
//    _ => Err("Invalid number of WTP outputs"),
//}

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


    #[test]
    fn bolt_program() {
//        let preimage_1 = [1; 32];
//        let preimage_2 = [2; 32];
//
//        let hash_2 = {
//            let mut hash = [0; 32];
//            hash.copy_from_slice(Params::new().hash_length(32).hash(&preimage_2).as_bytes());
//            hash
//        };
//        let hash_1 = {
//            let mut hash = [0; 32];
//            hash.copy_from_slice(
//                Params::new()
//                    .hash_length(32)
//                    .to_state()
//                    .update(&preimage_1)
//                    .update(&hash_2)
//                    .finalize()
//                    .as_bytes(),
//            );
//            hash
//        };

        // TODO: generate sample inputs
        let escrow_tx_predicate = [0u8; 1024]; // channel token + merch-close-address
        let close_witness_input = [1u8; 210];
        let cust_close_tx_predicate = [0u8; 1024];
        let merch_close_tx_predicate = [0u8; 1024];


        let mut mtx_a = TransactionData::nu4();
        mtx_a.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(5).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::open(escrow_tx_predicate)),
        });
        let tx_a = mtx_a.freeze().unwrap();


        // construct customer-close-tx
        let mut mtx_b = TransactionData::nu4();
        mtx_b.wtp_inputs.push(WtpIn {
            prevout: OutPoint::new(tx_a.txid().0, 0),
            witness: wtp::Witness::Bolt(bolt::Witness::open(close_witness_input)),
        });
        // to_customer
        mtx_b.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(4).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::close(cust_close_tx_predicate)),
        });
        // to_merchant
        mtx_b.wtp_outputs.push(WtpOut {
            value: Amount::from_u64(1).unwrap(),
            predicate: wtp::Predicate::Bolt(bolt::Predicate::close(merch_close_tx_predicate)),
        });

        let tx_b = mtx_b.freeze().unwrap();

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
