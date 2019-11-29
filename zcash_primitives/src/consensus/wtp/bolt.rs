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
                let is_valid = bolt::verify_channel_opening(p_open, w_open);

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
                let is_valid = bolt::verify_channel_closing(p_close, w_close);
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
        // TODO: generate sample inputs
        let mut _ser_channel_token = hex::decode("03ad405f05ba0bd2b88db730c7e267293728d2da3183351c4070a56f46c052d09302754e51904e5ddc5485946988d9eb4fc9b4ab7d13df86f40c4f69339ab2252e0ea35efc25c6dd699a5f6aed7fd25e6257f31051d1ab8d1c224fcc1c6b7e2aff4a25f4cbee450f00e7336e2dcb4388e237120ac0250beaf91d458bc9602fa001ee090bca5220dc6b586bf75516e0554b817208aa62be1f7b2d4f7e4d77f50cce18ae8beb15797ff8e4035a6b5cfc8f6714da199d2b62398c2c8a8560a6ac73001fa8b5c37c30804cdb7480d0c5ef7325fd07b72d3883d614f1cd0d272bbe360ea22022abfa5a145d09224d7baac1d9b056289c4537b32e029e179bc3071abe4e74ae6debc7472c223b9a66cf85b6b4bbee9061da4429337fb79b08a9c5c187c47b183b707e2232a69af9da98fd18cbdb48164a4d51bb49149eab7538539e7a561ed83e14703d2babb5f51913c43c22084ba925b16b938051f365ca546e9ee365d7b865cdecb5708a6ed693f212f46ec71bd8fc90390e12716e04a071b5f91d4ac1210eb37c162b06205574655293f4f2961024d604bb3f4025b4cb7eec6f35375006c052a51fcb0a81f1ff9b084f90b3d33b5170f5c0457eba4aef22d4bedab8098fe7464a9f9545efb349ee228651fb9e0f88b43e3953f75719ad7afba5eed73de480eea175ee64db0417d2c4c08ff2a30d6789cbfaa4feedd46c5cdf49ddc465face9734371ea321519e81ecdcfcec2b0f94215ff40839554394b36b1252bccb84fcff839cd1e416adc45aae33e135042af65d68d626382f5ef863598963aa34a7bc7a9dc8b06dd80e2605e5177ebfb10c813eb18296b81937eb0a54c6cf4cd4a9a05951d3dc98597c968a1af1b601a0488b12be6eaabb9f1e544bfa03c0d9c3a29371b0f4ab2ce108e4a6d08c508e75f2ec262339ecc20aba4faf2494191ff1257224d59b15413c162c6c80a4ca2d0684b2e6ecb66f10e82923fc26d65f721708640604558ff60911eb77495871ceae8c6ce4e22eaf29f209a6416efde17f711105b8d4b062811c01e0e51bc3834692d3a9f98be972bea710980fcbd63e4133e51defbb678d3d394762b74ddac12431a29371b0f4ab2ce108e4a6d08c508e75f2ec262339ecc20aba4faf2494191ff1257224d59b15413c162c6c80a4ca2d06b33e2d93f0209fc3645bb82aad0dab4fd8ac3800e340e33243c4bd8f6db73fb1e7902cabc628d0658512647e30776413a835285578439b1b52c1909cfaa2991dca145dc92d3e0ba6513cf51a3060f67fa51233d0e8a3217cd264fa82494d054d82324881008ae8287bdc1c290f3148a82963d5bb890e684b3dccd4bd477752a6f2d8838a9d120f1d348945f7e8e905ed90096a824aed32d05465188e2bb230a90c51d0ad2b1a69977b6855b516fc99b9aab1cef9eda7e05cf8305bb24b1eda66b18757ce92622fc8f5140aa87375881f3f6e395e89dcb889d9ed262ce53ff14f8fd1fd9059aeeedb0cf77cd4b1fd989b").unwrap();
        let mut _merch_close_addr = hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        _merch_close_addr.append(&mut _ser_channel_token);
        let mut escrow_tx_predicate = [0u8; 1106]; // channel token + merch-close-address
        escrow_tx_predicate.copy_from_slice(_merch_close_addr.as_slice());

        // 1 byte mode + 4 bytes cust_bal + 4 bytes merch_bal + 72 bytes cust_sig + 96 bytes close token
        let mut close_witness_input = [0u8; 212];
        let mut close_witness_vec = Vec::new();
        close_witness_vec.push(0x1);
        close_witness_vec.extend([0,0,0,85].iter());
        close_witness_vec.extend([0,0,0,25].iter());
        close_witness_vec.push(70);
        close_witness_vec.extend(hex::decode("3044022064650285b55624f1f64b2c75e76589fa4b1033dabaa7ff50ff026e1dc038279202204ca696e0a829687c87171e8e5dab17069be248ff2595fd9607f3346dadcb579f").unwrap());
        close_witness_vec.push(96);
        close_witness_vec.extend(hex::decode("83909c8d21ac0cf4e859e7f665ecf867892933537372bdf7125b3feb4b568dbf65f8a1c338d84aba91c9ffd6cce34752899a3fc0f78103f85e7fd673fd8a6739136a1c2e9aced6563599c51172fa4fdb58011a1a5cfa2530b7e8387bd58fbec3").unwrap());
        close_witness_vec.extend(hex::decode("031f63dcb88fe29d05dae0a0169186cd953b9db2921856e521a2b167eb83ee5347").unwrap());
        close_witness_vec.extend([0,0].iter());
        close_witness_input.copy_from_slice(close_witness_vec.as_slice());

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
