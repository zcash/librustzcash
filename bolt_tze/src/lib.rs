//! Bolt implementation of WTP consensus rules.
//!
//! See `README.md` for a description of the three Bolt programs. Here's one scenario covered by the programs:
//!
//! - `tx_a`: `[ [any input types...] ----> TzeOut(channel_token, merch-close-pk) ]` funding tx
//! - `tx_b`: `[ TzeIn(tx_a, (wallet || cust-sig || close-token)) -> { TzeOut(cust-bal, (wpk || block-height)), TxOut(merch-bal, merch-close-pk) } ]` cust-close-tx
//! - `tx_c`: `[ TzeIn(tx_b, (0x0 || cust-sig)) -> [any output types...] ]` cust-spending-tx after time delay
//!
//! For all the cases, see tests below

use zcash_primitives::{
    consensus::BranchId,
    extensions::transparent::Extension,
    transaction::components::{Amount, TzeOut},
    transaction::{signature_hash, SignableInput, Transaction, SIGHASH_ALL},
};

pub mod types;

use types::{
    convert_to_amount, verify_channel_closing, verify_channel_merch_closing,
    verify_channel_opening, Predicate, Witness,
};

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
        signature_hash(
            &self.tx(),
            BranchId::Heartwood,
            SIGHASH_ALL,
            SignableInput::Shielded,
        ) //FIXME, this probably shouldn't be Shielded?
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
    type Precondition = Predicate;
    type Witness = Witness;
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
                            if p_close.block_height < 0
                                || p_close.block_height - ctx.block_height() < 144
                            {
                                return Err(
                                    "The block height should be more than 24h in the future",
                                );
                            }

                            // Check that witness type set correctly
                            if w_open.witness_type != 0x1 {
                                return Err(
                                    "Invalid witness type specified for this Bolt WTP mode",
                                );
                            }

                            // Check that tx outputs have the correct balances
                            let is_tx_output1_correct =
                                convert_to_amount(w_open.cust_bal) == tx1_value;
                            let is_tx_output2_correct =
                                convert_to_amount(w_open.merch_bal) == tx2_output_value;
                            let is_tx_output_correct =
                                is_tx_output1_correct && is_tx_output2_correct;

                            // Get the tx hash for the transaction (signatures in witness are supposed to be valid w.r.t this hash)
                            let tx_hash = ctx.get_tx_hash();
                            // Verify channel opening against the witness info provided
                            let is_channel_valid =
                                verify_channel_opening(p_open, w_open, &tx_hash, tx2_pubkey);

                            if is_channel_valid && is_tx_output_correct {
                                Ok(())
                            } else {
                                Err("could not validate channel opening - cust close")
                            }
                        }
                        Ok(Predicate::MerchClose(p_close)) => {
                            // Check if block_height is more than 24h away.
                            if p_close.block_height < 0
                                || p_close.block_height - ctx.block_height() < 144
                            {
                                return Err(
                                    "The block height should be more than 24h in the future",
                                );
                            }

                            let tx1_value = tze_out.value;
                            let is_tx_output_correct =
                                convert_to_amount(w_open.cust_bal + w_open.merch_bal) == tx1_value;
                            // check_merchant_output(w_open, tx1_value, p_close);

                            let tx_hash = ctx.get_tx_hash();
                            let tx2_pubkey = p_close.pubkey.clone();
                            let is_valid =
                                verify_channel_opening(p_open, w_open, &tx_hash, tx2_pubkey);

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
                    return Err("Timelock has not been met");
                }
                if Amount::from_u64(p_close.amount as u64).unwrap()
                    != ctx.get_tx_output_value().unwrap()
                {
                    return Err("The outgoing amount is not correct.");
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
                        return Err("Timelock has not been met");
                    }
                    if ctx.get_tx_output_value().unwrap()
                        != Amount::from_u64((w_close.merch_bal + w_close.cust_bal) as u64).unwrap()
                    {
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
                        },
                        _ => Err("Invalid number of BOLT outputs"),
                    };

                    tx2_pk = tx2_pubkey.unwrap();

                    if ctx.get_tx_output_value().unwrap()
                        != Amount::from_u64(w_close.merch_bal as u64).unwrap()
                    {
                        return Err("The outgoing amount to merchant is not correct.");
                    }
                    if ctx.get_tx_tze_output_value().unwrap()
                        != Amount::from_u64(w_close.cust_bal as u64).unwrap()
                    {
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
    use std::fs::File;
    use std::io::Read;

    use zcash_primitives::{
        extensions::transparent::{self as tze, Extension, ToPayload},
        legacy::Script,
        transaction::{
            components::{Amount, OutPoint, TxOut, TzeIn, TzeOut},
            Transaction, TransactionData, TxId,
        },
    };

    use crate::types::{compute_tx_signature, Predicate, Witness};

    use super::{Context, Program};

    const OPEN_WITNESS_LEN: usize = 220;
    const MERCH_CLOSE_WITNESS_LEN: usize = 220;
    const CLOSE_WITNESS_LEN: usize = 180;
    const CLOSE_PREDICATE_LEN: usize = 1119;
    const OPEN_PREDICATE_LEN: usize = 1107;
    const MERCH_CLOSE_PREDICATE_LEN: usize = 1111;

    fn read_file<'a>(name: &'a str) -> std::io::Result<Vec<u8>> {
        let mut file = File::open(name).unwrap();

        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        return Ok(data);
    }

    fn generate_customer_close_witness(
        cust_bal: [u8; 8],
        merch_bal: [u8; 8],
        cust_sig: &Vec<u8>,
        close_token: &Vec<u8>,
        wpk: &Vec<u8>,
    ) -> [u8; OPEN_WITNESS_LEN] {
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
        for _i in 0..pad {
            close_witness_vec.push(0x0);
        }
        close_witness_input.copy_from_slice(close_witness_vec.as_slice());

        return close_witness_input;
    }

    fn generate_customer_merch_close_witness(
        cust_bal: [u8; 8],
        merch_bal: [u8; 8],
        cust_sig: &Vec<u8>,
        close_token: &Vec<u8>,
        wpk: &Vec<u8>,
    ) -> [u8; MERCH_CLOSE_WITNESS_LEN] {
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
        for _i in 0..pad {
            close_witness_vec.push(0x0);
        }
        close_witness_input.copy_from_slice(close_witness_vec.as_slice());

        return close_witness_input;
    }

    fn generate_merchant_unilateral_close_witness(
        cust_bal: [u8; 8],
        merch_bal: [u8; 8],
        sig: &Vec<u8>,
    ) -> [u8; MERCH_CLOSE_WITNESS_LEN] {
        let mut close_witness_input = [0u8; MERCH_CLOSE_WITNESS_LEN];
        let mut close_witness_vec: Vec<u8> = Vec::new();
        close_witness_vec.push(0x0);
        close_witness_vec.push(sig.len() as u8);
        close_witness_vec.extend(sig.iter());
        close_witness_vec.extend(cust_bal.iter());
        close_witness_vec.extend(merch_bal.iter());
        let pad = MERCH_CLOSE_WITNESS_LEN - close_witness_vec.len();
        for _i in 0..pad {
            close_witness_vec.push(0x0);
        }
        close_witness_input.copy_from_slice(close_witness_vec.as_slice());
        return close_witness_input;
    }

    fn generate_merchant_close_witness(
        cust_bal: [u8; 8],
        merch_bal: [u8; 8],
        cust_sig: &Vec<u8>,
        merch_sig: &Vec<u8>,
    ) -> [u8; OPEN_WITNESS_LEN] {
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
        for _i in 0..pad {
            close_witness_vec.push(0x0);
        }
        close_witness_input.copy_from_slice(close_witness_vec.as_slice());
        return close_witness_input;
    }

    fn generate_merchant_revoke_witness(
        address: &Vec<u8>,
        sig: &Vec<u8>,
        revoke_token: &Vec<u8>,
    ) -> [u8; CLOSE_WITNESS_LEN] {
        let mut revoke_witness_input = [0u8; CLOSE_WITNESS_LEN];
        let mut revoke_witness_vec: Vec<u8> = Vec::new();
        revoke_witness_vec.push(0x1);
        revoke_witness_vec.extend(address.iter());
        revoke_witness_vec.push(sig.len() as u8);
        revoke_witness_vec.extend(sig.iter());
        revoke_witness_vec.push(revoke_token.len() as u8);
        revoke_witness_vec.extend(revoke_token.iter());
        let pad = CLOSE_WITNESS_LEN - revoke_witness_vec.len();
        for _i in 0..pad {
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
        for _i in 0..pad {
            spend_witness_vec.push(0x0);
        }
        spend_witness_input.copy_from_slice(spend_witness_vec.as_slice());
        return spend_witness_input;
    }

    fn generate_predicate(
        pubkey: &Vec<u8>,
        amount: [u8; 8],
        block_height: [u8; 4],
        channel_token: &Vec<u8>,
    ) -> [u8; CLOSE_PREDICATE_LEN] {
        let mut tx_predicate = [0u8; CLOSE_PREDICATE_LEN];
        let mut tx_pred: Vec<u8> = Vec::new();
        tx_pred.extend(pubkey.iter());
        tx_pred.extend(amount.iter());
        tx_pred.extend(block_height.iter());
        tx_pred.extend(channel_token.iter());
        tx_predicate.copy_from_slice(tx_pred.as_slice());
        return tx_predicate;
    }

    fn generate_open_predicate(
        pubkey: &Vec<u8>,
        channel_token: &Vec<u8>,
    ) -> [u8; OPEN_PREDICATE_LEN] {
        let mut tx_predicate = [0u8; OPEN_PREDICATE_LEN];
        let mut tx_pred: Vec<u8> = Vec::new();
        tx_pred.extend(pubkey.iter());
        tx_pred.extend(channel_token.iter());
        tx_predicate.copy_from_slice(tx_pred.as_slice());
        return tx_predicate;
    }

    fn generate_merch_close_predicate(
        pubkey: &Vec<u8>,
        block_height: [u8; 4],
        channel_token: &Vec<u8>,
    ) -> [u8; MERCH_CLOSE_PREDICATE_LEN] {
        let mut tx_predicate = [0u8; MERCH_CLOSE_PREDICATE_LEN];
        let mut tx_pred: Vec<u8> = Vec::new();
        tx_pred.extend(pubkey.iter());
        tx_pred.extend(block_height.iter());
        tx_pred.extend(channel_token.iter());
        tx_predicate.copy_from_slice(tx_pred.as_slice());
        return tx_predicate;
    }

    fn tze_out<P: ToPayload>(amount: u64, value: &P) -> TzeOut {
        TzeOut {
            value: Amount::from_u64(amount).unwrap(),
            precondition: tze::Precondition::from(1, value),
        }
    }

    fn tze_in<W: ToPayload>(txid: TxId, value: &W) -> TzeIn {
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

    impl<'a> Context for Ctx<'a> {
        fn block_height(&self) -> i32 {
            self.height
        }

        fn tx(&self) -> &Transaction {
            &self.tx
        }
    }

    #[test]
    fn bolt_program_open_and_close() {
        let _ser_channel_token =
            hex::decode(read_file("bolt_testdata/channel.token").unwrap()).unwrap();

        let escrow_tx_hash = vec![
            218, 142, 74, 74, 236, 37, 47, 120, 241, 20, 203, 94, 78, 126, 131, 174, 4, 3, 75, 81,
            194, 90, 203, 24, 16, 158, 53, 237, 241, 57, 97, 137,
        ];

        let _pk_c =
            hex::decode("0398cb634c1bf97559dfcc47b6c8cc3cce8be2219e571ff721b95130efe065991a")
                .unwrap();
        let sk_c = hex::decode("ee3c802d34a1359b9d3b2a81773730325f7634e2991336c534cbd180980ec581")
            .unwrap();

        let _pk_m =
            hex::decode("03504d8f01942e63cde2caa0c741f8e651a0d339afa9ad5a854bc41e9240492ac2")
                .unwrap();
        let sk_m = hex::decode("4a86f3d5a1edc4ae633216db6efe07d8f358626d595de288816619a10c61e98c")
            .unwrap();

        let cust_sig1 = compute_tx_signature(&sk_c, &escrow_tx_hash);
        // println!("cust sig: {:?}, len: {}", cust_sig, cust_sig.len());

        let merch_tx_hash = vec![
            161, 57, 186, 255, 37, 146, 146, 208, 208, 38, 1, 222, 7, 151, 43, 160, 164, 115, 162,
            54, 211, 138, 190, 1, 179, 131, 22, 210, 56, 163, 143, 113,
        ];
        let cust_sig2 = compute_tx_signature(&sk_c, &merch_tx_hash);
        let merch_sig = compute_tx_signature(&sk_m, &merch_tx_hash);

        let wpk = hex::decode("02b4395f62fc0b786902b37924c2773195ad707ef07dd5ec7e31f2b3cda4804d8c")
            .unwrap();

        let mut _merch_close_addr =
            hex::decode("0a1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let _merch_close_addr2 =
            hex::decode("0b2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();

        let merch_close_address = Script(_merch_close_addr.clone());
        let merch_close_address_dup = Script(_merch_close_addr.clone());
        let merch_close_address_dup2 = Script(_merch_close_addr.clone());
        let merch_close_address_dup3 = Script(_merch_close_addr.clone());
        let merch_close_address_dup4 = Script(_merch_close_addr.clone());

        let escrow_tx_predicate = generate_open_predicate(&_merch_close_addr, &_ser_channel_token);

        // 1 byte mode + 4 bytes cust_bal + 4 bytes merch_bal + 72 bytes cust_sig + 96 bytes close token
        let close_token = hex::decode("8d4ff4d96f17760cabdd9728e667596c2c6d238427dd0529f2b6b60140fc71efc890e03502bdae679ca09236fbb11d9d832b9fc275bf44bad06fd9d0b0296722140273f6cba23859b48c3aaa5ed25455e70bd665165169956be25708026478b6").unwrap();

        let cust_close_witness_input = generate_customer_close_witness(
            [0, 0, 0, 0, 0, 0, 0, 140],
            [0, 0, 0, 0, 0, 0, 0, 70],
            &cust_sig1,
            &close_token,
            &wpk,
        );
        let merch_close_witness_input = generate_merchant_close_witness(
            [0, 0, 0, 0, 0, 0, 0, 200],
            [0, 0, 0, 0, 0, 0, 0, 10],
            &cust_sig2,
            &merch_sig,
        );

        let cust_close_tx_predicate = generate_predicate(
            &wpk,
            [0, 0, 0, 0, 0, 0, 0, 140],
            [0, 0, 0, 146],
            &_ser_channel_token,
        );
        let cust_close_tx_predicate_too_early = generate_predicate(
            &wpk,
            [0, 0, 0, 0, 0, 0, 0, 140],
            [0, 0, 0, 110],
            &_ser_channel_token,
        );
        let merch_close_tx_predicate = generate_merch_close_predicate(
            &_merch_close_addr2,
            [0, 0, 0, 146],
            &_ser_channel_token,
        );

        let merch_tx_hash2 = vec![
            218, 142, 74, 74, 236, 37, 47, 120, 241, 20, 203, 94, 78, 126, 131, 174, 4, 3, 75, 81,
            194, 90, 203, 24, 16, 158, 53, 237, 241, 57, 97, 137,
        ];
        let cust_sig3 = compute_tx_signature(&sk_c, &merch_tx_hash2);
        let cust_close_witness_input2 = generate_customer_merch_close_witness(
            [0, 0, 0, 0, 0, 0, 0, 140],
            [0, 0, 0, 0, 0, 0, 0, 70],
            &cust_sig3,
            &close_token,
            &wpk,
        );

        // escrow-tx (lock up 210 zats)
        let mut mtx_a = TransactionData::zfuture();
        mtx_a
            .tze_outputs
            .push(tze_out(210, &Predicate::open(escrow_tx_predicate)));
        let tx_a = mtx_a.freeze().unwrap();
        // println!("debug: Escrow transaction: {:?}", tx_a);

        // begin - customer-close-tx
        let mut mtx_b = TransactionData::zfuture();
        mtx_b.tze_inputs.push(tze_in(
            tx_a.txid(),
            &Witness::open(cust_close_witness_input),
        ));
        // to_customer
        mtx_b
            .tze_outputs
            .push(tze_out(140, &Predicate::close(cust_close_tx_predicate)));
        // to_merchant
        mtx_b.vout.push(TxOut {
            value: Amount::from_u64(70).unwrap(),
            script_pubkey: merch_close_address,
        });
        let tx_b = mtx_b.freeze().unwrap();
        // end - customer-close-tx
        // println!("debug: Customer close transaction: {:?}", tx_b);

        // begin - merchant-close-tx
        let mut mtx_c = TransactionData::zfuture();
        mtx_c.tze_inputs.push(tze_in(
            tx_a.txid(),
            &Witness::open(merch_close_witness_input),
        ));
        // to_merchant
        mtx_c.tze_outputs.push(tze_out(
            210,
            &Predicate::merch_close(merch_close_tx_predicate),
        ));
        let tx_c = mtx_c.freeze().unwrap();
        // end - merchant-close-tx
        // println!("debug: Merchant close transaction: {:?}", tx_c);

        // begin - customer-close-tx (spending from merchant-close-tx)
        let mut mtx_d = TransactionData::zfuture();
        mtx_d.tze_inputs.push(tze_in(
            tx_c.txid(),
            &Witness::merch_close(cust_close_witness_input2),
        ));
        // to_customer
        mtx_d
            .tze_outputs
            .push(tze_out(140, &Predicate::close(cust_close_tx_predicate)));
        // to_merchant
        mtx_d.vout.push(TxOut {
            value: Amount::from_u64(70).unwrap(),
            script_pubkey: merch_close_address_dup,
        });
        let tx_d = mtx_d.freeze().unwrap();
        // end - customer-close-tx (spending from merchant-close-tx)
        // println!("debug: Customer close transaction spending from merchant-close tx: {:?}", tx_d);

        // begin - customer-close-tx
        let mut mtx_e = TransactionData::zfuture();
        mtx_e.tze_inputs.push(tze_in(
            tx_a.txid(),
            &Witness::open(cust_close_witness_input),
        ));
        // to_customer
        mtx_e.tze_outputs.push(tze_out(
            140,
            &Predicate::close(cust_close_tx_predicate_too_early),
        ));
        // to_merchant
        mtx_e.vout.push(TxOut {
            value: Amount::from_u64(70).unwrap(),
            script_pubkey: merch_close_address_dup2,
        });
        let tx_e = mtx_e.freeze().unwrap();

        // begin - customer-close-tx (spending from merchant-close-tx)
        let mut mtx_f = TransactionData::zfuture();
        mtx_f.tze_inputs.push(tze_in(
            tx_c.txid(),
            &Witness::merch_close(cust_close_witness_input2),
        ));
        // to_customer
        mtx_f
            .tze_outputs
            .push(tze_out(130, &Predicate::close(cust_close_tx_predicate)));
        // to_merchant
        mtx_f.vout.push(TxOut {
            value: Amount::from_u64(70).unwrap(),
            script_pubkey: merch_close_address_dup3,
        });
        let tx_f = mtx_f.freeze().unwrap();
        // end - customer-close-tx (spending from merchant-close-tx)

        // begin - customer-close-tx (spending from merchant-close-tx)
        let mut mtx_g = TransactionData::zfuture();
        mtx_g.tze_inputs.push(tze_in(
            tx_c.txid(),
            &Witness::merch_close(cust_close_witness_input2),
        ));
        // to_customer
        mtx_g
            .tze_outputs
            .push(tze_out(140, &Predicate::close(cust_close_tx_predicate)));
        // to_merchant
        mtx_g.vout.push(TxOut {
            value: Amount::from_u64(60).unwrap(),
            script_pubkey: merch_close_address_dup4,
        });
        let tx_g = mtx_g.freeze().unwrap();
        // end - customer-close-tx (spending from merchant-close-tx)

        let program = Program {};

        // Verify tx_b
        {
            let ctx = Ctx::v1(1, &tx_b);
            assert_eq!(
                program.verify(
                    &tx_a.tze_outputs[0].precondition, // escrow
                    &tx_b.tze_inputs[0].witness,       // customer-close-tx
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
                    &tx_e.tze_inputs[0].witness,       // customer-close-tx
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
                    &tx_c.tze_inputs[0].witness,       // merchant-close-tx (initiating closing)
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
                    &tx_d.tze_inputs[0].witness,       // customer-close-tx
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
                    &tx_f.tze_inputs[0].witness,       // customer-close-tx
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
                    &tx_g.tze_inputs[0].witness,       // customer-close-tx
                    &ctx
                ),
                Err("The outgoing amount to merchant is not correct.")
            );
        }
    }

    #[test]
    fn bolt_program_unilateral_merch() {
        let _ser_channel_token =
            hex::decode(read_file("bolt_testdata/channel.token").unwrap()).unwrap();

        let escrow_tx_hash = vec![
            218, 142, 74, 74, 236, 37, 47, 120, 241, 20, 203, 94, 78, 126, 131, 174, 4, 3, 75, 81,
            194, 90, 203, 24, 16, 158, 53, 237, 241, 57, 97, 137,
        ];

        let _pk_c =
            hex::decode("0398cb634c1bf97559dfcc47b6c8cc3cce8be2219e571ff721b95130efe065991a")
                .unwrap();
        let sk_c = hex::decode("ee3c802d34a1359b9d3b2a81773730325f7634e2991336c534cbd180980ec581")
            .unwrap();

        let _pk_m =
            hex::decode("03504d8f01942e63cde2caa0c741f8e651a0d339afa9ad5a854bc41e9240492ac2")
                .unwrap();
        let sk_m = hex::decode("4a86f3d5a1edc4ae633216db6efe07d8f358626d595de288816619a10c61e98c")
            .unwrap();

        let _cust_sig1 = compute_tx_signature(&sk_c, &escrow_tx_hash);
        // println!("cust sig: {:?}, len: {}", cust_sig, cust_sig.len());

        let merch_tx_hash = vec![
            161, 57, 186, 255, 37, 146, 146, 208, 208, 38, 1, 222, 7, 151, 43, 160, 164, 115, 162,
            54, 211, 138, 190, 1, 179, 131, 22, 210, 56, 163, 143, 113,
        ];
        let cust_sig2 = compute_tx_signature(&sk_c, &merch_tx_hash);
        let merch_sig = compute_tx_signature(&sk_m, &merch_tx_hash);

        let _wpk =
            hex::decode("02b4395f62fc0b786902b37924c2773195ad707ef07dd5ec7e31f2b3cda4804d8c")
                .unwrap();

        let mut _merch_close_addr =
            hex::decode("0a1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let _merch_close_addr2 =
            hex::decode("0b2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();

        let _merch_close_address = Script(_merch_close_addr.clone());
        let merch_close_address_dup = Script(_merch_close_addr.clone());
        let merch_close_address_dup2 = Script(_merch_close_addr.clone());

        let escrow_tx_predicate = generate_open_predicate(&_merch_close_addr, &_ser_channel_token);

        // 1 byte mode + 4 bytes cust_bal + 4 bytes merch_bal + 72 bytes cust_sig + 96 bytes close token
        let _close_token = hex::decode("8d4ff4d96f17760cabdd9728e667596c2c6d238427dd0529f2b6b60140fc71efc890e03502bdae679ca09236fbb11d9d832b9fc275bf44bad06fd9d0b0296722140273f6cba23859b48c3aaa5ed25455e70bd665165169956be25708026478b6").unwrap();

        let merch_close_witness_input = generate_merchant_close_witness(
            [0, 0, 0, 0, 0, 0, 0, 200],
            [0, 0, 0, 0, 0, 0, 0, 10],
            &cust_sig2,
            &merch_sig,
        );

        let merch_close_tx_predicate = generate_merch_close_predicate(
            &_merch_close_addr2,
            [0, 0, 0, 146],
            &_ser_channel_token,
        );
        let merch_close_tx_predicate_too_early = generate_merch_close_predicate(
            &_merch_close_addr2,
            [0, 0, 0, 110],
            &_ser_channel_token,
        );

        let merch_tx_hash2 = vec![
            175, 134, 188, 203, 129, 93, 74, 219, 67, 195, 80, 143, 144, 87, 109, 169, 129, 138,
            65, 71, 66, 23, 117, 101, 91, 204, 217, 196, 36, 124, 91, 87,
        ];
        let merch_sig = compute_tx_signature(&sk_m, &merch_tx_hash2);
        let merch_close_witness = generate_merchant_unilateral_close_witness(
            [0, 0, 0, 0, 0, 0, 0, 140],
            [0, 0, 0, 0, 0, 0, 0, 70],
            &merch_sig,
        );

        // escrow-tx (lock up 210 zats)
        let mut mtx_a = TransactionData::zfuture();
        mtx_a
            .tze_outputs
            .push(tze_out(210, &Predicate::open(escrow_tx_predicate)));
        let tx_a = mtx_a.freeze().unwrap();
        // println!("debug: Escrow transaction: {:?}", tx_a);

        // begin - merchant-close-tx
        let mut mtx_b = TransactionData::zfuture();
        mtx_b.tze_inputs.push(tze_in(
            tx_a.txid(),
            &Witness::open(merch_close_witness_input),
        ));
        // to_merchant
        mtx_b.tze_outputs.push(tze_out(
            210,
            &Predicate::merch_close(merch_close_tx_predicate_too_early),
        ));
        let tx_b = mtx_b.freeze().unwrap();
        // end - merchant-close-tx

        // begin - merchant-close-tx
        let mut mtx_c = TransactionData::zfuture();
        mtx_c.tze_inputs.push(tze_in(
            tx_a.txid(),
            &Witness::open(merch_close_witness_input),
        ));
        // to_merchant
        mtx_c.tze_outputs.push(tze_out(
            210,
            &Predicate::merch_close(merch_close_tx_predicate),
        ));
        let tx_c = mtx_c.freeze().unwrap();
        // end - merchant-close-tx

        // begin - merchant-spending-tx (spending from merchant-close-tx)
        let mut mtx_d = TransactionData::zfuture();
        mtx_d.tze_inputs.push(tze_in(
            tx_c.txid(),
            &Witness::merch_close(merch_close_witness),
        ));
        // to_merchant
        mtx_d.vout.push(TxOut {
            value: Amount::from_u64(210).unwrap(),
            script_pubkey: merch_close_address_dup,
        });
        let tx_d = mtx_d.freeze().unwrap();
        // end - customer-close-tx (spending from merchant-close-tx)
        // println!("debug: Customer close transaction spending from merchant-close tx: {:?}", tx_d);

        // begin - merchant-spending-tx (spending from merchant-close-tx)
        let mut mtx_e = TransactionData::zfuture();
        mtx_e.tze_inputs.push(tze_in(
            tx_c.txid(),
            &Witness::merch_close(merch_close_witness),
        ));
        // to_merchant
        mtx_e.vout.push(TxOut {
            value: Amount::from_u64(200).unwrap(),
            script_pubkey: merch_close_address_dup2,
        });
        let tx_e = mtx_e.freeze().unwrap();
        // end - customer-close-tx (spending from merchant-close-tx)

        let program = Program {};

        // Verify tx_b
        {
            let ctx = Ctx::v1(1, &tx_b);
            assert_eq!(
                program.verify(
                    &tx_a.tze_outputs[0].precondition, // escrow
                    &tx_b.tze_inputs[0].witness,       // merchant-close-tx (initiating closing)
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
                    &tx_c.tze_inputs[0].witness,       // merchant-close-tx (initiating closing)
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
                    &tx_d.tze_inputs[0].witness,       // customer-close-tx
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
                    &tx_d.tze_inputs[0].witness,       // customer-close-tx
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
                    &tx_e.tze_inputs[0].witness,       // customer-close-tx
                    &ctx
                ),
                Err("The outgoing amount is not correct.")
            );
        }
    }

    #[test]
    fn bolt_merch_revoke_program() {
        let _ser_channel_token =
            hex::decode(read_file("bolt_testdata/channel.token").unwrap()).unwrap();

        let escrow_tx_hash = vec![
            218, 142, 74, 74, 236, 37, 47, 120, 241, 20, 203, 94, 78, 126, 131, 174, 4, 3, 75, 81,
            194, 90, 203, 24, 16, 158, 53, 237, 241, 57, 97, 137,
        ];

        let _pk_c =
            hex::decode("0398cb634c1bf97559dfcc47b6c8cc3cce8be2219e571ff721b95130efe065991a")
                .unwrap();
        let sk_c = hex::decode("ee3c802d34a1359b9d3b2a81773730325f7634e2991336c534cbd180980ec581")
            .unwrap();

        let _pk_m =
            hex::decode("03504d8f01942e63cde2caa0c741f8e651a0d339afa9ad5a854bc41e9240492ac2")
                .unwrap();
        let sk_m = hex::decode("4a86f3d5a1edc4ae633216db6efe07d8f358626d595de288816619a10c61e98c")
            .unwrap();

        let cust_sig1 = compute_tx_signature(&sk_c, &escrow_tx_hash);
        // println!("cust sig: {:?}, len: {}", cust_sig, cust_sig.len());

        let merch_tx_hash = vec![
            161, 57, 186, 255, 37, 146, 146, 208, 208, 38, 1, 222, 7, 151, 43, 160, 164, 115, 162,
            54, 211, 138, 190, 1, 179, 131, 22, 210, 56, 163, 143, 113,
        ];
        let _cust_sig2 = compute_tx_signature(&sk_c, &merch_tx_hash);
        let _merch_sig = compute_tx_signature(&sk_m, &merch_tx_hash);

        let wpk = hex::decode("02b4395f62fc0b786902b37924c2773195ad707ef07dd5ec7e31f2b3cda4804d8c")
            .unwrap();

        let mut _merch_close_addr =
            hex::decode("0a1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let _merch_close_addr2 =
            hex::decode("0b2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();
        let _cust_close_addr =
            hex::decode("0c3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap();

        let merch_close_address = Script(_merch_close_addr.clone());
        let _merch_close_address_dup = Script(_merch_close_addr.clone());
        let merch_close_address2 = Script(_merch_close_addr2.clone());
        let cust_close_addr = Script(_cust_close_addr.clone());
        let cust_close_addr_dup = Script(_cust_close_addr.clone());
        let cust_close_addr_dup2 = Script(_cust_close_addr.clone());

        let escrow_tx_predicate = generate_open_predicate(&_merch_close_addr, &_ser_channel_token);

        // 1 byte mode + 4 bytes cust_bal + 4 bytes merch_bal + 72 bytes cust_sig + 96 bytes close token
        let close_token = hex::decode("8d4ff4d96f17760cabdd9728e667596c2c6d238427dd0529f2b6b60140fc71efc890e03502bdae679ca09236fbb11d9d832b9fc275bf44bad06fd9d0b0296722140273f6cba23859b48c3aaa5ed25455e70bd665165169956be25708026478b6").unwrap();

        let cust_close_witness_input = generate_customer_close_witness(
            [0, 0, 0, 0, 0, 0, 0, 140],
            [0, 0, 0, 0, 0, 0, 0, 70],
            &cust_sig1,
            &close_token,
            &wpk,
        );

        let cust_close_tx_predicate = generate_predicate(
            &wpk,
            [0, 0, 0, 0, 0, 0, 0, 140],
            [0, 0, 0, 146],
            &_ser_channel_token,
        );

        let _merch_close_tx_predicate =
            generate_open_predicate(&_merch_close_addr2, &_ser_channel_token);

        let merch_sig = hex::decode("3045022100e171be9eb5ffc799eb944e87762116ddff9ae77de58f63175ca354b9d93922390220601aed54bc60d03012f7d1b76d2caa78f9d461b83f014d40ec33ea233de2246e").unwrap();
        let revoke_token = hex::decode("3045022100d4421207f4698bd93b0fd7de19a52f2cf90022c80261c4ff7423c6a5ae2c22e0022043eac6981cf37d873036cd5544dcf9a95cfe8271abc0d66f6c3db031307c2e52").unwrap();
        let merch_revoke_witness_input =
            generate_merchant_revoke_witness(&_merch_close_addr2, &merch_sig, &revoke_token);

        let cust_spend_tx_hash = vec![
            162, 216, 70, 64, 240, 17, 105, 190, 59, 6, 128, 231, 90, 96, 241, 201, 184, 90, 28, 9,
            3, 175, 79, 250, 236, 33, 159, 103, 66, 16, 181, 207,
        ];
        let cust_sig = compute_tx_signature(&sk_c, &cust_spend_tx_hash);
        let cust_spend_tx_witness = generate_spend_tx_witness(&_cust_close_addr, &cust_sig);

        let mut mtx_a = TransactionData::zfuture();
        mtx_a
            .tze_outputs
            .push(tze_out(210, &Predicate::open(escrow_tx_predicate)));
        let tx_a = mtx_a.freeze().unwrap();
        // println!("Escrow transaction: {:?}", tx_a);

        // construct customer-close-tx
        let mut mtx_b = TransactionData::zfuture();
        mtx_b.tze_inputs.push(tze_in(
            tx_a.txid(),
            &Witness::open(cust_close_witness_input),
        ));
        // to_customer
        mtx_b
            .tze_outputs
            .push(tze_out(140, &Predicate::close(cust_close_tx_predicate)));
        // to_merchant
        mtx_b.vout.push(TxOut {
            value: Amount::from_u64(70).unwrap(),
            script_pubkey: merch_close_address,
        });

        let tx_b = mtx_b.freeze().unwrap();

        let mut mtx_c = TransactionData::zfuture();
        mtx_c.tze_inputs.push(tze_in(
            tx_b.txid(),
            &Witness::close(merch_revoke_witness_input),
        ));
        // to_merchant
        mtx_c.vout.push(TxOut {
            value: Amount::from_u64(140).unwrap(),
            script_pubkey: merch_close_address2,
        });

        let tx_c = mtx_c.freeze().unwrap();

        let mut mtx_d = TransactionData::zfuture();
        mtx_d
            .tze_inputs
            .push(tze_in(tx_b.txid(), &Witness::close(cust_spend_tx_witness)));
        // to_merchant
        mtx_d.vout.push(TxOut {
            value: Amount::from_u64(140).unwrap(),
            script_pubkey: cust_close_addr,
        });

        let tx_d = mtx_d.freeze().unwrap();

        let mut mtx_e = TransactionData::zfuture();
        mtx_e
            .tze_inputs
            .push(tze_in(tx_b.txid(), &Witness::close(cust_spend_tx_witness)));
        // to_merchant
        mtx_e.vout.push(TxOut {
            value: Amount::from_u64(140).unwrap(),
            script_pubkey: cust_close_addr_dup,
        });

        let tx_e = mtx_e.freeze().unwrap();

        let mut mtx_f = TransactionData::zfuture();
        mtx_f
            .tze_inputs
            .push(tze_in(tx_b.txid(), &Witness::close(cust_spend_tx_witness)));
        // to_merchant
        mtx_f.vout.push(TxOut {
            value: Amount::from_u64(110).unwrap(),
            script_pubkey: cust_close_addr_dup2,
        });

        let tx_f = mtx_f.freeze().unwrap();

        let program = Program {};

        // Verify tx_b
        {
            let ctx = Ctx::v1(1, &tx_b);
            assert_eq!(
                program.verify(
                    &tx_a.tze_outputs[0].precondition, // escrow
                    &tx_b.tze_inputs[0].witness,       // customer-close-tx
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
                    &tx_c.tze_inputs[0].witness,       // merchant-revoke-tx
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
                    &tx_d.tze_inputs[0].witness,       // customer-spending-tx
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
                    &tx_e.tze_inputs[0].witness,       // customer-spending-tx
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
                    &tx_f.tze_inputs[0].witness,       // customer-spending-tx
                    &ctx
                ),
                Err("The outgoing amount is not correct.")
            );
        }
    }
}
