//! Types and functions for building transparent transaction components.

use std::fmt;

use crate::{
    legacy::TransparentAddress,
    transaction::components::{
        amount::Amount,
        transparent::{self, TxIn, TxOut},
    },
};

#[cfg(feature = "transparent-inputs")]
use crate::{
    consensus::{self},
    legacy::Script,
    transaction::{
        components::OutPoint, sighash_v4::signature_hash_data, SignableInput, TransactionData,
        Unauthorized, SIGHASH_ALL,
    },
};

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidAddress,
    InvalidAmount,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
        }
    }
}

#[cfg(feature = "transparent-inputs")]
struct TransparentInputInfo {
    sk: secp256k1::SecretKey,
    pubkey: [u8; secp256k1::constants::PUBLIC_KEY_SIZE],
    utxo: OutPoint,
    coin: TxOut,
}

pub struct TransparentBuilder {
    #[cfg(feature = "transparent-inputs")]
    secp: secp256k1::Secp256k1<secp256k1::SignOnly>,
    #[cfg(feature = "transparent-inputs")]
    inputs: Vec<TransparentInputInfo>,
    vout: Vec<TxOut>,
}

impl TransparentBuilder {
    pub fn empty() -> Self {
        TransparentBuilder {
            #[cfg(feature = "transparent-inputs")]
            secp: secp256k1::Secp256k1::gen_new(),
            #[cfg(feature = "transparent-inputs")]
            inputs: vec![],
            vout: vec![],
        }
    }

    #[cfg(feature = "transparent-inputs")]
    pub fn add_input(
        &mut self,
        sk: secp256k1::SecretKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<(), Error> {
        if coin.value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        // Ensure that the RIPEMD-160 digest of the public key associated with the
        // provided secret key matches that of the address to which the provided
        // output may be spent.
        let pubkey = secp256k1::PublicKey::from_secret_key(&self.secp, &sk).serialize();
        match coin.script_pubkey.address() {
            Some(TransparentAddress::PublicKey(hash)) => {
                use ripemd160::Ripemd160;
                use sha2::{Digest, Sha256};

                if hash[..] != Ripemd160::digest(&Sha256::digest(&pubkey))[..] {
                    return Err(Error::InvalidAddress);
                }
            }
            _ => return Err(Error::InvalidAddress),
        }

        self.inputs.push(TransparentInputInfo {
            sk,
            pubkey,
            utxo,
            coin,
        });

        Ok(())
    }

    pub fn add_output(&mut self, to: &TransparentAddress, value: Amount) -> Result<(), Error> {
        if value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        self.vout.push(TxOut {
            value,
            script_pubkey: to.script(),
        });

        Ok(())
    }

    pub fn value_balance(&self) -> Option<Amount> {
        #[cfg(feature = "transparent-inputs")]
        let input_sum = self
            .inputs
            .iter()
            .map(|input| input.coin.value)
            .sum::<Option<Amount>>()?;

        #[cfg(not(feature = "transparent-inputs"))]
        let input_sum = Amount::zero();

        input_sum
            - self
                .vout
                .iter()
                .map(|vo| vo.value)
                .sum::<Option<Amount>>()?
    }

    pub fn build(&self) -> Option<transparent::Bundle<transparent::Unauthorized>> {
        #[cfg(feature = "transparent-inputs")]
        let vin: Vec<TxIn<transparent::Unauthorized>> = self
            .inputs
            .iter()
            .map(|i| TxIn::new(i.utxo.clone()))
            .collect();

        #[cfg(not(feature = "transparent-inputs"))]
        let vin: Vec<TxIn<transparent::Unauthorized>> = vec![];

        if vin.is_empty() && self.vout.is_empty() {
            None
        } else {
            Some(transparent::Bundle {
                vin,
                vout: self.vout.clone(),
            })
        }
    }

    #[cfg(feature = "transparent-inputs")]
    pub fn create_signatures(
        self,
        mtx: &TransactionData<Unauthorized>,
        consensus_branch_id: consensus::BranchId,
    ) -> Option<Vec<Script>> {
        if self.inputs.is_empty() && self.vout.is_empty() {
            None
        } else {
            Some(
                self.inputs
                    .iter()
                    .enumerate()
                    .map(|(i, info)| {
                        let mut sighash = [0u8; 32];
                        sighash.copy_from_slice(&signature_hash_data(
                            mtx,
                            consensus_branch_id,
                            SIGHASH_ALL,
                            SignableInput::transparent(
                                i,
                                &info.coin.script_pubkey,
                                info.coin.value,
                            ),
                        ));

                        let msg =
                            secp256k1::Message::from_slice(sighash.as_ref()).expect("32 bytes");
                        let sig = self.secp.sign(&msg, &info.sk);

                        // Signature has to have "SIGHASH_ALL" appended to it
                        let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
                        sig_bytes.extend(&[SIGHASH_ALL as u8]);

                        // P2PKH scriptSig
                        Script::default() << &sig_bytes[..] << &info.pubkey[..]
                    })
                    .collect(),
            )
        }
    }
}
