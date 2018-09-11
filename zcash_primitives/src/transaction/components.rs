use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use pairing::{
    bls12_381::{Bls12, Fr, FrRepr},
    PrimeField, PrimeFieldRepr,
};
use sapling_crypto::{
    jubjub::{edwards, Unknown},
    redjubjub::Signature,
};
use std::io::{self, Read, Write};

use serialize::Vector;
use JUBJUB;

// π_A + π_B + π_C
const GROTH_PROOF_SIZE: usize = (48 + 96 + 48);
// π_A + π_A' + π_B + π_B' + π_C + π_C' + π_K + π_H
const PHGR_PROOF_SIZE: usize = (33 + 33 + 65 + 33 + 33 + 33 + 33 + 33);

const ZC_NUM_JS_INPUTS: usize = 2;
const ZC_NUM_JS_OUTPUTS: usize = 2;

pub struct Amount(pub i64);

pub struct Script(pub Vec<u8>);

impl Script {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let script = Vector::read(&mut reader, |r| r.read_u8())?;
        Ok(Script(script))
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        Vector::write(&mut writer, &self.0, |w, e| w.write_u8(*e))
    }
}

pub struct OutPoint {
    hash: [u8; 32],
    n: u32,
}

impl OutPoint {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut hash = [0; 32];
        reader.read_exact(&mut hash)?;
        let n = reader.read_u32::<LittleEndian>()?;
        Ok(OutPoint { hash, n })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.hash)?;
        writer.write_u32::<LittleEndian>(self.n)
    }
}

pub struct TxIn {
    pub prevout: OutPoint,
    script_sig: Script,
    pub sequence: u32,
}

impl TxIn {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let prevout = OutPoint::read(&mut reader)?;
        let script_sig = Script::read(&mut reader)?;
        let sequence = reader.read_u32::<LittleEndian>()?;

        Ok(TxIn {
            prevout,
            script_sig,
            sequence,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.prevout.write(&mut writer)?;
        self.script_sig.write(&mut writer)?;
        writer.write_u32::<LittleEndian>(self.sequence)
    }
}

pub struct TxOut {
    value: Amount,
    script_pubkey: Script,
}

impl TxOut {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let value = Amount(reader.read_i64::<LittleEndian>()?);
        let script_pubkey = Script::read(&mut reader)?;

        Ok(TxOut {
            value,
            script_pubkey,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_i64::<LittleEndian>(self.value.0)?;
        self.script_pubkey.write(&mut writer)
    }
}

pub struct SpendDescription {
    pub cv: edwards::Point<Bls12, Unknown>,
    pub anchor: Fr,
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub zkproof: [u8; GROTH_PROOF_SIZE],
    pub spend_auth_sig: Signature,
}

impl SpendDescription {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let cv = edwards::Point::<Bls12, Unknown>::read(&mut reader, &JUBJUB)?;
        let anchor = {
            let mut f = FrRepr::default();
            f.read_le(&mut reader)?;
            Fr::from_repr(f).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        };

        let mut nullifier = [0; 32];
        let mut rk = [0; 32];
        reader.read_exact(&mut nullifier)?;
        reader.read_exact(&mut rk)?;

        let mut zkproof = [0; GROTH_PROOF_SIZE];
        reader.read_exact(&mut zkproof)?;
        let spend_auth_sig = Signature::read(&mut reader)?;

        Ok(SpendDescription {
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.cv.write(&mut writer)?;
        self.anchor.into_repr().write_le(&mut writer)?;
        writer.write_all(&self.nullifier)?;
        writer.write_all(&self.rk)?;
        writer.write_all(&self.zkproof)?;
        self.spend_auth_sig.write(&mut writer)
    }
}

pub struct OutputDescription {
    pub cv: edwards::Point<Bls12, Unknown>,
    pub cmu: Fr,
    pub ephemeral_key: edwards::Point<Bls12, Unknown>,
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
    pub zkproof: [u8; GROTH_PROOF_SIZE],
}

impl OutputDescription {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let cv = edwards::Point::<Bls12, Unknown>::read(&mut reader, &JUBJUB)?;
        let cmu = {
            let mut f = FrRepr::default();
            f.read_le(&mut reader)?;
            Fr::from_repr(f).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        };
        let ephemeral_key = edwards::Point::<Bls12, Unknown>::read(&mut reader, &JUBJUB)?;

        let mut enc_ciphertext = [0; 580];
        let mut out_ciphertext = [0; 80];
        reader.read_exact(&mut enc_ciphertext)?;
        reader.read_exact(&mut out_ciphertext)?;

        let mut zkproof = [0; GROTH_PROOF_SIZE];
        reader.read_exact(&mut zkproof)?;

        Ok(OutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.cv.write(&mut writer)?;
        self.cmu.into_repr().write_le(&mut writer)?;
        self.ephemeral_key.write(&mut writer)?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)?;
        writer.write_all(&self.zkproof)
    }
}

enum SproutProof {
    Groth([u8; GROTH_PROOF_SIZE]),
    PHGR([u8; PHGR_PROOF_SIZE]),
}

pub struct JSDescription {
    vpub_old: Amount,
    vpub_new: Amount,
    anchor: [u8; 32],
    nullifiers: [[u8; 32]; ZC_NUM_JS_INPUTS],
    commitments: [[u8; 32]; ZC_NUM_JS_OUTPUTS],
    ephemeral_key: [u8; 32],
    random_seed: [u8; 32],
    macs: [[u8; 32]; ZC_NUM_JS_INPUTS],
    proof: SproutProof,
    ciphertexts: [[u8; 601]; ZC_NUM_JS_OUTPUTS],
}

impl JSDescription {
    pub fn read<R: Read>(mut reader: R, use_groth: bool) -> io::Result<Self> {
        let vpub_old = Amount(reader.read_i64::<LittleEndian>()?);
        let vpub_new = Amount(reader.read_i64::<LittleEndian>()?);

        let mut anchor = [0; 32];
        reader.read_exact(&mut anchor)?;

        let mut nullifiers = [[0; 32]; ZC_NUM_JS_INPUTS];
        nullifiers
            .iter_mut()
            .map(|nf| reader.read_exact(nf))
            .collect::<io::Result<()>>()?;

        let mut commitments = [[0; 32]; ZC_NUM_JS_OUTPUTS];
        commitments
            .iter_mut()
            .map(|cm| reader.read_exact(cm))
            .collect::<io::Result<()>>()?;

        let mut ephemeral_key = [0; 32];
        let mut random_seed = [0; 32];
        reader.read_exact(&mut ephemeral_key)?;
        reader.read_exact(&mut random_seed)?;

        let mut macs = [[0; 32]; ZC_NUM_JS_INPUTS];
        macs.iter_mut()
            .map(|mac| reader.read_exact(mac))
            .collect::<io::Result<()>>()?;

        let proof = match use_groth {
            true => {
                let mut proof = [0; GROTH_PROOF_SIZE];
                reader.read_exact(&mut proof)?;
                SproutProof::Groth(proof)
            }
            false => {
                let mut proof = [0; PHGR_PROOF_SIZE];
                reader.read_exact(&mut proof)?;
                SproutProof::PHGR(proof)
            }
        };

        let mut ciphertexts = [[0; 601]; ZC_NUM_JS_OUTPUTS];
        ciphertexts
            .iter_mut()
            .map(|ct| reader.read_exact(ct))
            .collect::<io::Result<()>>()?;

        Ok(JSDescription {
            vpub_old,
            vpub_new,
            anchor,
            nullifiers,
            commitments,
            ephemeral_key,
            random_seed,
            macs,
            proof,
            ciphertexts,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_i64::<LittleEndian>(self.vpub_old.0)?;
        writer.write_i64::<LittleEndian>(self.vpub_new.0)?;
        writer.write_all(&self.anchor)?;
        writer.write_all(&self.nullifiers[0])?;
        writer.write_all(&self.nullifiers[1])?;
        writer.write_all(&self.commitments[0])?;
        writer.write_all(&self.commitments[1])?;
        writer.write_all(&self.ephemeral_key)?;
        writer.write_all(&self.random_seed)?;
        writer.write_all(&self.macs[0])?;
        writer.write_all(&self.macs[1])?;

        match &self.proof {
            SproutProof::Groth(p) => writer.write_all(p)?,
            SproutProof::PHGR(p) => writer.write_all(p)?,
        }

        writer.write_all(&self.ciphertexts[0])?;
        writer.write_all(&self.ciphertexts[1])
    }
}
