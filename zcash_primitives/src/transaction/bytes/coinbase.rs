//! Byte-level coinbase bundle representation.

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use zcash_encoding::{CompactSize, Vector};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use crate::transaction::zip248::{
    CoinbaseBundle, LevelOfSupport, MAX_MINER_SIGNALS, MinerSignal, POLL_DIGEST_SIZE, PollDigest,
    SignalCode,
};

/// The size in bytes of the coinbase bundle's block height.
const BLOCK_HEIGHT_SIZE: usize = 4;
/// The size in bytes of a coinbase amount.
const AMOUNT_SIZE: usize = 8;
/// The size in bytes of one miner signal: its code and its level of support.
const MINER_SIGNAL_SIZE: usize = 2;

/// The effecting data of a version 7 coinbase bundle.
///
/// The fields are retained as they appear on the wire. Bundle-local field
/// constraints are enforced when the bundle is converted to its typed
/// representation, except for signal count, ordering, and poll-digest presence,
/// which describe the encoding itself.
///
/// [ZIP 248 §Coinbase Effecting Data](https://zips.z.cash/zip-0248#coinbase-effecting-data)
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseBundleBytes {
    block_height: BlockHeight,
    block_subsidy: u64,
    lockbox_value: u64,
    coinbase_data: Vec<u8>,
    miner_signals: Vec<MinerSignal>,
    poll_digest: Option<PollDigest>,
}

#[cfg(zcash_unstable = "nu8")]
impl CoinbaseBundleBytes {
    /// Constructs a coinbase bundle from its wire fields.
    ///
    /// Returns an error if the signal list exceeds [`MAX_MINER_SIGNALS`], its
    /// codes do not strictly ascend, or the poll digest's presence does not
    /// match the signal list.
    pub fn from_parts(
        block_height: BlockHeight,
        block_subsidy: u64,
        lockbox_value: u64,
        coinbase_data: Vec<u8>,
        miner_signals: Vec<MinerSignal>,
        poll_digest: Option<PollDigest>,
    ) -> io::Result<Self> {
        let bundle = Self {
            block_height,
            block_subsidy,
            lockbox_value,
            coinbase_data,
            miner_signals,
            poll_digest,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    fn validate(&self) -> io::Result<()> {
        if self.miner_signals.len() > MAX_MINER_SIGNALS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the coinbase bundle has more miner signals than signal codes",
            ));
        }
        // The digest is present exactly when there are signals.
        if self.poll_digest.is_some() == self.miner_signals.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the poll digest must be present exactly when there are miner signals",
            ));
        }
        if self
            .miner_signals
            .windows(2)
            .any(|pair| pair[0].signal_code() >= pair[1].signal_code())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "coinbase signal codes must strictly ascend",
            ));
        }
        Ok(())
    }

    /// Returns the height of the block in which the transaction is mined.
    pub fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// Returns the block subsidy as the raw wire integer.
    pub fn block_subsidy(&self) -> u64 {
        self.block_subsidy
    }

    /// Returns the part of the block subsidy deposited into the lockbox as the
    /// raw wire integer.
    pub fn lockbox_value(&self) -> u64 {
        self.lockbox_value
    }

    /// Returns the miner-chosen data.
    pub fn coinbase_data(&self) -> &[u8] {
        &self.coinbase_data
    }

    /// Returns the miner signals, in wire order.
    pub fn miner_signals(&self) -> &[MinerSignal] {
        &self.miner_signals
    }

    /// Returns the poll digest, if present.
    pub fn poll_digest(&self) -> Option<&PollDigest> {
        self.poll_digest.as_ref()
    }

    /// Reads a coinbase bundle's effecting data.
    ///
    /// Coinbase data is read incrementally without allocating for its claimed
    /// length. Signal codes must strictly ascend, and the count is bounded by
    /// [`MAX_MINER_SIGNALS`] before allocation. A poll digest follows nonempty
    /// signal lists.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut block_height = [0u8; BLOCK_HEIGHT_SIZE];
        reader.read_exact(&mut block_height)?;
        let block_height = BlockHeight::from(u32::from_le_bytes(block_height));

        let mut amount = [0u8; AMOUNT_SIZE];
        reader.read_exact(&mut amount)?;
        let block_subsidy = u64::from_le_bytes(amount);

        reader.read_exact(&mut amount)?;
        let lockbox_value = u64::from_le_bytes(amount);

        let coinbase_data = Vector::read_bytes(&mut reader)?;

        let signal_count = CompactSize::read_t::<_, usize>(&mut reader)?;
        if signal_count > MAX_MINER_SIGNALS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the coinbase bundle has more miner signals than signal codes",
            ));
        }
        let mut miner_signals = Vec::with_capacity(signal_count);
        for _ in 0..signal_count {
            let mut signal = [0u8; MINER_SIGNAL_SIZE];
            reader.read_exact(&mut signal)?;
            miner_signals.push(MinerSignal::from_parts(
                SignalCode::new(signal[0]),
                LevelOfSupport::new(signal[1]),
            ));
        }

        let poll_digest = if signal_count == 0 {
            None
        } else {
            let mut digest = [0u8; POLL_DIGEST_SIZE];
            reader.read_exact(&mut digest)?;
            Some(PollDigest::new(digest))
        };

        Self::from_parts(
            block_height,
            block_subsidy,
            lockbox_value,
            coinbase_data,
            miner_signals,
            poll_digest,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// Writes a coinbase bundle's effecting data.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.validate()?;
        writer.write_all(&u32::from(self.block_height).to_le_bytes())?;
        writer.write_all(&self.block_subsidy.to_le_bytes())?;
        writer.write_all(&self.lockbox_value.to_le_bytes())?;
        Vector::write_bytes(&mut writer, &self.coinbase_data)?;
        CompactSize::write(&mut writer, self.miner_signals.len())?;
        for signal in &self.miner_signals {
            writer.write_all(&[
                signal.signal_code().to_u8(),
                signal.level_of_support().to_u8(),
            ])?;
        }
        if let Some(poll_digest) = &self.poll_digest {
            writer.write_all(poll_digest.as_bytes())?;
        }
        Ok(())
    }

    /// Converts this byte representation to the typed coinbase bundle.
    ///
    /// Returns an error if an amount is outside the [`Zatoshis`] monetary
    /// domain or a bundle-local constraint is violated: the block height is
    /// outside `1..=499_999_999`, the lockbox value exceeds the block subsidy,
    /// the coinbase data exceeds [`zip248::MAX_COINBASE_DATA_LEN`](crate::transaction::zip248::MAX_COINBASE_DATA_LEN),
    /// the signal codes do not strictly ascend, or the poll digest presence
    /// does not match the signal list.
    pub fn to_coinbase_bundle(&self) -> io::Result<CoinbaseBundle> {
        let block_subsidy = Zatoshis::from_u64(self.block_subsidy).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "coinbase blockSubsidy out of valid monetary range",
            )
        })?;
        let lockbox_value = Zatoshis::from_u64(self.lockbox_value).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "coinbase lockboxValue out of valid monetary range",
            )
        })?;
        CoinbaseBundle::from_parts(
            self.block_height,
            block_subsidy,
            lockbox_value,
            self.coinbase_data.clone(),
            self.miner_signals.clone(),
            self.poll_digest,
        )
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "coinbase bundle violates a ZIP 248 field constraint",
            )
        })
    }
}

#[cfg(zcash_unstable = "nu8")]
impl From<&CoinbaseBundle> for CoinbaseBundleBytes {
    fn from(bundle: &CoinbaseBundle) -> Self {
        Self {
            block_height: bundle.block_height(),
            block_subsidy: u64::from(bundle.block_subsidy()),
            lockbox_value: u64::from(bundle.lockbox_value()),
            coinbase_data: bundle.coinbase_data().to_vec(),
            miner_signals: bundle.miner_signals().to_vec(),
            poll_digest: bundle.poll_digest().copied(),
        }
    }
}
