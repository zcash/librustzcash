//! Byte-level coinbase bundle representation.

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use zcash_encoding::CompactSize;
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use crate::transaction::zip248::CoinbaseBundle;

/// The size in bytes of the coinbase bundle's block height.
const BLOCK_HEIGHT_SIZE: usize = 4;
/// The size in bytes of a coinbase amount.
const AMOUNT_SIZE: usize = 8;

/// The effecting data of a version 7 coinbase bundle.
///
/// The fields are retained as they appear on the wire. Bundle-local field
/// constraints are enforced when the bundle is converted to its typed
/// representation.
///
/// [ZIP 248 §Coinbase Effecting Data](https://zips.z.cash/zip-0248#coinbase-effecting-data)
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseBundleBytes {
    block_height: BlockHeight,
    block_subsidy: u64,
    lockbox_value: u64,
    coinbase_data: Vec<u8>,
}

#[cfg(zcash_unstable = "nu8")]
impl CoinbaseBundleBytes {
    /// Constructs a coinbase bundle from its wire fields.
    pub fn from_parts(
        block_height: BlockHeight,
        block_subsidy: u64,
        lockbox_value: u64,
        coinbase_data: Vec<u8>,
    ) -> io::Result<Self> {
        Ok(Self {
            block_height,
            block_subsidy,
            lockbox_value,
            coinbase_data,
        })
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

    /// Reads a coinbase bundle's effecting data.
    ///
    /// The fields are retained as they appear on the wire. The payload length
    /// is bounded by the enclosing bundle's wire length.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut block_height = [0u8; BLOCK_HEIGHT_SIZE];
        reader.read_exact(&mut block_height)?;
        let block_height = BlockHeight::from(u32::from_le_bytes(block_height));

        let mut amount = [0u8; AMOUNT_SIZE];
        reader.read_exact(&mut amount)?;
        let block_subsidy = u64::from_le_bytes(amount);

        reader.read_exact(&mut amount)?;
        let lockbox_value = u64::from_le_bytes(amount);

        let data_len = CompactSize::read_t::<_, usize>(&mut reader)?;
        let mut coinbase_data = alloc::vec![0u8; data_len];
        reader.read_exact(&mut coinbase_data)?;

        Self::from_parts(block_height, block_subsidy, lockbox_value, coinbase_data)
    }

    /// Writes a coinbase bundle's effecting data.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&u32::from(self.block_height).to_le_bytes())?;
        writer.write_all(&self.block_subsidy.to_le_bytes())?;
        writer.write_all(&self.lockbox_value.to_le_bytes())?;
        CompactSize::write(&mut writer, self.coinbase_data.len())?;
        writer.write_all(&self.coinbase_data)
    }

    /// Converts this byte representation to the typed coinbase bundle.
    ///
    /// Returns an error if an amount is outside the [`Zatoshis`] monetary
    /// domain or a bundle-local constraint is violated: the block height is
    /// outside `1..=499_999_999`, the lockbox value exceeds the block subsidy,
    /// or the coinbase data exceeds [`MAX_COINBASE_DATA_LEN`].
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
        }
    }
}
