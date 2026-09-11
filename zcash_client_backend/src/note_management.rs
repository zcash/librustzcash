//! Note management: maintaining a target distribution of note values in the most recent
//! shielded pool.

use zcash_protocol::{
    ShieldedPool,
    consensus::{self, NetworkUpgrade},
};

use crate::data_api::wallet::TargetHeight;

/// Returns the pool in which note management maintains a note distribution at `target_height`:
/// Ironwood once NU6.3 is active, Orchard otherwise. Sapling is never this pool.
pub fn most_recent_shielded_pool<P: consensus::Parameters>(
    params: &P,
    target_height: TargetHeight,
) -> ShieldedPool {
    if params.is_nu_active(NetworkUpgrade::Nu6_3, target_height.into()) {
        ShieldedPool::Ironwood
    } else {
        ShieldedPool::Orchard
    }
}
