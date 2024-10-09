use crate::Pczt;

pub struct Combiner {
    pczts: Vec<Pczt>,
}

impl Combiner {
    /// Instantiates the Combiner role with the given PCZTs.
    pub fn new(pczts: Vec<Pczt>) -> Self {
        Self { pczts }
    }

    /// Combines the PCZTs.
    pub fn combine(self) -> Result<Pczt, Error> {
        self.pczts
            .into_iter()
            .try_fold(None, |acc, pczt| match acc {
                None => Ok(Some(pczt)),
                Some(acc) => merge(acc, pczt).map(Some),
            })
            .transpose()
            .unwrap_or(Err(Error::NoPczts))
    }
}

fn merge(lhs: Pczt, rhs: Pczt) -> Result<Pczt, Error> {
    Ok(Pczt {
        global: lhs.global.merge(rhs.global).ok_or(Error::DataMismatch)?,
        transparent: lhs
            .transparent
            .merge(rhs.transparent)
            .ok_or(Error::DataMismatch)?,
        sapling: lhs.sapling.merge(rhs.sapling).ok_or(Error::DataMismatch)?,
        orchard: lhs.orchard.merge(rhs.orchard).ok_or(Error::DataMismatch)?,
    })
}

/// Merges two values for an optional field together.
///
/// Returns `false` if the values cannot be merged.
pub(crate) fn merge_optional<T: PartialEq>(lhs: &mut Option<T>, rhs: Option<T>) -> bool {
    match (&lhs, rhs) {
        // If the RHS is not present, keep the LHS.
        (_, None) => (),
        // If the LHS is not present, set it to the RHS.
        (None, Some(rhs)) => *lhs = Some(rhs),
        // If both are present and are equal, nothing to do.
        (Some(lhs), Some(rhs)) if lhs == &rhs => (),
        // If both are present and are not equal, fail. Here we differ from BIP 174.
        (Some(_), Some(_)) => return false,
    }

    // Success!
    true
}

/// Errors that can occur while combining PCZTs.
#[derive(Debug)]
pub enum Error {
    NoPczts,
    DataMismatch,
}
