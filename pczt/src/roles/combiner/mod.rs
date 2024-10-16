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
            .fold(Ok(None), |acc, pczt| match acc {
                Err(e) => Err(e),
                Ok(None) => Ok(Some(pczt)),
                Ok(Some(acc)) => merge(acc, pczt).map(Some),
            })
            .transpose()
            .unwrap_or(Err(Error::NoPczts))
    }
}

fn merge(lhs: Pczt, rhs: Pczt) -> Result<Pczt, Error> {
    if lhs.version != rhs.version {
        return Err(Error::DataMismatch);
    }

    Ok(Pczt {
        version: lhs.version,
        global: lhs.global.merge(rhs.global).ok_or(Error::DataMismatch)?,
        transparent: lhs
            .transparent
            .merge(rhs.transparent)
            .ok_or(Error::DataMismatch)?,
        sapling: lhs.sapling.merge(rhs.sapling).ok_or(Error::DataMismatch)?,
        orchard: lhs.orchard.merge(rhs.orchard).ok_or(Error::DataMismatch)?,
    })
}

/// Errors that can occur while combining PCZTs.
#[derive(Debug)]
pub enum Error {
    NoPczts,
    DataMismatch,
}
