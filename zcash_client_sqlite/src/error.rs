use std::error;
use std::fmt;

#[derive(Debug)]
pub enum ErrorKind {
    TableNotEmpty,
    Database(rusqlite::Error),
}

#[derive(Debug)]
pub struct Error(pub(crate) ErrorKind);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            ErrorKind::TableNotEmpty => write!(f, "Table is not empty"),
            ErrorKind::Database(e) => write!(f, "{}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            ErrorKind::Database(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error(ErrorKind::Database(e))
    }
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }
}
