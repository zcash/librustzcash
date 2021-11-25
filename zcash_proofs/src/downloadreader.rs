//! [`io::Read`] implementations for [`minreq`].

use std::io;

/// A wrapper that implements [`io::Read`] on a [`minreq::ResponseLazy`].
pub enum ResponseLazyReader {
    Request(minreq::Request),
    Response(minreq::ResponseLazy),
    Complete(Result<(), String>),
}

impl From<minreq::Request> for ResponseLazyReader {
    fn from(request: minreq::Request) -> ResponseLazyReader {
        ResponseLazyReader::Request(request)
    }
}

impl From<minreq::ResponseLazy> for ResponseLazyReader {
    fn from(response: minreq::ResponseLazy) -> ResponseLazyReader {
        ResponseLazyReader::Response(response)
    }
}

impl io::Read for ResponseLazyReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use ResponseLazyReader::*;

        // Zero-sized buffer. This should never happen.
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            match self {
                // Launch a lazy response for this request
                Request(request) => match request.clone().send_lazy() {
                    Ok(response) => *self = Response(response),
                    Err(error) => {
                        let error = Err(format!("download request failed: {:?}", error));

                        *self = Complete(error);
                    }
                },

                // Read from the response
                Response(response) => {
                    // minreq has a very limited lazy reading interface.
                    match &mut response.next() {
                        // Read one byte into the buffer.
                        // We ignore the expected length, because we have no way of telling the BufReader.
                        Some(Ok((byte, _length))) => {
                            buf[0] = *byte;
                            return Ok(1);
                        }

                        // Reading failed.
                        Some(Err(error)) => {
                            let error = Err(format!("download response failed: {:?}", error));

                            *self = Complete(error);
                        }

                        // Finished reading.
                        None => *self = Complete(Ok(())),
                    }
                }

                Complete(result) => {
                    return match result {
                        // Return a zero-byte read for download success and EOF.
                        Ok(()) => Ok(0),
                        // Keep returning the download error,
                        Err(error) => Err(io::Error::new(io::ErrorKind::Other, error.clone())),
                    };
                }
            }
        }
    }
}
