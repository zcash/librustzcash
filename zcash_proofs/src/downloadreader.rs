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
        use ResponseLazyReader::{Complete, Request, Response};

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
                    for (i, buf_byte) in buf.iter_mut().enumerate() {
                        match response.next() {
                            // Load a byte into the buffer.
                            Some(Ok((byte, _length))) => {
                                *buf_byte = byte;
                            }

                            // The whole response has been processed.
                            None => {
                                *self = Complete(Ok(()));
                                return Ok(i);
                            }

                            // The response is corrupted.
                            Some(Err(error)) => {
                                let error = format!("download response failed: {:?}", error);

                                *self = Complete(Err(error.clone()));
                                return Err(io::Error::new(io::ErrorKind::Other, error));
                            }
                        }
                    }

                    return Ok(buf.len());
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
