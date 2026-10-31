use corez::io::{self, Write};
use zcash_encoding::{MAX_COMPACT_SIZE, Vector};
use zcash_script::script;

use super::Script;

#[test]
fn bulk_script_writes() {
    let max_len = usize::try_from(MAX_COMPACT_SIZE).unwrap();
    for len in [0, 8, 252, 253, 65535, 65536, max_len, max_len + 1] {
        let script = Script(script::Code((0..=255).cycle().take(len).collect()));
        let mut expected = vec![];
        let old = Vector::write(&mut expected, &script.0.0, |w, b| w.write_all(&[*b]))
            .map_err(|e| e.kind());
        let mut actual = vec![];
        let result = script.write(&mut actual).map_err(|e| e.kind());
        assert_eq!(result, old);
        if len > max_len {
            assert_eq!(result, Err(io::ErrorKind::InvalidInput));
        } else {
            result.unwrap();
            assert_eq!(actual, expected);
        }
    }
}

struct FailingWriter(usize);

impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0 == 0 {
            return Err(io::ErrorKind::Other.into());
        }
        let len = bytes.len().min(2).min(self.0);
        self.0 -= len;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn bulk_script_write_propagates_error() {
    let script = Script(script::Code(vec![0; 8]));
    // Accept the one-byte prefix and three payload bytes, then fail after short writes.
    let mut writer = FailingWriter(4);
    assert_eq!(
        script.write(&mut writer).unwrap_err().kind(),
        io::ErrorKind::Other,
    );
}
