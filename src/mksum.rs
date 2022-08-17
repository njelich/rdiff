use std::io::{BufWriter, Read, Result, Write};

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use byteorder::{BigEndian, WriteBytesExt};
use cast::usize;

use crate::rollsum::Window;

use super::rollsum::Rollsum;

#[derive(Debug, Copy, Clone)]
pub enum SignatureFormat {
    Blake2Sig = 0x72730137,
}

const RS_MAX_STRONG_SUM_LENGTH: usize = 32;

#[derive(Debug, Copy, Clone)]
pub struct SignatureOptions {
    pub magic: SignatureFormat,

    pub block_len: u32,

    pub strong_len: u32,
}

impl SignatureOptions {
    pub fn default() -> SignatureOptions {
        SignatureOptions {
            magic: SignatureFormat::Blake2Sig,
            block_len: super::DEFAULT_BLOCK_LEN,
            strong_len: RS_MAX_STRONG_SUM_LENGTH as u32,
        }
    }

    pub fn with_strong_len(self, s: u32) -> SignatureOptions {
        SignatureOptions {
            strong_len: s,
            ..self
        }
    }
}

fn write_u32be(f: &mut dyn Write, a: u32) -> Result<()> {
    f.write_u32::<BigEndian>(a)
}

fn fill_buffer(inf: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    let mut bytes_read: usize = 0;
    while bytes_read < buf.len() {
        let l = inf.read(&mut buf[bytes_read..])?;
        if l == 0 {
            break;
        } else {
            bytes_read += l;
        }
    }
    return Ok(bytes_read);
}

pub fn generate_signature(
    basis: &mut dyn Read,
    options: &SignatureOptions,
    sig: &mut dyn Write,
) -> Result<()> {
    let mut buf = vec![0; usize(options.block_len)];

    let sig = &mut BufWriter::new(sig);
    write_u32be(sig, options.magic as u32)?;
    write_u32be(sig, options.block_len)?;
    write_u32be(sig, options.strong_len)?;

    loop {
        let l = fill_buffer(basis, &mut buf)?;
        if l == 0 {
            break;
        }
        let b = &buf[..l];
        {
            let mut rs = Window::new();
            rs.update(b);
            write_u32be(sig, rs.digest())?;
        }
        {
            let mut hasher = Blake2bVar::new(32).unwrap();
            hasher.update(b);
            let mut d = [0u8; RS_MAX_STRONG_SUM_LENGTH];
            hasher.finalize_variable(&mut d).unwrap();
            sig.write(&d[..(options.strong_len as usize)])?;
        }
        if l < buf.len() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use std::vec::Vec;

    fn generate_signature_on_arrays(in_buf: &[u8]) -> Vec<u8> {
        let mut out_buf = Cursor::new(Vec::<u8>::new());
        let options = SignatureOptions::default();
        assert_eq!(options.block_len, 2 << 10);

        generate_signature(&mut in_buf.as_ref(), &options, &mut out_buf).unwrap();
        out_buf.into_inner()
    }

    #[test]
    pub fn empty_signature_header() {
        let out_buf = generate_signature_on_arrays(&[]);
        assert_eq!(
            out_buf.as_slice(),
            [b'r', b's', 0x01, 0x37, 0, 0, 8, 0, 0, 0, 0, 32,]
        );
    }

    #[test]
    pub fn small_file() {
        let out_buf = generate_signature_on_arrays("Hello world\n".as_bytes());

        assert_eq!(out_buf.len(), 12 + 4 + 32);
    }
}
