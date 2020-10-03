//! ssb-tfk
//!
//! A module that implements the tfk encoding of ssb message keys.
//! Spec defined [here](https://github.com/ssbc/envelope-spec/blob/master/encoding/tfk.md)

use snafu::{OptionExt, ResultExt, Snafu};
use ssb_multiformats::multihash::Multihash;
use std::io::Write;

#[derive(Snafu, Debug)]
pub enum Error {
    InvalidType,
    InvalidFormat,
    NotEnoughBytes,
    WriteError { source: std::io::Error },
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Type {
    Feed = 0,
    Message = 1,
    Blob = 2,
    DiffieHellman = 3,
}

impl Type {
    pub fn encode(&self) -> u8 {
        *self as u8
    }

    pub fn encode_write<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        writer.write(&[self.encode()]).context(WriteError)?;
        Ok(())
    }
    pub fn decode(byte: u8) -> Result<Self, Error> {
        match byte {
            0 => Ok(Type::Feed),
            1 => Ok(Type::Message),
            2 => Ok(Type::Blob),
            3 => Ok(Type::DiffieHellman),
            _ => Err(Error::InvalidType),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Format {
    Classic = 0,
    GabbyGrove = 1,
}

impl Format {
    pub fn encode(&self) -> u8 {
        *self as u8
    }
    pub fn encode_write<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        writer.write(&[self.encode()]).context(WriteError)?;
        Ok(())
    }

    pub fn decode(byte: u8) -> Result<Self, Error> {
        match byte {
            0 => Ok(Format::Classic),
            1 => Ok(Format::GabbyGrove),
            _ => Err(Error::InvalidFormat),
        }
    }
}
// TODO: let's use a vec here to start with. Later we could think about AsRef / Borrow or even just an
// array.
#[derive(PartialEq, Debug)]
pub struct Key(Vec<u8>);

#[derive(PartialEq, Debug)]
pub struct TypeFormatKey {
    pub tipe: Type,
    pub format: Format,
    pub key: Key,
}

impl TypeFormatKey {
    pub fn new(tipe: Type, format: Format, key: Key) -> TypeFormatKey {
        TypeFormatKey { tipe, format, key }
    }

    pub fn encode_write<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.tipe.encode_write(writer)?;
        self.format.encode_write(writer)?;
        writer.write(&self.key.0).context(WriteError)?;
        Ok(())
    }

    // TODO make this decode_read OR return the number of bytes read.
    pub fn decode(bytes: &[u8]) -> Result<TypeFormatKey, Error> {
        let tipe_byte = bytes.get(0).context(NotEnoughBytes)?;
        let tipe = Type::decode(*tipe_byte)?;

        let format_byte = bytes.get(1).context(NotEnoughBytes)?;
        let format = Format::decode(*format_byte)?;

        let key_bytes = bytes.get(2..).context(NotEnoughBytes)?;
        let key = Key(key_bytes.to_owned());

        Ok(TypeFormatKey { tipe, format, key })
    }
}

impl From<Multihash> for TypeFormatKey {
    fn from(multihash: Multihash) -> Self {
        let (tipe, key) = match multihash {
            Multihash::Message(hash) => (Type::Message, hash),
            Multihash::Blob(hash) => (Type::Blob, hash),
        };

        TypeFormatKey {
            tipe,
            key: Key(key.into()),
            format: Format::Classic,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn encode_decode() {
        let tipe = Type::Blob;
        let format = Format::GabbyGrove;
        let key = Key(vec![3, 4]);

        let tfk = TypeFormatKey {
            tipe,
            format,
            key,
        };

        let mut encoded = Vec::new();

        tfk.encode_write(&mut encoded).unwrap();

        let decoded = TypeFormatKey::decode(&encoded).unwrap();

        assert_eq!(decoded, tfk);
    }
}
