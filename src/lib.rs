//! ssb-tfk
//! A module that implements the tfk encoding of ssb message keys.
//! Spec defined [here](https://github.com/ssbc/envelope-spec/blob/master/encoding/tfk.md)

use snafu::{OptionExt, ResultExt, Snafu};
pub use ssb_multiformats::multifeed::Multifeed;
pub use ssb_multiformats::multihash::Multihash;
pub use ssb_multiformats::multikey::Multikey;
use std::convert::TryFrom;
use std::io::Read;
use std::io::Write;

#[derive(Snafu, Debug)]
pub enum Error {
    InvalidType,
    InvalidFormat,
    NotEnoughBytes,
    WriteError { source: std::io::Error },
    ReadError { source: std::io::Error },
}

const FEED_KEY_LENGTH: usize = 32;
const MESSAGE_KEY_LENGTH: usize = 32;
const BLOB_KEY_LENGTH: usize = 32;
const DIFFIE_HELLMAN_KEY_LENGTH: usize = 32;

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum KeyType {
    Feed([u8; FEED_KEY_LENGTH]),                    // 0
    Message([u8; MESSAGE_KEY_LENGTH]),              // 1
    Blob([u8; BLOB_KEY_LENGTH]),                    // 2
    DiffieHellman([u8; DIFFIE_HELLMAN_KEY_LENGTH]), // 3
}

impl KeyType {
    pub fn get_encoding_byte(&self) -> u8 {
        match self {
            KeyType::Feed(_) => 0,
            KeyType::Message(_) => 1,
            KeyType::Blob(_) => 2,
            KeyType::DiffieHellman(_) => 3,
        }
    }
    pub fn get_key_bytes(&self) -> &[u8] {
        match self {
            KeyType::Feed(bytes) => bytes,
            KeyType::Message(bytes) => bytes,
            KeyType::Blob(bytes) => bytes,
            KeyType::DiffieHellman(bytes) => bytes,
        }
    }

    pub fn decode_read<R: Read>(type_byte: u8, reader: &mut R) -> Result<Self, Error> {
        match type_byte {
            0 => {
                let mut key_bytes = [0u8; FEED_KEY_LENGTH];
                reader.read_exact(&mut key_bytes).context(ReadError)?;
                Ok(KeyType::Feed(key_bytes))
            }
            1 => {
                let mut key_bytes = [0u8; MESSAGE_KEY_LENGTH];
                reader.read_exact(&mut key_bytes).context(ReadError)?;
                Ok(KeyType::Message(key_bytes))
            }
            2 => {
                let mut key_bytes = [0u8; BLOB_KEY_LENGTH];
                reader.read_exact(&mut key_bytes).context(ReadError)?;
                Ok(KeyType::Blob(key_bytes))
            }
            3 => {
                let mut key_bytes = [0u8; DIFFIE_HELLMAN_KEY_LENGTH];
                reader.read_exact(&mut key_bytes).context(ReadError)?;
                Ok(KeyType::DiffieHellman(key_bytes))
            }
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

#[derive(PartialEq, Debug)]
pub struct TypeFormatKey {
    pub key_type: KeyType,
    pub format: Format,
}

impl TypeFormatKey {
    pub fn new(key_type: KeyType, format: Format) -> TypeFormatKey {
        TypeFormatKey { key_type, format }
    }

    pub fn encode_write<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        let type_byte = self.key_type.get_encoding_byte();
        writer.write(&[type_byte]).context(WriteError)?;

        self.format.encode_write(writer)?;

        let key = self.key_type.get_key_bytes();
        writer.write(key).context(WriteError)?;
        Ok(())
    }

    pub fn decode_read<R: Read>(reader: &mut R) -> Result<TypeFormatKey, Error> {
        let mut header_bytes = [0u8; 2];
        reader.read_exact(&mut header_bytes).context(ReadError)?;

        let key_type_byte = header_bytes.get(0).context(NotEnoughBytes)?;

        let format_byte = header_bytes.get(1).context(NotEnoughBytes)?;
        let format = Format::decode(*format_byte)?;

        let key_type = KeyType::decode_read(*key_type_byte, reader)?;

        Ok(TypeFormatKey { key_type, format })
    }
}

// All Multihashes can be converted to a TypeFormatKey so this conversion can never fail.
impl From<Multihash> for TypeFormatKey {
    fn from(multihash: Multihash) -> Self {
        let key_type = match multihash {
            Multihash::Message(hash) => KeyType::Message(hash),
            Multihash::Blob(hash) => KeyType::Blob(hash),
        };

        TypeFormatKey {
            key_type,
            format: Format::Classic,
        }
    }
}

// All Multifeeds can be converted to a TypeFormatKey so this conversion can never fail.
impl From<Multifeed> for TypeFormatKey {
    fn from(multifeed: Multifeed) -> Self {
        let key_type = match multifeed {
            Multifeed::Multikey(Multikey::Ed25519(hash)) => KeyType::Feed(hash.0),
        };

        TypeFormatKey {
            key_type,
            format: Format::Classic,
        }
    }
}

// _Not_all TypeFormatKeys are Multihashes so this conversion can fail.
impl TryFrom<TypeFormatKey> for Multihash {
    type Error = Error;

    fn try_from(type_format_key: TypeFormatKey) -> Result<Self, Self::Error> {
        match type_format_key.key_type {
            KeyType::Message(key) => Ok(Multihash::Message(key)),
            KeyType::Blob(key) => Ok(Multihash::Blob(key)),
            _ => Err(Error::InvalidType),
        }
    }
}

// _Not_all TypeFormatKeys are Multihashes so this conversion can fail.
impl TryFrom<TypeFormatKey> for Multifeed {
    type Error = Error;

    fn try_from(type_format_key: TypeFormatKey) -> Result<Self, Self::Error> {
        match type_format_key.key_type {
            KeyType::Feed(key) => Ok(Multifeed::Multikey(Multikey::from_ed25519(&key))),
            _ => Err(Error::InvalidType),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::convert::TryFrom;

    #[test]
    fn encode_decode() {
        let key_type = KeyType::Blob([6; BLOB_KEY_LENGTH]);
        let format = Format::GabbyGrove;

        let tfk = TypeFormatKey { key_type, format };

        let mut encoded = Vec::new();

        tfk.encode_write(&mut encoded).unwrap();

        let decoded = TypeFormatKey::decode_read(&mut encoded.as_slice()).unwrap();

        assert_eq!(decoded, tfk);
    }

    #[test]
    // Converts from a ssb "legacy" string -> multihash  -> tfk -> binary encoded tfk -> tfk -> multihash
    fn message_from_to_multihash() {
        let (multihash, _) =
            Multihash::from_legacy(b"%39f9I0e4bEln+yy6850joHRTqmEQfUyxssv54UANNuk=.sha256")
                .unwrap();
        let tfk: TypeFormatKey = multihash.clone().into();
        match tfk.key_type {
            KeyType::Message(_) => (),
            _ => assert!(false, "Incorrect key type"),
        }

        let mut encoded = Vec::new();

        tfk.encode_write(&mut encoded).unwrap();

        let decoded = TypeFormatKey::decode_read(&mut encoded.as_slice()).unwrap();

        let new_multihash = Multihash::try_from(decoded).unwrap();
        assert_eq!(new_multihash, multihash);
    }

    #[test]
    // Converts from a ssb "legacy" string -> multihash  -> tfk -> binary encoded tfk -> tfk -> multihash
    fn blob_from_to_multihash() {
        let (multihash, _) =
            Multihash::from_legacy(b"&39f9I0e4bEln+yy6850joHRTqmEQfUyxssv54UANNuk=.sha256")
                .unwrap();
        let tfk: TypeFormatKey = multihash.clone().into();
        match tfk.key_type {
            KeyType::Blob(_) => (),
            _ => assert!(false, "Incorrect key type"),
        }

        let mut encoded = Vec::new();

        tfk.encode_write(&mut encoded).unwrap();

        let decoded = TypeFormatKey::decode_read(&mut encoded.as_slice()).unwrap();

        let new_multihash = Multihash::try_from(decoded).unwrap();
        assert_eq!(new_multihash, multihash);
    }

    #[test]
    // Converts from a ssb "legacy" string -> multifeed  -> tfk -> binary encoded tfk -> tfk -> multifeed
    fn feed_from_to_multifeed() {
        let (multifeed, _) =
            Multifeed::from_legacy(b"@EtTsMe7l6ap8aRHp2H4XaUpqZpXkieOqjjM7cvj493Q=.ed25519")
                .unwrap();
        let tfk: TypeFormatKey = multifeed.clone().into();
        match tfk.key_type {
            KeyType::Feed(_) => (),
            _ => assert!(false, "Incorrect key type"),
        }

        let mut encoded = Vec::new();

        tfk.encode_write(&mut encoded).unwrap();

        let decoded = TypeFormatKey::decode_read(&mut encoded.as_slice()).unwrap();

        let new_multifeed = Multifeed::try_from(decoded).unwrap();
        assert_eq!(new_multifeed, multifeed);
    }
}
