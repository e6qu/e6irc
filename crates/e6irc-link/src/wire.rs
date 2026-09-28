//! The payload primitives every frame is written in: big-endian integers,
//! length-prefixed bytes and text, tagged options and addresses, counted
//! lists. The reader refuses anything past a field's bound, a length that runs
//! past the payload, text that is not UTF-8 and a payload with bytes left
//! over, so a decoded frame is exactly what an encoder could have written.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{DecodeError, EncodeError};

/// Writes one frame's payload.
pub struct Writer<'a>(pub(crate) &'a mut BytesMut);

impl Writer<'_> {
    pub(crate) fn u8(&mut self, value: u8) {
        self.0.put_u8(value);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.0.put_u16(value);
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.0.put_u32(value);
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.0.put_u64(value);
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    /// Bytes of at most `bound`, after a four-byte length.
    pub(crate) fn bytes(
        &mut self,
        field: &'static str,
        value: &[u8],
        bound: usize,
    ) -> Result<(), EncodeError> {
        if value.len() > bound {
            return Err(EncodeError::OverBound {
                field,
                length: value.len(),
                bound,
            });
        }
        self.u32(u32::try_from(value.len()).expect("every bound fits a u32"));
        self.0.put_slice(value);
        Ok(())
    }

    /// Text of at most `bound` bytes.
    pub(crate) fn text(
        &mut self,
        field: &'static str,
        value: &str,
        bound: usize,
    ) -> Result<(), EncodeError> {
        self.bytes(field, value.as_bytes(), bound)
    }

    pub(crate) fn option<T>(
        &mut self,
        value: Option<&T>,
        write: impl FnOnce(&mut Self, &T) -> Result<(), EncodeError>,
    ) -> Result<(), EncodeError> {
        match value {
            None => {
                self.u8(0);
                Ok(())
            }
            Some(value) => {
                self.u8(1);
                write(self, value)
            }
        }
    }

    pub(crate) fn ip(&mut self, address: IpAddr) {
        match address {
            IpAddr::V4(v4) => {
                self.u8(4);
                self.0.put_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                self.u8(6);
                self.0.put_slice(&v6.octets());
            }
        }
    }

    pub(crate) fn socket(&mut self, address: SocketAddr) {
        self.ip(address.ip());
        self.u16(address.port());
    }

    /// A list of at most `bound` entries, after a two-byte count.
    pub(crate) fn list<T>(
        &mut self,
        field: &'static str,
        entries: &[T],
        bound: usize,
        mut write: impl FnMut(&mut Self, &T) -> Result<(), EncodeError>,
    ) -> Result<(), EncodeError> {
        if entries.len() > bound {
            return Err(EncodeError::OverBound {
                field,
                length: entries.len(),
                bound,
            });
        }
        self.u16(u16::try_from(entries.len()).expect("every list bound fits a u16"));
        for entry in entries {
            write(self, entry)?;
        }
        Ok(())
    }
}

/// Reads one frame's payload.
pub struct Reader(pub(crate) Bytes);

impl Reader {
    fn need(&self, field: &'static str, length: usize) -> Result<(), DecodeError> {
        if self.0.remaining() < length {
            return Err(DecodeError::Truncated { field });
        }
        Ok(())
    }

    pub(crate) fn u8(&mut self, field: &'static str) -> Result<u8, DecodeError> {
        self.need(field, 1)?;
        Ok(self.0.get_u8())
    }

    pub(crate) fn u16(&mut self, field: &'static str) -> Result<u16, DecodeError> {
        self.need(field, 2)?;
        Ok(self.0.get_u16())
    }

    pub(crate) fn u32(&mut self, field: &'static str) -> Result<u32, DecodeError> {
        self.need(field, 4)?;
        Ok(self.0.get_u32())
    }

    pub(crate) fn u64(&mut self, field: &'static str) -> Result<u64, DecodeError> {
        self.need(field, 8)?;
        Ok(self.0.get_u64())
    }

    pub(crate) fn bool(&mut self, field: &'static str) -> Result<bool, DecodeError> {
        match self.u8(field)? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(DecodeError::UnknownTag { field, tag }),
        }
    }

    pub(crate) fn bytes(
        &mut self,
        field: &'static str,
        bound: usize,
    ) -> Result<Bytes, DecodeError> {
        let length = self.u32(field)? as usize;
        if length > bound {
            return Err(DecodeError::OverBound {
                field,
                length,
                bound,
            });
        }
        self.need(field, length)?;
        Ok(self.0.split_to(length))
    }

    pub(crate) fn text(
        &mut self,
        field: &'static str,
        bound: usize,
    ) -> Result<String, DecodeError> {
        let bytes = self.bytes(field, bound)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::NotUtf8 { field })
    }

    pub(crate) fn option<T>(
        &mut self,
        field: &'static str,
        read: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Option<T>, DecodeError> {
        match self.u8(field)? {
            0 => Ok(None),
            1 => read(self).map(Some),
            tag => Err(DecodeError::UnknownTag { field, tag }),
        }
    }

    pub(crate) fn ip(&mut self, field: &'static str) -> Result<IpAddr, DecodeError> {
        match self.u8(field)? {
            4 => {
                self.need(field, 4)?;
                let mut octets = [0; 4];
                self.0.copy_to_slice(&mut octets);
                Ok(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            6 => {
                self.need(field, 16)?;
                let mut octets = [0; 16];
                self.0.copy_to_slice(&mut octets);
                Ok(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            tag => Err(DecodeError::UnknownTag { field, tag }),
        }
    }

    pub(crate) fn socket(&mut self, field: &'static str) -> Result<SocketAddr, DecodeError> {
        let ip = self.ip(field)?;
        Ok(SocketAddr::new(ip, self.u16(field)?))
    }

    pub(crate) fn list<T>(
        &mut self,
        field: &'static str,
        bound: usize,
        mut read: impl FnMut(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Vec<T>, DecodeError> {
        let count = self.u16(field)? as usize;
        if count > bound {
            return Err(DecodeError::OverBound {
                field,
                length: count,
                bound,
            });
        }
        (0..count).map(|_| read(self)).collect()
    }

    /// The payload was read to its end: a byte left over is a frame no
    /// encoder wrote.
    pub(crate) fn finish(self) -> Result<(), DecodeError> {
        if self.0.has_remaining() {
            return Err(DecodeError::TrailingBytes {
                count: self.0.remaining(),
            });
        }
        Ok(())
    }
}
