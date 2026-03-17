use crate::core::errors::ChainError;

/// Zero-copy cursor over a byte slice.
///
/// All read methods return slices or primitives derived directly from `data`,
/// never allocating. The lifetime `'a` ties returned slices to the source buffer.
pub struct BufferReader<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> BufferReader<'a> {
    /// Construct a reader over `data`. The reader holds no allocations.
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, cursor: 0 }
    }

    /// Bytes not yet consumed.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.cursor)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Current read position (bytes consumed so far).
    #[inline]
    pub fn position(&self) -> usize {
        self.cursor
    }

    // -------------------------------------------------------------------------
    // Internal helpers — no bounds-check duplication
    // -------------------------------------------------------------------------

    /// Advance cursor by `n` bytes, returning the slice.
    ///
    /// Returns `Err(UnexpectedEof)` instead of panicking.
    #[inline]
    fn take(&mut self, n: usize, context: &'static str) -> Result<&'a [u8], ChainError> {
        let end = self
            .cursor
            .checked_add(n)
            .filter(|&e| e <= self.data.len())
            .ok_or(ChainError::UnexpectedEof { context })?;
        let slice = &self.data[self.cursor..end];
        self.cursor = end;
        Ok(slice)
    }

    // -------------------------------------------------------------------------
    // Public read API
    // -------------------------------------------------------------------------

    pub fn read_u8(&mut self) -> Result<u8, ChainError> {
        let b = self.take(1, "u8")?;
        Ok(b[0])
    }

    pub fn read_u16_le(&mut self) -> Result<u16, ChainError> {
        let b = self.take(2, "u16_le")?;
        // `take(2, …)` guarantees b.len() == 2; direct indexing is infallible.
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_u32_le(&mut self) -> Result<u32, ChainError> {
        let b = self.take(4, "u32_le")?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64_le(&mut self) -> Result<u64, ChainError> {
        let b = self.take(8, "u64_le")?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// Return a zero-copy sub-slice of the original buffer.
    ///
    /// The returned `&'a [u8]` has the same lifetime as the source data,
    /// not the lifetime of `self`.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ChainError> {
        self.take(len, "read_bytes")
    }

    /// Decode a Bitcoin-Core VarInt (compact size).
    ///
    /// Encoding:
    /// - `0x00..=0xfc` → value is the byte itself (1 byte total)
    /// - `0xfd`        → read u16-le (3 bytes total)
    /// - `0xfe`        → read u32-le (5 bytes total)
    /// - `0xff`        → read u64-le (9 bytes total)
    pub fn read_compact_size(&mut self) -> Result<u64, ChainError> {
        let first = self.read_u8()?;
        match first {
            0x00..=0xfc => Ok(first as u64),
            0xfd => {
                let v = self.read_u16_le().map_err(|_| ChainError::InvalidVarInt { byte: first })?;
                Ok(v as u64)
            }
            0xfe => {
                let v = self.read_u32_le().map_err(|_| ChainError::InvalidVarInt { byte: first })?;
                Ok(v as u64)
            }
            0xff => {
                let v = self.read_u64_le().map_err(|_| ChainError::InvalidVarInt { byte: first })?;
                Ok(v)
            }
        }
    }

    /// Read an i32 in little-endian order (used for tx version and script ints).
    pub fn read_i32_le(&mut self) -> Result<i32, ChainError> {
        let b = self.take(4, "i32_le")?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // EOF handling — every primitive reader must return Err on exhaustion
    // -------------------------------------------------------------------------

    #[test]
    fn eof_u8_empty_buffer() {
        let mut r = BufferReader::new(&[]);
        assert!(matches!(
            r.read_u8(),
            Err(ChainError::UnexpectedEof { context: "u8" })
        ));
    }

    #[test]
    fn eof_u16_le_truncated() {
        let mut r = BufferReader::new(&[0xAB]); // needs 2 bytes
        assert!(matches!(
            r.read_u16_le(),
            Err(ChainError::UnexpectedEof { context: "u16_le" })
        ));
    }

    #[test]
    fn eof_u32_le_truncated() {
        let mut r = BufferReader::new(&[0x01, 0x02, 0x03]); // needs 4 bytes
        assert!(matches!(
            r.read_u32_le(),
            Err(ChainError::UnexpectedEof { context: "u32_le" })
        ));
    }

    #[test]
    fn eof_u64_le_truncated() {
        let mut r = BufferReader::new(&[0x00; 7]); // needs 8 bytes
        assert!(matches!(
            r.read_u64_le(),
            Err(ChainError::UnexpectedEof { context: "u64_le" })
        ));
    }

    #[test]
    fn eof_read_bytes_partial() {
        let data = [0xDE, 0xAD];
        let mut r = BufferReader::new(&data);
        assert!(matches!(
            r.read_bytes(10),
            Err(ChainError::UnexpectedEof { context: "read_bytes" })
        ));
    }

    // -------------------------------------------------------------------------
    // VarInt — all four cases
    // -------------------------------------------------------------------------

    #[test]
    fn varint_direct_byte_zero() {
        let mut r = BufferReader::new(&[0x00]);
        assert_eq!(r.read_compact_size().unwrap(), 0);
    }

    #[test]
    fn varint_direct_byte_max() {
        let mut r = BufferReader::new(&[0xFC]);
        assert_eq!(r.read_compact_size().unwrap(), 0xFC);
    }

    #[test]
    fn varint_fd_u16_le() {
        // 0xFD followed by 0x0102 → value = 0x0201 = 513
        let mut r = BufferReader::new(&[0xFD, 0x01, 0x02]);
        assert_eq!(r.read_compact_size().unwrap(), 0x0201u64);
    }

    #[test]
    fn varint_fe_u32_le() {
        // 0xFE followed by 4 bytes → little-endian u32
        let mut r = BufferReader::new(&[0xFE, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!(r.read_compact_size().unwrap(), 0x1234_5678u64);
    }

    #[test]
    fn varint_ff_u64_le() {
        // 0xFF followed by 8 bytes → little-endian u64
        let bytes: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut r = BufferReader::new(bytes);
        assert_eq!(r.read_compact_size().unwrap(), u64::MAX);
    }

    #[test]
    fn varint_fd_eof_returns_err() {
        // 0xFD but only one continuation byte — must error
        let mut r = BufferReader::new(&[0xFD, 0x01]);
        assert!(r.read_compact_size().is_err());
    }

    #[test]
    fn varint_ff_eof_returns_err() {
        // 0xFF but only 4 continuation bytes instead of 8
        let mut r = BufferReader::new(&[0xFF, 0x00, 0x00, 0x00, 0x00]);
        assert!(r.read_compact_size().is_err());
    }

    // -------------------------------------------------------------------------
    // Zero-copy slice — pointer must point into the original buffer
    // -------------------------------------------------------------------------

    #[test]
    fn read_bytes_zero_copy_pointer_identity() {
        let data: &[u8] = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mut r = BufferReader::new(data);
        // Skip 2 bytes first.
        r.read_u16_le().unwrap();
        // Read 3 bytes starting at offset 2.
        let slice = r.read_bytes(3).unwrap();

        // The returned slice must be a sub-slice of `data`, not a copy.
        // Verify by pointer range.
        let data_start = data.as_ptr() as usize;
        let data_end = data_start + data.len();
        let slice_start = slice.as_ptr() as usize;
        let slice_end = slice_start + slice.len();

        assert!(
            slice_start >= data_start && slice_end <= data_end,
            "slice {:?} is not inside original buffer {:?}",
            slice_start..slice_end,      // ← usize..usize, consistente
            data_start..data_end,
        );

        assert_eq!(slice, &[0x03, 0x04, 0x05]);
    }

    #[test]
    fn remaining_and_is_empty() {
        let mut r = BufferReader::new(&[0xAA, 0xBB]);
        assert_eq!(r.remaining(), 2);
        assert!(!r.is_empty());
        r.read_u8().unwrap();
        assert_eq!(r.remaining(), 1);
        r.read_u8().unwrap();
        assert_eq!(r.remaining(), 0);
        assert!(r.is_empty());
    }

    #[test]
    fn sequential_reads_advance_cursor() {
        let data: &[u8] = &[0x01, 0x02, 0x00, 0x03, 0x04, 0x05, 0x06];
        let mut r = BufferReader::new(data);
        assert_eq!(r.read_u8().unwrap(), 0x01);
        assert_eq!(r.read_u16_le().unwrap(), 0x0002);
        let tail = r.read_bytes(4).unwrap();
        assert_eq!(tail, &[0x03, 0x04, 0x05, 0x06]);
        assert!(r.is_empty());
    }
}