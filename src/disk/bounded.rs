// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom, Write};

/// Give the GPT writer the logical disk's end, independently of the backing
/// device size. Reads and writes cannot escape that prefix.
#[derive(Debug)]
pub(super) struct Bounded<'a, D> {
    source: &'a mut D,
    length: u64,
    position: u64,
}

impl<'a, D: Seek> Bounded<'a, D> {
    pub(super) fn new(source: &'a mut D, length: u64) -> io::Result<Self> {
        source.seek(SeekFrom::Start(0))?;
        Ok(Self {
            source,
            length,
            position: 0,
        })
    }
}

impl<D: Read> Read for Bounded<'_, D> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = buffer.len().min(
            (self.length - self.position)
                .try_into()
                .unwrap_or(usize::MAX),
        );
        let count = self.source.read(&mut buffer[..count])?;
        self.position += count as u64;
        Ok(count)
    }
}

impl<D: Write> Write for Bounded<'_, D> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let count = buffer.len().min(
            (self.length - self.position)
                .try_into()
                .unwrap_or(usize::MAX),
        );
        let count = self.source.write(&buffer[..count])?;
        self.position += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.source.flush()
    }
}

impl<D: Seek> Seek for Bounded<'_, D> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let position = match position {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
            SeekFrom::End(offset) => i128::from(self.length) + i128::from(offset),
        };
        if !(0..=i128::from(self.length)).contains(&position) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside logical disk",
            ));
        }
        let position = u64::try_from(position).expect("bounded nonnegative disk offset");
        self.source.seek(SeekFrom::Start(position))?;
        self.position = position;
        Ok(position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn clamps_io_and_rejects_escaping_seeks() {
        let mut source = Cursor::new(vec![0; 1024]);
        let mut disk = Bounded::new(&mut source, 512).unwrap();
        assert_eq!(disk.seek(SeekFrom::End(-1)).unwrap(), 511);
        assert_eq!(disk.write(&[1, 2]).unwrap(), 1);
        assert_eq!(disk.write(&[2]).unwrap(), 0);
        assert!(disk.seek(SeekFrom::End(1)).is_err());
        assert!(disk.seek(SeekFrom::Current(-513)).is_err());
        assert!(disk.seek(SeekFrom::Start(u64::MAX)).is_err());
        disk.seek(SeekFrom::Start(511)).unwrap();
        let mut bytes = [0; 2];
        assert_eq!(disk.read(&mut bytes).unwrap(), 1);
        assert_eq!(bytes, [1, 0]);
        assert_eq!(source.into_inner()[512], 0);
    }
}
