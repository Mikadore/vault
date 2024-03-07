//! This module implements storage
//! on an underlying block device.
//! It manages allocating, freeing
//! and managing a group of blocks
//! called a `Segment`.

use super::{FSError, Result};
use packed_struct::prelude::*;
use tracing::debug;

/// Trait that abstracts out a block device,
/// this crate only implements a mmap file backing,
/// though.
pub trait BlockIO {
    /// Optional error type returned from the IO methods
    type IoError: std::error::Error + std::fmt::Debug;
    /// The total amount of blocks available
    /// to do IO
    fn block_count(&self) -> usize;
    /// The size of a single block. It is required
    /// all blocks are the same size.
    fn block_size(&self) -> usize;
    /// Read a single block at offset `block_number` (starting at 0),
    /// stores the block into the `block` argument (must be big enough).
    fn read_block(
        &mut self,
        block_number: u64,
        block: &mut [u8],
    ) -> std::result::Result<(), Self::IoError>;
    /// Write a single `block` at offset `block_number` (starting at 0).
    /// The `block` argument must be at least `block_size` long.
    fn write_block(
        &mut self,
        block_number: u64,
        block: &[u8],
    ) -> std::result::Result<(), Self::IoError>;
}

#[derive(PrimitiveEnum_u32, Clone, Copy, PartialEq, Debug)]
#[non_exhaustive]
pub enum SegmentTag {
    Unallocated = 0xDEADBEEF,
    RootBlock = 0xFFFF0000,
    SegmentBlock = 0x0000FFFF,
    Superblock = 0xFFFFFF,
}

#[derive(PackedStruct, Debug)]
#[packed_struct(endian = "lsb")]
pub struct Segment {
    pub root_block: u64,
    pub next_block: u64,
    pub used_data: u32,
    #[packed_field(element_size_bytes = "4", ty = "enum")]
    pub tag: SegmentTag,
}

#[derive(PackedStruct, Debug)]
#[packed_struct(endian = "lsb")]
pub struct Superblock {
    pub block_count: u64,
    pub block_size: u64,
    pub free_count: u64,
    pub next_free_block: u64,
}

pub struct Storage<Device: BlockIO> {
    device: Device,
    block_size: usize,
    block_count: usize,
    blocks_free: usize,
    buffer: Vec<u8>,
}

fn read_block<'slf>(
    device: &'slf mut impl BlockIO,
    mut buffer: &'slf mut [u8],
    block: usize,
) -> (Segment, &'slf [u8]) {
    device.read_block(block as u64, &mut buffer).unwrap();
    // This works because segment has only primitive members
    let segment_size = std::mem::size_of::<Segment>();
    let segment = Segment::unpack_from_slice(&buffer[..segment_size]).unwrap();
    (segment, &buffer[segment_size..])
}

impl<Device: BlockIO> Storage<Device> {
    pub fn read_block<'slf>(&'slf mut self, block: usize) -> (Segment, &'slf [u8]) {
        read_block(&mut self.device, &mut self.buffer, block)
    }

    pub fn open(mut device: Device) -> Result<Self> {
        let block_size = device.block_size();
        if block_size < 512 || block_size % 16 != 0 {
            return Err(FSError::InvalidBlockSize);
        }
        let block_count = device.block_count();
        if block_count <= 1 {
            return Err(FSError::InvalidDevice);
        }
        let mut buffer = vec![0; block_size];
        let (super_seg, super_dat) = read_block(&mut device, &mut buffer, 0);
        if super_seg.tag != SegmentTag::Superblock {
            return Err(FSError::InvalidBlockTag);
        }
        // Works for the same reason as reading a Segment
        let superblock =
            Superblock::unpack_from_slice(&super_dat[..std::mem::size_of::<Superblock>()]).unwrap();
        if superblock.block_size as usize != block_size {
            return Err(FSError::BlockSizeMismatch {
                expected: superblock.block_size as usize,
                device: block_size,
            });
        }
        if superblock.block_count as usize != block_count {
            debug!(
                "Reported block size ({}) is different from expected ({})",
                block_count, superblock.block_count
            );
        }
        Ok(Self {
            block_size,
            block_count,
            blocks_free: superblock.free_count as usize,
            buffer,
            device,
        })
    }
}
