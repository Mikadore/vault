use thiserror::Error;

pub mod storage;

use storage::{BlockIO, Storage};

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum FSError {
    #[error("Not enough space for operation")]
    NoMemory,
    #[error("The device's block size is not valid (must be at least 512 and a multiple of 16)")]
    InvalidBlockSize,
    #[error("The device is invalid")]
    InvalidDevice,
    #[error("The read block has an unexpected tag value. This indicates a corrupted filesystem")]
    InvalidBlockTag,
    #[error("The expected block size is {expected}, but the device reports {device}")]
    BlockSizeMismatch { expected: usize, device: usize },
}

type Result<T> = std::result::Result<T, FSError>;

#[derive(Debug)]
pub struct FileSystem<Storage: BlockIO> {
    block_count: usize,
    blocks_free: usize,
    block_size: usize,
    blocks_available: usize,
    inodes_count: usize,
    device: Storage,
}

impl<Storage: BlockIO> FileSystem<Storage> {}
