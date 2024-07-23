use thiserror::Error;

pub mod storage;

use storage::{BlockIO, Storage};

pub const BLOCK_SIZE: usize = 512;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum FSError {
    #[error("Not enough space for operation")]
    NoMemory,
    #[error("The device reported an incorrect block size {block_size}, must be 512")]
    InvalidBlockSize { block_size: usize },
    #[error("The device is invalid")]
    InvalidDevice,
    #[error("The read block has an unexpected tag value. This indicates a corrupted filesystem")]
    InvalidBlockTag,
}

type Result<T> = std::result::Result<T, FSError>;

#[derive(Debug)]
pub struct FileSystem<Storage: BlockIO> {
    block_count: usize,
    blocks_free: usize,
    blocks_available: usize,
    inodes_count: usize,
    device: Storage,
}

impl<Storage: BlockIO> FileSystem<Storage> {}
