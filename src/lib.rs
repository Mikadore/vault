#![feature(associated_type_defaults)]
pub mod container;
pub mod fs;

use std::{marker::PhantomData, path::Path};

use eyre::Result;
use fuser::Filesystem;

use container::ContainerFile;

#[derive(Debug)]
pub struct Vault<'mmap> {
    file: ContainerFile,
    _marker: PhantomData<&'mmap mut [u8]>,
}

impl<'mmap> Vault<'mmap> {
    pub fn block_size(&self) -> usize {
        self.file.block_size
    }

    pub fn block_count(&self) -> usize {
        self.file.data_size / self.block_size()
    }

    pub fn create(
        path: &Path,
        password: &str,
        block_size: u16,
        block_count: usize,
        pbkdf2_iterations: u32,
    ) -> Result<()> {
        ContainerFile::create(path, password, block_size, block_count, pbkdf2_iterations)
    }

    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let file = ContainerFile::open(path, password)?;
        Ok(Self {
            file,
            _marker: PhantomData,
        })
    }
}

impl<'mmap> Filesystem for Vault<'mmap> {}
