mod crypto;
mod header;

pub use header::{ContainerFileHeader, EncryptedData};

use crypto::{aes_xts::AESContext, Key};
use eyre::{ensure, Context, Result};
use packed_struct::prelude::*;
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;
use std::os::fd::IntoRawFd;
use std::path::Path;
use tracing::{debug, trace};

#[derive(Debug)]
pub struct ContainerFile {
    pub(crate) block_size: usize,
    pub(crate) aes_context: AESContext,
    pub(crate) data_addr: *mut u8,
    pub(crate) data_size: usize,
    pub(crate) buffer: Vec<u8>,
}

impl ContainerFile {
    fn stat_file_size(fd: libc::c_int) -> Result<usize> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let stat = unsafe { stat.assume_init() };
        trace!("Stat'ed file size: {}", stat.st_size);
        Ok(stat.st_size as usize)
    }

    pub fn mmap_container_file(fd: libc::c_int, size: usize) -> Result<*mut u8> {
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size - ContainerFileHeader::SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                ContainerFileHeader::SIZE as i64,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error().into());
        }
        Ok(addr as *mut u8)
    }

    fn read_and_parse_header(mut container: File, password: &str) -> Result<Self> {
        let mut buf = [0; ContainerFileHeader::SIZE];
        container
            .read_exact(&mut buf)
            .context("Couldn't read the vault file header... Maybe it is corrupt?")?;
        container.seek(SeekFrom::Start(0))?;
        let header = ContainerFileHeader::unpack_from_slice(&buf)?;
        ensure!(
            &header.magic == ContainerFileHeader::MAGIC,
            "Bad file magic"
        );
        ensure!(
            header.version == ContainerFileHeader::VERSION,
            "Version field in header must be 1"
        );

        let decrypted = header
            .decrypt_header(password)
            .wrap_err("Failed to decrypt file header")?;
        let fd = container.into_raw_fd();
        let size = Self::stat_file_size(fd)?;
        let block_count = decrypted.block_count as usize;
        let block_size = decrypted.block_size as usize;
        let expected_size = (block_count * block_size) + ContainerFileHeader::SIZE;
        ensure!(
            size == expected_size,
            "File is too small: required {} bytes, is {} bytes",
            expected_size,
            size
        );
        let mmap = Self::mmap_container_file(fd, size)?;
        let aes_context = AESContext::new(
            Key::from(decrypted.master_data_key),
            Key::from(decrypted.master_tweak_key),
        );
        Ok(Self {
            data_size: size - ContainerFileHeader::SIZE,
            data_addr: mmap,
            aes_context,
            block_size,
            buffer: vec![0; block_size],
        })
    }

    pub fn read_block(&mut self, block_number: usize, block: &mut [u8]) {
        assert!(
            block.len() >= self.block_size,
            "Provided buffer is too small"
        );
        let mut block = &mut block[..self.block_size];
        let offset = block_number * self.block_size;
        assert!(offset <= self.data_size, "block number out of range");
        let addr = self.data_addr.wrapping_add(offset);
        let data = unsafe { std::slice::from_raw_parts(addr, self.block_size) };
        block.copy_from_slice(&data);
        self.aes_context.aes_xts_decrypt(&mut block, block_number);
    }

    pub fn write_block(&mut self, block_number: usize, block: &[u8]) {
        assert!(block.len() == self.block_size);
        let offset = block_number as usize * self.block_size;
        assert!(offset <= self.data_size, "block number out of range");
        self.buffer.copy_from_slice(&block);
        self.aes_context
            .aes_xts_encrypt(&mut self.buffer, block_number);
        let addr = self.data_addr.wrapping_add(offset);
        let data: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(addr, self.block_size) };
        data.copy_from_slice(&self.buffer)
    }

    pub fn open(path: impl AsRef<Path>, password: &str) -> Result<Self> {
        let path = path.as_ref().canonicalize()?;
        debug!("Opening vault at {:?}", path);
        let container = File::options()
            .append(false)
            .read(true)
            .write(true)
            .open(path)
            .context("Couldn't open vault file")?;
        Self::read_and_parse_header(container, password)
    }

    pub fn create(
        path: impl AsRef<Path>,
        password: &str,
        block_size: u16,
        block_count: usize,
        pbkdf2_iterations: u32,
    ) -> Result<()> {
        let path = path.as_ref();
        debug!("Creating vault at {path:?}");
        ensure!(
            path.parent().map(|p| p.is_dir()).unwrap_or(false),
            "target file location has no parent directory"
        );
        ensure!(!path.is_file(), "target file location already exists");
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)?;
        let (encrypted_data, header) =
            ContainerFileHeader::new(password, block_size, block_count, pbkdf2_iterations)?;
        let header = header.pack().unwrap();
        // fill in header last to ensure the file is valid
        file.write_all(&[0; ContainerFileHeader::SIZE])?;
        let mut aes_ctx = AESContext::new(
            Key::from(encrypted_data.master_data_key),
            Key::from(encrypted_data.master_tweak_key),
        );
        let block = vec![0; block_size as usize];
        for block_number in 0..block_count {
            let mut data = block.clone();
            aes_ctx.aes_xts_encrypt(&mut data, block_number);
            file.write_all(&data)?;
        }
        file.seek(SeekFrom::Start(0))?;
        file.write(&header)?;
        file.flush()?;
        Ok(())
    }

    pub fn close(&mut self) -> Result<()> {
        let err = unsafe { libc::munmap(self.data_addr as *mut c_void, self.data_size) };
        if err != 0 {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }
}
