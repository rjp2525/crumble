//! PE (Portable Executable) header parsing for same-image process hollowing.
//! Pure safe byte math, no OS interaction.
//!
//! The injector maps THIS executable into a suspended browser process as a
//! genuine `SEC_IMAGE` view, so the OS loader performs all relocation,
//! import and TLS work. Only three header fields are still needed here: the
//! preferred base (where the view is requested), the entry-point RVA (the
//! resumed thread's instruction pointer), and `SizeOfImage` (for crash-site
//! classification while sampling the payload thread).

/// `IMAGE_FILE_MACHINE_AMD64`.
const MACHINE_AMD64: u16 = 0x8664;
/// PE32+ (64-bit) optional-header magic.
const MAGIC_PE32_PLUS: u16 = 0x20B;

/// The header fields of a 64-bit PE image the injector needs.
#[derive(Debug)]
pub struct PeImage {
    preferred_base: u64,
    entry_rva: u32,
    size_of_image: u32,
}

impl PeImage {
    /// Parses the headers of a PE32+ image, rejecting anything else (32-bit
    /// images, truncated or hostile files) with an error rather than a panic.
    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
            anyhow::bail!("not a PE file (missing MZ signature)");
        }
        let pe = read_u32(data, 0x3C)? as usize;
        if data.get(pe..pe + 4) != Some(b"PE\0\0") {
            anyhow::bail!("not a PE file (missing PE signature)");
        }
        let coff = pe + 4;
        if read_u16(data, coff)? != MACHINE_AMD64 {
            anyhow::bail!("unsupported machine type (need AMD64)");
        }
        let opt_size = read_u16(data, coff + 16)? as usize;
        let opt = coff + 20;
        if read_u16(data, opt)? != MAGIC_PE32_PLUS {
            anyhow::bail!("not a PE32+ (64-bit) image");
        }
        if opt + opt_size > data.len() {
            anyhow::bail!("truncated optional header");
        }
        Ok(Self {
            entry_rva: read_u32(data, opt + 16)?,
            preferred_base: read_u64(data, opt + 24)?,
            size_of_image: read_u32(data, opt + 56)?,
        })
    }

    /// The image base the PE wants (the section view is requested there).
    #[must_use]
    pub fn preferred_base(&self) -> u64 {
        self.preferred_base
    }

    /// RVA of the image entry point.
    #[must_use]
    pub fn entry_rva(&self) -> u32 {
        self.entry_rva
    }

    /// Total span of the mapped image (`SizeOfImage`).
    #[must_use]
    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }
}

fn read_u16(data: &[u8], at: usize) -> anyhow::Result<u16> {
    let bytes: [u8; 2] = data
        .get(at..at + 2)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("read past end at 0x{at:x}"))?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], at: usize) -> anyhow::Result<u32> {
    let bytes: [u8; 4] = data
        .get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("read past end at 0x{at:x}"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], at: usize) -> anyhow::Result<u64> {
    let bytes: [u8; 8] = data
        .get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("read past end at 0x{at:x}"))?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal synthetic PE32+ header set (DOS + PE + optional header).
    fn synthetic_pe() -> Vec<u8> {
        let mut data = vec![0u8; 0x200];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        data[0x40..0x44].copy_from_slice(b"PE\0\0");
        let coff = 0x44;
        data[coff..coff + 2].copy_from_slice(&MACHINE_AMD64.to_le_bytes());
        data[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // sections
        data[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes()); // opt size
        let opt = coff + 20;
        data[opt..opt + 2].copy_from_slice(&MAGIC_PE32_PLUS.to_le_bytes());
        data[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
        data[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // base
        data[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
        data
    }

    #[test]
    fn parses_headers() {
        let image = PeImage::parse(&synthetic_pe()).unwrap();
        assert_eq!(image.preferred_base(), 0x1_4000_0000);
        assert_eq!(image.entry_rva(), 0x1000);
        assert_eq!(image.size_of_image(), 0x3000);
    }

    #[test]
    fn rejects_garbage_pe32_and_truncation() {
        assert!(PeImage::parse(b"hello world").is_err());
        assert!(PeImage::parse(b"MZ").is_err());
        let mut pe = synthetic_pe();
        pe[0x44 + 20..0x44 + 22].copy_from_slice(&0x10Bu16.to_le_bytes()); // PE32 magic
        assert!(PeImage::parse(&pe).is_err());
        assert!(PeImage::parse(&synthetic_pe()[..0x100]).is_err());
    }
}
