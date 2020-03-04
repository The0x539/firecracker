use memory_model::DataInit;
use bitfield::bitfield;

pub const HEADER_SEARCH: u32 = 32768;
pub const HEADER_ALIGN: u32 = 8;

pub const HEADER_MAGIC: u32 = 0xE85250D6;

pub const BOOTLOADER_MAGIC: u32 = 0x36D76289;

pub const MOD_ALIGN: u32 = 0x00001000;

pub const INFO_ALIGN: u32 = 0x00000008;

pub const TAG_ALIGN: u32 = 0x00000008;

pub const TAG_TYPE_HRT: u32 = 0xF00DF00D;

#[repr(u16)]
pub enum TagType {
    End = 0,
    Cmdline = 1,
    BootloaderName = 2,
    Module = 3,
    BasicMemInfo = 4,
    BootDev = 5,
    Mmap = 6,
    Vbe = 7,
    Framebuffer = 8,
    ElfSections = 9,
    Apm = 10,
    Efi32 = 11,
    Efi64 = 12,
    Smbios = 13,
    AcpiOld = 14,
    AcpiNew = 15,
    Network = 16,
    EfiMmap = 17,
    EfiBs = 18,
    Efi32Ih = 19,
    Efi64Ih = 20,
    LoadBaseAddr = 21,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone)]
pub enum HeaderTagType {
    End = 0,
    InformationRequest = 1,
    Address = 2,
    EntryAddress = 3,
    ConsoleFlags = 4,
    Framebuffer = 5,
    ModuleAlign = 6,
    EfiBootServices = 7,
    EntryAddressEfi32 = 8,
    EntryAddressEfi64 = 9,
    Relocatable = 10,
    HybridRuntime = 0xF00D,
}
impl Default for HeaderTagType {
    fn default() -> Self { HeaderTagType::End }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Architecture {
    I386 = 0,
    Mips32 = 4,
}
impl Default for Architecture {
    fn default() -> Self { Architecture::I386 }
}

pub const HEADER_TAG_OPTIONAL: u32 = 1;

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
pub enum LoadPreference {
    None = 0,
    Low = 1,
    High = 2,
}
impl Default for LoadPreference {
    fn default() -> Self { LoadPreference::None }
}

pub const CONSOLE_FLAGS_CONSOLE_REQUIRED: u32 = 1;
pub const CONSOLE_FLAGS_EGA_TEXT_SUPPORTED: u32 = 2;

#[repr(u32)]
pub enum MmapEntryType {
    Available = 1,
    Reserved = 2,
    AcpiReclaimable = 3,
    Nvs = 4,
    BadRam = 5,
}

#[repr(u8)]
pub enum FramebufferType {
    Indexed = 0,
    Rgb = 1,
    EgaText = 2,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Header {
    pub magic: u32,
    pub architecture: Architecture,
    pub header_length: u32,
    pub checksum: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct HeaderTag {
    pub tag_type: HeaderTagType,
    pub flags: u16,
    pub size: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct HeaderInfoRequest {
    pub tag_types: [u32],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct HeaderAddress {
    pub header_addr: u32,
    pub load_addr: u32,
    pub load_end_addr: u32,
    pub bss_end_addr: u32,
}

// also using for EFI entry address tags
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct HeaderEntryAddress {
    pub entry_addr: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct HeaderConsole {
    pub console_flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct HeaderFramebuffer {
    pub width: u32,
    pub height: u32,
    pub depth: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct HeaderRelocatable {
    pub min_addr: u32,
    pub max_addr: u32,
    pub alignment: u32,
    pub preference: LoadPreference,
}

bitfield!{
    #[derive(Default, Copy, Clone)]
    pub struct HybridRuntimeFlags(u64);
    impl Debug;
    bool;
    pub relocatable, set_relocatable: 0;
    pub map_4kb, set_map_4kb: 8;
    pub map_2mb, set_map_2mb: 9;
    pub map_1gb, set_map_1gb: 10;
    pub map_512gb, set_map_512gb: 11;
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct HeaderHybridRuntime {
    pub flags: HybridRuntimeFlags,
    pub gpa_map_req: u64,
    pub hrt_hihalf_offset: u64,
    pub nautilus_entry_gva: u64,
    pub comm_page_gpa: u64,
    pub int_vec: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct InfoHeader {
    pub total_size: u32,
    pub reserved: u32,
}
unsafe impl DataInit for InfoHeader {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct InfoTag {
    pub tag_type: u32,
    pub size: u32,
}
unsafe impl DataInit for InfoTag {}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TagBasicMemInfo {
    pub base: InfoTag,
    pub mem_lower: u32,
    pub mem_upper: u32,
}
unsafe impl DataInit for TagBasicMemInfo {}
impl Default for TagBasicMemInfo {
    fn default() -> Self {
        Self {
            base: InfoTag {
                tag_type: TagType::BasicMemInfo as u32,
                size: 16,
            },
            ..Default::default()
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TagBootDev {
    pub base: InfoTag,
    pub bios_dev: u32,
    pub partition: u32,
    pub sub_partition: u32,
}
unsafe impl DataInit for TagBootDev {}
impl Default for TagBootDev {
    fn default() -> Self {
        Self {
            base: InfoTag {
                tag_type: TagType::BootDev as u32,
                size: 20,
            },
            ..Default::default()
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct TagCmdline {
    pub base: InfoTag,
    pub string: [u8],
}

#[repr(C)]
#[derive(Debug)]
pub struct TagModules {
    pub base: InfoTag,
    pub mod_start: u32,
    pub mod_end: u32,
    pub string: [u8],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct TagHybridRuntime {
    pub base:                   InfoTag,
    pub total_num_apics:        u32,
    pub first_hrt_apic_id:      u32,
    pub have_hrt_ioapic:        u32,
    pub first_hrt_ioapic_entry: u32,
    pub cpu_freq_khz:           u64,
    pub hrt_flags:              u64,
    pub max_mem_mapped:         u64,
    pub first_hrt_gpa:          u64,
    pub boot_state_gpa:         u64,
    pub gva_offset:             u64,
}
