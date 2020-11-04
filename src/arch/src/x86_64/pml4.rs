#![allow(missing_docs)]

use bitfield::bitfield;
use bytemuck::{Pod, TransparentWrapper, Zeroable};
use vm_memory::ByteValued;

bitfield! {
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
    #[derive(TransparentWrapper, Zeroable, Pod)]
    #[repr(transparent)]
    pub struct PML4e(u64);
    pub present, set_present: 0;
    pub writable, set_writable: 1;
    pub user_page, set_user_page: 2;
    pub write_through, set_write_through: 3;
    pub cache_disable, set_cache_disable: 4;
    pub accessed, set_accessed: 5;
    // IGN, _: 6;
    mbz, _: 8, 7;
    pub vmm_info, set_vmm_info: 11, 9;
    pub pdp_base_addr, set_pdp_base_addr: 51, 12;
    pub available, set_available: 62, 52;
    pub no_execute, set_no_execute: 63;
}

bitfield! {
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
    #[derive(TransparentWrapper, Zeroable, Pod)]
    #[repr(transparent)]
    pub struct PDPe(u64);
    pub present, set_present: 0;
    pub writable, set_writable: 1;
    pub user_page, set_user_page: 2;
    pub write_through, set_write_through: 3;
    pub cache_disable, set_cache_disable: 4;
    pub accessed, set_accessed: 5;
    // IGN, _: 6;
    pub is_1gb, set_1gb: 7;
    // IGN, _: 8;
    pub vmm_info, set_vmm_info: 11, 9;
    pub pd_base_addr, set_pd_base_addr: 51, 12;
    pub available, set_available: 62, 52;
    pub no_execute, set_no_execute: 63;

    // 1GB fields
    pub dirty, set_dirty: 6;
    pub global, set_global: 8;
    pub pat, set_pat: 12;
    pub page_base_addr, set_page_base_addr: 51, 30;
}

bitfield! {
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
    #[derive(TransparentWrapper, Zeroable, Pod)]
    #[repr(transparent)]
    pub struct PDe(u64);
    pub present, set_present: 0;
    pub writable, set_writable: 1;
    pub user_page, set_user_page: 2;
    pub write_through, set_write_through: 3;
    pub cache_disable, set_cache_disable: 4;
    pub accessed, set_accessed: 5;
    // IGN, _: 6;
    pub is_2mb, set_2mb: 7;
    // IGN, _: 8;
    pub vmm_info, set_vmm_info: 11, 9;
    pub pt_base_addr, set_pt_base_addr: 51, 12;
    pub available, set_available: 62, 52;
    pub no_execute, set_no_execute: 63;

    // 2MB fields
    pub dirty, set_dirty: 6;
    pub global, set_global: 8;
    pub pat, set_pat: 12;
    pub page_base_addr, set_page_base_addr: 51, 21;
}

bitfield! {
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
    #[derive(TransparentWrapper, Zeroable, Pod)]
    #[repr(transparent)]
    pub struct PTe(u64);
    pub present, set_present: 0;
    pub writable, set_writable: 1;
    pub user_page, set_user_page: 2;
    pub write_through, set_write_through: 3;
    pub cache_disable, set_cache_disable: 4;
    pub accessed, set_accessed: 5;
    pub dirty, set_dirty: 6;
    pub pat, set_pat: 7;
    pub global, set_global: 8;
    pub vmm_info, set_vmm_info: 11, 9;
    pub page_base_addr, set_page_base_addr: 51, 12;
    pub available, set_available: 62, 52;
    pub no_execute, set_no_execute: 63;
}

bitfield! {
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
    #[derive(TransparentWrapper, Zeroable, Pod)]
    #[repr(transparent)]
    pub struct IDTe(u128);
    u64;
    offset_1, set_offset_1: 15, 0;
    pub selector, set_selector: 31, 16;
    pub ist, set_ist: 39, 32;
    pub gate_type, set_gate_type: 43, 40;
    // reserved: 44;
    pub dpl, set_dpl: 46, 45;
    pub present, set_present: 47;
    offset_2, set_offset_2: 63, 48;
    offset_3, set_offset_3: 95, 64;
    // reserved: 127, 96;
}

impl IDTe {
    pub fn offset(&self) -> u64 {
        (self.offset_1() << 0) | (self.offset_2() << 16) | (self.offset_3() << 32)
    }
    pub fn set_offset(&mut self, val: u64) {
        self.set_offset_1((val & 0x0000_0000_0000_FFFF) >> 0);
        self.set_offset_2((val & 0x0000_0000_FFFF_0000) >> 16);
        self.set_offset_3((val & 0xFFFF_FFFF_0000_0000) >> 32);
    }
}

unsafe impl ByteValued for IDTe {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PagingLevel {
    Normal,
    Large,
    Huge,
    Colossal,
}
