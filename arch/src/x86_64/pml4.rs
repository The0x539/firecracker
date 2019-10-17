use bitfield::bitfield;

bitfield! {
    #[derive(Debug, Default, Copy, Clone)]
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

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum PagingLevel {
    Normal,
    Large,
    Huge,
    Colossal
}
