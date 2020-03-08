use bitfield::bitfield;

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
