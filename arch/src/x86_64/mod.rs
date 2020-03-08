// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

mod gdt;
pub mod interrupts;
pub mod layout;
mod mptable;
pub mod regs;

pub mod multiboot2;
pub mod pml4;

use std::mem::{self, size_of};

pub extern crate multiboot2_host;

use arch_gen::x86::bootparam::{boot_params, E820_RAM};
use arch_gen::x86::multiboot2::{
    self as mb,

    multiboot_tag as mb_tag,
    multiboot_tag_basic_meminfo as mb_tag_basic_meminfo,
    multiboot_tag_mmap as mb_tag_mmap,
    multiboot_mmap_entry as mb_mmap_entry,

    MULTIBOOT_TAG_TYPE_BASIC_MEMINFO as MB_TAG_TYPE_BASIC_MEMINFO,
    MULTIBOOT_TAG_TYPE_MMAP as MB_TAG_TYPE_MMAP,
};
use self::multiboot2::{
    TagHybridRuntime as mb_tag_hrt,
    TAG_TYPE_HRT as MB_TAG_TYPE_HRT,
};
use self::multiboot2_host::bootinfo as mb2_bootinfo;
use memory_model::{DataInit, GuestAddress, GuestMemory};

// This is a workaround to the Rust enforcement specifying that any implementation of a foreign
// trait (in this case `DataInit`) where:
// *    the type that is implementing the trait is foreign or
// *    all of the parameters being passed to the trait (if there are any) are also foreign
// is prohibited.
#[derive(Copy, Clone)]
struct BootParamsWrapper(boot_params);
#[derive(Copy, Clone)]
struct MbTagWrapper(mb_tag);
#[derive(Copy, Clone)]
struct MbMeminfoWrapper(mb_tag_basic_meminfo);
#[derive(Copy, Clone)]
struct MbMmapWrapper(mb_tag_mmap);
#[derive(Copy, Clone)]
struct MbEntryWrapper(mb_mmap_entry);
#[derive(Copy, Clone)]
struct MbTagHrtWrapper(mb_tag_hrt);

// It is safe to initialize BootParamsWrap which is a wrapper over `boot_params` (a series of ints).
unsafe impl DataInit for BootParamsWrapper {}
unsafe impl DataInit for MbTagWrapper {}
unsafe impl DataInit for MbMeminfoWrapper {}
unsafe impl DataInit for MbMmapWrapper {}
unsafe impl DataInit for MbEntryWrapper {}
unsafe impl DataInit for MbTagHrtWrapper {}

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Invalid e820 setup params.
    E820Configuration,
    /// Error writing MP table to memory.
    MpTableSetup(mptable::Error),
    /// The zero page extends past the end of guest_mem.
    ZeroPagePastRamEnd,
    /// Error writing the zero page of guest memory.
    ZeroPageSetup,
    /// Not enough space below kernel for multiboot info
    // this code is a hack, but I don't give a damn
    MultibootTooBig, // for the gotdamn RAM
    /// Error writing multiboot info
    MultibootSetup,
}

impl From<Error> for super::Error {
    fn from(e: Error) -> super::Error {
        super::Error::X86_64Setup(e)
    }
}

// Where BIOS/VGA magic would live on a real PC.
const EBDA_START: u64 = 0x9fc00;
const FIRST_ADDR_PAST_32BITS: usize = (1 << 32);
const MEM_32BIT_GAP_SIZE: usize = (768 << 20);

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemory structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
    let memory_gap_start = GuestAddress(FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE);
    let memory_gap_end = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let requested_memory_size = GuestAddress(size);
    let mut regions = Vec::new();

    // case1: guest memory fits before the gap
    if requested_memory_size <= memory_gap_start {
        regions.push((GuestAddress(0), size));
    // case2: guest memory extends beyond the gap
    } else {
        // push memory before the gap
        regions.push((GuestAddress(0), memory_gap_start.offset()));
        regions.push((
            memory_gap_end,
            requested_memory_size.offset_from(memory_gap_start),
        ));
    }

    regions
}

/// X86 specific memory hole/memory mapped devices/reserved area.
pub fn get_32bit_gap_start() -> usize {
    FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE
}

/// Returns the memory address where the kernel could be loaded.
pub fn get_kernel_start() -> usize {
    layout::HIMEM_START
}

pub fn configure_system(
    guest_mem: &GuestMemory,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    num_cpus: u8,
    is_multiboot: bool,
) -> super::Result<()> {
    if is_multiboot {
        return mb_configure_system(guest_mem, cmdline_addr, cmdline_size, num_cpus);
    } else {
        return bp_configure_system(guest_mem, cmdline_addr, cmdline_size, num_cpus);
    }
}

fn mb_configure_system(
    guest_mem: &GuestMemory,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    num_cpus: u8,
) -> super::Result<()> {
    /*
    let mut regions = std::cell::RefCell::new(Vec::new());
    guest_mem.with_regions::<_, ()>(|_index, base, size, _ptr| {
        regions.borrow_mut().push(mb2_bootinfo::MemMapEntry {
            base_addr: base.0 as u64,
            length: size as u64,
            // this seems like info that ought to exist but doesn't
            entry_type: mb::MULTIBOOT_MEMORY_AVAILABLE,
        });
        Ok(())
    });
    */
    let mut regions = std::cell::RefCell::new(Vec::new());
    guest_mem.with_regions::<_, ()>(|_index, base, size, _ptr| {
        regions.borrow_mut().push(mb2_bootinfo::MemMapEntry {
            base_addr: base.0 as u64,
            length: size as u64,
            // this seems like info that ought to exist but doesn't
            entry_type: mb::MULTIBOOT_MEMORY_AVAILABLE,
        });
        Ok(())
    });
    
    let tags = [
        mb2_bootinfo::Tag::HybridRuntime {
            total_num_apics: num_cpus as u32,
            first_hrt_apic_id: 0, // TODO: actual HRT setup
            have_hrt_ioapic: false,
            first_hrt_ioapic_entry: 0x0, // ???
            cpu_freq_khz: 1024, // TODO: ???
            hrt_flags: 0x0, // TODO: get that variable over here
            max_mem_mapped: 1024 * 1024 * 1024, // TODO: ???
            first_hrt_gpa: 0x0,
            boot_state_gpa: 0x0, // TODO: ???
            gva_offset: 0xFFFF_8000_0000_0000,
            comm_page_gpa: 0x0, // TODO: ???
            hrt_int_vector: 0x0, // TODO: ???
        },
        mb2_bootinfo::Tag::BasicMeminfo {
            mem_lower: 640, // thank you, bill gates
            mem_upper: ((guest_mem.end_addr().0 - 1024*1024) / 1024) as u32, // possibly wrong
        },
        mb2_bootinfo::Tag::MemMap {
            entries: regions.into_inner(),
        },
        mb2_bootinfo::Tag::End
    ];
    
    // Assume for the time being that we have space below the kernel
    let mb_addr = GuestAddress(layout::ZERO_PAGE_START);
    let mb_size = mb2_bootinfo::bootinfo_size(&tags) as usize;
    guest_mem
        .checked_offset(mb_addr, mb_size)
        .ok_or(Error::MultibootTooBig)?;

    // TODO: write directly to guest memory instead of using this intermediate buffer
    // Still better than the one-at-a-time thing that preceded this
    let mut buf = vec![0 as u8; mb_size];
    mb2_bootinfo::write_bootinfo(&tags, std::io::Cursor::new(&mut buf), 0)
        .map_err(|_| Error::MultibootSetup)?;

    guest_mem
        .write_slice_at_addr(&buf, mb_addr)
        .map_err(|_| Error::MultibootSetup)?;

    Ok(())
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `cmdline_addr` - Address in `guest_mem` where the kernel command line was loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the null terminator.
/// * `num_cpus` - Number of virtual CPUs the guest will have.
fn bp_configure_system(
    guest_mem: &GuestMemory,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    num_cpus: u8,
) -> super::Result<()> {
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000; // Must be non-zero.
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(get_32bit_gap_start());

    let himem_start = GuestAddress(layout::HIMEM_START);

    // Note that this puts the mptable at the last 1k of Linux's 640k base RAM
    mptable::setup_mptable(guest_mem, num_cpus).map_err(Error::MpTableSetup)?;

    let mut params: BootParamsWrapper = BootParamsWrapper(boot_params::default());

    params.0.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.0.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.0.hdr.header = KERNEL_HDR_MAGIC;
    params.0.hdr.cmd_line_ptr = cmdline_addr.offset() as u32;
    params.0.hdr.cmdline_size = cmdline_size as u32;
    params.0.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;

    add_e820_entry(&mut params.0, 0, EBDA_START, E820_RAM)?;

    let mem_end = guest_mem.end_addr();
    if mem_end < end_32bit_gap_start {
        add_e820_entry(
            &mut params.0,
            himem_start.offset() as u64,
            mem_end.offset_from(himem_start) as u64,
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params.0,
            himem_start.offset() as u64,
            end_32bit_gap_start.offset_from(himem_start) as u64,
            E820_RAM,
        )?;
        if mem_end > first_addr_past_32bits {
            add_e820_entry(
                &mut params.0,
                first_addr_past_32bits.offset() as u64,
                mem_end.offset_from(first_addr_past_32bits) as u64,
                E820_RAM,
            )?;
        }
    }

    let zero_page_addr = GuestAddress(layout::ZERO_PAGE_START);
    guest_mem
        .checked_offset(zero_page_addr, mem::size_of::<boot_params>())
        .ok_or(Error::ZeroPagePastRamEnd)?;
    guest_mem
        .write_obj_at_addr(params, zero_page_addr)
        .map_err(|_| Error::ZeroPageSetup)?;

    Ok(())
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(
    params: &mut boot_params,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> Result<(), Error> {
    if params.e820_entries >= params.e820_map.len() as u8 {
        return Err(Error::E820Configuration);
    }

    params.e820_map[params.e820_entries as usize].addr = addr;
    params.e820_map[params.e820_entries as usize].size = size;
    params.e820_map[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arch_gen::x86::bootparam::e820entry;

    #[test]
    fn regions_lt_4gb() {
        let regions = arch_memory_regions(1usize << 29);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(1usize << 29, regions[0].1);
    }

    #[test]
    fn regions_gt_4gb() {
        let regions = arch_memory_regions((1usize << 32) + 0x8000);
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(GuestAddress(1usize << 32), regions[1].0);
    }

    #[test]
    fn test_32bit_gap() {
        assert_eq!(
            get_32bit_gap_start(),
            FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE
        );
    }

    #[test]
    fn test_system_configuration() {
        let no_vcpus = 4;
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let config_err = configure_system(&gm, GuestAddress(0), 0, 1);
        assert!(config_err.is_err());
        match config_err.unwrap_err() {
            super::super::Error::X86_64Setup(e) => assert_eq!(
                e,
                super::Error::MpTableSetup(mptable::Error::NotEnoughMemory)
            ),
        }
        // Now assigning some memory that falls before the 32bit memory hole.
        let mem_size = 128 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let gm = GuestMemory::new(&arch_mem_regions).unwrap();
        configure_system(&gm, GuestAddress(0), 0, no_vcpus).unwrap();

        // Now assigning some memory that is equal to the start of the 32bit memory hole.
        let mem_size = 3328 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let gm = GuestMemory::new(&arch_mem_regions).unwrap();
        configure_system(&gm, GuestAddress(0), 0, no_vcpus).unwrap();

        // Now assigning some memory that falls after the 32bit memory hole.
        let mem_size = 3330 << 20;
        let arch_mem_regions = arch_memory_regions(mem_size);
        let gm = GuestMemory::new(&arch_mem_regions).unwrap();
        configure_system(&gm, GuestAddress(0), 0, no_vcpus).unwrap();
    }

    #[test]
    fn test_add_e820_entry() {
        let e820_map = [(e820entry {
            addr: 0x1,
            size: 4,
            type_: 1,
        }); 128];

        let expected_params = boot_params {
            e820_map,
            e820_entries: 1,
            ..Default::default()
        };

        let mut params: boot_params = Default::default();
        add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[0].size,
            e820_map[0].type_,
        )
        .unwrap();
        assert_eq!(
            format!("{:?}", params.e820_map[0]),
            format!("{:?}", expected_params.e820_map[0])
        );
        assert_eq!(params.e820_entries, expected_params.e820_entries);

        // Exercise the scenario where the field storing the length of the e820 entry table is
        // is bigger than the allocated memory.
        params.e820_entries = params.e820_map.len() as u8 + 1;
        assert!(add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[0].size,
            e820_map[0].type_
        )
        .is_err());
    }
}
