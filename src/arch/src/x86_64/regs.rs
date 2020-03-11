// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::mem;

use super::gdt::{gdt_entry, kvm_segment_from_gdt};
use kvm_bindings::{kvm_fpu, kvm_regs, kvm_sregs};
use kvm_ioctls::VcpuFd;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};
use x86_64::pml4::{self, PagingLevel};

// Initial pagetables.
const PML4_START: u64 = 0x9000;
const PDPTE_START: u64 = 0xa000;
const PDE_START: u64 = 0xb000;

const PAGE_SIZE: u64 = 4096;
const L4_UNIT: u64 = PAGE_SIZE;
const L3_UNIT: u64 = L4_UNIT * 512;
const L2_UNIT: u64 = L3_UNIT * 512;
const L1_UNIT: u64 = L2_UNIT * 512;

/// Errors thrown while setting up x86_64 registers.
#[derive(Debug)]
pub enum Error {
    /// Failed to get SREGs for this CPU.
    GetStatusRegisters(kvm_ioctls::Error),
    /// Failed to set base registers for this CPU.
    SetBaseRegisters(kvm_ioctls::Error),
    /// Failed to configure the FPU.
    SetFPURegisters(kvm_ioctls::Error),
    /// Failed to set SREGs for this CPU.
    SetStatusRegisters(kvm_ioctls::Error),
    /// Writing the GDT to RAM failed.
    WriteGDT,
    /// Writing the IDT to RAM failed.
    WriteIDT,
    /// Writing PDPTE to RAM failed.
    WritePDPTEAddress,
    /// Writing PDE to RAM failed.
    WritePDEAddress,
    /// Writing PML4 to RAM failed.
    WritePML4Address,
    /// Writing PTE to RAM failed.
    WritePTEAddress,
}
type Result<T> = std::result::Result<T, Error>;

/// Configure Floating-Point Unit (FPU) registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_fpu(vcpu: &VcpuFd) -> Result<()> {
    let fpu: kvm_fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };

    vcpu.set_fpu(&fpu).map_err(Error::SetFPURegisters)
}

/// Configure base registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `boot_ip` - Starting instruction pointer.
pub fn setup_regs(vcpu: &VcpuFd, boot_ip: u64, opt_hrt_tag: Option<(u64, u64)>) -> Result<()> {
    let regs: kvm_regs = match opt_hrt_tag {
        Some((_flags, gva_offset)) => kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: boot_ip,
            rax: 0x36D76289,
            rbx: super::layout::ZERO_PAGE_START,
            rsp: 0x10004000 + gva_offset,
            rbp: 0x10004000 + gva_offset,
            ..Default::default()
        },

        None => kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: boot_ip,
            // Frame pointer. It gets a snapshot of the stack pointer (rsp) so that when adjustments are
            // made to rsp (i.e. reserving space for local variables or pushing values on to the stack),
            // local variables and function parameters are still accessible from a constant offset from rbp.
            rsp: super::layout::BOOT_STACK_POINTER as u64,
            // Starting stack pointer.
            rbp: super::layout::BOOT_STACK_POINTER as u64,
            // Must point to zero page address per Linux ABI. This is x86_64 specific.
            rsi: super::layout::ZERO_PAGE_START as u64,
            ..Default::default()
        },
    };

    vcpu.set_regs(&regs).map_err(Error::SetBaseRegisters)
}

/// Configures the segment registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `mem` - The memory that will be passed to the guest.
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_sregs(
    mem: &GuestMemoryMmap,
    vcpu: &VcpuFd,
    opt_hrt_tag: Option<(u64, u64)>,
) -> Result<()> {
    let mut sregs: kvm_sregs = vcpu.get_sregs().map_err(Error::GetStatusRegisters)?;

    match opt_hrt_tag {
        Some((flags, offset)) => {
            nautilus_configure_segments_and_sregs(mem, &mut sregs)?;
            nautilus_setup_page_tables(mem, &mut sregs, flags, offset)?;
        }
        None => {
            linux_configure_segments_and_sregs(mem, &mut sregs)?;
            // TODO(dgreid) - Can this be done once per system instead?
            linux_setup_page_tables(mem, &mut sregs)?;
        }
    }

    //println!("{:#x?}", sregs);

    vcpu.set_sregs(&sregs).map_err(Error::SetStatusRegisters)
}

const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;

const BOOT_GDT_MAX: usize = 4;

const EFER_LMA: u64 = 0x400;
const EFER_LME: u64 = 0x100;

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;

fn write_gdt_table(table: &[u64], guest_mem: &GuestMemoryMmap) -> Result<()> {
    let boot_gdt_addr = GuestAddress(BOOT_GDT_OFFSET);
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, index * mem::size_of::<u64>())
            .ok_or(Error::WriteGDT)?;
        guest_mem
            .write_obj(*entry, addr)
            .map_err(|_| Error::WriteGDT)?;
    }
    Ok(())
}

fn write_gdt_table_at_addr(
    table: &[u64],
    guest_mem: &GuestMemoryMmap,
    gdt_base: GuestAddress,
) -> Result<()> {
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(gdt_base, index * mem::size_of::<u64>())
            .ok_or(Error::WriteGDT)?;
        guest_mem
            .write_obj(*entry, addr)
            .map_err(|_| Error::WriteGDT)?;
    }
    Ok(())
}

fn write_idt_value(val: u64, guest_mem: &GuestMemoryMmap) -> Result<()> {
    let boot_idt_addr = GuestAddress(BOOT_IDT_OFFSET);
    guest_mem
        .write_obj(val, boot_idt_addr)
        .map_err(|_| Error::WriteIDT)
}

fn linux_configure_segments_and_sregs(mem: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<()> {
    let gdt_table: [u64; BOOT_GDT_MAX as usize] = [
        gdt_entry(0, 0, 0),            // NULL
        gdt_entry(0xa09b, 0, 0xfffff), // CODE
        gdt_entry(0xc093, 0, 0xfffff), // DATA
        gdt_entry(0x808b, 0, 0xfffff), // TSS
    ];

    let code_seg = kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = kvm_segment_from_gdt(gdt_table[2], 2);
    let tss_seg = kvm_segment_from_gdt(gdt_table[3], 3);

    // Write segments
    write_gdt_table(&gdt_table[..], mem)?;
    sregs.gdt.base = BOOT_GDT_OFFSET as u64;
    sregs.gdt.limit = mem::size_of_val(&gdt_table) as u16 - 1;

    write_idt_value(0, mem)?;
    sregs.idt.base = BOOT_IDT_OFFSET as u64;
    sregs.idt.limit = mem::size_of::<u64>() as u16 - 1;

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;

    /* 64-bit protected mode */
    sregs.cr0 |= X86_CR0_PE;
    sregs.efer |= EFER_LME | EFER_LMA;

    Ok(())
}

#[derive(Default, Copy, Clone)]
struct U128(u128);
unsafe impl vm_memory::ByteValued for U128 {}

fn nautilus_configure_segments_and_sregs(
    mem: &GuestMemoryMmap,
    sregs: &mut kvm_sregs,
) -> Result<()> {
    let gdt_table: [u64; 3] = [
        gdt_entry(0, 0, 0),
        gdt_entry(0xa09a, 0, 0xfffff),
        gdt_entry(0xa092, 0, 0xfffff),
    ];

    let code_seg = kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = kvm_segment_from_gdt(gdt_table[2], 2);

    let last_addr = mem.last_addr().0 as u64;
    let last_page = (last_addr >> 12) << 12;

    let gdt_loc = last_page - 3 * PAGE_SIZE;
    write_gdt_table_at_addr(&gdt_table, mem, GuestAddress(gdt_loc))?;
    sregs.gdt.base = gdt_loc;
    sregs.gdt.limit = 24;

    let vmx_null_int_handler: [u8; 30] = [
        0x50,
        0x53,
        0x51,
        0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00,
        0x00,
        0x48, 0x8b, 0x5c, 0x24, 0x18,
        0x48, 0x8b, 0x4c, 0x24, 0x20,
        0x0f, 0x01, 0xc1,
        0x59,
        0x5b,
        0x58,
        0xf4,
        0x48, 0xcf,
    ];

    let idt_loc = last_page - 2 * PAGE_SIZE;
    let null_int_handler_loc = last_page - 4096;

    mem.write_obj(vmx_null_int_handler, GuestAddress(null_int_handler_loc))
        .map_err(|_| Error::WriteIDT)?;

    let mut trap_gate = pml4::IDTe(0x0);
    trap_gate.set_selector(0x8);
    trap_gate.set_gate_type(0xf);
    trap_gate.set_present(true);

    trap_gate.set_offset(null_int_handler_loc + 0xFFFF_8000_0000_0000);

    for i in 0..32 {
        mem.write_obj(U128(trap_gate.0), GuestAddress(idt_loc + 16 * i))
            .map_err(|_| Error::WriteIDT)?;
    }

    let mut int_gate = pml4::IDTe(0x0);
    int_gate.set_selector(0x8);
    int_gate.set_gate_type(0xe);
    int_gate.set_present(true);

    int_gate.set_offset(null_int_handler_loc + 0xFFFF_8000_0000_0000);

    for i in 32..256 {
        mem.write_obj(U128(int_gate.0), GuestAddress(idt_loc + 16 * i))
            .map_err(|_| Error::WriteIDT)?;
    }

    sregs.idt.base = idt_loc + 0xFFFF_8000_0000_0000;
    sregs.idt.limit = 16 * 256; // should maybe be 1 smaller

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;

    sregs.cr0 |= X86_CR0_PE;
    sregs.cr0 |= X86_CR0_PG;

    sregs.cr4 |= X86_CR4_PAE;

    sregs.efer |= EFER_LME;
    sregs.efer |= EFER_LMA;

    Ok(())
}

fn ceil_div(a: usize, b: usize) -> usize {
    a / b + (if a % b == 0 { 0 } else { 1 })
}

fn hrt_compute_pts(mem: &GuestMemoryMmap) -> (usize, usize, usize, usize) {
    let max_gva = mem.last_addr().0 as usize + 1;
    return (
        1,
        ceil_div(ceil_div(max_gva, 512 * 512 * 4096), 512),
        ceil_div(ceil_div(max_gva, 512 * 4096), 512),
        ceil_div(ceil_div(max_gva, 4096), 512),
    );
}

fn hrt_get_pt_loc(mem: &GuestMemoryMmap, paging_level: pml4::PagingLevel) -> u64 {
    let (l1, l2, l3, l4) = hrt_compute_pts(mem);
    let num_pt = match paging_level {
        PagingLevel::Colossal => l1,
        PagingLevel::Huge => l1 + l2,
        PagingLevel::Large => l1 + l2 + l3,
        PagingLevel::Normal => l1 + l2 + l3 + l4,
    } as u64;
    let last_addr = mem.last_addr().0;
    let last_page = last_addr >> 12;
    let enough_room = last_page - (4 + num_pt);
    enough_room << 12
}

fn nautilus_setup_page_tables(
    guest_mem: &GuestMemoryMmap,
    sregs: &mut kvm_sregs,
    hrt_flags: u64,
    gva_offset: u64,
) -> Result<()> {
    let min_gpa: u64 = 0;
    let max_gpa: u64 = guest_mem.last_addr().0;
    let min_gva: u64 = gva_offset;
    let max_gva: u64 = min_gva + max_gpa;

    println!(
        "guest phys mem: {:#X} - {:#X}\nguest virt mem: {:#X} - {:#X}",
        min_gpa, max_gpa, min_gva, max_gva
    );

    let paging_level = {
        if hrt_flags & 0x800 != 0 {
            PagingLevel::Colossal
        } else if hrt_flags & 0x400 != 0 {
            PagingLevel::Huge
        } else if hrt_flags & 0x200 != 0 {
            PagingLevel::Large
        } else if hrt_flags & 0x100 != 0 {
            PagingLevel::Normal
        } else {
            PagingLevel::Large // a sane default
        }
    };

    println!("paging level = {:#?}", paging_level);

    let (num_l1, num_l2, num_l3, num_l4) = hrt_compute_pts(guest_mem);
    println!(
        "{} PML4, {} PDP, {} PD, {} PT",
        num_l1, num_l2, num_l3, num_l4
    );
    let l1_start = hrt_get_pt_loc(guest_mem, paging_level);
    let l2_start = l1_start + PAGE_SIZE * num_l1 as u64;
    let l3_start = l2_start + PAGE_SIZE * num_l2 as u64;
    let l4_start = l3_start + PAGE_SIZE * num_l3 as u64;

    println!(
        "PML4 @ {:#X}, PDP @ {:#X}, PD @ {:#X}, PT @ {:#X}",
        l1_start, l2_start, l3_start, l4_start
    );

    let pml4_range = {
        if min_gva == 0x0 {
            0..num_l2
        } else if min_gva == 0xFFFF_8000_0000_0000 {
            256..256 + num_l2
        } else {
            println!("error: unsupported gva offset");
            return Err(Error::WritePML4Address);
        }
    };

    let start = pml4_range.start;
    let mut pml4 = [pml4::PML4e(0); 512];

    for i in pml4_range {
        let j = i - start;
        let cur_gpa = min_gpa + (j as u64) * L1_UNIT;

        pml4[i].set_present(true);
        pml4[i].set_writable(true);

        pml4[i].set_pdp_base_addr(
            match paging_level {
                PagingLevel::Colossal => cur_gpa as u64,
                _ => l2_start + (j as u64) * PAGE_SIZE,
            } >> 12,
        );

        pml4[i - start] = pml4[i];
    }

    let buf: [u8; 4096] = unsafe { mem::transmute(pml4) };
    guest_mem
        .write_slice(&buf, GuestAddress(l1_start))
        .map_err(|_| Error::WritePML4Address)?;

    if paging_level == PagingLevel::Colossal {
        sregs.cr3 = l1_start as u64;
        return Ok(());
    }

    for i in 0..num_l2 {
        let mut pdp = [pml4::PDPe(0); 512];

        let pdp_gpa = min_gpa + (i as u64) * L1_UNIT;
        let pdp_gva = min_gva + (i as u64) * L1_UNIT;

        for j in 0..512 {
            let cur_gpa = pdp_gpa + (j as u64) * L2_UNIT;
            let cur_gva = pdp_gva + (j as u64) * L2_UNIT;

            if cur_gva > max_gva {
                continue;
            }

            pdp[j].set_present(true);
            pdp[j].set_writable(true);

            pdp[j].set_1gb(paging_level == PagingLevel::Huge);

            pdp[j].set_pd_base_addr(
                match paging_level {
                    PagingLevel::Huge => cur_gpa,
                    _ => l3_start + (512 * i + j) as u64 * PAGE_SIZE,
                } >> 12,
            );
        }

        let buf: [u8; 4096] = unsafe { mem::transmute(pdp) };
        guest_mem
            .write_slice(&buf, GuestAddress(l2_start + (i as u64) * PAGE_SIZE))
            .map_err(|_| Error::WritePDPTEAddress)?;
    }

    if paging_level == PagingLevel::Huge {
        sregs.cr3 = l1_start as u64;
        return Ok(());
    }

    for i in 0..num_l3 {
        let mut pd = [pml4::PDe(0); 512];

        let pd_gva = min_gva + (i as u64) * L2_UNIT;
        let pd_gpa = min_gpa + (i as u64) * L2_UNIT;

        for j in 0..512 {
            let cur_gva = pd_gva + (j as u64) * L3_UNIT;
            let cur_gpa = pd_gpa + (j as u64) * L3_UNIT;

            if cur_gva > max_gva {
                continue;
            }

            pd[j].set_present(true);
            pd[j].set_writable(true);

            pd[j].set_2mb(paging_level == PagingLevel::Large);

            pd[j].set_pt_base_addr(
                match paging_level {
                    PagingLevel::Large => cur_gpa,
                    _ => l4_start + (512 * i + j) as u64 * PAGE_SIZE,
                } >> 12,
            );
        }

        let buf: [u8; 4096] = unsafe { mem::transmute(pd) };
        guest_mem
            .write_slice(&buf, GuestAddress(l3_start + (i as u64) * PAGE_SIZE))
            .map_err(|_| Error::WritePDEAddress)?;
    }

    if paging_level == PagingLevel::Large {
        sregs.cr3 = l1_start as u64;
        return Ok(());
    }

    for i in 0..num_l4 {
        let mut pt = [pml4::PTe(0); 512];

        let pt_gva = min_gva + (i as u64) * L3_UNIT;
        let pt_gpa = min_gpa + (i as u64) * L3_UNIT;

        for j in 0..512 {
            let cur_gva = pt_gva + (j as u64) * L3_UNIT;
            let cur_gpa = pt_gpa + (j as u64) * L4_UNIT;

            if cur_gva > max_gva {
                continue;
            }

            pt[j].set_present(true);
            pt[j].set_writable(true);

            pt[j].set_page_base_addr(cur_gpa >> 12);
        }

        let buf: [u8; 4096] = unsafe { mem::transmute(pt) };
        guest_mem
            .write_slice(&buf, GuestAddress(l4_start + (i as u64) * PAGE_SIZE))
            .map_err(|_| Error::WritePTEAddress)?;
    }

    sregs.cr3 = l1_start as u64;

    Ok(())
}

fn linux_setup_page_tables(mem: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<()> {
    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = GuestAddress(PML4_START);
    let boot_pdpte_addr = GuestAddress(PDPTE_START);
    let boot_pde_addr = GuestAddress(PDE_START);

    // Entry covering VA [0..512GB)
    mem.write_obj(boot_pdpte_addr.raw_value() as u64 | 0x03, boot_pml4_addr)
        .map_err(|_| Error::WritePML4Address)?;

    // Entry covering VA [0..1GB)
    mem.write_obj(boot_pde_addr.raw_value() as u64 | 0x03, boot_pdpte_addr)
        .map_err(|_| Error::WritePDPTEAddress)?;
    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512 {
        mem.write_obj((i << 21) + 0x83u64, boot_pde_addr.unchecked_add(i * 8))
            .map_err(|_| Error::WritePDEAddress)?;
    }

    sregs.cr3 = boot_pml4_addr.raw_value() as u64;
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_ioctls::Kvm;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap()
    }

    fn read_u64(gm: &GuestMemoryMmap, offset: u64) -> u64 {
        let read_addr = GuestAddress(offset as u64);
        gm.read_obj(read_addr).unwrap()
    }

    fn validate_segments_and_sregs(gm: &GuestMemoryMmap, sregs: &kvm_sregs) {
        assert_eq!(0x0, read_u64(&gm, BOOT_GDT_OFFSET));
        assert_eq!(0xaf_9b00_0000_ffff, read_u64(&gm, BOOT_GDT_OFFSET + 8));
        assert_eq!(0xcf_9300_0000_ffff, read_u64(&gm, BOOT_GDT_OFFSET + 16));
        assert_eq!(0x8f_8b00_0000_ffff, read_u64(&gm, BOOT_GDT_OFFSET + 24));
        assert_eq!(0x0, read_u64(&gm, BOOT_IDT_OFFSET));

        assert_eq!(0, sregs.cs.base);
        assert_eq!(0xfffff, sregs.ds.limit);
        assert_eq!(0x10, sregs.es.selector);
        assert_eq!(1, sregs.fs.present);
        assert_eq!(1, sregs.gs.g);
        assert_eq!(0, sregs.ss.avl);
        assert_eq!(0, sregs.tr.base);
        assert_eq!(0xfffff, sregs.tr.limit);
        assert_eq!(0, sregs.tr.avl);
        assert!(sregs.cr0 & X86_CR0_PE != 0);
        assert!(sregs.efer & EFER_LME != 0 && sregs.efer & EFER_LMA != 0);
    }

    #[test]
    fn test_configure_segments_and_sregs() {
        let mut sregs: kvm_sregs = Default::default();
        let gm = create_guest_mem();
        configure_segments_and_sregs(&gm, &mut sregs).unwrap();

        validate_segments_and_sregs(&gm, &sregs);
    }

    fn validate_page_tables(gm: &GuestMemoryMmap, sregs: &kvm_sregs) {
        assert_eq!(0xa003, read_u64(&gm, PML4_START));
        assert_eq!(0xb003, read_u64(&gm, PDPTE_START));
        for i in 0..512 {
            assert_eq!((i << 21) + 0x83u64, read_u64(&gm, PDE_START + (i * 8)));
        }

        assert_eq!(PML4_START as u64, sregs.cr3);
        assert!(sregs.cr4 & X86_CR4_PAE != 0);
        assert!(sregs.cr0 & X86_CR0_PG != 0);
    }

    #[test]
    fn test_setup_page_tables() {
        let mut sregs: kvm_sregs = Default::default();
        let gm = create_guest_mem();
        setup_page_tables(&gm, &mut sregs).unwrap();

        validate_page_tables(&gm, &sregs);
    }

    #[test]
    fn test_setup_fpu() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        setup_fpu(&vcpu).unwrap();

        let expected_fpu: kvm_fpu = kvm_fpu {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        };
        let actual_fpu: kvm_fpu = vcpu.get_fpu().unwrap();
        // TODO: auto-generate kvm related structures with PartialEq on.
        assert_eq!(expected_fpu.fcw, actual_fpu.fcw);
        // Setting the mxcsr register from kvm_fpu inside setup_fpu does not influence anything.
        // See 'kvm_arch_vcpu_ioctl_set_fpu' from arch/x86/kvm/x86.c.
        // The mxcsr will stay 0 and the assert below fails. Decide whether or not we should
        // remove it at all.
        // assert!(expected_fpu.mxcsr == actual_fpu.mxcsr);
    }

    #[test]
    fn test_setup_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let expected_regs: kvm_regs = kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: 1,
            rsp: super::super::layout::BOOT_STACK_POINTER as u64,
            rbp: super::super::layout::BOOT_STACK_POINTER as u64,
            rsi: super::super::layout::ZERO_PAGE_START as u64,
            ..Default::default()
        };

        setup_regs(&vcpu, expected_regs.rip).unwrap();

        let actual_regs: kvm_regs = vcpu.get_regs().unwrap();
        assert_eq!(actual_regs, expected_regs);
    }

    #[test]
    fn test_setup_sregs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let gm = create_guest_mem();

        assert!(vcpu.set_sregs(&Default::default()).is_ok());
        setup_sregs(&gm, &vcpu).unwrap();

        let mut sregs: kvm_sregs = vcpu.get_sregs().unwrap();
        // for AMD KVM_GET_SREGS returns g = 0 for each kvm_segment.
        // We set it to 1, otherwise the test will fail.
        sregs.gs.g = 1;

        validate_segments_and_sregs(&gm, &sregs);
        validate_page_tables(&gm, &sregs);
    }
}
