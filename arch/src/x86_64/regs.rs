// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::{io, mem, result};

use kvm_bindings::{kvm_fpu, kvm_msr_entry, kvm_msrs, kvm_regs, kvm_sregs, kvm_segment};
use kvm_ioctls::VcpuFd;

use super::gdt::{gdt_entry, kvm_segment_from_gdt};
use arch_gen::x86::msr_index;
use memory_model::{GuestAddress, GuestMemory};
use x86_64::multiboot2 as mb2;
use x86_64::pml4::{self, PagingLevel};

// Initial pagetables.
const PML4_START: usize = 0x9000;
const PDPTE_START: usize = 0xa000;
const PDE_START: usize = 0xb000;

const PAGE_SIZE: usize = 4096;
const L4_UNIT: usize = PAGE_SIZE;
const L3_UNIT: usize = L4_UNIT * 512;
const L2_UNIT: usize = L3_UNIT * 512;
const L1_UNIT: usize = L2_UNIT * 512;

const LEGACY_PT_UNIT: usize = L4_UNIT;
const LEGACY_PD_UNIT: usize = LEGACY_PT_UNIT * 1024;

const PAE_PT_UNIT: usize = L4_UNIT;
const PAE_PD_UNIT: usize = PAE_PT_UNIT * 512;
const PAE_PDP_UNIT: usize = PAE_PD_UNIT * 512;

const HRT_GVA_OFFSET: usize = 0xFFFF_8000_0000_0000;

#[derive(Debug)]
pub enum Error {
    /// Failed to get SREGs for this CPU.
    GetStatusRegisters(io::Error),
    /// Failed to set base registers for this CPU.
    SetBaseRegisters(io::Error),
    /// Failed to configure the FPU.
    SetFPURegisters(io::Error),
    /// Setting up MSRs failed.
    SetModelSpecificRegisters(io::Error),
    /// Failed to set SREGs for this CPU.
    SetStatusRegisters(io::Error),
    /// Writing the GDT to RAM failed.
    WriteGDT,
    /// Writing the IDT to RAM failed.
    WriteIDT,
    /// Writing PML4 to RAM failed.
    WritePML4Address,
    /// Writing PDPTE to RAM failed.
    WritePDPTEAddress,
    /// Writing PDE to RAM failed.
    WritePDEAddress,
    /// Writing PTE to RAM failed.
    WritePTEAddress,
}

pub type Result<T> = result::Result<T, Error>;

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

/// Configure Model Specific Registers (MSRs) for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_msrs(vcpu: &VcpuFd) -> Result<()> {
    let entry_vec = create_msr_entries();
    let vec_size_bytes =
        mem::size_of::<kvm_msrs>() + (entry_vec.len() * mem::size_of::<kvm_msr_entry>());
    let vec: Vec<u8> = Vec::with_capacity(vec_size_bytes);
    #[allow(clippy::cast_ptr_alignment)]
    let msrs: &mut kvm_msrs = unsafe {
        // Converting the vector's memory to a struct is unsafe.  Carefully using the read-only
        // vector to size and set the members ensures no out-of-bounds errors below.
        &mut *(vec.as_ptr() as *mut kvm_msrs)
    };

    unsafe {
        // Mapping the unsized array to a slice is unsafe because the length isn't known.
        // Providing the length used to create the struct guarantees the entire slice is valid.
        let entries: &mut [kvm_msr_entry] = msrs.entries.as_mut_slice(entry_vec.len());
        entries.copy_from_slice(&entry_vec);
    }
    msrs.nmsrs = entry_vec.len() as u32;

    vcpu.set_msrs(msrs)
        .map_err(Error::SetModelSpecificRegisters)
}

pub fn setup_regs(vcpu: &VcpuFd, boot_ip: u64, is_multiboot: bool) -> Result<()> {
    if is_multiboot {
        return mb_setup_regs(vcpu, boot_ip);
    } else {
        return linux_setup_regs(vcpu, boot_ip);
    }
}

fn mb_setup_regs(vcpu: &VcpuFd, boot_ip: u64) -> Result<()> {
    let regs: kvm_regs = kvm_regs {
        rflags: 0x0000_0000_0000_0002u64, // copied from linux ver???
        rip: boot_ip + HRT_GVA_OFFSET as u64,
        rax: 0x36d76289,
        rbx: super::layout::ZERO_PAGE_START as u64,
        rsp: 0x10004000 + HRT_GVA_OFFSET as u64, // maybe don't hardcode this
        ..Default::default()
    };
    
    println!("{:#X?}", regs);

    vcpu.set_regs(&regs).map_err(Error::SetBaseRegisters)
}

/// Configure base registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `boot_ip` - Starting instruction pointer.
fn linux_setup_regs(vcpu: &VcpuFd, boot_ip: u64) -> Result<()> {
    let regs: kvm_regs = kvm_regs {
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
    };

    vcpu.set_regs(&regs).map_err(Error::SetBaseRegisters)
}

pub fn setup_sregs(
    mem: &GuestMemory,
    vcpu: &VcpuFd,
    is_multiboot: bool,
    hrt_header: Option<mb2::HeaderHybridRuntime>
) -> Result<()> {
    if is_multiboot {
        return mb_setup_sregs(mem, vcpu, hrt_header);
    } else {
        return linux_setup_sregs(mem, vcpu);
    }
}

/// Configures the segment registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `mem` - The memory that will be passed to the guest.
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
fn linux_setup_sregs(mem: &GuestMemory, vcpu: &VcpuFd) -> Result<()> {
    let mut sregs: kvm_sregs = vcpu.get_sregs().map_err(Error::GetStatusRegisters)?;

    configure_segments_and_sregs(mem, &mut sregs)?;
    setup_page_tables(mem, &mut sregs)?; // TODO(dgreid) - Can this be done once per system instead?

    vcpu.set_sregs(&sregs).map_err(Error::SetStatusRegisters)
}


fn mb_setup_sregs(mem: &GuestMemory, vcpu: &VcpuFd, hrt_header: Option<mb2::HeaderHybridRuntime>) -> Result<()> {
    let mut sregs: kvm_sregs = vcpu.get_sregs().map_err(Error::GetStatusRegisters)?;
    mb_configure_segments_and_sregs(mem, &mut sregs)?;
    match hrt_header {
        Some(hdr) => {
            let base = hrt_setup_page_tables(mem, &mut sregs, hdr)?;
            sregs.cr3 = base.0 as u64;
        },
        None => ()
    }

    println!("{:#X?}", sregs);

    vcpu.set_sregs(&sregs).map_err(Error::SetStatusRegisters)
}

const BOOT_GDT_OFFSET: usize = 0x500;
const BOOT_IDT_OFFSET: usize = 0x520;

const BOOT_GDT_MAX: usize = 4;

const EFER_LMA: u64 = 0x400;
const EFER_LME: u64 = 0x100;

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;

fn write_gdt_table(table: &[u64], guest_mem: &GuestMemory) -> Result<()> {
    let boot_gdt_addr = GuestAddress(BOOT_GDT_OFFSET);
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, index * mem::size_of::<u64>())
            .ok_or(Error::WriteGDT)?;
        guest_mem
            .write_obj_at_addr(*entry, addr)
            .map_err(|_| Error::WriteGDT)?;
    }
    Ok(())
}

fn write_gdt_table_at_addr(table: &[u64], guest_mem: &GuestMemory, boot_gdt_addr: GuestAddress) -> Result<()> {
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, index * mem::size_of::<u64>())
            .ok_or(Error::WriteGDT)?;
        guest_mem
            .write_obj_at_addr(*entry, addr)
            .map_err(|_| Error::WriteGDT)?;
    }
    Ok(())
}

fn write_idt_value(val: u64, guest_mem: &GuestMemory) -> Result<()> {
    let boot_idt_addr = GuestAddress(BOOT_IDT_OFFSET);
    guest_mem
        .write_obj_at_addr(val, boot_idt_addr)
        .map_err(|_| Error::WriteIDT)
}

fn write_idt_value_at_addr(val: u64, guest_mem: &GuestMemory, boot_idt_addr: GuestAddress) -> Result<()> {
    guest_mem
        .write_obj_at_addr(val, boot_idt_addr)
        .map_err(|_| Error::WriteIDT)
}

fn configure_segments_and_sregs(mem: &GuestMemory, sregs: &mut kvm_sregs) -> Result<()> {
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

fn mb_configure_segments_and_sregs(mem: &GuestMemory, sregs: &mut kvm_sregs) -> Result<()> {
    let gdt_table: [u64; 3 as usize] = [
        gdt_entry(0, 0, 0),
        gdt_entry(0xa09a, 0, 0xffffffff),
        gdt_entry(0xa092, 0, 0xffffffff),
    ];

    let code_seg = kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = kvm_segment_from_gdt(gdt_table[2], 2);
    
    let end_addr = mem.end_addr();
    let end_page = page_align(end_addr);

    let gdt_loc = end_page.0 - 3*4096;
    write_gdt_table_at_addr(&gdt_table[..], mem, GuestAddress(gdt_loc))?;
    sregs.gdt.base = gdt_loc as u64;
    //sregs.gdt.limit = mem::size_of_val(&gdt_table) as u16 - 1;
    sregs.gdt.limit = 24; // should maybe be 1 smaller

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

    let idt_loc = end_page.0 - 2*4096;
    let null_int_handler_loc = end_page.0 - 4096;

    mem.write_obj_at_addr(vmx_null_int_handler, GuestAddress(null_int_handler_loc))
       .map_err(|_| Error::WriteIDT)?;

    let mut trap_gate = pml4::IDTe(0x0);
    trap_gate.set_selector(0x8);
    trap_gate.set_gate_type(0xf);
    trap_gate.set_present(true);
    println!("trap gate: {:#032X}", trap_gate.0);
    trap_gate.set_offset((null_int_handler_loc + HRT_GVA_OFFSET) as u64);
    println!("trap_gate: {:#032X}", trap_gate.0);
    

    println!("IDT[0..32] @ {:#X}..{:#X}: offset={:#X} selector={:#x} type={:#x} present={}", idt_loc+16*0, idt_loc+16*32, trap_gate.offset(), trap_gate.selector(), trap_gate.gate_type(), trap_gate.present());
    for i in 0..32 {
        mem.write_obj_at_addr(trap_gate.0, GuestAddress(idt_loc+16*i))
           .map_err(|_| Error::WriteIDT)?;
    }

    let mut int_gate = pml4::IDTe(0x0);
    int_gate.set_selector(0x8);
    int_gate.set_gate_type(0xe);
    int_gate.set_present(true);
    println!("int gate: {:#032X}", int_gate.0);
    int_gate.set_offset((null_int_handler_loc + HRT_GVA_OFFSET) as u64);
    println!("int_gate: {:#032X}", int_gate.0);
    
    println!("IDT[32..256] @ {:#X}..{:#X}: offset={:#X} selector={:#x} type={:#x} present={}", idt_loc+16*32, idt_loc+16*256, int_gate.offset(), int_gate.selector(), int_gate.gate_type(), int_gate.present());
    for i in 32..256 {
        mem.write_obj_at_addr(int_gate.0, GuestAddress(idt_loc+16*i))
           .map_err(|_| Error::WriteIDT)?;
    }

    sregs.idt.base = (idt_loc + HRT_GVA_OFFSET) as u64;
    sregs.idt.limit = 16*256; // should maybe be 1 smaller

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    //sregs.tr = tss_seg;

    sregs.cr0 |= X86_CR0_PE;
    sregs.cr0 |= X86_CR0_PG;

    sregs.cr4 |= X86_CR4_PAE;

    sregs.efer |= EFER_LME;
    sregs.efer |= EFER_LMA;

    Ok(())
}

fn ceil_div(a: usize, b: usize) -> usize {
    return a / b + {
        if a % b == 0 {
            0
        } else {
            1
        }
    };
}

fn hrt_compute_legacy_pts(mem: &GuestMemory) -> (usize, usize) {
    let max_gva = mem.end_addr().0;
    return (
        1,
        ceil_div(ceil_div(max_gva, 4096), 1024)
    );
}

fn hrt_compute_pae_pts(mem: &GuestMemory) -> (usize, usize, usize) {
    let max_gva = mem.end_addr().0;
    return (
        1,
        ceil_div(ceil_div(max_gva, 512*4096), 512),
        ceil_div(ceil_div(max_gva, 4096), 512)
    )
}

fn hrt_compute_pts(mem: &GuestMemory) -> (usize, usize, usize, usize) {
    let max_gva = mem.end_addr().0;
    // TODO: use ceil division
    return (
        1,
        ceil_div(ceil_div(max_gva, 512*512*4096), 512),
        ceil_div(ceil_div(max_gva, 512*4096), 512),
        ceil_div(ceil_div(max_gva, 4096), 512)
    );
}

fn page_align(addr: GuestAddress) -> GuestAddress {
    return GuestAddress((addr.0 >> 12) << 12);
}

fn hrt_get_legacy_pt_loc(
    mem: &GuestMemory,
) -> GuestAddress {
    let (pde, pte) = hrt_compute_legacy_pts(mem);
    let num_pt = pde + pte;
    let end_addr = mem.end_addr();
    let end_page = page_align(end_addr);
    let enough_room = end_page.0 - (4+num_pt)*4096;
    return page_align(GuestAddress(enough_room));
}

fn hrt_get_pae_pt_loc(
    mem: &GuestMemory,
) -> GuestAddress {
    let (pdpe, pde, pte) = hrt_compute_pae_pts(mem);
    let num_pt = pdpe + pde + pte;
    let end_addr = mem.end_addr();
    let end_page = page_align(end_addr);
    let enough_room = end_page.0 - (4+num_pt)*4096;
    return page_align(GuestAddress(enough_room));
}

fn hrt_get_pt_loc(
    mem: &GuestMemory,
    paging_level: pml4::PagingLevel,
) -> GuestAddress {
    let (l1, l2, l3, l4) = hrt_compute_pts(mem);
    let num_pt = match paging_level {
        PagingLevel::Colossal => l1,
        PagingLevel::Huge => l1 + l2,
        PagingLevel::Large => l1 + l2 + l3,
        PagingLevel::Normal => l1 + l2 + l3 + l4,
    };
    let end_addr = mem.end_addr();
    let end_page = page_align(end_addr);
    let enough_room = end_page.0 - (4+num_pt)*4096;
    return page_align(GuestAddress(enough_room));
}

fn hrt_setup_legacy_page_tables(
    mem: &GuestMemory,
    sregs: &mut kvm_sregs,
    hrt_header: mb2::HeaderHybridRuntime,
) -> Result<GuestAddress> {
    let min_addr = 0;
    let max_addr = mem.end_addr().0;
    
    println!("guest phys mem: {:#X} - {:#X}\nguest virt mem: {:#X} - {:#X}", min_addr, max_addr, min_addr, max_addr);

    let (num_pd, num_pt) = hrt_compute_legacy_pts(mem);
    println!("{} PDT, {} PT", num_pd, num_pt);

    let pd_start = hrt_get_legacy_pt_loc(mem);
    let pt_start = pd_start.unchecked_add(4096 * num_pd);

    println!("PD @ {:#X}, PT @ {:#X}", pd_start.0, pt_start.0);
    
    for i in 0..1024 {
        let cur_addr = min_addr + i*LEGACY_PD_UNIT;

        let mut pde = pml4::LegacyPDe(0x0);
        pde.set_present(true);
        pde.set_writable(true);
        let pt_base_addr = page_align(pt_start.unchecked_add(i * PAGE_SIZE));
        
        pde.set_4mb(false);
    
        pde.set_pt_base_addr(pt_base_addr.0 as u32 >> 12);
        let entry_loc = pd_start.unchecked_add(4 * i);

        mem.write_obj_at_addr(pde.0, entry_loc);
        println!("PD[{}] @ {:#X} -> {:#X} ({:#X} -> {:#X}, large={})", i, entry_loc.0, pde.pt_base_addr(), cur_addr, cur_addr, pde.is_4mb());
    }

    'outer: for i in 0..num_pt {
        let pt_addr = min_addr + i*LEGACY_PD_UNIT;
        
        for j in 0..1024 {
            let cur_addr = pt_addr + j*LEGACY_PT_UNIT;
            
            if cur_addr >= max_addr {
                break 'outer;
            }

            let mut pte = pml4::LegacyPTe(0x0);
            pte.set_present(true);
            pte.set_writable(true);
            pte.set_page_base_addr(cur_addr as u32);
            let entry_loc = pt_start.unchecked_add(4096*i + 4*j); // might be 512 rather than 4096
            mem.write_obj_at_addr(pte.0, entry_loc);
            println!("PT[{}][{}] @ {:#X} -> {:#X} ({:#X} -> {:#X})", i, j, entry_loc.0, pte.page_base_addr(), cur_addr, cur_addr);
        }
    }

    Ok(pd_start)
}

fn hrt_setup_pae_page_tables(
    mem: &GuestMemory,
    sregs: &mut kvm_sregs,
    hrt_header: mb2::HeaderHybridRuntime,
) -> Result<GuestAddress> {
    let min_addr = 0;
    let max_addr = mem.end_addr().0;
    
    println!("guest phys mem: {:#X} - {:#X}\nguest virt mem: {:#X} - {:#X}", min_addr, max_addr, min_addr, max_addr);

    let (num_pdp, num_pd, num_pt) = hrt_compute_pae_pts(mem);
    println!("{} PDP, {} PD, {} PT", num_pdp, num_pd, num_pt);

    let pdp_start = hrt_get_pae_pt_loc(mem);
    let pd_start = pdp_start.unchecked_add(4096 * num_pdp);
    let pt_start = pd_start.unchecked_add(4096 * num_pd);

    println!("PDP @ {:#X}, PD @ {:#X}, PT @ {:#X}", pdp_start.0, pd_start.0, pt_start.0);

    for i in 0..512 {
        let cur_addr = min_addr + i*PAE_PDP_UNIT;

        let mut pdpe = pml4::PAE_PDPe(0x0);

        pdpe.set_present(true);

        let pd_base_addr = page_align(pd_start.unchecked_add(i * PAGE_SIZE));

        pdpe.set_pd_base_addr(pd_base_addr.0 as u64 >> 12);
        let entry_loc = pdp_start.unchecked_add(8 * i);
        
        if cur_addr > max_addr {
            mem.write_obj_at_addr(0x0 as u64, entry_loc);
            continue;
        }

        mem.write_obj_at_addr(pdpe.0, entry_loc);
        println!("PDP[{}] @ {:#X} -> {:#X} ({:#X} -> {:#X})", i, entry_loc.0, pdpe.pd_base_addr(), cur_addr, cur_addr);
    }

    for i in 0..num_pd {
        let pd_addr = min_addr + i*PAE_PDP_UNIT;
        for j in 0..512 { 
            let cur_addr = pd_addr + j*PAE_PD_UNIT;
            
            let mut pde = pml4::PAE_PDe(0x0);
            pde.set_present(true);
            pde.set_writable(true);

            let pt_base_addr = pt_start.unchecked_add((512*i + j) * PAGE_SIZE);
            pde.set_pt_base_addr(pt_base_addr.0 as u64 >> 12);

            let entry_loc = pd_start.unchecked_add(4096*i + 8*j);

            if cur_addr > max_addr {
                mem.write_obj_at_addr(0x0 as u64, entry_loc);
                continue;
            }

            mem.write_obj_at_addr(pde.0, entry_loc);
            println!("PD[{}][{}] @ {:#X} -> {:#X} ({:#X} -> {:#X})", i, j, entry_loc.0, pde.pt_base_addr(), cur_addr, cur_addr)
        }
    }

    for i in 0..num_pt {
        let pt_addr = min_addr + i*PAE_PD_UNIT;
        for j in 0..512 {
            let cur_addr = pt_addr + j*PAE_PT_UNIT;

            let mut pte = pml4::PAE_PTe(0x0);
            pte.set_present(true);
            pte.set_writable(true);

            pte.set_page_base_addr(cur_addr as u64 >> 12);

            let entry_loc = pt_start.unchecked_add(4096*i + 8*j);

            if cur_addr > max_addr {
                mem.write_obj_at_addr(0x0 as u64, entry_loc);
                continue;
            }

            mem.write_obj_at_addr(pte.0, entry_loc);
            println!("PT[{}][{}] @ {:#X} -> {:#X} ({:#X} -> {:#X})", i, j, entry_loc.0, pte.page_base_addr(), cur_addr, cur_addr);
        }
    }
    
    Ok(pdp_start)
}

fn hrt_setup_page_tables(
    mem: &GuestMemory,
    sregs: &mut kvm_sregs,
    hrt_header: mb2::HeaderHybridRuntime,
) -> Result<GuestAddress> {
    let min_gpa = GuestAddress(0);
    let max_gpa = mem.end_addr();
    let min_gva = hrt_header.hrt_hihalf_offset as usize;
    let max_gva = min_gva + max_gpa.0;

    println!("guest phys mem: {:#X} - {:#X}\nguest virt mem: {:#X} - {:#X}", min_gpa.0, max_gpa.0, min_gva, max_gva);

    let paging_level = {
        if hrt_header.flags.map_512gb() {
            PagingLevel::Colossal
        } else if hrt_header.flags.map_1gb() {
            PagingLevel::Huge
        } else if hrt_header.flags.map_2mb() {
            PagingLevel::Large
        } else if hrt_header.flags.map_4kb() {
            PagingLevel::Normal
        } else {
            println!("could not determine paging level");
            return Ok(GuestAddress(0x0)); // really need to work on my error handling
        }
    };

    println!("paging level = {:#?}", paging_level);
    
    let (num_l1, num_l2, num_l3, num_l4) = hrt_compute_pts(mem);
    println!("{} PML4, {} PDP, {} PD, {} PT", num_l1, num_l2, num_l3, num_l4);
    let l1_start = hrt_get_pt_loc(mem, paging_level);
    let l2_start = l1_start.unchecked_add(4096 * num_l1);
    let l3_start = l2_start.unchecked_add(4096 * num_l2);
    let l4_start = l3_start.unchecked_add(4096 * num_l3);

    println!("PML4 @ {:#X}, PDP @ {:#X}, PD @ {:#X}, PT @ {:#X}", l1_start.0, l2_start.0, l3_start.0, l4_start.0);

    for i in 0..512 {
        mem.write_obj_at_addr(0x0 as u64, l1_start.unchecked_add(i * 8));
    }

    let pml4_range = {
        if min_gva == 0x0 {
            0..num_l2
        } else if min_gva == HRT_GVA_OFFSET {
            256..256+num_l2
        } else {
            println!("error: unsupported gva offset");
            return Err(Error::WritePML4Address);
        }
    };
    
    let start = pml4_range.start;

    for i in pml4_range {
        let j = i - start;
        let cur_gva = min_gva + j*L1_UNIT;
        let cur_gpa = min_gpa.unchecked_add(j*L1_UNIT);

        let mut pml4e = pml4::PML4e(0x0);
        pml4e.set_present(true);
        pml4e.set_writable(true);
        let pdp_base_addr = match paging_level {
            PagingLevel::Colossal => page_align(cur_gpa),
            _ => page_align(l2_start.unchecked_add((i - start) * PAGE_SIZE))
        };
        pml4e.set_pdp_base_addr(pdp_base_addr.0 as u64 >> 12);
        let entry_loc = l1_start.unchecked_add(i * 8);
        mem.write_obj_at_addr(pml4e.0, entry_loc)
            .map_err(|_| Error::WritePML4Address)?;
        mem.write_obj_at_addr(pml4e.0, GuestAddress(entry_loc.0 - 0x800))
            .map_err(|_| Error::WritePML4Address)?;
        println!("PML4[{}] @ {:#X} = {:#X} ({:#X} -> {:#X})", i, entry_loc.0, pml4e.pdp_base_addr(), cur_gva, cur_gpa.0);
    }

    if paging_level == PagingLevel::Colossal {
        return Ok(l1_start);
    }

    for i in 0..num_l2 {
        let pdp_gva = min_gva + i*L1_UNIT;
        let pdp_gpa = min_gpa.unchecked_add(i*L1_UNIT);

        for j in 0..512 {
            let cur_gva = pdp_gva + j*L2_UNIT;
            let cur_gpa = pdp_gpa.unchecked_add(j*L2_UNIT);
            let mut pdpe = pml4::PDPe(0x0);
            pdpe.set_present(true);
            pdpe.set_writable(true);
            let pd_base_addr = match paging_level {
                PagingLevel::Huge => page_align(cur_gpa),
                _ => page_align(l3_start.unchecked_add((512*i + j) * PAGE_SIZE))
            };
            pdpe.set_1gb(paging_level == PagingLevel::Huge);
            pdpe.set_pd_base_addr(pd_base_addr.0 as u64 >> 12);
            let entry_loc = l2_start.unchecked_add((512*i + j) * 8);
            if cur_gva > max_gva {
                mem.write_obj_at_addr(0x0 as u64, entry_loc)
                    .map_err(|_| Error::WritePDPTEAddress)?;
                continue;
            }
            mem.write_obj_at_addr(pdpe.0, entry_loc)
                .map_err(|_| Error::WritePDPTEAddress)?;
            println!("PDP[{}][{}] @ {:#X} = {:#X} ({:#X} -> {:#X}, huge={})", i, j, entry_loc.0, pdpe.pd_base_addr(), cur_gva, cur_gpa.0, pdpe.is_1gb());
        }
    }

    if paging_level == PagingLevel::Huge {
        return Ok(l1_start);
    }

    for i in 0..num_l3 {
        let pd_gva = min_gva + i*L2_UNIT;
        let pd_gpa = min_gpa.unchecked_add(i*L2_UNIT);

        for j in 0..512 {
            let cur_gva = pd_gva + j*L3_UNIT;
            let cur_gpa = pd_gpa.unchecked_add(j*L3_UNIT);
            let mut pde = pml4::PDe(0x0);
            pde.set_present(true);
            pde.set_writable(true);
            let pt_base_addr = match paging_level {
                PagingLevel::Large => page_align(cur_gpa),
                _ => page_align(l4_start.unchecked_add((512*i + j) * PAGE_SIZE))
            };
            pde.set_2mb(paging_level == PagingLevel::Large);
            pde.set_pt_base_addr(pt_base_addr.0 as u64 >> 12);
            let entry_loc = l3_start.unchecked_add((512*i + j) * 8);
            if cur_gva > max_gva {
                mem.write_obj_at_addr(0x0 as u64, entry_loc)
                    .map_err(|_| Error::WritePDEAddress)?;
                continue;
            }
            mem.write_obj_at_addr(pde.0, entry_loc)
                .map_err(|_| Error::WritePDEAddress)?;
            println!("PD[{}][{}] @ {:#X} = {:#X} ({:#X} -> {:#X}, large={})", i, j, entry_loc.0, pde.pt_base_addr(), cur_gva, cur_gpa.0, pde.is_2mb());
        }
    }

    if paging_level == PagingLevel::Large {
        return Ok(l1_start);
    }

    'outer: for i in 0..num_l4 {
        let pt_gva = min_gva + i*L3_UNIT;
        let pt_gpa = min_gpa.unchecked_add(i*L3_UNIT);

        for j in 0..512 {
            let cur_gva = pt_gva + j*L3_UNIT;
            let cur_gpa = pt_gpa.unchecked_add(j*L4_UNIT);
            let mut pte = pml4::PTe(0x0);
            pte.set_present(true);
            pte.set_writable(true);
            pte.set_page_base_addr(page_align(cur_gpa).0 as u64 >> 12);
            let entry_loc = l4_start.unchecked_add((512*i + j) * 8);
            if cur_gva > max_gva {
                mem.write_obj_at_addr(0x0 as u64, entry_loc)
                    .map_err(|_| Error::WritePTEAddress)?;
                continue;
            }
            mem.write_obj_at_addr(pte.0, entry_loc)
                .map_err(|_| Error::WritePTEAddress)?;
            println!("PT[{}][{}] @ {:#X} -> {:#X} ({:#X} -> {:#X})", i, j, entry_loc.0, pte.page_base_addr(), cur_gva, cur_gpa.0);
        }
    }
    
    Ok(l1_start)
}

fn setup_page_tables(mem: &GuestMemory, sregs: &mut kvm_sregs) -> Result<()> {
    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = GuestAddress(PML4_START);
    let boot_pdpte_addr = GuestAddress(PDPTE_START);
    let boot_pde_addr = GuestAddress(PDE_START);

    // Entry covering VA [0..512GB)
    mem.write_obj_at_addr(boot_pdpte_addr.offset() as u64 | 0x03, boot_pml4_addr)
        .map_err(|_| Error::WritePML4Address)?;

    // Entry covering VA [0..1GB)
    mem.write_obj_at_addr(boot_pde_addr.offset() as u64 | 0x03, boot_pdpte_addr)
        .map_err(|_| Error::WritePDPTEAddress)?;
    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512 {
        mem.write_obj_at_addr(
            (i << 21) + 0x83u64,
            boot_pde_addr.unchecked_add((i * 8) as usize),
        )
        .map_err(|_| Error::WritePDEAddress)?;
    }

    sregs.cr3 = boot_pml4_addr.offset() as u64;
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    Ok(())
}

fn create_msr_entries() -> Vec<kvm_msr_entry> {
    let mut entries = Vec::<kvm_msr_entry>::new();

    entries.push(kvm_msr_entry {
        index: msr_index::MSR_IA32_SYSENTER_CS,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: msr_index::MSR_IA32_SYSENTER_ESP,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: msr_index::MSR_IA32_SYSENTER_EIP,
        data: 0x0,
        ..Default::default()
    });
    // x86_64 specific msrs, we only run on x86_64 not x86.
    entries.push(kvm_msr_entry {
        index: msr_index::MSR_STAR,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: msr_index::MSR_CSTAR,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: msr_index::MSR_KERNEL_GS_BASE,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: msr_index::MSR_SYSCALL_MASK,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: msr_index::MSR_LSTAR,
        data: 0x0,
        ..Default::default()
    });
    // end of x86_64 specific code
    entries.push(kvm_msr_entry {
        index: msr_index::MSR_IA32_TSC,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: msr_index::MSR_IA32_MISC_ENABLE,
        data: u64::from(msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING),
        ..Default::default()
    });

    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_ioctls::Kvm;
    use memory_model::{GuestAddress, GuestMemory};

    fn create_guest_mem() -> GuestMemory {
        GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap()
    }

    fn read_u64(gm: &GuestMemory, offset: usize) -> u64 {
        let read_addr = GuestAddress(offset);
        gm.read_obj_from_addr(read_addr).unwrap()
    }

    fn validate_segments_and_sregs(gm: &GuestMemory, sregs: &kvm_sregs) {
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

    fn validate_page_tables(gm: &GuestMemory, sregs: &kvm_sregs) {
        assert_eq!(0xa003, read_u64(&gm, PML4_START));
        assert_eq!(0xb003, read_u64(&gm, PDPTE_START));
        for i in 0..512 {
            assert_eq!(
                (i << 21) + 0x83u64,
                read_u64(&gm, PDE_START + (i * 8) as usize)
            );
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
    #[allow(clippy::cast_ptr_alignment)]
    fn test_setup_msrs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        setup_msrs(&vcpu).unwrap();

        // This test will check against the last MSR entry configured (the tenth one).
        // See create_msr_entries for details.
        let test_kvm_msrs_entry = [kvm_msr_entry {
            index: msr_index::MSR_IA32_MISC_ENABLE,
            ..Default::default()
        }];
        let vec_size_bytes = mem::size_of::<kvm_msrs>() + mem::size_of::<kvm_msr_entry>();
        let vec: Vec<u8> = Vec::with_capacity(vec_size_bytes);
        let mut msrs: &mut kvm_msrs = unsafe {
            // Converting the vector's memory to a struct is unsafe.  Carefully using the read-only
            // vector to size and set the members ensures no out-of-bounds errors below.
            &mut *(vec.as_ptr() as *mut kvm_msrs)
        };

        unsafe {
            let entries: &mut [kvm_msr_entry] = msrs.entries.as_mut_slice(1);
            entries.copy_from_slice(&test_kvm_msrs_entry);
        }

        msrs.nmsrs = 1;
        // get_msrs returns the number of msrs that it succeed in reading. We only want to read 1
        // in this test case scenario.
        let read_msrs = vcpu.get_msrs(&mut msrs).unwrap();
        assert_eq!(read_msrs, 1);

        // Official entries that were setup when we did setup_msrs. We need to assert that the
        // tenth one (i.e the one with index msr_index::MSR_IA32_MISC_ENABLE has the data we
        // expect.
        let entry_vec = create_msr_entries();
        unsafe {
            assert_eq!(entry_vec[9], msrs.entries.as_slice(1)[0]);
        }
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
