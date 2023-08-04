// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/highmem.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mod_devicetable.h>
#include <linux/mm.h>
#include <linux/objtool.h>
#include <linux/sched.h>
#include <linux/sched/smt.h>
#include <linux/slab.h>
#include <linux/tboot.h>
#include <linux/trace_events.h>
#include <linux/entry-kvm.h>
#include <linux/no_kvm.h>

#include <asm/apic.h>
#include <asm/asm.h>
#include <asm/cpu.h>
#include <asm/cpu_device_id.h>
#include <asm/debugreg.h>
#include <asm/desc.h>
#include <asm/fpu/api.h>
#include <asm/fpu/xstate.h>
#include <asm/idtentry.h>
#include <asm/io.h>
#include <asm/irq_remapping.h>
#include <asm/kexec.h>
#include <asm/perf_event.h>
#include <asm/mmu_context.h>
#include <asm/mshyperv.h>
#include <asm/mwait.h>
#include <asm/spec-ctrl.h>
#include <asm/virtext.h>
#include <asm/vmx.h>

#include "capabilities.h"
#include "cpuid.h"
#include "hyperv.h"
#include "kvm_onhyperv.h"
#include "irq.h"
#include "kvm_cache_regs.h"
#include "lapic.h"
#include "mmu.h"
#include "nested.h"
#include "pmu.h"
#include "sgx.h"
#include "trace.h"
#include "vmcs.h"
#include "vmcs12.h"
#include "vmx.h"
#include "x86.h"
#include "smm.h"

#ifdef CONFIG_SYSCTL
static int sysctl_custom_cpuid = 0;
static int sysctl_custom_msr_write = 0;
static int sysctl_custom_msr_read = 0;
static int sysctl_custom_apic_write = 0;
static int sysctl_custom_other = 0;

static struct ctl_table custom_exits_debug_table[] = {
	{
		.procname	= "orphan_cpuid",
		.data		= &sysctl_custom_cpuid,
		.maxlen		= sizeof(sysctl_custom_cpuid),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "orphan_msr_write",
		.data		= &sysctl_custom_msr_write,
		.maxlen		= sizeof(sysctl_custom_msr_write),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
    {
		.procname	= "orphan_msr_read",
		.data		= &sysctl_custom_msr_read,
		.maxlen		= sizeof(sysctl_custom_msr_read),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
    {
		.procname	= "orphan_apic_write",
		.data		= &sysctl_custom_apic_write,
		.maxlen		= sizeof(sysctl_custom_apic_write),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
    {
		.procname	= "orphan_other",
		.data		= &sysctl_custom_other,
		.maxlen		= sizeof(sysctl_custom_other),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

#endif /* CONFIG_SYSCTL */

static DEFINE_STATIC_KEY_FALSE(vmx_l1d_should_flush);

bool vmx_cpuid_exit(struct vcpu_vmx *vmx)
{
    return vmx->exit_reason.basic == EXIT_REASON_CPUID;
}
bool vcpu_cpuid_exit(struct kvm_vcpu *vcpu)
{
    return vmx_cpuid_exit(to_vmx(vcpu));
}

__always_inline __no_kvm_section static int no_kvm_emulate_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;

	// if (cpuid_fault_enabled(vcpu) && !kvm_require_cpl(vcpu, 0))
	// 	return 1;

	eax = kvm_rax_read(vcpu);
	ecx = kvm_rcx_read(vcpu);
	kvm_cpuid(vcpu, &eax, &ebx, &ecx, &edx, false);
    // asm volatile("cpuid"
    //     : "=a" (eax),
    //     "=b" (ebx),
    //     "=c" (ecx),
    //     "=d" (edx)
    //     : "0" (eax), "2" (ecx)
    //     : "memory");

	kvm_rax_write(vcpu, eax);
	kvm_rbx_write(vcpu, ebx);
	kvm_rcx_write(vcpu, ecx);
	kvm_rdx_write(vcpu, edx);
	return kvm_skip_emulated_instruction(vcpu);
}

__always_inline __no_kvm_section static void no_kvm_vcpu_enter_exit(struct kvm_vcpu *vcpu,
					unsigned int flags)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

    guest_state_enter_irqoff();

    /* L1D Flush includes CPU buffer clear to mitigate MDS */
    if (static_branch_unlikely(&vmx_l1d_should_flush))
        vmx_l1d_flush(vcpu);
    else if (static_branch_unlikely(&mds_user_clear))
        mds_clear_cpu_buffers();
    else if (static_branch_unlikely(&mmio_stale_data_clear) &&
        kvm_arch_has_assigned_device(vcpu->kvm))
        mds_clear_cpu_buffers();

    vmx_disable_fb_clear(vmx);

    if (vcpu->arch.cr2 != native_read_cr2())
        native_write_cr2(vcpu->arch.cr2);

    vmx->fail = __vmx_vcpu_run(vmx, (unsigned long *)&vcpu->arch.regs,
                flags);

    vcpu->arch.cr2 = native_read_cr2();

    vmx_enable_fb_clear(vmx);

    if (unlikely(vmx->fail)) {
        vmx->exit_reason.full = 0xdead;
    } else {
        vmx->exit_reason.full = vmcs_read32(VM_EXIT_REASON);
    }

    if ((u16)vmx->exit_reason.basic == EXIT_REASON_EXCEPTION_NMI &&
        is_nmi(vmx_get_intr_info(vcpu))) {
        kvm_before_interrupt(vcpu, KVM_HANDLING_NMI);
        vmx_do_nmi_irqoff();
        kvm_after_interrupt(vcpu);
    }

    guest_state_exit_irqoff();
}

__always_inline __no_kvm_section static bool handle_orphan_exit(struct kvm_vcpu *vcpu) {
    switch (to_vmx(vcpu)->exit_reason.basic) {
    case EXIT_REASON_CPUID:
        ++sysctl_custom_cpuid;
        no_kvm_emulate_cpuid(vcpu);
        return true;
/*
	case EXIT_REASON_MSR_WRITE:
        ++sysctl_custom_msr_write;
		handle_fastpath_set_msr_irqoff(vcpu);
        return true;
    case EXIT_REASON_MSR_READ:
        ++sysctl_custom_msr_read;
        return false;
    case EXIT_REASON_APIC_WRITE:
        ++sysctl_custom_apic_write;
        return false;
*/
/*
    case EXIT_REASON_PREEMPTION_TIMER:
		handle_fastpath_preemption_timer(vcpu);
        return true;
*/
	default:
        ++sysctl_custom_other;
		return false;
	}
}

__always_inline __no_kvm_section static int no_kvm_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

    for (;;) {
        /* 
        *   needed, causes failure on login
        *   "/lib64/libc.so.6: CPU ISA level is lower than required"
        */
        if (kvm_register_is_dirty(vcpu, VCPU_REGS_RSP))
            vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
        if (kvm_register_is_dirty(vcpu, VCPU_REGS_RIP))
            vmcs_writel(GUEST_RIP, vcpu->arch.regs[VCPU_REGS_RIP]);
        vcpu->arch.regs_dirty = 0;

        /*
        * Refresh vmcs.HOST_CR3 if necessary.  This must be done immediately
        * prior to VM-Enter, as the kernel may load a new ASID (PCID) any time
        * it switches back to the current->mm, which can occur in KVM context
        * when switching to a temporary mm to patch kernel code, e.g. if KVM
        * toggles a static key while handling a VM-Exit.
        */
        /*
        cr3 = __get_current_cr3_fast();
        if (unlikely(cr3 != vmx->loaded_vmcs->host_state.cr3)) {
            vmcs_writel(HOST_CR3, cr3);
            vmx->loaded_vmcs->host_state.cr3 = cr3;
        }

        cr4 = cr4_read_shadow();
        if (unlikely(cr4 != vmx->loaded_vmcs->host_state.cr4)) {
            vmcs_writel(HOST_CR4, cr4);
            vmx->loaded_vmcs->host_state.cr4 = cr4;
        }
        */
        pt_guest_enter(vmx);

        atomic_switch_perf_msrs(vmx);

        /* The actual VMENTER/EXIT is in the .noinstr.text section. */
        no_kvm_vcpu_enter_exit(vcpu, __vmx_vcpu_run_flags(vmx));
        
       // needed - crashes on login
    #ifndef CONFIG_X86_64
        loadsegment(ds, __USER_DS);
        loadsegment(es, __USER_DS);
    #endif

        vcpu->arch.regs_avail &= ~VMX_REGS_LAZY_LOAD_SET;

        pt_guest_exit(vmx);
        if (unlikely(vmx->fail))
            return vmx->exit_reason.basic;

        if (unlikely(vmx->exit_reason.failed_vmentry))
            return vmx->exit_reason.basic;

        vmx->loaded_vmcs->launched = 1;
        
        if (! handle_orphan_exit(vcpu))
            break;
    }
	return vmx->exit_reason.basic;
}

fastpath_t noinline __no_kvm_section handle_orphan_vm_exits(struct kvm_vcpu *vcpu)
{
    // pr_info("Inside custom orphan VM exit handler\n");
    for (;;) {
        int exit_reason = no_kvm_vcpu_run(vcpu);
        switch (exit_reason) {
        	case EXIT_REASON_CPUID:
                break;
            default:
                return EXIT_FASTPATH_NONE;
        }
    }
}
EXPORT_SYMBOL(handle_orphan_vm_exits);

static struct page *orphan_vm_code_page = NULL;
static struct ctl_table_header *sysctl_table = NULL;
static int __init orphan_vm_init(void) 
{
    __kernel_size_t text_len = 0;
    sysctl_custom_cpuid = 0;
    sysctl_custom_msr_write = 0;
    sysctl_custom_msr_read = 0;
    sysctl_custom_apic_write = 0;
    sysctl_custom_other = 0;

    #ifdef CONFIG_ORPHAN_VM
    void *control_page;
    text_len = __no_kvm_end - __no_kvm_start;

    orphan_vm_code_page = alloc_page(0);
    if (orphan_vm_code_page == NULL) {
        return -1;
    }
    control_page = page_address(orphan_vm_code_page) + PAGE_SIZE;
    if (text_len < PAGE_SIZE) {
    	__memcpy(control_page, handle_orphan_vm_exits, text_len);
    } else {
        pr_warn("orphan VM code size is larger than page!");
    }
    // TODO: jump to code page instead
    jump_orphan_vm = handle_orphan_vm_exits;
    #else
    jump_orphan_vm = handle_orphan_vm_exits;
    #endif
    pr_info("Loading no_kvm module, orphan func len: %lu\n", text_len);

    pr_info("prepping custom_exits_debug_table table");
    sysctl_table = register_sysctl("alex", custom_exits_debug_table);
    return sysctl_table == NULL;
}

static void __exit orphan_vm_exit(void) 
{
    pr_info("Unloading no_kvm module");
    jump_orphan_vm = NULL;

    if (orphan_vm_code_page)
        __free_page(orphan_vm_code_page);

    orphan_vm_code_page = NULL;
    if (sysctl_table)
        unregister_sysctl_table(sysctl_table);
}

module_init(orphan_vm_init);
module_exit(orphan_vm_exit);

MODULE_LICENSE("GPL v2");
