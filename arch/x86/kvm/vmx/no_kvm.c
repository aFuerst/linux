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
static int sysctl_custom_cpuid_loop = 0;
static int sysctl_custom_other = 0;

static struct ctl_table custom_exits_debug_table[] = {
	{
		.procname	= "orphan_cpuid_handled",
		.data		= &sysctl_custom_cpuid,
		.maxlen		= sizeof(sysctl_custom_cpuid),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "orphan_cpuid_loop",
		.data		= &sysctl_custom_cpuid_loop,
		.maxlen		= sizeof(sysctl_custom_cpuid_loop),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
    {
		.procname	= "orphan_custom_other",
		.data		= &sysctl_custom_other,
		.maxlen		= sizeof(sysctl_custom_other),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

#endif /* CONFIG_SYSCTL */

static bool __read_mostly enable_vnmi = 1;
static bool __read_mostly enable_preemption_timer = 1;
static DEFINE_STATIC_KEY_FALSE(vmx_l1d_should_flush);

bool vmx_cpuid_exit(struct vcpu_vmx *vmx)
{
    return vmx->exit_reason.basic == EXIT_REASON_CPUID;
}
bool vcpu_cpuid_exit(struct kvm_vcpu *vcpu)
{
    return vmx_cpuid_exit(to_vmx(vcpu));
}

static int no_kvm_emulate_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;
    ++sysctl_custom_cpuid;

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

static fastpath_t no_kvm_exit_handlers_fastpath(struct kvm_vcpu *vcpu)
{
    return EXIT_FASTPATH_NONE;
	/*
    switch (to_vmx(vcpu)->exit_reason.basic) {
	case EXIT_REASON_CPUID:
		return no_kvm_emulate_cpuid(vcpu);
	default:
        ++sysctl_custom_other;
		return EXIT_FASTPATH_NONE;
	}
    */
}

static noinstr void no_kvm_vcpu_enter_exit(struct kvm_vcpu *vcpu,
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

static fastpath_t entry_no_kvm_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long cr3, cr4;

	/* Record the guest's net vcpu time for enforced NMI injections. */
	if (unlikely(!enable_vnmi &&
		     vmx->loaded_vmcs->soft_vnmi_blocked))
		vmx->loaded_vmcs->entry_time = ktime_get();

	/*
	 * Don't enter VMX if guest state is invalid, let the exit handler
	 * start emulation until we arrive back to a valid state.  Synthesize a
	 * consistency check VM-Exit due to invalid guest state and bail.
	 */
	if (unlikely(vmx->emulation_required)) {
		vmx->fail = 0;

		vmx->exit_reason.full = EXIT_REASON_INVALID_STATE;
		vmx->exit_reason.failed_vmentry = 1;
		kvm_register_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_1);
		vmx->exit_qualification = ENTRY_FAIL_DEFAULT;
		kvm_register_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_2);
		vmx->exit_intr_info = 0;
		return EXIT_FASTPATH_NONE;
	}

	trace_kvm_entry(vcpu);

	if (vmx->ple_window_dirty) {
		vmx->ple_window_dirty = false;
		vmcs_write32(PLE_WINDOW, vmx->ple_window);
	}

	/*
	 * We did this in prepare_switch_to_guest, because it needs to
	 * be within srcu_read_lock.
	 */
	WARN_ON_ONCE(vmx->nested.need_vmcs12_to_shadow_sync);

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

	/* When KVM_DEBUGREG_WONT_EXIT, dr6 is accessible in guest. */
	if (unlikely(vcpu->arch.switch_db_regs & KVM_DEBUGREG_WONT_EXIT))
		set_debugreg(vcpu->arch.dr6, 6);

	/* When single-stepping over STI and MOV SS, we must clear the
	 * corresponding interruptibility bits in the guest state. Otherwise
	 * vmentry fails as it then expects bit 14 (BS) in pending debug
	 * exceptions being set, but that's not correct for the guest debugging
	 * case. */
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		vmx_set_interrupt_shadow(vcpu, 0);

	kvm_load_guest_xsave_state(vcpu);

	pt_guest_enter(vmx);

	atomic_switch_perf_msrs(vmx);
	if (intel_pmu_lbr_is_enabled(vcpu))
		vmx_passthrough_lbr_msrs(vcpu);

	if (enable_preemption_timer)
		vmx_update_hv_timer(vcpu);

	kvm_wait_lapic_expire(vcpu);

	/* The actual VMENTER/EXIT is in the .noinstr.text section. */
	no_kvm_vcpu_enter_exit(vcpu, __vmx_vcpu_run_flags(vmx));
    return no_kvm_exit_handlers_fastpath(vcpu);

}

static fastpath_t no_kvm_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long cr3, cr4;

    for (;;) {
        /* Record the guest's net vcpu time for enforced NMI injections. */
        // if (unlikely(!enable_vnmi &&
        //         vmx->loaded_vmcs->soft_vnmi_blocked))
        //     vmx->loaded_vmcs->entry_time = ktime_get();

        /*
        * Don't enter VMX if guest state is invalid, let the exit handler
        * start emulation until we arrive back to a valid state.  Synthesize a
        * consistency check VM-Exit due to invalid guest state and bail.
        */
        // if (unlikely(vmx->emulation_required)) {
        //     vmx->fail = 0;

        //     vmx->exit_reason.full = EXIT_REASON_INVALID_STATE;
        //     vmx->exit_reason.failed_vmentry = 1;
        //     kvm_register_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_1);
        //     vmx->exit_qualification = ENTRY_FAIL_DEFAULT;
        //     kvm_register_mark_available(vcpu, VCPU_EXREG_EXIT_INFO_2);
        //     vmx->exit_intr_info = 0;
        //     return EXIT_FASTPATH_NONE;
        // }

        // trace_kvm_entry(vcpu);

        if (vmx->ple_window_dirty) {
            vmx->ple_window_dirty = false;
            vmcs_write32(PLE_WINDOW, vmx->ple_window);
        }

        /*
        * We did this in prepare_switch_to_guest, because it needs to
        * be within srcu_read_lock.
        */
        WARN_ON_ONCE(vmx->nested.need_vmcs12_to_shadow_sync);

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

        /* When KVM_DEBUGREG_WONT_EXIT, dr6 is accessible in guest. */
        // if (unlikely(vcpu->arch.switch_db_regs & KVM_DEBUGREG_WONT_EXIT))
        //     set_debugreg(vcpu->arch.dr6, 6);

        /* When single-stepping over STI and MOV SS, we must clear the
        * corresponding interruptibility bits in the guest state. Otherwise
        * vmentry fails as it then expects bit 14 (BS) in pending debug
        * exceptions being set, but that's not correct for the guest debugging
        * case. */
        // if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
        //     vmx_set_interrupt_shadow(vcpu, 0);

        // kvm_load_guest_xsave_state(vcpu);

        pt_guest_enter(vmx);

        atomic_switch_perf_msrs(vmx);
        // if (intel_pmu_lbr_is_enabled(vcpu))
        //     vmx_passthrough_lbr_msrs(vcpu);

        // if (enable_preemption_timer)
        //     vmx_update_hv_timer(vcpu);

        // kvm_wait_lapic_expire(vcpu);

        /* The actual VMENTER/EXIT is in the .noinstr.text section. */
        no_kvm_vcpu_enter_exit(vcpu, __vmx_vcpu_run_flags(vmx));

        /* All fields are clean at this point */
        if (kvm_is_using_evmcs()) {
            current_evmcs->hv_clean_fields |=
                HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;

            current_evmcs->hv_vp_id = kvm_hv_get_vpindex(vcpu);
        }

        /* MSR_IA32_DEBUGCTLMSR is zeroed on vmexit. Restore it if needed */
        // if (vmx->host_debugctlmsr)
        //     update_debugctlmsr(vmx->host_debugctlmsr);

    #ifndef CONFIG_X86_64
        /*
        * The sysexit path does not restore ds/es, so we must set them to
        * a reasonable value ourselves.
        *
        * We can't defer this to vmx_prepare_switch_to_host() since that
        * function may be executed in interrupt context, which saves and
        * restore segments around it, nullifying its effect.
        */
        loadsegment(ds, __USER_DS);
        loadsegment(es, __USER_DS);
    #endif

        vcpu->arch.regs_avail &= ~VMX_REGS_LAZY_LOAD_SET;

        pt_guest_exit(vmx);

        // kvm_load_host_xsave_state(vcpu);

        // if (is_guest_mode(vcpu)) {
            /*
            * Track VMLAUNCH/VMRESUME that have made past guest state
            * checking.
            */
        //     if (vmx->nested.nested_run_pending &&
        //         !vmx->exit_reason.failed_vmentry)
        //         ++vcpu->stat.nested_run;

        //     vmx->nested.nested_run_pending = 0;
        // }

        // vmx->idt_vectoring_info = 0;

        if (unlikely(vmx->fail))
            return EXIT_FASTPATH_NONE;

        // if (unlikely((u16)vmx->exit_reason.basic == EXIT_REASON_MCE_DURING_VMENTRY))
        //     kvm_machine_check();

        // if (likely(!vmx->exit_reason.failed_vmentry))
        //     vmx->idt_vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);

        // trace_kvm_exit(vcpu, KVM_ISA_VMX);

        if (unlikely(vmx->exit_reason.failed_vmentry))
            return EXIT_FASTPATH_NONE;

        vmx->loaded_vmcs->launched = 1;

        // vmx_recover_nmi_blocking(vmx);
        // vmx_complete_interrupts(vmx);

        // if (is_guest_mode(vcpu))
        //     return EXIT_FASTPATH_NONE;

        if (vmx_cpuid_exit(vmx)) {
            no_kvm_emulate_cpuid(vcpu);
            ++sysctl_custom_cpuid_loop;
        } else {
            break;
        }
    }
	return no_kvm_exit_handlers_fastpath(vcpu);
}

fastpath_t noinline __section(".no_kvm.text") __weak handle_orphan_vm_exits(struct kvm_vcpu *vcpu)
{
    // union vmx_exit_reason exit_reason;
    pr_info("Moving to custom orphan VM exit handler\n");
    // return EXIT_FASTPATH_NONE;
    // return no_kvm_vcpu_run(vcpu);;
    for (;;) {
        fastpath_t path = no_kvm_vcpu_run(vcpu);
        switch (to_vmx(vcpu)->exit_reason.basic) {
        	case EXIT_REASON_CPUID:
                ++sysctl_custom_cpuid_loop;
                break;
            default:
                ++sysctl_custom_other;
                return path;
        }
        // return path;
        /*
        bool was_cpuid = false;
        vmx->fail = __vmx_vcpu_run(vmx, (unsigned long *)&vmx->vcpu.arch.regs,
					flags);
        if (unlikely(vmx->fail)) {
            return;
        }
        // vmx_enable_fb_clear(vmx);

        exit_reason.full = vmcs_read32(VM_EXIT_REASON);

        switch (exit_reason.basic) {
        case EXIT_REASON_CPUID:
            kvm_emulate_cpuid(&vmx->vcpu);
            ++sysctl_custom_cpuid;
            was_cpuid=true;
            break;

        default:
            ++sysctl_custom_other;
            return;
        }
        if (was_cpuid)
            ++sysctl_custom_cpuid_loop;
        */
    }
}
EXPORT_SYMBOL(handle_orphan_vm_exits);

static int i = 0;
noinline __section(".no_kvm.text") static void test_func(void)
{
    i++;
}

static struct page *orphan_vm_code_page = NULL;
static struct ctl_table_header *sysctl_table = NULL;
static int __init orphan_vm_init(void) 
{
    void *control_page;
    test_func();
    pr_info("Loading no_kvm module, orphan func len: %lu\n", __no_kvm_text_end - __no_kvm_text_start);
    orphan_vm_code_page = alloc_page(0);
    if (orphan_vm_code_page == NULL) {
        return -1;
    }
    control_page = page_address(orphan_vm_code_page) + PAGE_SIZE;
	__memcpy(control_page, handle_orphan_vm_exits, KEXEC_CONTROL_CODE_MAX_SIZE);

    pr_info("prepping custom_exits_debug_table table");
    sysctl_table = register_sysctl("alex", custom_exits_debug_table);
    return sysctl_table == NULL;
}

static void __exit orphan_vm_exit(void) 
{
    pr_info("Unloading no_kvm module");

    if (orphan_vm_code_page)
        __free_page(orphan_vm_code_page);

    orphan_vm_code_page = NULL;
    unregister_sysctl_table(sysctl_table);
}

module_init(orphan_vm_init);
module_exit(orphan_vm_exit);

MODULE_LICENSE("GPL v2");
