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
#include <linux/moduleloader.h>
#include <linux/mod_devicetable.h>
#include <linux/mm.h>
#include <linux/objtool.h>
#include <linux/sched.h>
#include <linux/sched/smt.h>
#include <linux/slab.h>
#include <linux/tboot.h>
#include <linux/trace_events.h>
#include <linux/entry-kvm.h>
#include "no_kvm.h"

#include <linux/kexec.h>
#include <linux/string.h>
#include <linux/gfp.h>
#include <linux/reboot.h>
#include <linux/numa.h>
#include <linux/ftrace.h>
#include <linux/io.h>
#include <linux/suspend.h>
#include <linux/vmalloc.h>
#include <linux/efi.h>
#include <linux/cc_platform.h>

#include <asm/init.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/io_apic.h>
#include <asm/kexec-bzimage64.h>
#include <asm/setup.h>

#include <asm/apic.h>
#include <asm/set_memory.h>
#include <asm/pgtable.h>
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

// static DEFINE_STATIC_KEY_FALSE(vmx_l1d_should_flush);
// static DEFINE_PER_CPU(struct cached_cpuid, cached_cpuids);

#define VMX_SEGMENT_FIELD(seg)					\
	[VCPU_SREG_##seg] = {                                   \
		.selector = GUEST_##seg##_SELECTOR,		\
		.base = GUEST_##seg##_BASE,		   	\
		.limit = GUEST_##seg##_LIMIT,		   	\
		.ar_bytes = GUEST_##seg##_AR_BYTES,	   	\
	}
static const struct kvm_vmx_segment_field {
	unsigned selector;
	unsigned base;
	unsigned limit;
	unsigned ar_bytes;
} kvm_vmx_segment_fields[] = {
	VMX_SEGMENT_FIELD(CS),
	VMX_SEGMENT_FIELD(DS),
	VMX_SEGMENT_FIELD(ES),
	VMX_SEGMENT_FIELD(FS),
	VMX_SEGMENT_FIELD(GS),
	VMX_SEGMENT_FIELD(SS),
	VMX_SEGMENT_FIELD(TR),
	VMX_SEGMENT_FIELD(LDTR),
};
bool pt_mode_is_system = true;

__no_kvm_section void no_kvm_spec_ctrl_restore_host(struct vcpu_vmx *vmx,
					unsigned int flags)
{
	u64 hostval = this_cpu_read(x86_spec_ctrl_current);

	if (!cpu_feature_enabled(X86_FEATURE_MSR_SPEC_CTRL))
		return;

	if (flags & VMX_RUN_SAVE_SPEC_CTRL)
		vmx->spec_ctrl = __rdmsr(MSR_IA32_SPEC_CTRL);

	/*
	 * If the guest/host SPEC_CTRL values differ, restore the host value.
	 *
	 * For legacy IBRS, the IBRS bit always needs to be written after
	 * transitioning from a less privileged predictor mode, regardless of
	 * whether the guest/host values differ.
	 */
	if (cpu_feature_enabled(X86_FEATURE_KERNEL_IBRS) ||
	    vmx->spec_ctrl != hostval)
		native_wrmsrl(MSR_IA32_SPEC_CTRL, hostval);

	barrier_nospec();
}


__no_kvm_section void no_kvm_update_host_rsp(struct vcpu_vmx *vmx, unsigned long host_rsp)
{
	if (unlikely(host_rsp != vmx->loaded_vmcs->host_state.rsp)) {
		vmx->loaded_vmcs->host_state.rsp = host_rsp;
		__vmcs_writel(HOST_RSP, __vmcs_readl(HOST_RSP) & ~host_rsp);
		// vmcs_writel(HOST_RSP, host_rsp);
	}
}


/*
 * Check if MSR is intercepted for currently loaded MSR bitmap.
 */
__no_kvm_section __always_inline static bool no_kvm_msr_write_intercepted(struct vcpu_vmx *vmx, u32 msr)
{
	if (!(exec_controls_get(vmx) & CPU_BASED_USE_MSR_BITMAPS))
		return true;

	return vmx_test_msr_bitmap_write(vmx->loaded_vmcs->msr_bitmap, msr);
}

__no_kvm_section __always_inline static void no_kvm_pt_load_msr(struct pt_ctx *ctx, u32 addr_range)
{
	u32 i;

	wrmsrl(MSR_IA32_RTIT_STATUS, ctx->status);
	wrmsrl(MSR_IA32_RTIT_OUTPUT_BASE, ctx->output_base);
	wrmsrl(MSR_IA32_RTIT_OUTPUT_MASK, ctx->output_mask);
	wrmsrl(MSR_IA32_RTIT_CR3_MATCH, ctx->cr3_match);
	for (i = 0; i < addr_range; i++) {
		wrmsrl(MSR_IA32_RTIT_ADDR0_A + i * 2, ctx->addr_a[i]);
		wrmsrl(MSR_IA32_RTIT_ADDR0_B + i * 2, ctx->addr_b[i]);
	}
}

__no_kvm_section __always_inline static void no_kvm_pt_save_msr(struct pt_ctx *ctx, u32 addr_range)
{
	u32 i;

	rdmsrl(MSR_IA32_RTIT_STATUS, ctx->status);
	rdmsrl(MSR_IA32_RTIT_OUTPUT_BASE, ctx->output_base);
	rdmsrl(MSR_IA32_RTIT_OUTPUT_MASK, ctx->output_mask);
	rdmsrl(MSR_IA32_RTIT_CR3_MATCH, ctx->cr3_match);
	for (i = 0; i < addr_range; i++) {
		rdmsrl(MSR_IA32_RTIT_ADDR0_A + i * 2, ctx->addr_a[i]);
		rdmsrl(MSR_IA32_RTIT_ADDR0_B + i * 2, ctx->addr_b[i]);
	}
}

__no_kvm_section __always_inline void no_kvm_pt_guest_enter(struct vcpu_vmx *vmx)
{
	if (pt_mode_is_system)
		return;

	/*
	 * GUEST_IA32_RTIT_CTL is already set in the VMCS.
	 * Save host state before VM entry.
	 */
	rdmsrl(MSR_IA32_RTIT_CTL, vmx->pt_desc.host.ctl);
	if (vmx->pt_desc.guest.ctl & RTIT_CTL_TRACEEN) {
		wrmsrl(MSR_IA32_RTIT_CTL, 0);
		no_kvm_pt_save_msr(&vmx->pt_desc.host, vmx->pt_desc.num_address_ranges);
		no_kvm_pt_load_msr(&vmx->pt_desc.guest, vmx->pt_desc.num_address_ranges);
	}
}

__no_kvm_section __always_inline void no_kvm_pt_guest_exit(struct vcpu_vmx *vmx)
{
	if (pt_mode_is_system)
		return;

	if (vmx->pt_desc.guest.ctl & RTIT_CTL_TRACEEN) {
		no_kvm_pt_save_msr(&vmx->pt_desc.guest, vmx->pt_desc.num_address_ranges);
		no_kvm_pt_load_msr(&vmx->pt_desc.host, vmx->pt_desc.num_address_ranges);
	}

	/*
	 * KVM requires VM_EXIT_CLEAR_IA32_RTIT_CTL to expose PT to the guest,
	 * i.e. RTIT_CTL is always cleared on VM-Exit.  Restore it if necessary.
	 */
	if (vmx->pt_desc.host.ctl)
		wrmsrl(MSR_IA32_RTIT_CTL, vmx->pt_desc.host.ctl);
}

__no_kvm_section __always_inline unsigned int __no_kvm_vcpu_run_flags(struct vcpu_vmx *vmx)
{
	unsigned int flags = 0;

	if (vmx->loaded_vmcs->launched)
		flags |= VMX_RUN_VMRESUME;

	/*
	 * If writes to the SPEC_CTRL MSR aren't intercepted, the guest is free
	 * to change it directly without causing a vmexit.  In that case read
	 * it after vmexit and store it in vmx->spec_ctrl.
	 */
	if (!no_kvm_msr_write_intercepted(vmx, MSR_IA32_SPEC_CTRL))
		flags |= VMX_RUN_SAVE_SPEC_CTRL;

	return flags;
}


__no_kvm_section __always_inline void no_kvm_disable_fb_clear(struct vcpu_vmx *vmx)
{
	u64 msr;

	if (!vmx->disable_fb_clear)
		return;

	msr = __rdmsr(MSR_IA32_MCU_OPT_CTRL);
	msr |= FB_CLEAR_DIS;
	native_wrmsrl(MSR_IA32_MCU_OPT_CTRL, msr);
	/* Cache the MSR value to avoid reading it later */
	vmx->msr_ia32_mcu_opt_ctrl = msr;
}
__no_kvm_section __always_inline void no_kvm_enable_fb_clear(struct vcpu_vmx *vmx)
{
	if (!vmx->disable_fb_clear)
		return;

	vmx->msr_ia32_mcu_opt_ctrl &= ~FB_CLEAR_DIS;
	native_wrmsrl(MSR_IA32_MCU_OPT_CTRL, vmx->msr_ia32_mcu_opt_ctrl);
}


__no_kvm_section __always_inline static void no_kvm_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	u32 interruptibility_old = __vmcs_readl(GUEST_INTERRUPTIBILITY_INFO);
	u32 interruptibility = interruptibility_old;

	interruptibility &= ~(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS);

	if (mask & KVM_X86_SHADOW_INT_MOV_SS)
		interruptibility |= GUEST_INTR_STATE_MOV_SS;
	else if (mask & KVM_X86_SHADOW_INT_STI)
		interruptibility |= GUEST_INTR_STATE_STI;

	if ((interruptibility != interruptibility_old))
		__vmcs_writel(GUEST_INTERRUPTIBILITY_INFO, interruptibility);
}

__no_kvm_section __always_inline static bool no_kvm_is_long_mode(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_X86_64
	return !!(vcpu->arch.efer & EFER_LMA);
#else
	return false;
#endif
}

__no_kvm_section __always_inline static bool no_kvm_segment_cache_test_set(struct vcpu_vmx *vmx, unsigned seg,
				       unsigned field)
{
	bool ret;
	u32 mask = 1 << (seg * SEG_FIELD_NR + field);

	if (!kvm_register_is_available(&vmx->vcpu, VCPU_EXREG_SEGMENTS)) {
		kvm_register_mark_available(&vmx->vcpu, VCPU_EXREG_SEGMENTS);
		vmx->segment_cache.bitmask = 0;
	}
	ret = vmx->segment_cache.bitmask & mask;
	vmx->segment_cache.bitmask |= mask;
	return ret;
}


__no_kvm_section __always_inline static u32 no_kvm_read_guest_seg_ar(struct vcpu_vmx *vmx, unsigned seg)
{
	u32 *p = &vmx->segment_cache.seg[seg].ar;

	if (!no_kvm_segment_cache_test_set(vmx, seg, SEG_FIELD_AR))
		*p = __vmcs_readl(kvm_vmx_segment_fields[seg].ar_bytes);
	return *p;
}

__no_kvm_section __always_inline static void no_kvm_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	u32 ar = no_kvm_read_guest_seg_ar(to_vmx(vcpu), VCPU_SREG_CS);

	*db = (ar >> 14) & 1;
	*l = (ar >> 13) & 1;
}


__no_kvm_section __always_inline static bool no_kvm_is_64_bit_mode(struct kvm_vcpu *vcpu)
{
	int cs_db, cs_l;

	// WARN_ON_ONCE(vcpu->arch.guest_state_protected);

	if (!no_kvm_is_long_mode(vcpu))
		return false;
	no_kvm_get_cs_db_l_bits(vcpu, &cs_db, &cs_l);
	return cs_l;
}


__no_kvm_section __always_inline static bool no_kvm_skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	union vmx_exit_reason exit_reason = to_vmx(vcpu)->exit_reason;
	unsigned long rip, orig_rip;
	u32 instr_len;

	/*
	 * Using VMCS.VM_EXIT_INSTRUCTION_LEN on EPT misconfig depends on
	 * undefined behavior: Intel's SDM doesn't mandate the VMCS field be
	 * set when EPT misconfig occurs.  In practice, real hardware updates
	 * VM_EXIT_INSTRUCTION_LEN on EPT misconfig, but other hypervisors
	 * (namely Hyper-V) don't set it due to it being undefined behavior,
	 * i.e. we end up advancing IP with some random value.
	 */
	// pr_info("no_kvm_skip_emulated_instruction !static_cpu_has(X86_FEATURE_HYPERVISOR): %s", !static_cpu_has(X86_FEATURE_HYPERVISOR) ? "true" : "false");
	if (exit_reason.basic != EXIT_REASON_EPT_MISCONFIG) {
		instr_len = __vmcs_readl(VM_EXIT_INSTRUCTION_LEN);
		
		/*
		 * Emulating an enclave's instructions isn't supported as KVM
		 * cannot access the enclave's memory or its true RIP, e.g. the
		 * vmcs.GUEST_RIP points at the exit point of the enclave, not
		 * the RIP that actually triggered the VM-Exit.  But, because
		 * most instructions that cause VM-Exit will #UD in an enclave,
		 * most instruction-based VM-Exits simply do not occur.
		 *
		 * There are a few exceptions, notably the debug instructions
		 * INT1ICEBRK and INT3, as they are allowed in debug enclaves
		 * and generate #DB/#BP as expected, which KVM might intercept.
		 * But again, the CPU does the dirty work and saves an instr
		 * length of zero so VMMs don't shoot themselves in the foot.
		 * WARN if KVM tries to skip a non-zero length instruction on
		 * a VM-Exit from an enclave.
		 */
		if (!instr_len)
			goto rip_updated;

		// WARN_ONCE(exit_reason.enclave_mode,
		// 	  "skipping instruction after SGX enclave VM-Exit");

		orig_rip = kvm_rip_read(vcpu);
		rip = orig_rip + instr_len;
#ifdef CONFIG_X86_64
		/*
		 * We need to mask out the high 32 bits of RIP if not in 64-bit
		 * mode, but just finding out that we are in 64-bit mode is
		 * quite expensive.  Only do it if there was a carry.
		 */
		if (unlikely(((rip ^ orig_rip) >> 31) == 3) && !no_kvm_is_64_bit_mode(vcpu))
			rip = (u32)rip;
#endif
		kvm_rip_write(vcpu, rip);
        return true;
	} else {
		return false;
	}

rip_updated:
	/* skipping an emulated instruction also counts */
	no_kvm_set_interrupt_shadow(vcpu, 0);

	return true;
}

static __no_kvm_section __always_inline bool no_kvm_cpuid_fault_enabled(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.msr_misc_features_enables &
		  MSR_MISC_FEATURES_ENABLES_CPUID_FAULT;
}

int no_kvm_get_cpl(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (unlikely(vmx->rmode.vm86_active))
		return 0;
	else {
		int ar = no_kvm_read_guest_seg_ar(vmx, VCPU_SREG_SS);
		return VMX_AR_DPL(ar);
	}
}
bool no_kvm_require_cpl(struct kvm_vcpu *vcpu, int required_cpl)
{
	if (no_kvm_get_cpl(vcpu) <= required_cpl)
		return true;
	// TODO: this
	// kvm_queue_exception_e(vcpu, GP_VECTOR, 0);
	return false;
}

__no_kvm_section __always_inline static int no_kvm_emulate_cpuid(struct kvm_vcpu *vcpu)
{
    // int cpuid;
	u32 eax, ebx, ecx, edx;
	// kvm_emulate_cpuid(vcpu);
	// return true;

	if (no_kvm_cpuid_fault_enabled(vcpu) && !no_kvm_require_cpl(vcpu, 0)) {
		cust_printf("no_kvm: !! cpuid enabled\n");
		return true;
	}
	cust_printf("no_kvm: !! cpuid emulated\n");

	eax = kvm_rax_read(vcpu);
	ecx = kvm_rcx_read(vcpu);
	// kvm_cpuid(vcpu, &eax, &ebx, &ecx, &edx, false);
    asm volatile("cpuid"
        : "=a" (eax),
        "=b" (ebx),
        "=c" (ecx),
        "=d" (edx)
        : "0" (eax), "2" (ecx)
        : "memory");

	kvm_rax_write(vcpu, eax);
	kvm_rbx_write(vcpu, ebx);
	kvm_rcx_write(vcpu, ecx);
	kvm_rdx_write(vcpu, edx);
	return no_kvm_skip_emulated_instruction(vcpu);
}

__no_kvm_section __always_inline static void no_kvm_vcpu_enter_exit(struct kvm_vcpu *vcpu,
					unsigned int flags)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	#if IS_MODULE(CONFIG_ORPHAN_VM)
    guest_state_enter_irqoff();
	#endif

    /* L1D Flush includes CPU buffer clear to mitigate MDS */
    /*
    if (static_branch_unlikely(&vmx_l1d_should_flush))
        vmx_l1d_flush(vcpu);
    else if (static_branch_unlikely(&mds_user_clear))
        mds_clear_cpu_buffers();
    else if (static_branch_unlikely(&mmio_stale_data_clear) &&
        kvm_arch_has_assigned_device(vcpu->kvm))
        mds_clear_cpu_buffers();
    */
    no_kvm_disable_fb_clear(vmx);

    if (vcpu->arch.cr2 != native_read_cr2())
        native_write_cr2(vcpu->arch.cr2);

    vmx->fail = __no_kvm_vcpu_run(vmx, (unsigned long *)&vcpu->arch.regs,
                flags);

    vcpu->arch.cr2 = native_read_cr2();

    no_kvm_enable_fb_clear(vmx);

    if (unlikely(vmx->fail)) {
        vmx->exit_reason.full = 0xdead;
    } else {
        vmx->exit_reason.full = __vmcs_readl(VM_EXIT_REASON);
    }

    /*
    if ((u16)vmx->exit_reason.basic == EXIT_REASON_EXCEPTION_NMI &&
        is_nmi(vmx_get_intr_info(vcpu))) {
        kvm_before_interrupt(vcpu, KVM_HANDLING_NMI);
        vmx_do_nmi_irqoff();
        kvm_after_interrupt(vcpu);
    }
    */

    #if IS_MODULE(CONFIG_ORPHAN_VM)
    guest_state_exit_irqoff();
	#endif
}

__no_kvm_section __always_inline static bool no_kvm_handle_orphan_exit(struct kvm_vcpu *vcpu) {
    switch (to_vmx(vcpu)->exit_reason.basic) {
    case EXIT_REASON_CPUID:
        ++sysctl_custom_cpuid;
		cust_printf("no_kvm: !! handling cpuid\n");
		// return false;
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
		cust_printf("no_kvm: !! handling other\n");
		return false;
	}
}
__no_kvm_section __always_inline static void no_kvm_update_hv_timer(struct kvm_vcpu *vcpu, int cpu_preemption_timer_multi)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u64 tscl;
	u32 delta_tsc;

	if (vmx->req_immediate_exit) {
		__vmcs_writel(VMX_PREEMPTION_TIMER_VALUE, 0);
		vmx->loaded_vmcs->hv_timer_soft_disabled = false;
	} else if (vmx->hv_deadline_tsc != -1) {
		tscl = rdtsc();
		if (vmx->hv_deadline_tsc > tscl)
			/* set_hv_timer ensures the delta fits in 32-bits */
			delta_tsc = (u32)((vmx->hv_deadline_tsc - tscl) >>
				cpu_preemption_timer_multi);
		else
			delta_tsc = 0;

		__vmcs_writel(VMX_PREEMPTION_TIMER_VALUE, delta_tsc);
		vmx->loaded_vmcs->hv_timer_soft_disabled = false;
	} else if (!vmx->loaded_vmcs->hv_timer_soft_disabled) {
		__vmcs_writel(VMX_PREEMPTION_TIMER_VALUE, -1);
		vmx->loaded_vmcs->hv_timer_soft_disabled = true;
	}
}

__no_kvm_section __always_inline static void no_kvm_vcpu_run(struct kvm_vcpu *vcpu, int cpu_preemption_timer_multi)
{
	unsigned long cr3, cr4;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	if (vmx->ple_window_dirty) {
		vmx->ple_window_dirty = false;
		__vmcs_writel(PLE_WINDOW, vmx->ple_window);
	}

	/* 
	*   needed, causes failure on login
	*   "/lib64/libc.so.6: CPU ISA level is lower than required"
	*/
	if (kvm_register_is_dirty(vcpu, VCPU_REGS_RSP))
		__vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
	if (kvm_register_is_dirty(vcpu, VCPU_REGS_RIP))
		__vmcs_writel(GUEST_RIP, vcpu->arch.regs[VCPU_REGS_RIP]);
	vcpu->arch.regs_dirty = 0;

	/*
	* Refresh vmcs.HOST_CR3 if necessary.  This must be done immediately
	* prior to VM-Enter, as the kernel may load a new ASID (PCID) any time
	* it switches back to the current->mm, which can occur in KVM context
	* when switching to a temporary mm to patch kernel code, e.g. if KVM
	* toggles a static key while handling a VM-Exit.
	*/
	// /*
	cr3 = __read_cr3(); //__get_current_cr3_fast();
	if (unlikely(cr3 != vmx->loaded_vmcs->host_state.cr3)) {
		__vmcs_writel(HOST_CR3, cr3);
		vmx->loaded_vmcs->host_state.cr3 = cr3;
	}

	cr4 = cr4_read_shadow();
	if (unlikely(cr4 != vmx->loaded_vmcs->host_state.cr4)) {
		__vmcs_writel(HOST_CR4, cr4);
		vmx->loaded_vmcs->host_state.cr4 = cr4;
	}

	// */
	no_kvm_pt_guest_enter(vmx);

	no_kvm_update_hv_timer(vcpu, cpu_preemption_timer_multi);

	kvm_wait_lapic_expire(vcpu);
	
	/* The actual VMENTER/EXIT is in the .noinstr.text section. */
	no_kvm_vcpu_enter_exit(vcpu, __no_kvm_vcpu_run_flags(vmx));
	
	// needed - crashes on login
#ifndef CONFIG_X86_64
	loadsegment(ds, __USER_DS);
	loadsegment(es, __USER_DS);
#endif

	vcpu->arch.regs_avail &= ~VMX_REGS_LAZY_LOAD_SET;

	no_kvm_pt_guest_exit(vmx);
}

#define MAX_APIC_VECTOR			256
#define APIC_VECTORS_PER_REG		32

__no_kvm_section __always_inline static int no_kvm_find_highest_vector(void *bitmap)
{
	int vec;
	u32 *reg;

	for (vec = MAX_APIC_VECTOR - APIC_VECTORS_PER_REG;
	     vec >= 0; vec -= APIC_VECTORS_PER_REG) {
		reg = bitmap + REG_POS(vec);
		if (*reg)
			return __fls(*reg) + vec;
	}

	return -1;
}
__no_kvm_section __always_inline static int no_kvm_apic_search_irr(struct kvm_lapic *apic)
{
	return no_kvm_find_highest_vector(apic->regs + APIC_IRR);
}
__no_kvm_section __always_inline static int no_kvm_apic_find_highest_irr(struct kvm_lapic *apic)
{
	int result;

	/*
	 * Note that irr_pending is just a hint. It will be always
	 * true with virtual interrupt delivery enabled.
	 */
	if (!apic->irr_pending)
		return -1;

	result = no_kvm_apic_search_irr(apic);
	// ASSERT(result == -1 || result >= 16);

	return result;
}
__no_kvm_section __always_inline int no_kvm_lapic_find_highest_irr(struct kvm_vcpu *vcpu)
{
	/* This may race with setting of irr in __apic_accept_irq() and
	 * value returned may be wrong, but kvm_vcpu_kick() in __apic_accept_irq
	 * will cause vmexit immediately and the value will be recalculated
	 * on the next vmentry.
	 */
	return no_kvm_apic_find_highest_irr(vcpu->arch.apic);
}
__no_kvm_section __always_inline bool __no_kvm_apic_update_irr(u32 *pir, void *regs, int *max_irr)
{
	u32 i, vec;
	u32 pir_val, irr_val, prev_irr_val;
	int max_updated_irr;

	max_updated_irr = -1;
	*max_irr = -1;

	for (i = vec = 0; i <= 7; i++, vec += 32) {
		pir_val = READ_ONCE(pir[i]);
		irr_val = *((u32 *)(regs + APIC_IRR + i * 0x10));
		if (pir_val) {
			prev_irr_val = irr_val;
			irr_val |= xchg(&pir[i], 0);
			*((u32 *)(regs + APIC_IRR + i * 0x10)) = irr_val;
			if (prev_irr_val != irr_val) {
				max_updated_irr =
					__fls(irr_val ^ prev_irr_val) + vec;
			}
		}
		if (irr_val)
			*max_irr = __fls(irr_val) + vec;
	}

	return ((max_updated_irr != -1) &&
		(max_updated_irr == *max_irr));
}
__no_kvm_section __always_inline bool no_kvm_apic_update_irr(struct kvm_vcpu *vcpu, u32 *pir, int *max_irr)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	return __no_kvm_apic_update_irr(pir, apic->regs, max_irr);
}
__no_kvm_section __always_inline static void no_kvm_set_rvi(int vector)
{
	u16 status;
	u8 old;

	if (vector == -1)
		vector = 0;

	status = vmcs_read16(GUEST_INTR_STATUS);
	old = (u8)status & 0xff;
	if ((u8)vector != old) {
		status &= ~0xff;
		status |= (u8)vector;
		vmcs_write16(GUEST_INTR_STATUS, status);
	}
}
__no_kvm_section __always_inline static int no_kvm_sync_pir_to_irr(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int max_irr;
	bool got_posted_interrupt;

	if (pi_test_on(&vmx->pi_desc)) {
		pi_clear_on(&vmx->pi_desc);
		/*
		 * IOMMU can write to PID.ON, so the barrier matters even on UP.
		 * But on x86 this is just a compiler barrier anyway.
		 */
		smp_mb__after_atomic();
		cust_printf("vmx_sync_pir_to_irr -> kvm_apic_update_irr\n");
		got_posted_interrupt =
			no_kvm_apic_update_irr(vcpu, vmx->pi_desc.pir, &max_irr);
	} else {
		cust_printf("vmx_sync_pir_to_irr -> no_kvm_lapic_find_highest_irr\n");
		max_irr = no_kvm_lapic_find_highest_irr(vcpu);
		got_posted_interrupt = false;
	}

	/*
	 * Newly recognized interrupts are injected via either virtual interrupt
	 * delivery (RVI) or KVM_REQ_EVENT.  Virtual interrupt delivery is
	 * disabled in two cases:
	 *
	 * 1) If L2 is running and the vCPU has a new pending interrupt.  If L1
	 * wants to exit on interrupts, KVM_REQ_EVENT is needed to synthesize a
	 * VM-Exit to L1.  If L1 doesn't want to exit, the interrupt is injected
	 * into L2, but KVM doesn't use virtual interrupt delivery to inject
	 * interrupts into L2, and so KVM_REQ_EVENT is again needed.
	 *
	 * 2) If APICv is disabled for this vCPU, assigned devices may still
	 * attempt to post interrupts.  The posted interrupt vector will cause
	 * a VM-Exit and the subsequent entry will call sync_pir_to_irr.
	 */
	if (!is_guest_mode(vcpu) && kvm_vcpu_apicv_active(vcpu)) {
		cust_printf("calling vmx_set_rvi\n");
		no_kvm_set_rvi(max_irr);
	} else if (got_posted_interrupt) {
		cust_printf("calling kvm_make_request(KVM_REQ_EVENT\n");
		kvm_make_request(KVM_REQ_EVENT, vcpu);
	} else {
		cust_printf("vmx_sync_pir_to_irr no posting\n");
	}

	return max_irr;
}

__no_kvm_section __always_inline void no_kvm_vmexit(void);
__no_kvm_section bool handle_orphan_vm_exits(struct kvm_vcpu *vcpu, int cpu_preemption_timer_multi)
{
    struct vcpu_vmx *vmx;
    cust_printf("no_kvm: landing in orphan handler");
    if (vcpu == NULL)  {
        return false;
        cust_printf("no_kvm: vCPU null in orphan handler, returning");
    }
	// return false;
    
    vmx = to_vmx(vcpu);
    vcpu->arch.cr2 = native_read_cr2();
    vmx->loaded_vmcs->launched = 1;
    // return;
    no_kvm_enable_fb_clear(vmx);

    if (unlikely(vmx->fail)) {
        vmx->exit_reason.full = 0xdead;
    } else {
        vmx->exit_reason.full = __vmcs_readl(VM_EXIT_REASON);
    }

    // return;
	#if IS_MODULE(CONFIG_ORPHAN_VM)
    guest_state_exit_irqoff();
	#endif

    // needed - crashes on login
    #ifndef CONFIG_X86_64
        loadsegment(ds, __USER_DS);
        loadsegment(es, __USER_DS);
    #endif
	// return;
    vcpu->arch.regs_avail &= ~VMX_REGS_LAZY_LOAD_SET;

    no_kvm_pt_guest_exit(vmx);
	no_kvm_sync_pir_to_irr(vcpu);
	// return false;
    cust_printf("no_kvm: Inside custom orphan VM exit handler\n");
	vmcs_writel(HOST_RIP, (unsigned long)no_kvm_vmexit); /* 22.2.5 */
    for (;;) {
        if (!no_kvm_handle_orphan_exit(vcpu)) {
            cust_printf("returning from orphan handler\n");
            return false;
        }
		// return false;
		cust_printf("no_kvm: jumping to custom no_kvm_vcpu_run\n");
        no_kvm_vcpu_run(vcpu, cpu_preemption_timer_multi);
		return false;
		no_kvm_sync_pir_to_irr(vcpu);
	}
}
// EXPORT_SYMBOL(handle_orphan_vm_exits);
/*
noinline __no_kvm_section __always_inline void do_nothing(struct kvm_vcpu *vcpu, unsigned int flags)
{
    // pr_info("!!!inside do_nothing!!! %p, %d", vcpu, flags);
    int i=0;
    for (;;) {
        i += 1;
        i -= 1;
    }
}
*/
// static struct page *orphan_vm_code_page = NULL;
static struct ctl_table_header *sysctl_table = NULL;

#ifdef CONFIG_ORPHAN_VM
static void *orphan_vm_code_page = NULL;
static int init_orphan_page(void)
{
    __kernel_size_t text_len = 0;
    text_len = __no_kvm_end - __no_kvm_start;
    // orphan_vm_code_page = __vmalloc(text_len, GFP_KERNEL, PAGE_KERNEL_EXEC);
    // orphan_vm_code_page = __vmalloc_node(text_len, 1, GFP_KERNEL, PAGE_KERNEL_EXEC,
                //   NUMA_NO_NODE, __builtin_return_address(0));
    // orphan_vm_code_page = __vmalloc_node_range(text_len, 1, VMALLOC_START, VMALLOC_END,
	// 			GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE, __builtin_return_address(0));
    orphan_vm_code_page = __vmalloc_prot(text_len, GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL_EXEC);
    // orphan_vm_code_page = (void*) __get_free_page(GFP_KERNEL);
    // orphan_vm_code_page = module_alloc(PAGE_SIZE);
    pr_info("allocated orphan_vm_code_page %p %p\n", orphan_vm_code_page, (void*)__pa(orphan_vm_code_page));
    if (!orphan_vm_code_page) {
        cust_printf("orphan_vm_code_page allocation failed\n");
        return -1;
    }
    pr_info("Loading no_kvm module, orphan func len: %lu\n", text_len);
    __memcpy(orphan_vm_code_page, handle_orphan_vm_exits, text_len);

    pr_info("marking memory as ROX %p\n", orphan_vm_code_page);
	set_memory_rox((unsigned long)orphan_vm_code_page, text_len);

    // struct page *page = virt_to_page(orphan_vm_code_page);
    // pr_info("orphan_vm_code_page: virt_addr_valid = %s", virt_addr_valid(orphan_vm_code_page) ? "true" : "false");

    jump_orphan_vm = (bool (*)(struct kvm_vcpu *vcpu, int cpu_preemption_timer_multi)) orphan_vm_code_page;
    pr_info("init function jumping to code page %p\n", orphan_vm_code_page);
    jump_orphan_vm(NULL, 0);

	return 0;
}
#endif

static int __init orphan_vm_init(void) 
{
    pr_info("!!!!!!!!!! ORPHAN VM INIT !!!!!!!!!!!!!\n");
    sysctl_custom_cpuid = 0;
    sysctl_custom_msr_write = 0;
    sysctl_custom_msr_read = 0;
    sysctl_custom_apic_write = 0;
    sysctl_custom_other = 0;
    pt_mode_is_system = true;

    pr_info("prepping custom_exits_debug_table table\n");
    sysctl_table = register_sysctl("alex", custom_exits_debug_table);
    if (!sysctl_table)
        return -1;

    #ifdef CONFIG_ORPHAN_VM
		pr_info("Allocating and setting control page\n");
		return init_orphan_page();
    #else
	    jump_orphan_vm = handle_orphan_vm_exits;
    #endif
    return 0;
}

static void __exit orphan_vm_exit(void) 
{
    pr_info("Unloading no_kvm module");
    jump_orphan_vm = NULL;

	#ifdef CONFIG_ORPHAN_VM
    orphan_vm_code_page = NULL;
    if (orphan_vm_code_page)
        vfree(orphan_vm_code_page);
	#endif

    if (sysctl_table)
        unregister_sysctl_table(sysctl_table);
}

module_init(orphan_vm_init);
module_exit(orphan_vm_exit);

MODULE_LICENSE("GPL v2");
