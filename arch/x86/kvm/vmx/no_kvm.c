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

// static bool no_kvm_cpuid(struct kvm_vcpu *vcpu, u32 *eax, u32 *ebx,
// 	       u32 *ecx, u32 *edx, bool exact_only)
// {
//     // u32 orig_function = *eax, 
// 	u32 function = *eax, index = *ecx;
// 	struct kvm_cpuid_entry2 *entry;
// 	bool exact, used_max_basic = false;

// 	entry = kvm_find_cpuid_entry_index(vcpu, function, index);
// 	exact = !!entry;

// 	if (!entry && !exact_only) {
// 		entry = get_out_of_range_cpuid_entry(vcpu, &function, index);
// 		used_max_basic = !!entry;
// 	}

// 	if (entry) {
// 		*eax = entry->eax;
// 		*ebx = entry->ebx;
// 		*ecx = entry->ecx;
// 		*edx = entry->edx;
// 		if (function == 7 && index == 0) {
// 			u64 data;
// 		        if (!__kvm_get_msr(vcpu, MSR_IA32_TSX_CTRL, &data, true) &&
// 			    (data & TSX_CTRL_CPUID_CLEAR))
// 				*ebx &= ~(F(RTM) | F(HLE));
// 		} else if (function == 0x80000007) {
// 			if (kvm_hv_invtsc_suppressed(vcpu))
// 				*edx &= ~SF(CONSTANT_TSC);
// 		}
// 	} else {
// 		*eax = *ebx = *ecx = *edx = 0;
// 		/*
// 		 * When leaf 0BH or 1FH is defined, CL is pass-through
// 		 * and EDX is always the x2APIC ID, even for undefined
// 		 * subleaves. Index 1 will exist iff the leaf is
// 		 * implemented, so we pass through CL iff leaf 1
// 		 * exists. EDX can be copied from any existing index.
// 		 */
// 		if (function == 0xb || function == 0x1f) {
// 			entry = kvm_find_cpuid_entry_index(vcpu, function, 1);
// 			if (entry) {
// 				*ecx = index & 0xff;
// 				*edx = entry->edx;
// 			}
// 		}
// 	}
//     // trace_kvm_cpuid(orig_function, index, *eax, *ebx, *ecx, *edx, exact,
// 	// 		used_max_basic);
// 	return exact;
// }

/*
static int no_kvm_emulate_cpuid(struct kvm_vcpu *vcpu)
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
}*/

#ifdef CONFIG_SYSCTL
int sysctl_custom_cpuid = 0;
int sysctl_custom_cpuid_loop = 0;
int sysctl_custom_other = 0;

static struct ctl_table custom_exits_debug_table[] = {
	{
		.procname	= "cpuid_handled",
		.data		= &sysctl_custom_cpuid,
		.maxlen		= sizeof(sysctl_custom_cpuid),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "cpuid_loop",
		.data		= &sysctl_custom_cpuid_loop,
		.maxlen		= sizeof(sysctl_custom_cpuid_loop),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
    {
		.procname	= "custom_other",
		.data		= &sysctl_custom_other,
		.maxlen		= sizeof(sysctl_custom_other),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static int __init custom_exits_sysctl_init(void)
{
	pr_info("prepping custom_exits_debug_table table");
	register_sysctl_init("alex", custom_exits_debug_table);
	return 0;
}
late_initcall(custom_exits_sysctl_init);
#endif /* CONFIG_SYSCTL */

void handle_orphan_vm_exits(struct vcpu_vmx *vmx, unsigned int flags)
{
    union vmx_exit_reason exit_reason;
    pr_err_once("Moving to custom orphan VM exit handler\n");
    for (;;) {
        bool was_cpuid = false;
        vmx->fail = __vmx_vcpu_run(vmx, (unsigned long *)&vmx->vcpu.arch.regs,
					flags);
        if (unlikely(vmx->fail)) {
            return;
        }
        vmx_enable_fb_clear(vmx);

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
    }
}

static struct page *orphan_vm_code_page;
static __init int orphan_vm_init(void) 
{
    void *control_page;
    orphan_vm_code_page = alloc_page(0);
    if (orphan_vm_code_page == NULL) {
        return -1;
    }
    control_page = page_address(orphan_vm_code_page) + PAGE_SIZE;
	__memcpy(control_page, handle_orphan_vm_exits, KEXEC_CONTROL_CODE_MAX_SIZE);
    return 0;
}
module_init(orphan_vm_init);