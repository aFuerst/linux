#ifndef __KVM_X86_NO_KVM_H
#define __KVM_X86_NO_KVM_H

#include "vmx.h"

#if IS_ENABLED(CONFIG_ORPHAN_VM)
#define __no_kvm_section __section(".no_kvm.text")
extern char __no_kvm_start[];
extern char __no_kvm_end[];
bool __no_kvm_vcpu_run(struct vcpu_vmx *vmx, unsigned long *regs,
		    unsigned int flags);
void no_kvm_update_host_rsp(struct vcpu_vmx *vmx, unsigned long host_rsp);
void no_kvm_spec_ctrl_restore_host(struct vcpu_vmx *vmx,
					unsigned int flags);
// struct cached_cpuid {
//     u32 eax;
//     u32 ebx;
//     u32 ecx;
//     u32 edx;
// }

#endif /* IS_ENABLED(CONFIG_ORPHAN_VM) */

#endif /* __KVM_X86_NO_KVM_H */
