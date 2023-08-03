#ifndef __KVM_X86_NO_KVM_H
#define __KVM_X86_NO_KVM_H

#if IS_ENABLED(CONFIG_ORPHAN_VM)
fastpath_t __weak handle_orphan_vm_exits(struct kvm_vcpu *vcpu);

extern char __no_kvm_text_start[];
extern char __no_kvm_text_end[];

#else
fastpath_t handle_orphan_vm_exits(struct kvm_vcpu *vcpu) 
{
    return EXIT_FASTPATH_NONE;
}

#endif /* IS_ENABLED(CONFIG_ORPHAN_VM) */

#endif /* __KVM_X86_NO_KVM_H */
