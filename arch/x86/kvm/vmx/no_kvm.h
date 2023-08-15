#ifndef __KVM_X86_NO_KVM_H
#define __KVM_X86_NO_KVM_H

#include "vmx.h"

#if IS_ENABLED(CONFIG_ORPHAN_VM)
#define __no_kvm_section __section(".no_kvm.text")
extern char __no_kvm_start[];
extern char __no_kvm_end[];
__no_kvm_section __always_inline bool __no_kvm_vcpu_run(struct vcpu_vmx *vmx, unsigned long *regs,
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

void cust_printf(const char *to_print);

/*
 * readX/writeX() are used to access memory mapped devices. On some
 * architectures the memory mapped IO stuff needs to be accessed
 * differently. On the x86 architecture, we just read/write the
 * memory location directly.
 */

static inline __attribute__((__always_inline__))
 unsigned char no_kvm_readb(const volatile void  *addr)
{
	return *(volatile unsigned char *) addr;
}
static inline __attribute__((__always_inline__))
 unsigned short no_kvm_readw(const volatile void  *addr)
{
	return *(volatile unsigned short *) addr;
}
static inline __attribute__((__always_inline__))
 unsigned int no_kvm_readl(const volatile void  *addr)
{
	return *(volatile unsigned int *) addr;
}

static inline __attribute__((__always_inline__))
 void no_kvm_writeb(unsigned char b, volatile void  *addr)
{
	*(volatile unsigned char *) addr = b;
}
static inline __attribute__((__always_inline__))
 void no_kvm_writew(unsigned short b, volatile void  *addr)
{
	*(volatile unsigned short *) addr = b;
}
static inline __attribute__((__always_inline__))
 void no_kvm_writel(unsigned int b, volatile void  *addr)
{
	*(volatile unsigned int *) addr = b;
}

static inline __attribute__((__always_inline__))
uint8_t no_kvm_inb(uint16_t port)
{
	uint8_t result;

	__asm__ __volatile__ (
		"inb %w1,%0"
		:"=a" (result)
		:"Nd" (port));
	return result;
}

 static inline __attribute__((__always_inline__))
uint16_t no_kvm_inw(uint16_t port)
{
	uint16_t result;

	__asm__ __volatile__ (
		"inw %w1,%0"
		:"=a" (result)
		:"Nd" (port));
	return result;
}

 static inline __attribute__((__always_inline__))
uint32_t no_kvm_inl(uint32_t port)
{
	uint32_t result;

	__asm__ __volatile__ (
		"inl %w1,%0"
		:"=a" (result)
		:"Nd" (port));
	return result;
}

 static inline __attribute__((__always_inline__))
void no_kvm_outb (uint8_t value, uint16_t port)
{
	__asm__ __volatile__ (
		"outb %b0,%w1"
		:
		:"a" (value), "Nd" (port));
}

 static inline __attribute__((__always_inline__))
void no_kvm_outw (uint16_t value, uint16_t port)
{
	__asm__ __volatile__ (
		"outw %w0,%w1"
		:
		:"a" (value), "Nd" (port));
}

 static inline __attribute__((__always_inline__))
void no_kvm_outl (uint32_t value, uint16_t port)
{
	__asm__ __volatile__ (
		"outl %0,%w1"
		:
		:"a" (value), "Nd" (port));
}
#endif /* IS_ENABLED(CONFIG_ORPHAN_VM) */

#endif /* __KVM_X86_NO_KVM_H */
