// SPDX-License-Identifier: GPL-2.0

#include <linux/entry-kvm.h>
#include <linux/kvm_host.h>

static int xfer_to_guest_mode_work(struct kvm_vcpu *vcpu, unsigned long ti_work)
{
	do {
		int ret;

		if (ti_work & (_TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL)) {
		#ifdef CUST_DBG_LOGS
			trace_printk("guest xfer work SIG\n");
		#endif
			kvm_handle_signal_exit(vcpu);
			return -EINTR;
		}

		if (ti_work & _TIF_NEED_RESCHED) {
		#ifdef CUST_DBG_LOGS
			trace_printk("guest xfer work SCHED\n");
		#endif
			schedule();
		}

		if (ti_work & _TIF_NOTIFY_RESUME) {
		#ifdef CUST_DBG_LOGS
			trace_printk("guest xfer work RESUME\n");
		#endif
			resume_user_mode_work(NULL);
		}

		// trace_printk("guest xfer work ARCH\n");
		ret = arch_xfer_to_guest_mode_handle_work(vcpu, ti_work);
		if (ret) {
		#ifdef CUST_DBG_LOGS
			trace_printk("guest xfer work ret: %d\n", ret);
		#endif
			return ret;
		}

		ti_work = read_thread_flags();
		#ifdef CUST_DBG_LOGS
		trace_printk("loop guest xfer work 0x%lX\n", ti_work);
		#endif
	} while (ti_work & XFER_TO_GUEST_MODE_WORK || need_resched());
		#ifdef CUST_DBG_LOGS
	trace_printk("guest xfer work ret 0\n");
	#endif

	return 0;
}

int xfer_to_guest_mode_handle_work(struct kvm_vcpu *vcpu)
{
	unsigned long ti_work;

	/*
	 * This is invoked from the outer guest loop with interrupts and
	 * preemption enabled.
	 *
	 * KVM invokes xfer_to_guest_mode_work_pending() with interrupts
	 * disabled in the inner loop before going into guest mode. No need
	 * to disable interrupts here.
	 */
	ti_work = read_thread_flags();
	#ifdef CUST_DBG_LOGS
	trace_printk("guest xfer work 0x%lX\n", ti_work);
	#endif
	if (!(ti_work & XFER_TO_GUEST_MODE_WORK))
		return 0;

	return xfer_to_guest_mode_work(vcpu, ti_work);
}
EXPORT_SYMBOL_GPL(xfer_to_guest_mode_handle_work);
