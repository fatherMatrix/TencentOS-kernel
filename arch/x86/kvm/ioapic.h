/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_IO_APIC_H
#define __KVM_IO_APIC_H

#include <linux/kvm_host.h>

#include <kvm/iodev.h>

struct kvm;
struct kvm_vcpu;

#define IOAPIC_NUM_PINS  KVM_IOAPIC_NUM_PINS
#define MAX_NR_RESERVED_IOAPIC_PINS KVM_MAX_IRQ_ROUTES
#define IOAPIC_VERSION_ID 0x11	/* IOAPIC version */
#define IOAPIC_EDGE_TRIG  0
#define IOAPIC_LEVEL_TRIG 1

#define IOAPIC_DEFAULT_BASE_ADDRESS  0xfec00000
#define IOAPIC_MEM_LENGTH            0x100

/* Direct registers. */
#define IOAPIC_REG_SELECT  0x00
#define IOAPIC_REG_WINDOW  0x10

/* Indirect registers. */
#define IOAPIC_REG_APIC_ID 0x00	/* x86 IOAPIC only */
#define IOAPIC_REG_VERSION 0x01
#define IOAPIC_REG_ARB_ID  0x02	/* x86 IOAPIC only */

/*ioapic delivery mode*/
#define	IOAPIC_FIXED			0x0
#define	IOAPIC_LOWEST_PRIORITY		0x1
#define	IOAPIC_PMI			0x2
#define	IOAPIC_NMI			0x4
#define	IOAPIC_INIT			0x5
#define	IOAPIC_EXTINT			0x7

#ifdef CONFIG_X86
#define RTC_GSI 8
#else
#define RTC_GSI -1U
#endif

struct dest_map {
	/* vcpu bitmap where IRQ has been sent */
	DECLARE_BITMAP(map, KVM_MAX_VCPU_ID);

	/*
	 * Vector sent to a given vcpu, only valid when
	 * the vcpu's bit in map is set
	 */
	u8 vectors[KVM_MAX_VCPU_ID];
};


struct rtc_status {
	int pending_eoi;
	struct dest_map dest_map;
};

union kvm_ioapic_redirect_entry {
	u64 bits;
	struct {
		/*
		 * 该中断对应的中断向量号
		 */
		u8 vector;
		/*
		 * 决定该中断怎么发送到cpu，取值为：
		 * - APIC_DM_LOWEST
		 * - APIC_DM_FIXED
		 * - APIC_DM_NMI
		 * - ...
		 *
		 * 这几个取值的含义可以看intel的文档，有详细说明
		 */
		u8 delivery_mode:3;
		u8 dest_mode:1;
		u8 delivery_status:1;
		u8 polarity:1;
		u8 remote_irr:1;
		u8 trig_mode:1;
		u8 mask:1;
		u8 reserve:7;
		u8 reserved[4];
		u8 dest_id;
	} fields;
};

struct kvm_ioapic {
	/*
	 * 表示IOAPIC设备的MMIO地址
	 */
	u64 base_address;
	u32 ioregsel;
	u32 id;
	u32 irr;
	u32 pad;
	/*
	 * IOAPIC的重定向表，包括：
	 * - 中断向量号
	 * - 触发模式
	 * - 发送到LAPIC的id
	 * - ...
	 *
	 * PIC的中断号与中断向量是固定映射，通过ICW1寄存器配置IRQ0的中断向量，
	 * 其余IRQ的中断向量在IRQ0的中断向量基础上线性增加。
	 * IOAPCI的每一个中断号（即每一个引脚）都可以通过中断重定向表单独配置其
	 * 对应的中断向量。
	 */
	union kvm_ioapic_redirect_entry redirtbl[IOAPIC_NUM_PINS];
	/*
	 * 表示中断线的状态
	 */
	unsigned long irq_states[IOAPIC_NUM_PINS];
	/*
	 * 表示IOAPIC对应的设备
	 */
	struct kvm_io_device dev;
	/*
	 * 表示对应的虚拟机
	 */
	struct kvm *kvm;
	void (*ack_notifier)(void *opaque, int irq);
	spinlock_t lock;
	struct rtc_status rtc_status;
	struct delayed_work eoi_inject;
	u32 irq_eoi[IOAPIC_NUM_PINS];
	u32 irr_delivered;
};

#ifdef DEBUG
#define ASSERT(x)  							\
do {									\
	if (!(x)) {							\
		printk(KERN_EMERG "assertion failed %s: %d: %s\n",	\
		       __FILE__, __LINE__, #x);				\
		BUG();							\
	}								\
} while (0)
#else
#define ASSERT(x) do { } while (0)
#endif

static inline int ioapic_in_kernel(struct kvm *kvm)
{
	int mode = kvm->arch.irqchip_mode;

	/* Matches smp_wmb() when setting irqchip_mode */
	smp_rmb();
	return mode == KVM_IRQCHIP_KERNEL;
}

void kvm_rtc_eoi_tracking_restore_one(struct kvm_vcpu *vcpu);
bool kvm_apic_match_dest(struct kvm_vcpu *vcpu, struct kvm_lapic *source,
		int short_hand, unsigned int dest, int dest_mode);
int kvm_apic_compare_prio(struct kvm_vcpu *vcpu1, struct kvm_vcpu *vcpu2);
void kvm_ioapic_update_eoi(struct kvm_vcpu *vcpu, int vector,
			int trigger_mode);
int kvm_ioapic_init(struct kvm *kvm);
void kvm_ioapic_destroy(struct kvm *kvm);
int kvm_ioapic_set_irq(struct kvm_ioapic *ioapic, int irq, int irq_source_id,
		       int level, bool line_status);
void kvm_ioapic_clear_all(struct kvm_ioapic *ioapic, int irq_source_id);
int kvm_irq_delivery_to_apic(struct kvm *kvm, struct kvm_lapic *src,
			     struct kvm_lapic_irq *irq,
			     struct dest_map *dest_map);
void kvm_get_ioapic(struct kvm *kvm, struct kvm_ioapic_state *state);
void kvm_set_ioapic(struct kvm *kvm, struct kvm_ioapic_state *state);
void kvm_ioapic_scan_entry(struct kvm_vcpu *vcpu,
			   ulong *ioapic_handled_vectors);
void kvm_scan_ioapic_routes(struct kvm_vcpu *vcpu,
			    ulong *ioapic_handled_vectors);
#endif
