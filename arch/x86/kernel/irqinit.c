// SPDX-License-Identifier: GPL-2.0
#include <linux/linkage.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/timex.h>
#include <linux/random.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/device.h>
#include <linux/bitops.h>
#include <linux/acpi.h>
#include <linux/io.h>
#include <linux/delay.h>

#include <linux/atomic.h>
#include <asm/timer.h>
#include <asm/hw_irq.h>
#include <asm/pgtable.h>
#include <asm/desc.h>
#include <asm/apic.h>
#include <asm/setup.h>
#include <asm/i8259.h>
#include <asm/traps.h>
#include <asm/prom.h>

/*
 * ISA PIC or low IO-APIC triggered (INTA-cycle or APIC) interrupts:
 * (these are usually mapped to vectors 0x30-0x3f)
 */

/*
 * The IO-APIC gives us many more interrupt sources. Most of these
 * are unused but an SMP system is supposed to have enough memory ...
 * sometimes (mostly wrt. hw bugs) we get corrupted vectors all
 * across the spectrum, so we really want to be prepared to get all
 * of these. Plus, more powerful systems might have more than 64
 * IO-APIC registers.
 *
 * (these are usually mapped into the 0x30-0xff vector range)
 */

/*
 * IRQ2 is cascade interrupt to second interrupt controller
 */
static struct irqaction irq2 = {
	.handler = no_action,
	.name = "cascade",
	.flags = IRQF_NO_THREAD,
};

/*
 * 每个中断号各自对应的irq_desc结构体的指针
 */
DEFINE_PER_CPU(vector_irq_t, vector_irq) = {
	[0 ... NR_VECTORS - 1] = VECTOR_UNUSED,
};

void __init init_ISA_irqs(void)
{
	struct irq_chip *chip = legacy_pic->chip;
	int i;

	/*
	 * Try to set up the through-local-APIC virtual wire mode earlier.
	 *
	 * On some 32-bit UP machines, whose APIC has been disabled by BIOS
	 * and then got re-enabled by "lapic", it hangs at boot time without this.
	 *
	 * 这里是先设置virtual-wire mode
	 */
	init_bsp_APIC();

	legacy_pic->init(0);

	/*
	 * 对isa中断源设置电流层处理函数
	 */
	for (i = 0; i < nr_legacy_irqs(); i++)
		irq_set_chip_and_handler(i, chip, handle_level_irq);
}

void __init init_IRQ(void)
{
	int i;

	/*
	 * On cpu 0, Assign ISA_IRQ_VECTOR(irq) to IRQ 0..15.
	 * If these IRQ's are handled by legacy interrupt-controllers like PIC,
	 * then this configuration will likely be static after the boot. If
	 * these IRQ's are handled by more mordern controllers like IO-APIC,
	 * then this vector space can be freed and re-used dynamically as the
	 * irq's migrate etc.
	 *
	 * 0x30~0x3f中断向量对应于0~15中断号
	 *
	 * irq_to_desc是从基数树中获取irq_desc结构体的指针；vector_irq中也是包含
	 * 了irq(index)到irq_desc指针(item)的映射；
	 *
	 * vector_irq数组和irq_to_desc树的区别：
	 * - vector_irq是vector到irq_desc的转换；irq_to_desc树是irq到irq_desc树
	 *   的转换
	 * - vector_irq数组中有exception的位置；exception部分在哪里初始化？
	 * - vector_irq本身是per-cpu的，那么其他cpu的vector_irq在哪里初始化呢？
	 */
	for (i = 0; i < nr_legacy_irqs(); i++)
		per_cpu(vector_irq, 0)[ISA_IRQ_VECTOR(i)] = irq_to_desc(i);

	BUG_ON(irq_init_percpu_irqstack(smp_processor_id()));

	/*
	 * 这里对应native_init_IRQ
	 */
	x86_init.irqs.intr_init();
}

void __init native_init_IRQ(void)
{
	/* Execute any quirks before the call gates are initialised: */
	/*
	 * 对应init_ISA_irqs;
	 * 这里面会设置APIC为virtual-wire mode
	 */
	x86_init.irqs.pre_vector_init();

	/*
	 * 设置idt表中对应的项：
	 * - LAPIC中的
	 *   x 时钟中断
	 *   x ...
	 * - IOAPIC中的
	 *   x ...
	 */
	idt_setup_apic_and_irq_gates();
	lapic_assign_system_vectors();

	/*
	 * 这里难道是对2号irq做特殊处理？
	 * - 2号有可能是用来级联slave 8259a；
	 */
	if (!acpi_ioapic && !of_ioapic && nr_legacy_irqs())
		setup_irq(2, &irq2);
}
