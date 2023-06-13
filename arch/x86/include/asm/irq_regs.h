/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Per-cpu current frame pointer - the location of the last exception frame on
 * the stack, stored in the per-cpu area.
 *
 * Jeremy Fitzhardinge <jeremy@goop.org>
 */
#ifndef _ASM_X86_IRQ_REGS_H
#define _ASM_X86_IRQ_REGS_H

#include <asm/percpu.h>

#define ARCH_HAS_OWN_IRQ_REGS

DECLARE_PER_CPU(struct pt_regs *, irq_regs);

/*
 * 这里是去读一个per-cpu的变量irq_regs，这个变量的赋值是在每个中断/异常开始的时
 * 候；值的来源是中断/异常后会将pt_regs的地址放入rdi寄存器中，这给了我们处理中断
 * 现场寄存器的机会；当然，这个机会也必须给我们才对；
 */
static inline struct pt_regs *get_irq_regs(void)
{
	return __this_cpu_read(irq_regs);
}

static inline struct pt_regs *set_irq_regs(struct pt_regs *new_regs)
{
	struct pt_regs *old_regs;

	old_regs = get_irq_regs();
	__this_cpu_write(irq_regs, new_regs);

	return old_regs;
}

#endif /* _ASM_X86_IRQ_REGS_32_H */
