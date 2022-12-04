// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (c) 1991,1992,1995  Linus Torvalds
 *  Copyright (c) 1994  Alan Modra
 *  Copyright (c) 1995  Markus Kuhn
 *  Copyright (c) 1996  Ingo Molnar
 *  Copyright (c) 1998  Andrea Arcangeli
 *  Copyright (c) 2002,2006  Vojtech Pavlik
 *  Copyright (c) 2003  Andi Kleen
 *
 */

#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/i8253.h>
#include <linux/time.h>
#include <linux/export.h>

#include <asm/vsyscall.h>
#include <asm/x86_init.h>
#include <asm/i8259.h>
#include <asm/timer.h>
#include <asm/hpet.h>
#include <asm/time.h>

unsigned long profile_pc(struct pt_regs *regs)
{
	unsigned long pc = instruction_pointer(regs);

	if (!user_mode(regs) && in_lock_functions(pc)) {
#ifdef CONFIG_FRAME_POINTER
		return *(unsigned long *)(regs->bp + sizeof(long));
#else
		unsigned long *sp = (unsigned long *)regs->sp;
		/*
		 * Return address is either directly at stack pointer
		 * or above a saved flags. Eflags has bits 22-31 zero,
		 * kernel addresses don't.
		 */
		if (sp[0] >> 22)
			return sp[0];
		if (sp[1] >> 22)
			return sp[1];
#endif
	}
	return pc;
}
EXPORT_SYMBOL(profile_pc);

/*
 * Default timer interrupt handler for PIT/HPET
 */
static irqreturn_t timer_interrupt(int irq, void *dev_id)
{
	global_clock_event->event_handler(global_clock_event);
	return IRQ_HANDLED;
}

static struct irqaction irq0  = {
	.handler = timer_interrupt,
	.flags = IRQF_NOBALANCING | IRQF_IRQPOLL | IRQF_TIMER,
	.name = "timer"
};

static void __init setup_default_timer_irq(void)
{
	/*
	 * Unconditionally register the legacy timer; even without legacy
	 * PIC/PIT we need this for the HPET0 in legacy replacement mode.
	 */
	if (setup_irq(0, &irq0))
		pr_info("Failed to register legacy timer interrupt\n");
}

/* Default timer init function */
void __init hpet_time_init(void)
{
	if (!hpet_enable()) {
		if (!pit_timer_init())
			return;
	}

	/*
	 * 完成将PIT设置为BSP的本地tick设备后，内核在setup_default_timer_irq中
	 * 完成中断处理函数的设定并使能中断信号。之后BSP在初始化过程中有会周期
	 * 性地收到PIT产生的0号时钟中断，并进行中断处理
	 */
	setup_default_timer_irq();
}

static __init void x86_late_time_init(void)
{
	/*
	 * Before PIT/HPET init, select the interrupt mode. This is required
	 * to make the decision whether PIT should be initialized correct.
	 */
	x86_init.irqs.intr_mode_select();

	/* Setup the legacy timers
	 *
	 * 对应hpet_time_init
	 */
	x86_init.timers.timer_init();

	/*
	 * After PIT/HPET timers init, set up the final interrupt mode for
	 * delivering IRQs.
	 */
	x86_init.irqs.intr_mode_init();
	tsc_init();
}

/*
 * Initialize TSC and delay the periodic timer init to
 * late x86_late_time_init() so ioremap works.
 */
void __init time_init(void)
{
	late_time_init = x86_late_time_init;
}

/*
 * Sanity check the vdso related archdata content.
 */
void clocksource_arch_init(struct clocksource *cs)
{
	if (cs->archdata.vclock_mode == VCLOCK_NONE)
		return;

	if (cs->archdata.vclock_mode > VCLOCK_MAX) {
		pr_warn("clocksource %s registered with invalid vclock_mode %d. Disabling vclock.\n",
			cs->name, cs->archdata.vclock_mode);
		cs->archdata.vclock_mode = VCLOCK_NONE;
	}

	if (cs->mask != CLOCKSOURCE_MASK(64)) {
		pr_warn("clocksource %s registered with invalid mask %016llx. Disabling vclock.\n",
			cs->name, cs->mask);
		cs->archdata.vclock_mode = VCLOCK_NONE;
	}
}
