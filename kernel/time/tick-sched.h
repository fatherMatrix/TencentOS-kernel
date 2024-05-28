/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TICK_SCHED_H
#define _TICK_SCHED_H

#include <linux/hrtimer.h>

enum tick_device_mode {
	TICKDEV_MODE_PERIODIC,
	TICKDEV_MODE_ONESHOT,
};

/*
 * 这是对时钟事件源设备的一层包装
 * - 在引入动态时钟特性时引入；
 *
 * - 是percpu的：tick_cpu_device
 *   > 每当系统中发现新的clock_event_device时，都会检查是否适合作为tick_device
 *     新的底层设备
 *     x 参见：tick_check_new_device()
 *
 * - 当使用高精度时钟时，tick_device（Tick层）的工作完全屏蔽，交由tick_sched（
 *   由hrtimer模拟的tick层操作来负责
 *   > Tick层的主要工作就是tick来临时处理调度、timer_list等
 */
struct tick_device {
	struct clock_event_device *evtdev;
	enum tick_device_mode mode;
};

enum tick_nohz_mode {
	NOHZ_MODE_INACTIVE,
	NOHZ_MODE_LOWRES,
	NOHZ_MODE_HIGHRES,
};

/**
 * struct tick_sched - sched tick emulation and no idle tick control/stats
 * @sched_timer:	hrtimer to schedule the periodic tick in high
 *			resolution mode
 * @check_clocks:	Notification mechanism about clocksource changes
 * @nohz_mode:		Mode - one state of tick_nohz_mode
 * @inidle:		Indicator that the CPU is in the tick idle mode
 * @tick_stopped:	Indicator that the idle tick has been stopped
 * @idle_active:	Indicator that the CPU is actively in the tick idle mode;
 *			it is resetted during irq handling phases.
 * @do_timer_lst:	CPU was the last one doing do_timer before going idle
 * @got_idle_tick:	Tick timer function has run with @inidle set
 * @last_tick:		Store the last tick expiry time when the tick
 *			timer is modified for nohz sleeps. This is necessary
 *			to resume the tick timer operation in the timeline
 *			when the CPU returns from nohz sleep.
 * @next_tick:		Next tick to be fired when in dynticks mode.
 * @idle_jiffies:	jiffies at the entry to idle for idle time accounting
 * @idle_calls:		Total number of idle calls
 * @idle_sleeps:	Number of idle calls, where the sched tick was stopped
 * @idle_entrytime:	Time when the idle call was entered
 * @idle_waketime:	Time when the idle was interrupted
 * @idle_exittime:	Time when the idle state was left
 * @idle_sleeptime:	Sum of the time slept in idle with sched tick stopped
 * @iowait_sleeptime:	Sum of the time slept in idle with sched tick stopped, with IO outstanding
 * @timer_expires:	Anticipated timer expiration time (in case sched tick is stopped)
 * @timer_expires_base:	Base time clock monotonic for @timer_expires
 * @next_timer:		Expiry time of next expiring timer for debugging purpose only
 * @tick_dep_mask:	Tick dependency mask - is set, if someone needs the tick
 * - 在启用了高精度定时器的情况下，Tick层（tick_handle_periodic）不再被调用，使
 *   用tick_sched来模拟
 *   > 该模拟还考虑了动态时钟的情况，即停掉定时器以省电
 *   > 该结构体是percpu的：tick_cpu_sched
 *   > 操作：
 *     x 初始化：tick_setup_sched_timer()
 *                 sched_timer.function = tick_sched_timer
 */
struct tick_sched {
	/*
	 * 在高精度定时器启用情况下，用来模拟tick的hrtimer
	 * - function是tick_sched_timer()
	 *   > 参见：tick_setup_sched_timer()
	 */
	struct hrtimer			sched_timer;
	unsigned long			check_clocks;
	enum tick_nohz_mode		nohz_mode;

	unsigned int			inidle		: 1;
	unsigned int			tick_stopped	: 1;
	unsigned int			idle_active	: 1;
	unsigned int			do_timer_last	: 1;
	unsigned int			got_idle_tick	: 1;

	ktime_t				last_tick;
	ktime_t				next_tick;
	unsigned long			idle_jiffies;
	unsigned long			idle_calls;
	unsigned long			idle_sleeps;
	ktime_t				idle_entrytime;
	ktime_t				idle_waketime;
	ktime_t				idle_exittime;
	ktime_t				idle_sleeptime;
	ktime_t				iowait_sleeptime;
	unsigned long			last_jiffies;
	u64				timer_expires;
	u64				timer_expires_base;
	u64				next_timer;
	ktime_t				idle_expires;
	atomic_t			tick_dep_mask;
};

extern struct tick_sched *tick_get_tick_sched(int cpu);

extern void tick_setup_sched_timer(void);
#if defined CONFIG_NO_HZ_COMMON || defined CONFIG_HIGH_RES_TIMERS
extern void tick_cancel_sched_timer(int cpu);
#else
static inline void tick_cancel_sched_timer(int cpu) { }
#endif

#ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
extern int __tick_broadcast_oneshot_control(enum tick_broadcast_state state);
#else
static inline int
__tick_broadcast_oneshot_control(enum tick_broadcast_state state)
{
	return -EBUSY;
}
#endif

#endif
