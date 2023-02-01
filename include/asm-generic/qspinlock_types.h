/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Queued spinlock
 *
 * (C) Copyright 2013-2015 Hewlett-Packard Development Company, L.P.
 *
 * Authors: Waiman Long <waiman.long@hp.com>
 */
#ifndef __ASM_GENERIC_QSPINLOCK_TYPES_H
#define __ASM_GENERIC_QSPINLOCK_TYPES_H

/*
 * Including atomic.h with PARAVIRT on will cause compilation errors because
 * of recursive header file incluson via paravirt_types.h. So don't include
 * it if PARAVIRT is on.
 */
#ifndef CONFIG_PARAVIRT
#include <linux/types.h>
#include <linux/atomic.h>
#endif

/*
 * 内存大小只需要32bit，4个字节
 *
 *  0      7     8     9    15 16  17 18            31
 * +--------+---------+-------+------+----------------+
 * | locked | pending |   x   | tail |    tail cpu    |
 * +--------+---------+-------+------+----------------+
 *     8b        1b              2b    
 *
 * locked:	表示qspinlock是否加锁。0表示未加锁，其余值表示已加锁。
 *        	- _Q_LOCKED_VAL == 1
 *         	- _Q_SLOW_VAL == 3 （用于pv场景）
 *
 * pending: 	第一个等待锁的cpu需要先设置pending位，后续等待锁的cpu则全部进入
 * 		mcs队列自旋等待。
 * 		最初Waiman Long的patch并未包含该位，引入该位后，第一个等待者可
 * 		以避免与访问自己的mcs数组相关的缓存未命中惩罚
 *
 * tail:	2个bit位，每个cpu在同一时刻可能存在4中不同的上下文：Normal、
 * 		SoftIRQ、IRQ、NMI。因此每个cpu的per-cpu mcs spinlock需要包含一
 * 		组共4个mcs，每个mcs对应一个上下文场景。
 * 		参考pre-cpu全局数组qnodes。
 *
 * tail cpu: 	队尾的cpu编号+1，将编号加一是为了和没有cpu排队的情况区分开。
 *
 * 排队的几个位置：
 * - 第一个锁等待者在将pending位置1后，就在qspinlock结构的locked上自旋，直到锁
 *   持有者将锁释放（将pending位置0）
 * - 第二个锁等待者需要将自己放入mcs队列尾部，因为其是mcs队列的头，所以其在
 *   qspinlock结构的pending | locked上自旋，直到qspinlock的pending和locked均变
 *   为0
 * - 第三个及以后的锁等待者将自己放入mcs队列尾部，并在自己的per-cpu mcs上自旋，
 *   直到到达队列头部，然后退化为第二种情况。
 *
 *
 * (tail, pending, locked)初始时为(0, 0, 0)
 */
typedef struct qspinlock {
	union {
		atomic_t val;

		/*
		 * By using the whole 2nd least significant byte for the
		 * pending bit, we can allow better optimization of the lock
		 * acquisition for the pending bit holder.
		 */
#ifdef __LITTLE_ENDIAN
		struct {
			u8	locked;
			u8	pending;
		};
		struct {
			u16	locked_pending;
			u16	tail;
		};
#else
		struct {
			u16	tail;
			u16	locked_pending;
		};
		struct {
			u8	reserved[2];
			u8	pending;
			u8	locked;
		};
#endif
	};
} arch_spinlock_t;

/*
 * Initializier
 */
#define	__ARCH_SPIN_LOCK_UNLOCKED	{ { .val = ATOMIC_INIT(0) } }

/*
 * Bitfields in the atomic value:
 *
 * When NR_CPUS < 16K
 *  0- 7: locked byte
 *     8: pending
 *  9-15: not used
 * 16-17: tail index
 * 18-31: tail cpu (+1)
 *
 * When NR_CPUS >= 16K
 *  0- 7: locked byte
 *     8: pending
 *  9-10: tail index
 * 11-31: tail cpu (+1)
 */
#define	_Q_SET_MASK(type)	(((1U << _Q_ ## type ## _BITS) - 1)\
				      << _Q_ ## type ## _OFFSET)
#define _Q_LOCKED_OFFSET	0
#define _Q_LOCKED_BITS		8
#define _Q_LOCKED_MASK		_Q_SET_MASK(LOCKED)

#define _Q_PENDING_OFFSET	(_Q_LOCKED_OFFSET + _Q_LOCKED_BITS)
#if CONFIG_NR_CPUS < (1U << 14)
#define _Q_PENDING_BITS		8
#else
#define _Q_PENDING_BITS		1
#endif
#define _Q_PENDING_MASK		_Q_SET_MASK(PENDING)

#define _Q_TAIL_IDX_OFFSET	(_Q_PENDING_OFFSET + _Q_PENDING_BITS)
#define _Q_TAIL_IDX_BITS	2
#define _Q_TAIL_IDX_MASK	_Q_SET_MASK(TAIL_IDX)

#define _Q_TAIL_CPU_OFFSET	(_Q_TAIL_IDX_OFFSET + _Q_TAIL_IDX_BITS)
#define _Q_TAIL_CPU_BITS	(32 - _Q_TAIL_CPU_OFFSET)
#define _Q_TAIL_CPU_MASK	_Q_SET_MASK(TAIL_CPU)

#define _Q_TAIL_OFFSET		_Q_TAIL_IDX_OFFSET
#define _Q_TAIL_MASK		(_Q_TAIL_IDX_MASK | _Q_TAIL_CPU_MASK)

#define _Q_LOCKED_VAL		(1U << _Q_LOCKED_OFFSET)
#define _Q_PENDING_VAL		(1U << _Q_PENDING_OFFSET)

#endif /* __ASM_GENERIC_QSPINLOCK_TYPES_H */
