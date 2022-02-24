/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * RCU segmented callback lists
 *
 * This seemingly RCU-private file must be available to SRCU users
 * because the size of the TREE SRCU srcu_struct structure depends
 * on these definitions.
 *
 * Copyright IBM Corporation, 2017
 *
 * Authors: Paul E. McKenney <paulmck@linux.net.ibm.com>
 */

#ifndef __INCLUDE_LINUX_RCU_SEGCBLIST_H
#define __INCLUDE_LINUX_RCU_SEGCBLIST_H

#include <linux/types.h>
#include <linux/atomic.h>

/* Simple unsegmented callback lists. */
struct rcu_cblist {
	struct rcu_head *head;
	struct rcu_head **tail;
	long len;
	long len_lazy;
};

#define RCU_CBLIST_INITIALIZER(n) { .head = NULL, .tail = &n.head }

/* Complicated segmented callback lists.  ;-) */

/*
 * Index values for segments in rcu_segcblist structure.
 *
 * The segments are as follows:
 *
 * [head, *tails[RCU_DONE_TAIL]):
 *	Callbacks whose grace period has elapsed, and thus can be invoked.
 *	宽限期已过的回调。这些回调已准备好调用。
 *
 * [*tails[RCU_DONE_TAIL], *tails[RCU_WAIT_TAIL]):
 *	Callbacks waiting for the current GP from the current CPU's viewpoint.
 *	等待当前宽限期的回调。请注意，不同的CPU可以对哪个宽限期是当前有不同的
 *	想法，因此是gp_seq字段。
 *
 * [*tails[RCU_WAIT_TAIL], *tails[RCU_NEXT_READY_TAIL]):
 *	Callbacks that arrived before the next GP started, again from
 *	the current CPU's viewpoint.  These can be handled by the next GP.
 *	等待下一个宽限期开始的回调。
 *
 * [*tails[RCU_NEXT_READY_TAIL], *tails[RCU_NEXT_TAIL]):
 *	Callbacks that might have arrived after the next GP started.
 *	There is some uncertainty as to when a given GP starts and
 *	ends, but a CPU knows the exact times if it is the one starting
 *	or ending the GP.  Other CPUs know that the previous GP ends
 *	before the next one starts.
 *	尚未与宽限期关联的回调。
 *
 * Note that RCU_WAIT_TAIL cannot be empty unless RCU_NEXT_READY_TAIL is also
 * empty.
 *
 * The ->gp_seq[] array contains the grace-period number at which the
 * corresponding segment of callbacks will be ready to invoke.  A given
 * element of this array is meaningful only when the corresponding segment
 * is non-empty, and it is never valid for RCU_DONE_TAIL (whose callbacks
 * are already ready to invoke) or for RCU_NEXT_TAIL (whose callbacks have
 * not yet been assigned a grace-period number).
 */
#define RCU_DONE_TAIL		0	/* Also RCU_WAIT head. */
#define RCU_WAIT_TAIL		1	/* Also RCU_NEXT_READY head. */
#define RCU_NEXT_READY_TAIL	2	/* Also RCU_NEXT head. */
#define RCU_NEXT_TAIL		3
#define RCU_CBLIST_NSEGS	4

struct rcu_segcblist {
	struct rcu_head *head;
	/*
 	 * tails[*_TAIL]保存了rcu_head->next的地址，右开区间指的是 
 	 * *tails[*_TAIL]，因此，tails[*_TAIL]指向的next所在的rcu_head还是要被
 	 * 包含在区间内的
 	 */ 
	struct rcu_head **tails[RCU_CBLIST_NSEGS];
	/*
 	 * 存储与tails数组对应的每段的宽限期编号
 	 */ 
	unsigned long gp_seq[RCU_CBLIST_NSEGS];
	/*
 	 * len为回调函数的数量，len_lazy包含明确仅释放内存的回调数量，因此其调
 	 * 用可以安全地推迟
 	 */ 
#ifdef CONFIG_RCU_NOCB_CPU
	atomic_long_t len;
#else
	long len;
#endif
	long len_lazy;
	u8 enabled;
	u8 offloaded;
};

#define RCU_SEGCBLIST_INITIALIZER(n) \
{ \
	.head = NULL, \
	.tails[RCU_DONE_TAIL] = &n.head, \
	.tails[RCU_WAIT_TAIL] = &n.head, \
	.tails[RCU_NEXT_READY_TAIL] = &n.head, \
	.tails[RCU_NEXT_TAIL] = &n.head, \
}

#endif /* __INCLUDE_LINUX_RCU_SEGCBLIST_H */
