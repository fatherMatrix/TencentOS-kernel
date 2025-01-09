// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Queued spinlock
 *
 * (C) Copyright 2013-2015 Hewlett-Packard Development Company, L.P.
 * (C) Copyright 2013-2014,2018 Red Hat, Inc.
 * (C) Copyright 2015 Intel Corp.
 * (C) Copyright 2015 Hewlett-Packard Enterprise Development LP
 *
 * Authors: Waiman Long <longman@redhat.com>
 *          Peter Zijlstra <peterz@infradead.org>
 */

#ifndef _GEN_PV_LOCK_SLOWPATH

#include <linux/smp.h>
#include <linux/bug.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/mutex.h>
#include <linux/prefetch.h>
#include <asm/byteorder.h>
#include <asm/qspinlock.h>

/*
 * Include queued spinlock statistics code
 */
#include "qspinlock_stat.h"

/*
 * The basic principle of a queue-based spinlock can best be understood
 * by studying a classic queue-based spinlock implementation called the
 * MCS lock. The paper below provides a good description for this kind
 * of lock.
 *
 * http://www.cise.ufl.edu/tr/DOC/REP-1992-71.pdf
 *
 * This queued spinlock implementation is based on the MCS lock, however to make
 * it fit the 4 bytes we assume spinlock_t to be, and preserve its existing
 * API, we must modify it somehow.
 *
 * In particular; where the traditional MCS lock consists of a tail pointer
 * (8 bytes) and needs the next pointer (another 8 bytes) of its own node to
 * unlock the next pending (next->locked), we compress both these: {tail,
 * next->locked} into a single u32 value.
 *
 * Since a spinlock disables recursion of its own context and there is a limit
 * to the contexts that can nest; namely: task, softirq, hardirq, nmi. As there
 * are at most 4 nesting levels, it can be encoded by a 2-bit number. Now
 * we can encode the tail by combining the 2-bit nesting level with the cpu
 * number. With one byte for the lock value and 3 bytes for the tail, only a
 * 32-bit word is now needed. Even though we only need 1 bit for the lock,
 * we extend it to a full byte to achieve better performance for architectures
 * that support atomic byte write.
 *
 * We also change the first spinner to spin on the lock bit instead of its
 * node; whereby avoiding the need to carry a node from lock to unlock, and
 * preserving existing lock API. This also makes the unlock code simpler and
 * faster.
 *
 * N.B. The current implementation only supports architectures that allow
 *      atomic operations on smaller 8-bit and 16-bit data types.
 *
 */

#include "mcs_spinlock.h"
#define MAX_NODES	4

/*
 * On 64-bit architectures, the mcs_spinlock structure will be 16 bytes in
 * size and four of them will fit nicely in one 64-byte cacheline. For
 * pvqspinlock, however, we need more space for extra data. To accommodate
 * that, we insert two more long words to pad it up to 32 bytes. IOW, only
 * two of them can fit in a cacheline in this case. That is OK as it is rare
 * to have more than 2 levels of slowpath nesting in actual use. We don't
 * want to penalize pvqspinlocks to optimize for a rare case in native
 * qspinlocks.
 */
struct qnode {
	struct mcs_spinlock mcs;
#ifdef CONFIG_PARAVIRT_SPINLOCKS
	long reserved[2];
#endif
};

/*
 * The pending bit spinning loop count.
 * This heuristic is used to limit the number of lockword accesses
 * made by atomic_cond_read_relaxed when waiting for the lock to
 * transition out of the "== _Q_PENDING_VAL" state. We don't spin
 * indefinitely because there's no guarantee that we'll make forward
 * progress.
 */
#ifndef _Q_PENDING_LOOPS
#define _Q_PENDING_LOOPS	1
#endif

/*
 * Per-CPU queue node structures; we can never have more than 4 nested
 * contexts: task, softirq, hardirq, nmi.
 *
 * Exactly fits one 64-byte cacheline on a 64-bit architecture.
 *
 * PV doubles the storage and uses the second cacheline for PV state.
 *
 * 每个cpu一个数组，每个数组包含4个元素，对应4种上下文。
 */
static DEFINE_PER_CPU_ALIGNED(struct qnode, qnodes[MAX_NODES]);
/* 使source insight可以索引到这里 */
struct qnode qnodes[MAX_NODES];

/*
 * We must be able to distinguish between no-tail and the tail at 0:0,
 * therefore increment the cpu number by one.
 */

static inline __pure u32 encode_tail(int cpu, int idx)
{
	u32 tail;

	tail  = (cpu + 1) << _Q_TAIL_CPU_OFFSET;
	tail |= idx << _Q_TAIL_IDX_OFFSET; /* assume < 4 */

	return tail;
}

static inline __pure struct mcs_spinlock *decode_tail(u32 tail)
{
	int cpu = (tail >> _Q_TAIL_CPU_OFFSET) - 1;
	int idx = (tail &  _Q_TAIL_IDX_MASK) >> _Q_TAIL_IDX_OFFSET;

	return per_cpu_ptr(&qnodes[idx].mcs, cpu);
}

static inline __pure
struct mcs_spinlock *grab_mcs_node(struct mcs_spinlock *base, int idx)
{
	return &((struct qnode *)base + idx)->mcs;
}

#define _Q_LOCKED_PENDING_MASK (_Q_LOCKED_MASK | _Q_PENDING_MASK)

#if _Q_PENDING_BITS == 8
/**
 * clear_pending - clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,* -> *,0,*
 */
static __always_inline void clear_pending(struct qspinlock *lock)
{
	WRITE_ONCE(lock->pending, 0);
}

/**
 * clear_pending_set_locked - take ownership and clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,0 -> *,0,1
 *
 * Lock stealing is not allowed if this function is used.
 */
static __always_inline void clear_pending_set_locked(struct qspinlock *lock)
{
	WRITE_ONCE(lock->locked_pending, _Q_LOCKED_VAL);
}

/*
 * xchg_tail - Put in the new queue tail code word & retrieve previous one
 * @lock : Pointer to queued spinlock structure
 * @tail : The new queue tail code word
 * Return: The previous queue tail code word
 *
 * xchg(lock, tail), which heads an address dependency
 *
 * p,*,* -> n,*,* ; prev = xchg(lock, node)
 *
 * 这里是NR_CPU < (1 << 14)的版本，即pending位自己独占一个char的情况，此时tail字段
 * 本身也处于一个对齐的u16中，此时可以对这个u16使用xchg指令
 * - 否则，就只能像另一个版本那样做cmpxchg了
 */
static __always_inline u32 xchg_tail(struct qspinlock *lock, u32 tail)
{
	/*
	 * We can use relaxed semantics since the caller ensures that the
	 * MCS node is properly initialized before updating the tail.
	 */
	return (u32)xchg_relaxed(&lock->tail,
				 tail >> _Q_TAIL_OFFSET) << _Q_TAIL_OFFSET;
}

#else /* _Q_PENDING_BITS == 8 */

/**
 * clear_pending - clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,* -> *,0,*
 */
static __always_inline void clear_pending(struct qspinlock *lock)
{
	atomic_andnot(_Q_PENDING_VAL, &lock->val);
}

/**
 * clear_pending_set_locked - take ownership and clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,0 -> *,0,1
 */
static __always_inline void clear_pending_set_locked(struct qspinlock *lock)
{
	atomic_add(-_Q_PENDING_VAL + _Q_LOCKED_VAL, &lock->val);
}

/**
 * xchg_tail - Put in the new queue tail code word & retrieve previous one
 * @lock : Pointer to queued spinlock structure
 * @tail : The new queue tail code word
 * Return: The previous queue tail code word
 *
 * xchg(lock, tail)
 *
 * p,*,* -> n,*,* ; prev = xchg(lock, node)
 */
static __always_inline u32 xchg_tail(struct qspinlock *lock, u32 tail)
{
	u32 old, new, val = atomic_read(&lock->val);

	for (;;) {
		new = (val & _Q_LOCKED_PENDING_MASK) | tail;
		/*
		 * We can use relaxed semantics since the caller ensures that
		 * the MCS node is properly initialized before updating the
		 * tail.
		 */
		old = atomic_cmpxchg_relaxed(&lock->val, val, new);
		if (old == val)
			break;

		val = old;
	}
	return old;
}
#endif /* _Q_PENDING_BITS == 8 */

/**
 * queued_fetch_set_pending_acquire - fetch the whole lock value and set pending
 * @lock : Pointer to queued spinlock structure
 * Return: The previous lock value
 *
 * *,*,* -> *,1,*
 */
#ifndef queued_fetch_set_pending_acquire
static __always_inline u32 queued_fetch_set_pending_acquire(struct qspinlock *lock)
{
	return atomic_fetch_or_acquire(_Q_PENDING_VAL, &lock->val);
}
#endif

/**
 * set_locked - Set the lock bit and own the lock
 * @lock: Pointer to queued spinlock structure
 *
 * *,*,0 -> *,0,1
 */
static __always_inline void set_locked(struct qspinlock *lock)
{
	WRITE_ONCE(lock->locked, _Q_LOCKED_VAL);
}


/*
 * Generate the native code for queued_spin_unlock_slowpath(); provide NOPs for
 * all the PV callbacks.
 */

static __always_inline void __pv_init_node(struct mcs_spinlock *node) { }
static __always_inline void __pv_wait_node(struct mcs_spinlock *node,
					   struct mcs_spinlock *prev) { }
static __always_inline void __pv_kick_node(struct qspinlock *lock,
					   struct mcs_spinlock *node) { }
static __always_inline u32  __pv_wait_head_or_lock(struct qspinlock *lock,
						   struct mcs_spinlock *node)
						   { return 0; }

#define pv_enabled()		false

#define pv_init_node		__pv_init_node
#define pv_wait_node		__pv_wait_node
#define pv_kick_node		__pv_kick_node
#define pv_wait_head_or_lock	__pv_wait_head_or_lock

#ifdef CONFIG_PARAVIRT_SPINLOCKS
#define queued_spin_lock_slowpath	native_queued_spin_lock_slowpath
#endif

#endif /* _GEN_PV_LOCK_SLOWPATH */

/**
 * queued_spin_lock_slowpath - acquire the queued spinlock
 * @lock: Pointer to queued spinlock structure
 * @val: Current value of the queued spinlock 32-bit word
 *
 * (queue tail, pending bit, lock value)
 *
 *              fast     :    slow                                  :    unlock
 *                       :                                          :
 * uncontended  (0,0,0) -:--> (0,0,1) ------------------------------:--> (*,*,0)
 *                       :       | ^--------.------.             /  :
 *                       :       v           \      \            |  :
 * pending               :    (0,1,1) +--> (0,1,0)   \           |  :
 *                       :       | ^--'              |           |  :
 *                       :       v                   |           |  :
 * uncontended           :    (n,x,y) +--> (n,0,0) --'           |  :
 *   queue               :       | ^--'                          |  :
 *                       :       v                               |  :
 * contended             :    (*,x,y) +--> (*,0,0) ---> (*,0,1) -'  :
 *   queue               :         ^--'                             :
 */
void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
{
	struct mcs_spinlock *prev, *next, *node;
	u32 old, tail;
	int idx;

	BUILD_BUG_ON(CONFIG_NR_CPUS >= (1U << _Q_TAIL_CPU_BITS));

	if (pv_enabled())
		goto pv_queue;

	if (virt_spin_lock(lock))
		return;

	/*
	 * Wait for in-progress pending->locked hand-overs with a bounded
	 * number of spins so that we guarantee forward progress.
	 *
	 * 0,1,0 -> 0,0,1
	 *
	 * 如果此时状态为(0,1,0)，这是一个临时状态。即cpu a获取了锁后cpu b设
	 * 置了pending位(0,1,1)，在自旋等待locked变为0。然后cpu a释放了锁，形
	 * 成了(0,1,0)。
	 * 这是一个临时状态，因此当前cpu需要自旋，直到该临时状态消失或者自旋次
	 * 数耗尽（自旋次数等于1 << 9）。
	 * - 临时状态消失的原因是cpu b会将(0,1,0) -> (0,0,1)
	 *
	 * 会不会出现自旋次数耗尽但临时状态仍未消失的情况？
	 * - 如果硬件出问题了，可能会存在。
	 *   > 因为从(0,1,1) -> (0,1,0)这个操作到(0,1,0) -> (0,0,1)这个操作之间
	 *     没啥指令，这两个操作是紧挨着的；
	 *     x 参见本函数下面
	 *
	 * --------------------------------------------------------------------
	 *
	 * 这里这个pending位本身是个优化，没有pending位的话功能也是ok的。
	 */
	if (val == _Q_PENDING_VAL) {
		int cnt = _Q_PENDING_LOOPS;
		/*
		 * 一直读，直到条件为真。
		 * 即：临时状态(0, 1, 0)消失或自旋次数耗尽。
		 */
		val = atomic_cond_read_relaxed(&lock->val,
					       (VAL != _Q_PENDING_VAL) || !cnt--);
	}

	/*
	 * If we observe any contention; queue.
	 *
	 * 如果val的非locked字段中有不为0的位，则意味着有pending或者tail，即有
	 * cpu在排队。
	 */
	if (val & ~_Q_LOCKED_MASK)
		goto queue;

	/*
	 * 到这里说明前边发现并没有cpu在排队，我们可以尝试获取一下锁
	 */

	/*
	 * trylock || pending
	 *
	 * 0,0,* -> 0,1,* -> 0,0,1 pending, trylock
	 * - 返回的val是原来的值
	 * - 这里对pending位的设置是无条件的，会出现误抢，通过下面的if处理
	 */
	val = queued_fetch_set_pending_acquire(lock);

	/*
	 * If we observe contention, there is a concurrent locker.
	 *
	 * Undo and queue; our setting of PENDING might have made the
	 * n,0,0 -> 0,0,0 transition fail and it will now be waiting
	 * on @next to become !NULL.
	 */
	if (unlikely(val & ~_Q_LOCKED_MASK)) {
	/*
	 * 由于上面的val返回的是lock中原来的值，如果原来没有pending位，则说明我
	 * 们是第一个给上面设置pending位的，但这个时候（lock中有tail）我们不能
	 * 设置pending位，所以要清除这个多余的pending位
	 * - 别人解释的比较清楚：
	 *   > 执行这个操作之前，锁的状态可能是任何值(*, *, *)，执行完这个操作之
	 *     后，锁的值可能是(*, 1, *)。如果抢这个pending位之前锁的值的pending
	 *     位或tail域就已经不是0了，就表明一定有一个别的CPU已经抢到过pending
	 *     位了（要么pending位是1，表示有CPU在自旋等待在锁上；要么pending位
	 *     是0，但是tail不是0，表示还有CPU在自旋等待，在这之前肯定还有一个CPU
	 *     抢到过pending位，但现在释放了。），当前CPU竞争失败，这时将跳到队
	 *     列模式去处理。但是，如果在原子设置这个pending位之前，pending位是0
	 *     的话，说明这个pending位被当前CPU误“抢”了，原来的状态是(n, 0, *)，
	 *     队列不为空，为了保证自旋锁的次序，本CPU不能“抢”pending位。所以，
	 *     还需要将设置的pending位再清空成0。
	 *     o 不过为什么能直接这样操作，没有竞争吗？这是因为最多只会有一个CPU
	 *       监测到这种pending位从0到1的跳变。因此，能执行clear_pending函数的
	 *       只能有一个CPU，不会和别的CPU竞争，所以这里只需要保证原子操作和可
	 *       见性就行了
	 * - 我理解别人的说法，关键是pending位只能有一个cpu设置，当下个cpu看到有
	 *   pending位后，要经过tail位去排队了。
	 *   > 那么什么时候可以再去设置pending位呢？
	 *     x 我理解应该是这一轮排队全部结束后，即tail、pending位都清空过一次
	 *       后
	 */

		/* Undo PENDING if we set it. */
		if (!(val & _Q_PENDING_MASK))
			clear_pending(lock);

		goto queue;
	}

	/*
	 * We're pending, wait for the owner to go away.
	 *
	 * 0,1,1 -> 0,1,0
	 *
	 * this wait loop must be a load-acquire such that we match the
	 * store-release that clears the locked bit and create lock
	 * sequentiality; this is because not all
	 * clear_pending_set_locked() implementations imply full
	 * barriers.
	 *
	 * 我们是设置pending位的人，自旋等待locked位清除
	 * - 这说明我们是第一个排队的人
	 * - 只有一个cpu可以进入到这里，因为只有一个cpu可以正式的抢到pending位
	 *
	 * ！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
	 * ！！ 首位排队者在这里等待
	 * ！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
	 */
	if (val & _Q_LOCKED_MASK)
		atomic_cond_read_acquire(&lock->val, !(VAL & _Q_LOCKED_MASK));

	/*
	 * take ownership and clear the pending bit.
	 *
	 * 0,1,0 -> 0,0,1
	 *
	 * 清除pending位并设置locked位，标记我们获取了锁
	 * - 上面执行完、这里还未执行时，是上面提到的临时情况
	 */
	clear_pending_set_locked(lock);
	lockevent_inc(lock_pending);
	return;

	/*
	 * End of pending bit optimistic spinning and beginning of MCS
	 * queuing.
	 */
queue:
	lockevent_inc(lock_slowpath);
pv_queue:
	/*
	 * 定义如下：
	 * - static DEFINE_PER_CPU_ALIGNED(struct qnode, qnodes[MAX_NODES]);
	 *   > 本文件最上方
	 */
	node = this_cpu_ptr(&qnodes[0].mcs);
	/*
	 * 每个cpu上第1个qnode的mcs_spinlock.count记录本cpu使用了几个qnode
	 */
	idx = node->count++;
	tail = encode_tail(smp_processor_id(), idx);

	/*
	 * 4 nodes are allocated based on the assumption that there will
	 * not be nested NMIs taking spinlocks. That may not be true in
	 * some architectures even though the chance of needing more than
	 * 4 nodes will still be extremely unlikely. When that happens,
	 * we fall back to spinning on the lock directly without using
	 * any MCS node. This is not the most elegant solution, but is
	 * simple enough.
	 * - 如果嵌套层数超过4层，则退化为普通自旋锁
	 *   > 这种情况仅在某些NMI可嵌套的架构上会出现
	 */
	if (unlikely(idx >= MAX_NODES)) {
		lockevent_inc(lock_no_node);
		while (!queued_spin_trylock(lock))
			cpu_relax();
		goto release;
	}
	/*
	 * 获取目前需要使用的qnode
	 */
	node = grab_mcs_node(node, idx);

	/*
	 * Keep counts of non-zero index values:
	 */
	lockevent_cond_inc(lock_use_node2 + idx - 1, idx);

	/*
	 * Ensure that we increment the head node->count before initialising
	 * the actual node. If the compiler is kind enough to reorder these
	 * stores, then an IRQ could overwrite our assignments.
	 */
	barrier();

	node->locked = 0;
	node->next = NULL;
	pv_init_node(node);

	/*
	 * We touched a (possibly) cold cacheline in the per-cpu queue node;
	 * attempt the trylock once more in the hope someone let go while we
	 * weren't watching.
	 * - 这里是一次乱序抢锁的尝试
	 *   > 执行到这里后，可能自旋锁已经完全变为了0。如果此时确实为0，则所有
	 *     执行到这里的cpu都可以乱序尝试一次cmpxchg设置lock位，谁设置上了，
	 *     谁就成功了
	 *     o 注意这里是乱序的，无法保证公平性
	 *     o 此时还没开始在本地mcs的lock上自旋，且只有一次尝试，不会带来持续
	 *       的缓存颠簸
	 */
	if (queued_spin_trylock(lock))
		goto release;

	/*
	 * Ensure that the initialisation of @node is complete before we
	 * publish the updated tail via xchg_tail() and potentially link
	 * @node into the waitqueue via WRITE_ONCE(prev->next, node) below.
	 */
	smp_wmb();

	/*
	 * Publish the updated tail.
	 * We have already touched the queueing cacheline; don't bother with
	 * pending stuff.
	 *
	 * p,*,* -> n,*,*
	 *
	 * 将我们自己插入三元组中的tail，tail本身指向的就是排队的最后一个
	 */
	old = xchg_tail(lock, tail);
	next = NULL;

	/*
	 * if there was a previous node; link it and wait until reaching the
	 * head of the waitqueue.
	 */
	if (old & _Q_TAIL_MASK) {
		prev = decode_tail(old);

		/*
		 * Link @node into the waitqueue.
		 *
		 * 如何保证做这个操作的同时，prev这个cpu本身没有获取到锁且快速
		 * 释放了锁呢？
		 * - 因为上面修改tail是原子xchg，在prev这个节点在放锁的时候检测
		 *   到这种情况并做操作
		 */
		WRITE_ONCE(prev->next, node);

		/*
		 * 下面两个函数都是等mcs node中的locked变为true
		 * - 对于pvspinlock，在pv_wait_node()中等待；
		 *   > pvspinlock如果在pv_wait_node()中等待结束，则下面的又一个
		 *     等待必定会绕过；
		 * - 对于spinlock，在arch_mcs_spin_lock_contended()中等待；
		 *   > 未定义CONFIG_PARAVIRT_SPINLOCK时，pv_wait_node() -> __pv_wait_node()
		 *     最终会编译为空语句
		 *
		 * 值得注意的是，mcs node中的locked变为true，并不代表对应cpu获取
		 * 到了本自旋锁，只说明其到了队列头
		 *
		 * ！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
		 * ！！ 非首位的排队者在这里等待
		 * ！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
		 */
		pv_wait_node(node, prev);
		arch_mcs_spin_lock_contended(&node->locked);

		/*
		 * While waiting for the MCS lock, the next pointer may have
		 * been set by another lock waiter. We optimistically load
		 * the next pointer & prefetch the cacheline for writing
		 * to reduce latency in the upcoming MCS unlock operation.
		 */
		next = READ_ONCE(node->next);
		if (next)
			prefetchw(next);
	}

	/*
	 * we're at the head of the waitqueue, wait for the owner & pending to
	 * go away.
	 *
	 * *,x,y -> *,0,0
	 *
	 * this wait loop must use a load-acquire such that we match the
	 * store-release that clears the locked bit and create lock
	 * sequentiality; this is because the set_locked() function below
	 * does not imply a full barrier.
	 *
	 * The PV pv_wait_head_or_lock function, if active, will acquire
	 * the lock and return a non-zero value. So we have to skip the
	 * atomic_cond_read_acquire() call. As the next PV queue head hasn't
	 * been designated yet, there is no way for the locked value to become
	 * _Q_SLOW_VAL. So both the set_locked() and the
	 * atomic_cmpxchg_relaxed() calls will be safe.
	 *
	 * If PV isn't active, 0 will be returned instead.
	 *
	 */
	if ((val = pv_wait_head_or_lock(lock, node)))
		goto locked;

	/*
	 * 等待pending和locked位被清除
	 * - 这里是非pvspinlock到达队列头的情况，此时等待pending和locked位被清除
	 */
	val = atomic_cond_read_acquire(&lock->val, !(VAL & _Q_LOCKED_PENDING_MASK));

locked:
	/*
	 * claim the lock:
	 *
	 * n,0,0 -> 0,0,1 : lock, uncontended
	 * *,*,0 -> *,*,1 : lock, contended
	 *
	 * If the queue head is the only one in the queue (lock value == tail)
	 * and nobody is pending, clear the tail code and grab the lock.
	 * Otherwise, we only need to grab the lock.
	 */

	/*
	 * In the PV case we might already have _Q_LOCKED_VAL set, because
	 * of lock stealing; therefore we must also allow:
	 *
	 * n,0,1 -> 0,0,1
	 *
	 * Note: at this point: (val & _Q_PENDING_MASK) == 0, because of the
	 *       above wait condition, therefore any concurrent setting of
	 *       PENDING will make the uncontended transition fail.
	 *
	 * 我们是当前唯一想要获取这把锁的人了，可以直接获取锁；
	 * - 并且会将整个锁完全设置为(0,0,1)
	 */
	if ((val & _Q_TAIL_MASK) == tail) {
		if (atomic_try_cmpxchg_relaxed(&lock->val, &val, _Q_LOCKED_VAL))
			goto release; /* No contention */
	}

	/*
	 * Either somebody is queued behind us or _Q_PENDING_VAL got set
	 * which will then detect the remaining tail and queue behind us
	 * ensuring we'll see a @next.
	 * - 走到这里说明tail不指向我们，我们肯定有一个next。此时只能设置locked
	 */
	set_locked(lock);

	/*
	 * contended path; wait for next if not observed yet, release.
	 * - 虽然我们知道我们肯定有一个next，但是这个next有可能还未被设置，此处
	 *   等待其被publish
	 *   > 没有几条指令，可以等一下
	 */
	if (!next)
		next = smp_cond_load_relaxed(&node->next, (VAL));

	/*
	 * 将排队的下一个mcs_spinlock.locked设置为1
	 * - again：排队的mcs_spinlock.locked为1仅表示该mcs到达了队列头
	 */
	arch_mcs_spin_unlock_contended(&next->locked);
	/*
	 * 如何唤醒vcpu呢？
	 * - spin_unlock() ~> __pv_queued_spin_unlock_slowpath() -> pv_kick() -> kvm_kick_cpu()
	 */
	pv_kick_node(lock, next);

release:
	/*
	 * release the node
	 */
	__this_cpu_dec(qnodes[0].mcs.count);
}
EXPORT_SYMBOL(queued_spin_lock_slowpath);

/*
 * Generate the paravirt code for queued_spin_unlock_slowpath().
 * - tkernel4开启了CONFIG_PARAVIRT_SPINLOCKS选项
 */
#if !defined(_GEN_PV_LOCK_SLOWPATH) && defined(CONFIG_PARAVIRT_SPINLOCKS)
#define _GEN_PV_LOCK_SLOWPATH

#undef  pv_enabled
#define pv_enabled()	true

#undef pv_init_node
#undef pv_wait_node
#undef pv_kick_node
#undef pv_wait_head_or_lock

#undef  queued_spin_lock_slowpath
#define queued_spin_lock_slowpath	__pv_queued_spin_lock_slowpath

#include "qspinlock_paravirt.h"
#include "qspinlock.c"

#endif

/*
 * 如果看不明白上边做了什么的话，gcc -E预处理一下下面的演示代码：
 * #ifndef __ZJL__
 * #define FUNC native_func
 * #endif // __ZJL__
 *
 * int FUNC()
 * {
 *	return 0;
 * }
 *
 * #ifndef __ZJL__
 * #define __ZJL__
 * #undef FUNC
 * #define FUNC pv_func
 * #include "a.c"
 * #endif
 */
