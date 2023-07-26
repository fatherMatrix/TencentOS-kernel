/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kernel/workqueue_internal.h
 *
 * Workqueue internal header file.  Only to be included by workqueue and
 * core kernel subsystems.
 */
#ifndef _KERNEL_WORKQUEUE_INTERNAL_H
#define _KERNEL_WORKQUEUE_INTERNAL_H

#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/preempt.h>

struct worker_pool;

/*
 * The poor guys doing the actual heavy lifting.  All on-duty workers are
 * either serving the manager role, on idle list or on busy hash.  For
 * details on the locking annotation (L, I, X...), refer to workqueue.c.
 *
 * Only to be used in workqueue and async.
 *
 * 用于描述处理工作任务的工作线程；
 * - 每个worker都对应一个内核线程，存储于task字段；
 */
struct worker {
	/* 
	 * on idle list while idle, on busy hash table while busy
	 *
	 * worker根据工作状态，可以添加到worker_pool的空闲链表和忙碌链表中；
	 * - idle状态：链接到worker_pool->idle_list链表中；
	 * - busy状态：谅解到worker_pool->bush_hash链表中；
	 */
	union {
		struct list_head	entry;	/* L: while idle */
		struct hlist_node	hentry;	/* L: while busy */
	};

	/*
	 * work_struct用来描述一个工作内容，此字段表示当前worker正在处理的工作；
	 */
	struct work_struct	*current_work;	/* L: work being processed */
	/*
	 * 当前执行的工作的处理函数
	 * - 应该是从work_struct中拷贝过来的；
	 */
	work_func_t		current_func;	/* L: current_work's fn */
	/*
	 * 当前work_struct所属的pool_workqueue
	 */
	struct pool_workqueue	*current_pwq; /* L: current_work's pwq */
	/*
	 * 已调度的工作链表，连接到worker_struct->entry
	 */
	struct list_head	scheduled;	/* L: scheduled works */

	/* 64 bytes boundary on 64bit, 32 on 32bit */

	/*
	 * 对应的内核线程
	 * - 一个worker实际上就是一个内核线程
	 */
	struct task_struct	*task;		/* I: worker task */
	/*
	 * 该工作线程所属的worker_pool
	 */
	struct worker_pool	*pool;		/* A: the associated pool */
						/* L: for rescuers */
	/*
	 * 作为链表元素挂入worker_pool->workers链表中
	 */
	struct list_head	node;		/* A: anchored at pool->workers */
						/* A: runs through worker->node */

	/*
	 * 最近一次运行的时间戳，用于判定该工作线程是否可以被destory时使用；
	 */
	unsigned long		last_active;	/* L: last active timestamp */
	/*
	 * 标志位
	 */
	unsigned int		flags;		/* X: flags */
	/*
	 * 工作线程的id号
	 */
	int			id;		/* I: worker id */
	int			sleeping;	/* None */

	/*
	 * Opaque string set with work_set_desc().  Printed out with task
	 * dump for debugging - WARN, BUG, panic or sysrq.
	 *
	 * 工作线程的描述说明
	 */
	char			desc[WORKER_DESC_LEN];

	/* used only by rescuers to point to the target workqueue */
	struct workqueue_struct	*rescue_wq;	/* I: the workqueue to rescue */

	/* used by the scheduler to determine a worker's last known identity */
	work_func_t		last_func;
};

/**
 * current_wq_worker - return struct worker if %current is a workqueue worker
 */
static inline struct worker *current_wq_worker(void)
{
	if (in_task() && (current->flags & PF_WQ_WORKER))
		return kthread_data(current);
	return NULL;
}

/*
 * Scheduler hooks for concurrency managed workqueue.  Only to be used from
 * sched/ and workqueue.c.
 */
void wq_worker_running(struct task_struct *task);
void wq_worker_sleeping(struct task_struct *task);
work_func_t wq_worker_last_func(struct task_struct *task);

#endif /* _KERNEL_WORKQUEUE_INTERNAL_H */
