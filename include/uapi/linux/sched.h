/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SCHED_H
#define _UAPI_LINUX_SCHED_H

#include <linux/types.h>

/*
 * cloning flags:
 */
#define CSIGNAL		0x000000ff	/* signal mask to be sent at exit */
#define CLONE_VM	0x00000100	/* set if VM shared between processes */
#define CLONE_FS	0x00000200	/* set if fs info shared between processes */
#define CLONE_FILES	0x00000400	/* set if open files shared between processes */
#define CLONE_SIGHAND	0x00000800	/* set if signal handlers and blocked signals shared */
#define CLONE_PIDFD	0x00001000	/* set if a pidfd should be placed in parent */
#define CLONE_PTRACE	0x00002000	/* set if we want to let tracing continue on the child too */
#define CLONE_VFORK	0x00004000	/* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT	0x00008000	/* set if we want to have the same parent as the cloner */
#define CLONE_THREAD	0x00010000	/* Same thread group? */
#define CLONE_NEWNS	0x00020000	/* New mount namespace group */
#define CLONE_SYSVSEM	0x00040000	/* share system V SEM_UNDO semantics */
#define CLONE_SETTLS	0x00080000	/* create a new TLS for the child */
#define CLONE_PARENT_SETTID	0x00100000	/* set the TID in the parent */
#define CLONE_CHILD_CLEARTID	0x00200000	/* clear the TID in the child */
#define CLONE_DETACHED		0x00400000	/* Unused, ignored */
#define CLONE_UNTRACED		0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID	0x01000000	/* set the TID in the child */
#define CLONE_NEWCGROUP		0x02000000	/* New cgroup namespace */
#define CLONE_NEWUTS		0x04000000	/* New utsname namespace */
#define CLONE_NEWIPC		0x08000000	/* New ipc namespace */
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
#define CLONE_NEWNET		0x40000000	/* New network namespace */
#define CLONE_IO		0x80000000	/* Clone io context */

#ifndef __ASSEMBLY__
/**
 * struct clone_args - arguments for the clone3 syscall
 * @flags:       Flags for the new process as listed above.
 *               All flags are valid except for CSIGNAL and
 *               CLONE_DETACHED.
 * @pidfd:       If CLONE_PIDFD is set, a pidfd will be
 *               returned in this argument.
 * @child_tid:   If CLONE_CHILD_SETTID is set, the TID of the
 *               child process will be returned in the child's
 *               memory.
 * @parent_tid:  If CLONE_PARENT_SETTID is set, the TID of
 *               the child process will be returned in the
 *               parent's memory.
 * @exit_signal: The exit_signal the parent process will be
 *               sent when the child exits.
 * @stack:       Specify the location of the stack for the
 *               child process.
 *               Note, @stack is expected to point to the
 *               lowest address. The stack direction will be
 *               determined by the kernel and set up
 *               appropriately based on @stack_size.
 * @stack_size:  The size of the stack for the child process.
 * @tls:         If CLONE_SETTLS is set, the tls descriptor
 *               is set to tls.
 *
 * The structure is versioned by size and thus extensible.
 * New struct members must go at the end of the struct and
 * must be properly 64bit aligned.
 */
struct clone_args {
	__aligned_u64 flags;
	__aligned_u64 pidfd;
	__aligned_u64 child_tid;
	__aligned_u64 parent_tid;
	__aligned_u64 exit_signal;
	__aligned_u64 stack;
	__aligned_u64 stack_size;
	__aligned_u64 tls;
};
#endif

#define CLONE_ARGS_SIZE_VER0 64 /* sizeof first published struct */

/*
 * 调度类：stop -> deadline -> realtime -> cfs -> idle
 *
 * +------------------+----------------+-----------+
 * | class            | policy         | prio      |
 * +------------------+----------------+-----------+
 * | stop             | /              | /         |
 * | stop_sched_class |                |           |
 * +------------------+----------------+-----------+
 * | deadline         | SCHED_DEADLINE | -1        |
 * | dl_sched_class   |                |           |
 * +------------------+----------------+-----------+
 * | realtime         | SCHED_FIFO     | 0   - 99  |
 * | rt_sched_class   | SCHED_RR       |           |
 * +------------------+----------------+-----------+
 * | cfs              | SCHED_NORMAL   | 100 - 139 |
 * | fair_sched_class | SCHED_BATCH    |           |
 * |                  | SCHED_IDLE     |           |
 * +------------------+----------------+-----------+
 * | idle             | /              | /         |
 * | idle_sched_class |                |           |
 * +------------------+----------------+-----------+
 */

/*
 * Scheduling policies
 */

/*
 * SCHED_NORMAL（以前称为SCHED_OTHER）分时调度策略是非实时进程的默认调度策略。
 * 所有普通进程的静态优先级都为0，因此，任何一个基于SCHED_FIFO或SCHED_RR调度策
 * 略的就绪进程都会抢占他们。Linux内核没有实现这类调度策略。？
 * - 参见fair_policy()
 */
#define SCHED_NORMAL		0
/*
 * SCHED_FIFO（先进先出调度）策略与SCHED_RR类似，只不过没有时间片概念。一旦进程
 * 获得了CPU控制权，它会一直运行下去直到下面的某个条件被满足：
 * - 自愿放弃CPU
 * - 进程终止
 * - 被高优先级的进程抢占
 */
#define SCHED_FIFO		1
/*
 * SCHED_RR（循环调度）策略表示优先级相同的进程以循环分享时间的方式来运行。进程
 * 每次使用CPU的时间为一个固定长度的时间片。进程会保持占有CPU直到下面的某个条件
 * 得到满足。
 * - 时间片用完
 * - 自愿放弃CPU
 * - 进程终止
 * - 被高优先级的进程抢占
 */
#define SCHED_RR		2
/*
 * SCHED_BATCH（批处理调度）策略是普通进程调度策略。这个调度策略表示让调度起认为
 * 该进程是CPU消耗型的。因此，调度器对这类进程的唤醒惩罚比较小。在Linux内核里，
 * 该类调度策略表示使用CFS
 */
#define SCHED_BATCH		3
/* SCHED_ISO: reserved but not implemented yet */
#define SCHED_IDLE		5
#define SCHED_DEADLINE		6

/* Can be ORed in to make sure the process is reverted back to SCHED_NORMAL on fork */
#define SCHED_RESET_ON_FORK     0x40000000

/*
 * For the sched_{set,get}attr() calls
 */
#define SCHED_FLAG_RESET_ON_FORK	0x01
#define SCHED_FLAG_RECLAIM		0x02
#define SCHED_FLAG_DL_OVERRUN		0x04
#define SCHED_FLAG_KEEP_POLICY		0x08
#define SCHED_FLAG_KEEP_PARAMS		0x10
#define SCHED_FLAG_UTIL_CLAMP_MIN	0x20
#define SCHED_FLAG_UTIL_CLAMP_MAX	0x40

#define SCHED_FLAG_KEEP_ALL	(SCHED_FLAG_KEEP_POLICY | \
				 SCHED_FLAG_KEEP_PARAMS)

#define SCHED_FLAG_UTIL_CLAMP	(SCHED_FLAG_UTIL_CLAMP_MIN | \
				 SCHED_FLAG_UTIL_CLAMP_MAX)

#define SCHED_FLAG_ALL	(SCHED_FLAG_RESET_ON_FORK	| \
			 SCHED_FLAG_RECLAIM		| \
			 SCHED_FLAG_DL_OVERRUN		| \
			 SCHED_FLAG_KEEP_ALL		| \
			 SCHED_FLAG_UTIL_CLAMP)

#endif /* _UAPI_LINUX_SCHED_H */
