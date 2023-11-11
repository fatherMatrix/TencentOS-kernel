/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/journal-head.h
 *
 * buffer_head fields for JBD
 *
 * 27 May 2001 Andrew Morton
 *	Created - pulled out of fs.h
 */

#ifndef JOURNAL_HEAD_H_INCLUDED
#define JOURNAL_HEAD_H_INCLUDED

typedef unsigned int		tid_t;		/* Unique transaction ID */
typedef struct transaction_s	transaction_t;	/* Compound transaction type */


struct buffer_head;

struct journal_head {
	/*
	 * Points back to our buffer_head. [jbd_lock_bh_journal_head()]
	 */
	struct buffer_head *b_bh;

	/*
	 * Reference count - see description in journal.c
	 * [jbd_lock_bh_journal_head()]
	 */
	int b_jcount;

	/*
	 * Journalling list for this buffer [jbd_lock_bh_state()]
	 * NOTE: We *cannot* combine this with b_modified into a bitfield
	 * as gcc would then (which the C standard allows but which is
	 * very unuseful) make 64-bit accesses to the bitfield and clobber
	 * b_jcount if its update races with bitfield modification.
	 *
	 * 当前journal_head位于transaction的哪个链表上
	 */
	unsigned b_jlist;

	/*
	 * This flag signals the buffer has been modified by
	 * the currently running transaction
	 * [jbd_lock_bh_state()]
	 *
	 * 标志该缓冲区是否被当前正在运行的transaction修改过
	 */
	unsigned b_modified;

	/*
	 * Copy of the buffer data frozen for writing to the log.
	 * [jbd_lock_bh_state()]
	 *
	 * 当jbd遇到需要转义的块时，将buffer_head指向的缓冲区数据拷贝出来，冻
	 * 结起来，供写入日志使用
	 */
	char *b_frozen_data;

	/*
	 * Pointer to a saved copy of the buffer containing no uncommitted
	 * deallocation references, so that allocations can avoid overwriting
	 * uncommitted deletes. [jbd_lock_bh_state()]
	 *
	 * 含有未提交的删除信息的元数据块（磁盘块位图）的拷贝；
	 * - 主要用来针对未提交的删除操作：一次删除动作后紧跟的分配动作使用的是
	 *   b_committed_data中的数据，不会影响到写入日志中的数据
	 */
	char *b_committed_data;

	/*
	 * Pointer to the compound transaction which owns this buffer's
	 * metadata: either the running transaction or the committing
	 * transaction (if there is one).  Only applies to buffers on a
	 * transaction's data or metadata journaling list.
	 * [j_list_lock] [jbd_lock_bh_state()]
	 * Either of these locks is enough for reading, both are needed for
	 * changes.
	 *
	 * 指向所属的transaction
	 */
	transaction_t *b_transaction;

	/*
	 * Pointer to the running compound transaction which is currently
	 * modifying the buffer's metadata, if there was already a transaction
	 * committing it when the new transaction touched it.
	 * [t_list_lock] [jbd_lock_bh_state()]
	 *
	 * 当transaction A正在提交本缓冲区，此时transaction B想要修改本缓冲区的
	 * 元数据，那么b_next_transaction指向transaction B；
	 */
	transaction_t *b_next_transaction;

	/*
	 * Doubly-linked list of buffers on a transaction's data, metadata or
	 * forget queue. [t_list_lock] [jbd_lock_bh_state()]
	 */
	struct journal_head *b_tnext, *b_tprev;

	/*
	 * Pointer to the compound transaction against which this buffer
	 * is checkpointed.  Only dirty buffers can be checkpointed.
	 * [j_list_lock]
	 */
	transaction_t *b_cp_transaction;

	/*
	 * Doubly-linked list of buffers still remaining to be flushed
	 * before an old transaction can be checkpointed.
	 * [j_list_lock]
	 */
	struct journal_head *b_cpnext, *b_cpprev;

	/* Trigger type */
	struct jbd2_buffer_trigger_type *b_triggers;

	/* Trigger type for the committing transaction's frozen data */
	struct jbd2_buffer_trigger_type *b_frozen_triggers;
};

#endif		/* JOURNAL_HEAD_H_INCLUDED */
