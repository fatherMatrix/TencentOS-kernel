// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__XFS_LOG_PRIV_H__
#define __XFS_LOG_PRIV_H__

struct xfs_buf;
struct xlog;
struct xlog_ticket;
struct xfs_mount;

/*
 * Flags for log structure
 */
#define XLOG_ACTIVE_RECOVERY	0x2	/* in the middle of recovery */
#define	XLOG_RECOVERY_NEEDED	0x4	/* log was recovered */
#define XLOG_IO_ERROR		0x8	/* log hit an I/O error, and being
					   shutdown */
#define XLOG_TAIL_WARN		0x10	/* log tail verify warning issued */

/*
 * get client id from packed copy.
 *
 * this hack is here because the xlog_pack code copies four bytes
 * of xlog_op_header containing the fields oh_clientid, oh_flags
 * and oh_res2 into the packed copy.
 *
 * later on this four byte chunk is treated as an int and the
 * client id is pulled out.
 *
 * this has endian issues, of course.
 */
static inline uint xlog_get_client_id(__be32 i)
{
	return be32_to_cpu(i) >> 24;
}

/*
 * In core log state
 */
#define XLOG_STATE_ACTIVE    0x0001 /* Current IC log being written to */
#define XLOG_STATE_WANT_SYNC 0x0002 /* Want to sync this iclog; no more writes */
#define XLOG_STATE_SYNCING   0x0004 /* This IC log is syncing */
#define XLOG_STATE_DONE_SYNC 0x0008 /* Done syncing to disk */
#define XLOG_STATE_DO_CALLBACK \
			     0x0010 /* Process callback functions */
#define XLOG_STATE_CALLBACK  0x0020 /* Callback functions now */
#define XLOG_STATE_DIRTY     0x0040 /* Dirty IC log, not ready for ACTIVE status*/
#define XLOG_STATE_IOERROR   0x0080 /* IO error happened in sync'ing log */
#define XLOG_STATE_ALL	     0x7FFF /* All possible valid flags */
#define XLOG_STATE_NOTUSED   0x8000 /* This IC log not being used */

/*
 * Flags to log ticket
 */
#define XLOG_TIC_INITED		0x1	/* has been initialized */
#define XLOG_TIC_PERM_RESERV	0x2	/* permanent reservation */

#define XLOG_TIC_FLAGS \
	{ XLOG_TIC_INITED,	"XLOG_TIC_INITED" }, \
	{ XLOG_TIC_PERM_RESERV,	"XLOG_TIC_PERM_RESERV" }

/*
 * Below are states for covering allocation transactions.
 * By covering, we mean changing the h_tail_lsn in the last on-disk
 * log write such that no allocation transactions will be re-done during
 * recovery after a system crash. Recovery starts at the last on-disk
 * log write.
 *
 * These states are used to insert dummy log entries to cover
 * space allocation transactions which can undo non-transactional changes
 * after a crash. Writes to a file with space
 * already allocated do not result in any transactions. Allocations
 * might include space beyond the EOF. So if we just push the EOF a
 * little, the last transaction for the file could contain the wrong
 * size. If there is no file system activity, after an allocation
 * transaction, and the system crashes, the allocation transaction
 * will get replayed and the file will be truncated. This could
 * be hours/days/... after the allocation occurred.
 *
 * The fix for this is to do two dummy transactions when the
 * system is idle. We need two dummy transaction because the h_tail_lsn
 * in the log record header needs to point beyond the last possible
 * non-dummy transaction. The first dummy changes the h_tail_lsn to
 * the first transaction before the dummy. The second dummy causes
 * h_tail_lsn to point to the first dummy. Recovery starts at h_tail_lsn.
 *
 * These dummy transactions get committed when everything
 * is idle (after there has been some activity).
 *
 * There are 5 states used to control this.
 *
 *  IDLE -- no logging has been done on the file system or
 *		we are done covering previous transactions.
 *  NEED -- logging has occurred and we need a dummy transaction
 *		when the log becomes idle.
 *  DONE -- we were in the NEED state and have committed a dummy
 *		transaction.
 *  NEED2 -- we detected that a dummy transaction has gone to the
 *		on disk log with no other transactions.
 *  DONE2 -- we committed a dummy transaction when in the NEED2 state.
 *
 * There are two places where we switch states:
 *
 * 1.) In xfs_sync, when we detect an idle log and are in NEED or NEED2.
 *	We commit the dummy transaction and switch to DONE or DONE2,
 *	respectively. In all other states, we don't do anything.
 *
 * 2.) When we finish writing the on-disk log (xlog_state_clean_log).
 *
 *	No matter what state we are in, if this isn't the dummy
 *	transaction going out, the next state is NEED.
 *	So, if we aren't in the DONE or DONE2 states, the next state
 *	is NEED. We can't be finishing a write of the dummy record
 *	unless it was committed and the state switched to DONE or DONE2.
 *
 *	If we are in the DONE state and this was a write of the
 *		dummy transaction, we move to NEED2.
 *
 *	If we are in the DONE2 state and this was a write of the
 *		dummy transaction, we move to IDLE.
 *
 *
 * Writing only one dummy transaction can get appended to
 * one file space allocation. When this happens, the log recovery
 * code replays the space allocation and a file could be truncated.
 * This is why we have the NEED2 and DONE2 states before going idle.
 */

#define XLOG_STATE_COVER_IDLE	0
#define XLOG_STATE_COVER_NEED	1
#define XLOG_STATE_COVER_DONE	2
#define XLOG_STATE_COVER_NEED2	3
#define XLOG_STATE_COVER_DONE2	4

#define XLOG_COVER_OPS		5

/* Ticket reservation region accounting */ 
#define XLOG_TIC_LEN_MAX	15

/*
 * Reservation region
 * As would be stored in xfs_log_iovec but without the i_addr which
 * we don't care about.
 */
typedef struct xlog_res {
	uint	r_len;	/* region length		:4 */
	uint	r_type;	/* region's transaction type	:4 */
} xlog_res_t;

typedef struct xlog_ticket {
	struct list_head   t_queue;	 /* reserve/write queue */
	struct task_struct *t_task;	 /* task that owns this ticket */
	xlog_tid_t	   t_tid;	 /* transaction identifier	 : 4  */
	atomic_t	   t_ref;	 /* ticket reference count       : 4  */
	/*
	 * 当前剩余量？
	 */
	int		   t_curr_res;	 /* current reservation in bytes : 4  */
	/*
	 * 总量？
	 */
	int		   t_unit_res;	 /* unit reservation in bytes    : 4  */
	char		   t_ocnt;	 /* original count		 : 1  */
	char		   t_cnt;	 /* current count		 : 1  */
	char		   t_clientid;	 /* who does this belong to;	 : 1  */
	char		   t_flags;	 /* properties of reservation	 : 1  */

        /* reservation array fields */
	uint		   t_res_num;                    /* num in array : 4 */
	uint		   t_res_num_ophdrs;		 /* num op hdrs  : 4 */
	uint		   t_res_arr_sum;		 /* array sum    : 4 */
	uint		   t_res_o_flow;		 /* sum overflow : 4 */
	xlog_res_t	   t_res_arr[XLOG_TIC_LEN_MAX];  /* array of res : 8 * 15 */ 
} xlog_ticket_t;

/*
 * - A log record header is 512 bytes.  There is plenty of room to grow the
 *	xlog_rec_header_t into the reserved space.
 * - ic_data follows, so a write to disk can start at the beginning of
 *	the iclog.
 * - ic_forcewait is used to implement synchronous forcing of the iclog to disk.
 * - ic_next is the pointer to the next iclog in the ring.
 * - ic_log is a pointer back to the global log structure.
 * - ic_size is the full size of the log buffer, minus the cycle headers.
 * - ic_io_size is the size of the currently pending log buffer write, which
 *	might be smaller than ic_size
 * - ic_offset is the current number of bytes written to in this iclog.
 * - ic_refcnt is bumped when someone is writing to the log.
 * - ic_state is the state of the iclog.
 *
 * Because of cacheline contention on large machines, we need to separate
 * various resources onto different cachelines. To start with, make the
 * structure cacheline aligned. The following fields can be contended on
 * by independent processes:
 *
 *	- ic_callbacks
 *	- ic_refcnt
 *	- fields protected by the global l_icloglock
 *
 * so we need to ensure that these fields are located in separate cachelines.
 * We'll put all the read-only and l_icloglock fields in the first cacheline,
 * and move everything else out to subsequent cachelines.
 */
typedef struct xlog_in_core {
	/*
	 * __xfs_log_force_lsn()中等待写iclog到disk log space完成；
	 * wake该队列的点在： xlog_state_clean_iclog()
	 */
	wait_queue_head_t	ic_force_wait;
	/*
	 * __xfs_log_force_lsn()中写iclog到disk log space之前等待，用于等待
	 * 上一个iclog（ic_prev）写完；
	 * wake该队列的点在： xlog_state_done_syncing()
	 */
	wait_queue_head_t	ic_write_wait;
	struct xlog_in_core	*ic_next;
	struct xlog_in_core	*ic_prev;
	struct xlog		*ic_log;
	/*
	 * log->l_iclog_size - log->l_iclog_hsize
	 */
	u32			ic_size;
	u32			ic_io_size;
	/*
	 * 看注释应该是log->l_iclog_size - log->l_iclog_hsize后的数据区域中写入
	 * 的字节数
	 * - 即ic_datap指向ic_offset为0的位置
	 */
	u32			ic_offset;
	unsigned short		ic_state;
	/*
	 * log buffer负载区域中的数据区域：
	 * - ic_datap = ic_data + xlog->l_iclog_hsize
	 */
	char			*ic_datap;	/* pointer to iclog data */

	/* Callback structures need their own cacheline */
	spinlock_t		ic_callback_lock ____cacheline_aligned_in_smp;
	/*
	 * 链表头，链表元素是xfs_cil_ctx->iclog_entry；
	 * - xfs_cil_ctx被写入log buffer（iclog）后，需要将xfs_cil_ctx链接到
	 *   iclog中，等iclog被写入disk后，依次调用相关回调；
	 * - 只有本iclog包含了xfs_cil_ctx的尾部提交标记，才会包含xfs_cil_ctx
	 */
	struct list_head	ic_callbacks;

	/* reference counts need their own cacheline */
	atomic_t		ic_refcnt ____cacheline_aligned_in_smp;
	/*
	 * log buffer的负载区域
	 */
	xlog_in_core_2_t	*ic_data;
	/*
	 * 每个log record（log buffer）都以xlog_rec_header开头
	 */
#define ic_header	ic_data->hic_header
#ifdef DEBUG
	bool			ic_fail_crc : 1;
#endif
	struct semaphore	ic_sema;
	/*
	 * iclog写到disk log space完成的回调；
	 */
	struct work_struct	ic_end_io_work;
	/*
	 * 用于将iclog写到disk log space的bio
	 */
	struct bio		ic_bio;
	struct bio_vec		ic_bvec[];
} xlog_in_core_t;

/*
 * The CIL context is used to aggregate per-transaction details as well be
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * passed to the iclog for checkpoint post-commit processing.  After being
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * passed to the iclog, another context needs to be allocated for tracking the
 * next set of transactions to be aggregated into a checkpoint.
 */
struct xfs_cil;

struct xfs_cil_ctx {
	struct xfs_cil		*cil;
	/*
	 * 每次新建时比上一个增加1
	 * - 这个东西表示的本质内容与start_lsn，commit_lsn不同，相对大小无意义
	 */
	xfs_lsn_t		sequence;	/* chkpt sequence # */
	/*
	 * 来源是xlog_in_core->ic_header.h_lsn
	 * - 此处用于记录本xfs_cil_ctx所写入的第一个iclog的h_lsn字段
	 *   > iclog->ic_header.h_lsn表示该iclog在disk log space的写入起始位置
	 *   > 参见xlog_write()
	 * - 本字段也是xfs_log_item->li_lsn的来源
	 *   > 参见xlog_cil_committed() -> call xfs_trans_committed_bulk()
	 */
	xfs_lsn_t		start_lsn;	/* first LSN of chkpt commit */
	/*
	 * 来源是xlog_in_core->ic_header.h_lsn
	 * - 此处是用于记录本xfs_cil_ctx写入完成后的commit log所写入的iclog的
	 *   h_lsn字段
	 *   > commit log本身会不会跨iclog呢？
	 */
	xfs_lsn_t		commit_lsn;	/* chkpt commit record lsn */
	struct xlog_ticket	*ticket;	/* chkpt ticket */
	int			nvecs;		/* number of regions */
	int			space_used;	/* aggregate size of regions */
	struct list_head	busy_extents;	/* busy extents in chkpt */
	/*
	 * CIL上取下来的xfs_log_item对应的xfs_log_vec会挂到这里，对应文档中
	 * 3.3.3 Checkpoints
	 */
	struct xfs_log_vec	*lv_chain;	/* logvecs being pushed */
	/*
	 * 作为链表元素加入xlog_in_core->ic_callbacks
	 * - 当xfs_cil_ctx的内容全部经由xlog_write写入iclog后，会将xfs_cil_ctx通
	 *   过本字段挂入事务结束标记所写入的iclog
	 */
	struct list_head	iclog_entry;
	/*
	 * 当xlog_cil_push()被调用后，当前的xfs_cil_ctx会通过本字段将自己链接进
	 * xfs_cil的xc_committing链表，等待后续的依次处理；
	 */
	struct list_head	committing;	/* ctx committing list */
	struct work_struct	discard_endio_work;
};

/*
 * Committed Item List structure
 *
 * This structure is used to track log items that have been committed but not
 *                                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * yet written into the log. It is used only when the delayed logging mount
 * ^^^^^^^^^^^^^^^^^^^^^^^^
 * option is enabled.
 *
 * This structure tracks the list of committing checkpoint contexts so
 * we can avoid the problem of having to hold out new transactions during a
 * flush until we have a the commit record LSN of the checkpoint. We can
 * traverse the list of committing contexts in xlog_cil_push_lsn() to find a
 * sequence match and extract the commit LSN directly from there. If the
 * checkpoint is still in the process of committing, we can block waiting for
 * the commit LSN to be determined as well. This should make synchronous
 * operations almost as efficient as the old logging methods.
 *
 * CIL用于跟踪已经提交，但还没有写入log的log items；
 */
struct xfs_cil {
	struct xlog		*xc_log;
	/*
	 * 链表头，链表元素是xfs_log_item->li_cil
	 * - 6. Transaction commit就是将xfs_log_item插入这个链表
	 */
	struct list_head	xc_cil;
	/*
	 * 保护xc_cil链表
	 */
	spinlock_t		xc_cil_lock;

	/*
	 * xfs_log_commit_cil()中使用了这个信号量
	 */
	struct rw_semaphore	xc_ctx_lock ____cacheline_aligned_in_smp;
	/*
	 * checkpoint context
	 * - 当前接受事务提交的context，同一时刻只有一个
	 * - 当本context被要求push到iclog中时，本context被挂到xc_committing链表
	 *   中，xc_ctx指向一个新的context
	 */
	struct xfs_cil_ctx	*xc_ctx;

	spinlock_t		xc_push_lock ____cacheline_aligned_in_smp;
	/*
	 * 要求CIL push到iclog的最新的lsn
	 */
	xfs_lsn_t		xc_push_seq;
	/*
	 * 链表头，链表元素是xc_cil_ctx->committing
	 * - checkpoint context在被xlog_cil_push()到真正写入log buffer之前，会先
	 *   挂到CIL的这个链表上；
	 */
	struct list_head	xc_committing;
	/*
	 * 本CIL中有xfs_cil_ctx被完全写入iclog后会进行一次唤醒
	 */
	wait_queue_head_t	xc_commit_wait;
	/*
	 * 来源是CIL目前关联的xfs_cil_ctx->sequence
	 * - 每次xlog_cil_push()中新建xfs_cil_ctx时都会随之更新本字段
	 * - 目前关联的xfs_cil_ctx保存在本结构体xc_ctx中
	 */
	xfs_lsn_t		xc_current_sequence;
	struct work_struct	xc_push_work;
} ____cacheline_aligned_in_smp;

/*
 * The amount of log space we allow the CIL to aggregate is difficult to size.
 * Whatever we choose, we have to make sure we can get a reservation for the
 * log space effectively, that it is large enough to capture sufficient
 * relogging to reduce log buffer IO significantly, but it is not too large for
 * the log or induces too much latency when writing out through the iclogs. We
 * track both space consumed and the number of vectors in the checkpoint
 * context, so we need to decide which to use for limiting.
 *
 * Every log buffer we write out during a push needs a header reserved, which
 * is at least one sector and more for v2 logs. Hence we need a reservation of
 * at least 512 bytes per 32k of log space just for the LR headers. That means
 * 16KB of reservation per megabyte of delayed logging space we will consume,
 * plus various headers.  The number of headers will vary based on the num of
 * io vectors, so limiting on a specific number of vectors is going to result
 * in transactions of varying size. IOWs, it is more consistent to track and
 * limit space consumed in the log rather than by the number of objects being
 * logged in order to prevent checkpoint ticket overruns.
 *
 * Further, use of static reservations through the log grant mechanism is
 * problematic. It introduces a lot of complexity (e.g. reserve grant vs write
 * grant) and a significant deadlock potential because regranting write space
 * can block on log pushes. Hence if we have to regrant log space during a log
 * push, we can deadlock.
 *
 * However, we can avoid this by use of a dynamic "reservation stealing"
 * technique during transaction commit whereby unused reservation space in the
 * transaction ticket is transferred to the CIL ctx commit ticket to cover the
 * space needed by the checkpoint transaction. This means that we never need to
 * specifically reserve space for the CIL checkpoint transaction, nor do we
 * need to regrant space once the checkpoint completes. This also means the
 * checkpoint transaction ticket is specific to the checkpoint context, rather
 * than the CIL itself.
 *
 * With dynamic reservations, we can effectively make up arbitrary limits for
 * the checkpoint size so long as they don't violate any other size rules.
 * Recovery imposes a rule that no transaction exceed half the log, so we are
 * limited by that.  Furthermore, the log transaction reservation subsystem
 * tries to keep 25% of the log free, so we need to keep below that limit or we
 * risk running out of free log space to start any new transactions.
 *
 * In order to keep background CIL push efficient, we will set a lower
 * threshold at which background pushing is attempted without blocking current
 * transaction commits.  A separate, higher bound defines when CIL pushes are
 * enforced to ensure we stay within our maximum checkpoint size bounds.
 * threshold, yet give us plenty of space for aggregation on large logs.
 */
#define XLOG_CIL_SPACE_LIMIT(log)	(log->l_logsize >> 3)

/*
 * ticket grant locks, queues and accounting have their own cachlines
 * as these are quite hot and can be operated on concurrently.
 */
struct xlog_grant_head {
	spinlock_t		lock ____cacheline_aligned_in_smp;
	/*
	 * 排队等待有空间的xlog_ticket->t_queue；
	 */
	struct list_head	waiters;
	atomic64_t		grant;
};

/*
 * The reservation head lsn is not made up of a cycle number and block number.
 * Instead, it uses a cycle number and byte number.  Logs don't expect to
 * overflow 31 bits worth of byte offset, so using a byte number will mean
 * that round off problems won't occur when releasing partial reservations.
 */
struct xlog {
	/* The following fields don't need locking */
	struct xfs_mount	*l_mp;	        /* mount point */
	struct xfs_ail		*l_ailp;	/* AIL log is working with */
	struct xfs_cil		*l_cilp;	/* CIL log is working with */
	struct xfs_buftarg	*l_targ;        /* buftarg of log */
	struct workqueue_struct	*l_ioend_workqueue; /* for I/O completions */
	struct delayed_work	l_work;		/* background flush work */
	uint			l_flags;
	uint			l_quotaoffs_flag; /* XFS_DQ_*, for QUOTAOFFs */
	struct list_head	*l_buf_cancel_table;
	/*
	 * l_iclog_hsize = l_iclog_heads << BBSHIFT
	 * - 参见xlog_alloc_log() -> xlog_get_iclog_buffer_size()
	 * - 一个header占一个sector吗？
	 */
	int			l_iclog_hsize;  /* size of iclog header */
	int			l_iclog_heads;  /* # of iclog header sectors */
	uint			l_sectBBsize;   /* sector size in BBs (2^n) */
	/*
	 * 表示每个iclog buffer的尺寸，来源是xfs_mount->m_logbsize
	 * - xlog_in_core->ic_data的分配尺寸
	 * - 参见xlog_get_iclog_buffer_size()
	 */
	int			l_iclog_size;	/* size of log in bytes */
	/*
	 * 表示iclog buffer的数量，来源为mp->m_logbufs
	 * - 参见xlog_get_iclog_buffer_size()
	 */
	int			l_iclog_bufs;	/* number of iclog buffers */
	xfs_daddr_t		l_logBBstart;   /* start block of log */
	/*
	 * disk log space的字节长度
	 */
	int			l_logsize;      /* size of log in bytes */
	/*
	 * disk log space的BB个数
	 * - Basic Block
	 */
	int			l_logBBsize;    /* size of log in BB chunks */

	/* The following block of fields are changed while holding icloglock */
	/*
	 * 当向log buffer中写log，但log buffer状态不为ACTIVE时，在此等待队列上
	 * 睡眠。这里等待的是某些iclog被flush到磁盘的过程结束。
	 * - 等待点在： xlog_state_get_iclog_space()
	 * - wake该队列的点在： xlog_state_do_callback()
	 */
	wait_queue_head_t	l_flush_wait ____cacheline_aligned_in_smp;
						/* waiting for iclog flush */
	int			l_covered_state;/* state of "covering disk
						 * log entries" */
	/*
	 * l_iclog链表，是一个ring，循环使用；
	 */
	xlog_in_core_t		*l_iclog;       /* head log queue	*/
	spinlock_t		l_icloglock;    /* grab to change iclog state */
	/*
	 * 下面这个东西是log buffer/iclog的，还是disk log space的？
	 * - 卧槽，看l_curr_block和xlog->l_logBBsize做比较，猜测应该是disk log
	 *   > 参见xlog_state_switch_iclogs()注释
	 *   > 是的，确实是disk log space的
	 */
	int			l_curr_cycle;   /* Cycle number of log writes */
	int			l_prev_cycle;   /* Cycle number before last
						 * block increment */
	int			l_curr_block;   /* current logical log block */
	int			l_prev_block;   /* previous logical log block */

	/*
	 * l_last_sync_lsn and l_tail_lsn are atomics so they can be set and
	 * read without needing to hold specific locks. To avoid operations
	 * contending with other hot objects, place each of them on a separate
	 * cacheline.
	 */
	/*
	 * 来源是iclog->ic_header.h_lsn
	 * - 表示的是最新的已经写到disk log space的iclog的h_lsn
	 * - 该字段控制AIL flush可以进行的最大lsn
	 *   > 大于该lsn表示iclog还未写入disk log space，AIL flush不安全
	 */
	atomic64_t		l_last_sync_lsn ____cacheline_aligned_in_smp;
	/*
	 * lsn of 1st LR with unflushed * buffers
	 * - 在iclog中等待写到磁盘metadata region上的（AIL中的）最小的lsn 
	 *   > 最小的表示AIL中最老的
	 * - 参见：xlog_assign_tail_lsn_locked()
	 *
	 * 这个值变大，表示disk log space上释放了一些空间！
	 */
	atomic64_t		l_tail_lsn ____cacheline_aligned_in_smp;

	/*
	 * 上面的lsn和xlog_grant_head都编码了位置信息，但编码格式不同；
	 * - 对lsn，参见： xlog_assign_atomic_lsn()
	 * - 对xlog_grant_head，参见： xlog_assign_grant_head()
	 *
	 * l_reserve_head表示log space on disk上已保留的日志尾巴；
	 *
	 * 这个两个head的区别？
	 */
	struct xlog_grant_head	l_reserve_head;
	struct xlog_grant_head	l_write_head;

	struct xfs_kobj		l_kobj;

	/* The following field are used for debugging; need to hold icloglock */
#ifdef DEBUG
	void			*l_iclog_bak[XLOG_MAX_ICLOGS];
	/* log record crc error injection factor */
	uint32_t		l_badcrc_factor;
#endif
	/* log recovery lsn tracking (for buffer submission */
	xfs_lsn_t		l_recovery_lsn;
};

#define XLOG_BUF_CANCEL_BUCKET(log, blkno) \
	((log)->l_buf_cancel_table + ((uint64_t)blkno % XLOG_BC_TABLE_SIZE))

#define XLOG_FORCED_SHUTDOWN(log)	((log)->l_flags & XLOG_IO_ERROR)

/* common routines */
extern int
xlog_recover(
	struct xlog		*log);
extern int
xlog_recover_finish(
	struct xlog		*log);
extern void
xlog_recover_cancel(struct xlog *);

extern __le32	 xlog_cksum(struct xlog *log, struct xlog_rec_header *rhead,
			    char *dp, int size);

extern kmem_zone_t *xfs_log_ticket_zone;
struct xlog_ticket *
xlog_ticket_alloc(
	struct xlog	*log,
	int		unit_bytes,
	int		count,
	char		client,
	bool		permanent,
	xfs_km_flags_t	alloc_flags);


static inline void
xlog_write_adv_cnt(void **ptr, int *len, int *off, size_t bytes)
{
	*ptr += bytes;
	*len -= bytes;
	*off += bytes;
}

void	xlog_print_tic_res(struct xfs_mount *mp, struct xlog_ticket *ticket);
void	xlog_print_trans(struct xfs_trans *);
int
xlog_write(
	struct xlog		*log,
	struct xfs_log_vec	*log_vector,
	struct xlog_ticket	*tic,
	xfs_lsn_t		*start_lsn,
	struct xlog_in_core	**commit_iclog,
	uint			flags);

/*
 * When we crack an atomic LSN, we sample it first so that the value will not
 * change while we are cracking it into the component values. This means we
 * will always get consistent component values to work from. This should always
 * be used to sample and crack LSNs that are stored and updated in atomic
 * variables.
 */
static inline void
xlog_crack_atomic_lsn(atomic64_t *lsn, uint *cycle, uint *block)
{
	xfs_lsn_t val = atomic64_read(lsn);

	*cycle = CYCLE_LSN(val);
	*block = BLOCK_LSN(val);
}

/*
 * Calculate and assign a value to an atomic LSN variable from component pieces.
 */
static inline void
xlog_assign_atomic_lsn(atomic64_t *lsn, uint cycle, uint block)
{
	atomic64_set(lsn, xlog_assign_lsn(cycle, block));
}

/*
 * When we crack the grant head, we sample it first so that the value will not
 * change while we are cracking it into the component values. This means we
 * will always get consistent component values to work from.
 */
static inline void
xlog_crack_grant_head_val(int64_t val, int *cycle, int *space)
{
	*cycle = val >> 32;
	*space = val & 0xffffffff;
}

static inline void
xlog_crack_grant_head(atomic64_t *head, int *cycle, int *space)
{
	xlog_crack_grant_head_val(atomic64_read(head), cycle, space);
}

static inline int64_t
xlog_assign_grant_head_val(int cycle, int space)
{
	return ((int64_t)cycle << 32) | space;
}

static inline void
xlog_assign_grant_head(atomic64_t *head, int cycle, int space)
{
	atomic64_set(head, xlog_assign_grant_head_val(cycle, space));
}

/*
 * Committed Item List interfaces
 */
int	xlog_cil_init(struct xlog *log);
void	xlog_cil_init_post_recovery(struct xlog *log);
void	xlog_cil_destroy(struct xlog *log);
bool	xlog_cil_empty(struct xlog *log);

/*
 * CIL force routines
 */
xfs_lsn_t
xlog_cil_force_lsn(
	struct xlog *log,
	xfs_lsn_t sequence);

static inline void
xlog_cil_force(struct xlog *log)
{
	xlog_cil_force_lsn(log, log->l_cilp->xc_current_sequence);
}

/*
 * Unmount record type is used as a pseudo transaction type for the ticket.
 * It's value must be outside the range of XFS_TRANS_* values.
 */
#define XLOG_UNMOUNT_REC_TYPE	(-1U)

/*
 * Wrapper function for waiting on a wait queue serialised against wakeups
 * by a spinlock. This matches the semantics of all the wait queues used in the
 * log code.
 */
static inline void xlog_wait(wait_queue_head_t *wq, spinlock_t *lock)
{
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue_exclusive(wq, &wait);
	__set_current_state(TASK_UNINTERRUPTIBLE);
	spin_unlock(lock);
	schedule();
	remove_wait_queue(wq, &wait);
}

/*
 * The LSN is valid so long as it is behind the current LSN. If it isn't, this
 * means that the next log record that includes this metadata could have a
 * smaller LSN. In turn, this means that the modification in the log would not
 * replay.
 */
static inline bool
xlog_valid_lsn(
	struct xlog	*log,
	xfs_lsn_t	lsn)
{
	int		cur_cycle;
	int		cur_block;
	bool		valid = true;

	/*
	 * First, sample the current lsn without locking to avoid added
	 * contention from metadata I/O. The current cycle and block are updated
	 * (in xlog_state_switch_iclogs()) and read here in a particular order
	 * to avoid false negatives (e.g., thinking the metadata LSN is valid
	 * when it is not).
	 *
	 * The current block is always rewound before the cycle is bumped in
	 * xlog_state_switch_iclogs() to ensure the current LSN is never seen in
	 * a transiently forward state. Instead, we can see the LSN in a
	 * transiently behind state if we happen to race with a cycle wrap.
	 */
	cur_cycle = READ_ONCE(log->l_curr_cycle);
	smp_rmb();
	cur_block = READ_ONCE(log->l_curr_block);

	if ((CYCLE_LSN(lsn) > cur_cycle) ||
	    (CYCLE_LSN(lsn) == cur_cycle && BLOCK_LSN(lsn) > cur_block)) {
		/*
		 * If the metadata LSN appears invalid, it's possible the check
		 * above raced with a wrap to the next log cycle. Grab the lock
		 * to check for sure.
		 */
		spin_lock(&log->l_icloglock);
		cur_cycle = log->l_curr_cycle;
		cur_block = log->l_curr_block;
		spin_unlock(&log->l_icloglock);

		if ((CYCLE_LSN(lsn) > cur_cycle) ||
		    (CYCLE_LSN(lsn) == cur_cycle && BLOCK_LSN(lsn) > cur_block))
			valid = false;
	}

	return valid;
}

#endif	/* __XFS_LOG_PRIV_H__ */
