// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2010 Red Hat, Inc. All Rights Reserved.
 */

#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_shared.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_extent_busy.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"
#include "xfs_log.h"
#include "xfs_log_priv.h"
#include "xfs_trace.h"

struct workqueue_struct *xfs_discard_wq;

/*
 * Allocate a new ticket. Failing to get a new ticket makes it really hard to
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * recover, so we don't allow failure here. Also, we allocate in a context that
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * we don't want to be issuing transactions from, so we need to tell the
 * allocation code this as well.
 *
 * We don't reserve any space for the ticket - we are going to steal whatever
 * space we require from transactions as they commit. To ensure we reserve all
 * the space required, we need to set the current reservation of the ticket to
 * zero so that we know to steal the initial transaction overhead from the
 * first transaction commit.
 */
static struct xlog_ticket *
xlog_cil_ticket_alloc(
	struct xlog	*log)
{
	struct xlog_ticket *tic;

	tic = xlog_ticket_alloc(log, 0, 1, XFS_TRANSACTION, 0,
				KM_NOFS);

	/*
	 * set the current reservation to zero so we know to steal the basic
	 * transaction overhead reservation from the first transaction commit.
	 */
	tic->t_curr_res = 0;
	return tic;
}

/*
 * After the first stage of log recovery is done, we know where the head and
 * tail of the log are. We need this log initialisation done before we can
 * initialise the first CIL checkpoint context.
 *
 * Here we allocate a log ticket to track space usage during a CIL push.  This
 * ticket is passed to xlog_write() directly so that we don't slowly leak log
 * space by failing to account for space used by log headers and additional
 * region headers for split regions.
 */
void
xlog_cil_init_post_recovery(
	struct xlog	*log)
{
	log->l_cilp->xc_ctx->ticket = xlog_cil_ticket_alloc(log);
	log->l_cilp->xc_ctx->sequence = 1;
}

static inline int
xlog_cil_iovec_space(
	uint	niovecs)
{
	return round_up((sizeof(struct xfs_log_vec) +
					niovecs * sizeof(struct xfs_log_iovec)),
			sizeof(uint64_t));
}

/*
 * Allocate or pin log vector buffers for CIL insertion.
 *             ^^^^^^^^^^^^^^^^^^^^^^
 *            只看见了alloc，没看见pin
 *
 * The CIL currently uses disposable buffers for copying a snapshot of the
 * modified items into the log during a push. The biggest problem with this is
 * the requirement to allocate the disposable buffer during the commit if:
 *	a) does not exist; or
 *	b) it is too small
 *
 * If we do this allocation within xlog_cil_insert_format_items(), it is done
 * under the xc_ctx_lock, which means that a CIL push cannot occur during
 *                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * the memory allocation. This means that we have a potential deadlock situation
 * ^^^^^^^^^^^^^^^^^^^^^^
 *  CIL push需要争抢这里已经持有的xc_ctx_lock，因此无法进行
 * under low memory conditions when we have lots of dirty metadata pinned in
 * the CIL and we need a CIL commit to occur to free memory.
 *
 * To avoid this, we need to move the memory allocation outside the
 * xc_ctx_lock, but because the log vector buffers are disposable, that opens
 * up a TOCTOU race condition w.r.t. the CIL committing and removing the log
 * vector buffers between the check and the formatting of the item into the
 * log vector buffer within the xc_ctx_lock.
 *
 * Because the log vector buffer needs to be unchanged during the CIL push
 * process, we cannot share the buffer between the transaction commit (which
 * modifies the buffer) and the CIL push context that is writing the changes
 * into the log. This means skipping preallocation of buffer space is
 * unreliable, but we most definitely do not want to be allocating and freeing
 * buffers unnecessarily during commits when overwrites can be done safely.
 *
 * The simplest solution to this problem is to allocate a shadow buffer when a
 * log item is committed for the second time, and then to only use this buffer
 * if necessary. The buffer can remain attached to the log item until such time
 * it is needed, and this is the buffer that is reallocated to match the size of
 * the incoming modification. Then during the formatting of the item we can swap
 * the active buffer with the new one if we can't reuse the existing buffer. We
 * don't free the old buffer as it may be reused on the next modification if
 * it's size is right, otherwise we'll free and reallocate it at that point.
 *
 * This function builds a vector for the changes in each log item in the
 * transaction. It then works out the length of the buffer needed for each log
 * item, allocates them and attaches the vector to the log item in preparation
 * for the formatting step which occurs under the xc_ctx_lock.
 *
 * While this means the memory footprint goes up, it avoids the repeated
 * alloc/free pattern that repeated modifications of an item would otherwise
 * cause, and hence minimises the CPU overhead of such behaviour.
 */
static void
xlog_cil_alloc_shadow_bufs(
	struct xlog		*log,
	struct xfs_trans	*tp)
{
	struct xfs_log_item	*lip;

	list_for_each_entry(lip, &tp->t_items, li_trans) {
		struct xfs_log_vec *lv;
		int	niovecs = 0;
		int	nbytes = 0;
		int	buf_size;
		bool	ordered = false;

		/* Skip items which aren't dirty in this transaction. */
		if (!test_bit(XFS_LI_DIRTY, &lip->li_flags))
			continue;

		/*
		 * get number of vecs and size of data to be stored
		 *
		 * CUI: refcount update intent item: xfs_cui_item_ops.xfs_cui_item_size()
		 */
		lip->li_ops->iop_size(lip, &niovecs, &nbytes);

		/*
		 * Ordered items need to be tracked but we do not wish to write
		 * them. We need a logvec to track the object, but we do not
		 * need an iovec or buffer to be allocated for copying data.
		 */
		if (niovecs == XFS_LOG_VEC_ORDERED) {
			ordered = true;
			niovecs = 0;
			nbytes = 0;
		}

		/*
		 * We 64-bit align the length of each iovec so that the start
		 * of the next one is naturally aligned.  We'll need to
		 * account for that slack space here. Then round nbytes up
		 * to 64-bit alignment so that the initial buffer alignment is
		 * easy to calculate and verify.
		 */
		nbytes += niovecs * sizeof(uint64_t);
		nbytes = round_up(nbytes, sizeof(uint64_t));

		/*
		 * The data buffer needs to start 64-bit aligned, so round up
		 * that space to ensure we can align it appropriately and not
		 * overrun the buffer.
		 */
		buf_size = nbytes + xlog_cil_iovec_space(niovecs);

		/*
		 * if we have no shadow buffer, or it is too small, we need to
		 * reallocate it.
		 */
		if (!lip->li_lv_shadow ||
		    buf_size > lip->li_lv_shadow->lv_size) {
		/*
		 * 进入的两种情况：
		 * - xfs_log_item->li_lv_shadow为空
		 * - xfs_log_item->li_lv_shadow不为空，但其尺寸小于buf
		 */

			/*
			 * We free and allocate here as a realloc would copy
			 * unecessary data. We don't use kmem_zalloc() for the
			 * same reason - we don't need to zero the data area in
			 * the buffer, only the log vector header and the iovec
			 * storage.
			 */
			kmem_free(lip->li_lv_shadow);

			lv = kmem_alloc_large(buf_size, KM_NOFS);
			/*
			 * 至少整个xfs_log_vec部分是全部都清零了的；
			 */
			memset(lv, 0, xlog_cil_iovec_space(niovecs));

			lv->lv_item = lip;
			lv->lv_size = buf_size;
			if (ordered)
				lv->lv_buf_len = XFS_LOG_VEC_ORDERED;
			else
			/*
			 * 上面通过kmem_alloc_large()分配了一个肯定足够大的内存，
			 * 这个内存头部存放的是xfs_log_vec结构体，其lv_iovecp字段
			 * 指向一个xfs_log_iovec数组，这个数组在这块内存中紧挨着
			 * xfs_log_vec的尾部，这个(struct xfs_log_iovec *)&lv[1]
			 * 就是为了求得xfs_log_vec结构体结束后的第一个字节；
			 */
				lv->lv_iovecp = (struct xfs_log_iovec *)&lv[1];
			lip->li_lv_shadow = lv;
		} else {
		/*
		 * 进入只有一种情况：
		 * - xfs_log_item->li_lv_shadow不为空，且其尺寸大于等于buf
		 */
			/* same or smaller, optimise common overwrite case */
			lv = lip->li_lv_shadow;
			if (ordered)
				lv->lv_buf_len = XFS_LOG_VEC_ORDERED;
			else
				lv->lv_buf_len = 0;
			lv->lv_bytes = 0;
			lv->lv_next = NULL;
		}

		/* Ensure the lv is set up according to ->iop_size */
		lv->lv_niovecs = niovecs;

		/* The allocated data region lies beyond the iovec region */
		/*
		 * xfs_log_iovec本身也只是一个定位的结构体，真实的数据跟在
		 * xfs_log_iovec数组后面；
		 * - 详见xfs_log_vec结构体注释；
		 *
		 * 这个东西是不是文档中提到的memory buffer？
		 * - 是的！
		 */
		lv->lv_buf = (char *)lv + xlog_cil_iovec_space(niovecs);
	}

}

/*
 * Prepare the log item for insertion into the CIL. Calculate the difference in
 * log space and vectors it will consume, and if it is a new item pin it as
 * well.
 */
STATIC void
xfs_cil_prepare_item(
	struct xlog		*log,
	struct xfs_log_vec	*lv,
	struct xfs_log_vec	*old_lv,
	int			*diff_len,
	int			*diff_iovecs)
{
	/* Account for the new LV being passed in */
	if (lv->lv_buf_len != XFS_LOG_VEC_ORDERED) {
		*diff_len += lv->lv_bytes;
		*diff_iovecs += lv->lv_niovecs;
	}

	/*
	 * If there is no old LV, this is the first time we've seen the item in
	 * this CIL context and so we need to pin it. If we are replacing the
	 * old_lv, then remove the space it accounts for and make it the shadow
	 * buffer for later freeing. In both cases we are now switching to the
	 * shadow buffer, so update the the pointer to it appropriately.
	 *
	 * 所以lv一开始没有分配，第一次总是会用lv_shadow；
	 */
	if (!old_lv) {
		/*
		 * pin log item，不同类型的log item有不同的方法
		 */
		if (lv->lv_item->li_ops->iop_pin)
			lv->lv_item->li_ops->iop_pin(lv->lv_item);
		lv->lv_item->li_lv_shadow = NULL;
	} else if (old_lv != lv) {
		ASSERT(lv->lv_buf_len != XFS_LOG_VEC_ORDERED);

		*diff_len -= old_lv->lv_bytes;
		*diff_iovecs -= old_lv->lv_niovecs;
		lv->lv_item->li_lv_shadow = old_lv;
	}

	/* attach new log vector to log item */
	/*
	 * 将xfs_log_vec关联到xfs_log_item;
	 */
	lv->lv_item->li_lv = lv;

	/*
	 * If this is the first time the item is being committed to the
	 * CIL, store the sequence number on the log item so we can
	 * tell in future commits whether this is the first checkpoint
	 * the item is being committed into.
	 */
	if (!lv->lv_item->li_seq)
		lv->lv_item->li_seq = log->l_cilp->xc_ctx->sequence;
}

/*
 * Format log item into a flat buffers
 *
 * For delayed logging, we need to hold a formatted buffer containing all the
 * changes on the log item. This enables us to relog the item in memory and
 * write it out asynchronously without needing to relock the object that was
 * modified at the time it gets written into the iclog.
 *
 * This function takes the prepared log vectors attached to each log item, and
 * formats the changes into the log vector buffer. The buffer it uses is
 * dependent on the current state of the vector in the CIL - the shadow lv is
 * guaranteed to be large enough for the current modification, but we will only
 * use that if we can't reuse the existing lv. If we can't reuse the existing
 * lv, then simple swap it out for the shadow lv. We don't free it - that is
 * done lazily either by th enext modification or the freeing of the log item.
 *
 * We don't set up region headers during this process; we simply copy the
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * regions into the flat buffer. We can do this because we still have to do a
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * formatting step to write the regions into the iclog buffer.  Writing the
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^
 * ophdrs during the iclog write means that we can support splitting large
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * regions across iclog boundares without needing a change in the format of the
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * item/region encapsulation.
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^
 *
 * Hence what we need to do now is change the rewrite the vector array to point
 * to the copied region inside the buffer we just allocated. This allows us to
 * format the regions into the iclog as though they are being formatted
 * directly out of the objects themselves.
 */
static void
xlog_cil_insert_format_items(
	struct xlog		*log,
	struct xfs_trans	*tp,
	int			*diff_len,
	int			*diff_iovecs)
{
	struct xfs_log_item	*lip;


	/* Bail out if we didn't find a log item.  */
	if (list_empty(&tp->t_items)) {
		ASSERT(0);
		return;
	}

	list_for_each_entry(lip, &tp->t_items, li_trans) {
		struct xfs_log_vec *lv;
		struct xfs_log_vec *old_lv = NULL;
		struct xfs_log_vec *shadow;
		bool	ordered = false;

		/* Skip items which aren't dirty in this transaction. */
		if (!test_bit(XFS_LI_DIRTY, &lip->li_flags))
			continue;

		/*
		 * The formatting size information is already attached to
		 * the shadow lv on the log item.
		 */
		shadow = lip->li_lv_shadow;
		if (shadow->lv_buf_len == XFS_LOG_VEC_ORDERED)
			ordered = true;

		/* Skip items that do not have any vectors for writing */
		/*
		 * 这种情况意味着啥都不需要写
		 */
		if (!shadow->lv_niovecs && !ordered)
			continue;

		/* compare to existing item size */
		old_lv = lip->li_lv;
		/*
		 * 意思就是谁大用谁
		 */
		if (lip->li_lv && shadow->lv_size <= lip->li_lv->lv_size) {
			/* same or smaller, optimise common overwrite case */
			lv = lip->li_lv;
			lv->lv_next = NULL;

			if (ordered)
				goto insert;

			/*
			 * set the item up as though it is a new insertion so
			 * that the space reservation accounting is correct.
			 */
			*diff_iovecs -= lv->lv_niovecs;
			*diff_len -= lv->lv_bytes;

			/* Ensure the lv is set up according to ->iop_size */
			lv->lv_niovecs = shadow->lv_niovecs;

			/* reset the lv buffer information for new formatting */
			lv->lv_buf_len = 0;
			lv->lv_bytes = 0;
			lv->lv_buf = (char *)lv +
					xlog_cil_iovec_space(lv->lv_niovecs);
		} else {
			/* switch to shadow buffer! */
			lv = shadow;
			lv->lv_item = lip;
			if (ordered) {
				/* track as an ordered logvec */
				ASSERT(lip->li_lv == NULL);
				goto insert;
			}
		}

		ASSERT(IS_ALIGNED((unsigned long)lv->lv_buf, sizeof(uint64_t)));
		/*
		 * 这里也是定义了与xfs_log_item类型相关的format方法，用于将其格式化
		 * 到memory buffer中去；
		 * - 对于xfs_inode_log_item，是 xfs_inode_item_format()
		 */
		lip->li_ops->iop_format(lip, lv);
insert:
		/*
		 * 里面调用了iop_pin()，所以是先format后pin
		 * - 也不一定，要看old_lv是否已经分配了；
		 */
		xfs_cil_prepare_item(log, lv, old_lv, diff_len, diff_iovecs);
	}
}

/*
 * Insert the log items into the CIL and calculate the difference in space
 * consumed by the item. Add the space to the checkpoint ticket and calculate
 * if the change requires additional log metadata. If it does, take that space
 * as well. Remove the amount of space we added to the checkpoint ticket from
 * the current transaction ticket so that the accounting works out correctly.
 */
static void
xlog_cil_insert_items(
	struct xlog		*log,
	struct xfs_trans	*tp)
{
	struct xfs_cil		*cil = log->l_cilp;
	struct xfs_cil_ctx	*ctx = cil->xc_ctx;
	struct xfs_log_item	*lip;
	int			len = 0;
	int			diff_iovecs = 0;
	int			iclog_space;
	int			iovhdr_res = 0, split_res = 0, ctx_res = 0;

	ASSERT(tp);

	/*
	 * We can do this safely because the context can't checkpoint until we
	 * are done so it doesn't matter exactly how we update the CIL.
	 *
	 * 准备好一个可以插入到CIL中xfs_log_item
	 * - 关联已经准备好的xfs_log_vec/xfs_log_iovec
	 * - 将logical log format到xfs_log_vec->lv_buf中
	 */
	xlog_cil_insert_format_items(log, tp, &len, &diff_iovecs);

	spin_lock(&cil->xc_cil_lock);

	/*
	 * account for space used by new iovec headers
	 * - 这里之所以有个diff操作，是因为本次commit的xfs_trans中所包含的
	 *   xfs_log_item本身已经处于CIL中了，这里因为relog accumulate导致没有
	 *   生成新的xfs_log_item，而是把原来的xfs_log_item在CIL中后移。此时：
	 *   > 如果继续使用上次commit时分配的xfs_log_vec，就可能存在尺寸不同的
	 *     情况，此时所以要重新计算log vec的尺寸和用量。
	 *   > 如果使用本次分配的xfs_log_vec shadow，则diff_xxx会是0，不影响
	 */
	iovhdr_res = diff_iovecs * sizeof(xlog_op_header_t);
	len += iovhdr_res;
	ctx->nvecs += diff_iovecs;

	/* attach the transaction to the CIL if it has any busy extents */
	if (!list_empty(&tp->t_busy))
		list_splice_init(&tp->t_busy, &ctx->busy_extents);

	/*
	 * Now transfer enough transaction reservation to the context ticket
	 * for the checkpoint. The context ticket is special - the unit
	 * reservation has to grow as well as the current reservation as we
	 * steal from tickets so we can correctly determine the space used
	 * during the transaction commit.
	 */
	if (ctx->ticket->t_curr_res == 0) {
		ctx_res = ctx->ticket->t_unit_res;
		ctx->ticket->t_curr_res = ctx_res;
		tp->t_ticket->t_curr_res -= ctx_res;
	}

	/* do we need space for more log record headers? */
	/*
	 * xlog_in_core->ic_data的分配尺寸剪掉iclog header尺寸
	 */
	iclog_space = log->l_iclog_size - log->l_iclog_hsize;
	if (len > 0 && (ctx->space_used / iclog_space !=
				(ctx->space_used + len) / iclog_space)) {
		split_res = (len + iclog_space - 1) / iclog_space;
		/* need to take into account split region headers, too */
		split_res *= log->l_iclog_hsize + sizeof(struct xlog_op_header);
		ctx->ticket->t_unit_res += split_res;
		ctx->ticket->t_curr_res += split_res;
		tp->t_ticket->t_curr_res -= split_res;
		ASSERT(tp->t_ticket->t_curr_res >= len);
	}
	tp->t_ticket->t_curr_res -= len;
	ctx->space_used += len;

	/*
	 * If we've overrun the reservation, dump the tx details before we move
	 * the log items. Shutdown is imminent...
	 */
	if (WARN_ON(tp->t_ticket->t_curr_res < 0)) {
		xfs_warn(log->l_mp, "Transaction log reservation overrun:");
		xfs_warn(log->l_mp,
			 "  log items: %d bytes (iov hdrs: %d bytes)",
			 len, iovhdr_res);
		xfs_warn(log->l_mp, "  split region headers: %d bytes",
			 split_res);
		xfs_warn(log->l_mp, "  ctx ticket: %d bytes", ctx_res);
		xlog_print_trans(tp);
	}

	/*
	 * Now (re-)position everything modified at the tail of the CIL.
	 * We do this here so we only need to take the CIL lock once during
	 * the transaction commit.
	 *
	 * 这里是将在tp->t_items链表上的元素在cil->xc_cil链表上后移，所以
	 * 不需要使用safe版本；
	 * - 这就是relog产生的多个log发生accumulate的地方。第N+1次修改不会在CIL
	 *   中产生一个新的xfs_log_item，而是将第N次修改的xfs_log_item在CIL中后
	 *   移，此时xfs_log_item中保存的是第N+1次的修改；
	 */
	list_for_each_entry(lip, &tp->t_items, li_trans) {

		/* Skip items which aren't dirty in this transaction. */
		if (!test_bit(XFS_LI_DIRTY, &lip->li_flags))
			continue;

		/*
		 * Only move the item if it isn't already at the tail. This is
		 * to prevent a transient list_empty() state when reinserting
		 * an item that is already the only item in the CIL.
		 *
		 * 其实并没有看到哪里调用了list_add(&lip->li_cil, &cil->xc_cil)，
		 * 仅有的包含插入操作的代码就是这里。
		 * - 如果lip->li_cil从来没有插入过cil->xc_cil链表中，下面的if语
		 *   句也是会进入的；应该就是通过这种方法完成了插入的吧。
		 *
		 * 这个时候，CIL中直接挂xfs_log_item；
		 * - 后面这个链表会直接从CIL中摘除，转换后放到Checkpoint Context
		 *   的链表中，彼时链表元素是xfs_log_vec；
		 *   > 参见：文档 3.3.3 Checkpoints
		 *
		 * CIL中的元素什么时候处理呢？
		 * - xfs_log_force_lsn() ~> xlog_cil_push()
		 */
		if (!list_is_last(&lip->li_cil, &cil->xc_cil))
			list_move_tail(&lip->li_cil, &cil->xc_cil);
	}

	spin_unlock(&cil->xc_cil_lock);

	if (tp->t_ticket->t_curr_res < 0)
		xfs_force_shutdown(log->l_mp, SHUTDOWN_LOG_IO_ERROR);
}

static void
xlog_cil_free_logvec(
	struct xfs_log_vec	*log_vector)
{
	struct xfs_log_vec	*lv;

	for (lv = log_vector; lv; ) {
		struct xfs_log_vec *next = lv->lv_next;
		/*
		 * xfs_log_iovec是紧跟在xfs_log_vec后，两者一起分配内存的；所以
		 * 这里也是一起释放掉；
		 */
		kmem_free(lv);
		lv = next;
	}
}

static void
xlog_discard_endio_work(
	struct work_struct	*work)
{
	struct xfs_cil_ctx	*ctx =
		container_of(work, struct xfs_cil_ctx, discard_endio_work);
	struct xfs_mount	*mp = ctx->cil->xc_log->l_mp;

	xfs_extent_busy_clear(mp, &ctx->busy_extents, false);
	kmem_free(ctx);
}

/*
 * Queue up the actual completion to a thread to avoid IRQ-safe locking for
 * pagb_lock.  Note that we need a unbounded workqueue, otherwise we might
 * get the execution delayed up to 30 seconds for weird reasons.
 */
static void
xlog_discard_endio(
	struct bio		*bio)
{
	struct xfs_cil_ctx	*ctx = bio->bi_private;

	INIT_WORK(&ctx->discard_endio_work, xlog_discard_endio_work);
	queue_work(xfs_discard_wq, &ctx->discard_endio_work);
	bio_put(bio);
}

static void
xlog_discard_busy_extents(
	struct xfs_mount	*mp,
	struct xfs_cil_ctx	*ctx)
{
	struct list_head	*list = &ctx->busy_extents;
	struct xfs_extent_busy	*busyp;
	struct bio		*bio = NULL;
	struct blk_plug		plug;
	int			error = 0;

	ASSERT(mp->m_flags & XFS_MOUNT_DISCARD);

	blk_start_plug(&plug);
	list_for_each_entry(busyp, list, list) {
		trace_xfs_discard_extent(mp, busyp->agno, busyp->bno,
					 busyp->length);

		error = __blkdev_issue_discard(mp->m_ddev_targp->bt_bdev,
				XFS_AGB_TO_DADDR(mp, busyp->agno, busyp->bno),
				XFS_FSB_TO_BB(mp, busyp->length),
				GFP_NOFS, 0, &bio);
		if (error && error != -EOPNOTSUPP) {
			xfs_info(mp,
	 "discard failed for extent [0x%llx,%u], error %d",
				 (unsigned long long)busyp->bno,
				 busyp->length,
				 error);
			break;
		}
	}

	if (bio) {
		bio->bi_private = ctx;
		bio->bi_end_io = xlog_discard_endio;
		submit_bio(bio);
	} else {
		xlog_discard_endio_work(&ctx->discard_endio_work);
	}
	blk_finish_plug(&plug);
}

/*
 * Mark all items committed and clear busy extents. We free the log vector
 * chains in a separate pass so that we unpin the log items as quickly as
 * possible.
 */
static void
xlog_cil_committed(
	struct xfs_cil_ctx	*ctx,
	bool			abort)
{
	struct xfs_mount	*mp = ctx->cil->xc_log->l_mp;

	/*
	 * If the I/O failed, we're aborting the commit and already shutdown.
	 * Wake any commit waiters before aborting the log items so we don't
	 * block async log pushers on callbacks. Async log pushers explicitly do
	 * not wait on log force completion because they may be holding locks
	 * required to unpin items.
	 */
	if (abort) {
		spin_lock(&ctx->cil->xc_push_lock);
		wake_up_all(&ctx->cil->xc_commit_wait);
		spin_unlock(&ctx->cil->xc_push_lock);
	}

	/*
	 * 将ctx中xfs_log_item插入到AIL中；
	 */
	xfs_trans_committed_bulk(ctx->cil->xc_log->l_ailp, ctx->lv_chain,
					ctx->start_lsn, abort);

	xfs_extent_busy_sort(&ctx->busy_extents);
	xfs_extent_busy_clear(mp, &ctx->busy_extents,
			     (mp->m_flags & XFS_MOUNT_DISCARD) && !abort);

	spin_lock(&ctx->cil->xc_push_lock);
	list_del(&ctx->committing);
	spin_unlock(&ctx->cil->xc_push_lock);

	/*
	 * 此时可以释放掉xfs_log_item关联的xfs_log_vec/xfs_log_iovec了
	 * - 为什么不是写入iclog就释放呢？
	 */
	xlog_cil_free_logvec(ctx->lv_chain);

	if (!list_empty(&ctx->busy_extents))
		xlog_discard_busy_extents(mp, ctx);
	else
		kmem_free(ctx);
}

void
xlog_cil_process_committed(
	struct list_head	*list,
	bool			aborted)
{
	struct xfs_cil_ctx	*ctx;

	while ((ctx = list_first_entry_or_null(list,
			struct xfs_cil_ctx, iclog_entry))) {
		list_del(&ctx->iclog_entry);
		xlog_cil_committed(ctx, aborted);
	}
}

/*
 * Push the Committed Item List to the log. If @push_seq flag is zero, then it
 * is a background flush and so we can chose to ignore it. Otherwise, if the
 * current sequence is the same as @push_seq we need to do a flush. If
 * @push_seq is less than the current sequence, then it has already been
 * flushed and we don't need to do anything - the caller will wait for it to
 * complete if necessary.
 *
 * @push_seq is a value rather than a flag because that allows us to do an
 * unlocked check of the sequence number for a match. Hence we can allows log
 * forces to run racily and not issue pushes for the same sequence twice. If we
 * get a race between multiple pushes for the same sequence they will block on
 * the first one and then abort, hence avoiding needless pushes.
 */
STATIC int
xlog_cil_push(
	struct xlog		*log)
{
	struct xfs_cil		*cil = log->l_cilp;
	struct xfs_log_vec	*lv;
	struct xfs_cil_ctx	*ctx;
	struct xfs_cil_ctx	*new_ctx;
	struct xlog_in_core	*commit_iclog;
	struct xlog_ticket	*tic;
	int			num_iovecs;
	int			error = 0;
	struct xfs_trans_header thdr;
	struct xfs_log_iovec	lhdr;
	struct xfs_log_vec	lvhdr = { NULL };
	xfs_lsn_t		commit_lsn;
	xfs_lsn_t		push_seq;

	if (!cil)
		return 0;

	/*
	 * 每次push都要生成一个新的xfs_cil_ctx
	 */
	new_ctx = kmem_zalloc(sizeof(*new_ctx), KM_NOFS);
	/*
	 * 给新分配的xfs_cil_ctx分配xlog_ticket
	 * - 这个ticket的作用是？
	 */
	new_ctx->ticket = xlog_cil_ticket_alloc(log);

	down_write(&cil->xc_ctx_lock);
	ctx = cil->xc_ctx;

	spin_lock(&cil->xc_push_lock);
	push_seq = cil->xc_push_seq;
	ASSERT(push_seq <= ctx->sequence);

	/*
	 * Check if we've anything to push. If there is nothing, then we don't
	 * move on to a new sequence number and so we have to be able to push
	 * this sequence again later.
	 */
	if (list_empty(&cil->xc_cil)) {
		cil->xc_push_seq = 0;
		spin_unlock(&cil->xc_push_lock);
		goto out_skip;
	}


	/* check for a previously pushed seqeunce */
	if (push_seq < cil->xc_ctx->sequence) {
		spin_unlock(&cil->xc_push_lock);
		goto out_skip;
	}

	/*
	 * We are now going to push this context, so add it to the committing
	 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
	 * list before we do anything else. This ensures that anyone waiting on
	 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
	 * this push can easily detect the difference between a "push in
	 * progress" and "CIL is empty, nothing to do".
	 *
	 * IOWs, a wait loop can now check for:
	 *	the current sequence not being found on the committing list;
	 *	an empty CIL; and
	 *	an unchanged sequence number
	 * to detect a push that had nothing to do and therefore does not need
	 * waiting on. If the CIL is not empty, we get put on the committing
	 * list before emptying the CIL and bumping the sequence number. Hence
	 * an empty CIL and an unchanged sequence number means we jumped out
	 * above after doing nothing.
	 *
	 * Hence the waiter will either find the commit sequence on the
	 * committing list or the sequence number will be unchanged and the CIL
	 * still dirty. In that latter case, the push has not yet started, and
	 * so the waiter will have to continue trying to check the CIL
	 * committing list until it is found. In extreme cases of delay, the
	 * sequence may fully commit between the attempts the wait makes to wait
	 * on the commit sequence.
	 *
	 * 将要push的checkpoint context挂到CIL的xc_committing链表上；
	 */
	list_add(&ctx->committing, &cil->xc_committing);
	spin_unlock(&cil->xc_push_lock);

	/*
	 * pull all the log vectors off the items in the CIL, and
	 * remove the items from the CIL. We don't need the CIL lock
	 * here because it's only needed on the transaction commit
	 * side which is currently locked out by the flush lock.
	 */
	lv = NULL;
	num_iovecs = 0;
	/*
	 * 将CIL整个取下来，将其中每一个xfs_log_item对应的xfs_log_vec挂到
	 * xfs_cil_ctx->lv_chain上；
	 */
	while (!list_empty(&cil->xc_cil)) {
		struct xfs_log_item	*item;

		item = list_first_entry(&cil->xc_cil,
					struct xfs_log_item, li_cil);
		list_del_init(&item->li_cil);
		/*
		 * 第一次运行到这里时一定走第一个分支
		 */
		if (!ctx->lv_chain)
			ctx->lv_chain = item->li_lv;
		else
			lv->lv_next = item->li_lv;
		lv = item->li_lv;
		/*
		 * xfs_log_item不再关联向xfs_log_vec；
		 * - 如此一来，xfs_log_item其实就是空的了；
		 * - 但问题是后面又把该xfs_log_item挂到AIL上了，这时log item中
		 *   还有什么呢？挂到AIL上后又是怎么互斥的？
		 *   > 挂到AIL中的xfs_log_item已经不再关心其xfs_log_vec了，因为
		 *     vec中的内容是要写到iclog -> disk log space的，AIL上只挂已
		 *     经写完日志的xfs_log_item。在AIL上，我们仅关心xfs_log_item
		 *     目前对应的object本身的数据。
		 */
		item->li_lv = NULL;
		num_iovecs += lv->lv_niovecs;
	}

	/*
	 * initialise the new context and attach it to the CIL. Then attach
	 * the current context to the CIL committing lsit so it can be found
	 * during log forces to extract the commit lsn of the sequence that
	 * needs to be forced.
	 *
	 * 将新的xfs_cli_ctx关联给CIL
	 */
	INIT_LIST_HEAD(&new_ctx->committing);
	INIT_LIST_HEAD(&new_ctx->busy_extents);
	/*
	 * 新分配的checkpoint context->sequence设置为老context->sequence + 1；
	 */
	new_ctx->sequence = ctx->sequence + 1;
	new_ctx->cil = cil;
	cil->xc_ctx = new_ctx;

	/*
	 * The switch is now done, so we can drop the context lock and move out
	 * of a shared context. We can't just go straight to the commit record,
	 * though - we need to synchronise with previous and future commits so
	 * that the commit records are correctly ordered in the log to ensure
	 * that we process items during log IO completion in the correct order.
	 *
	 * For example, if we get an EFI in one checkpoint and the EFD in the
	 * next (e.g. due to log forces), we do not want the checkpoint with
	 * the EFD to be committed before the checkpoint with the EFI.  Hence
	 * we must strictly order the commit records of the checkpoints so
	 * that: a) the checkpoint callbacks are attached to the iclogs in the
	 * correct order; and b) the checkpoints are replayed in correct order
	 * in log recovery.
	 *
	 * Hence we need to add this context to the committing context list so
	 * that higher sequences will wait for us to write out a commit record
	 * before they do.
	 *
	 * xfs_log_force_lsn requires us to mirror the new sequence into the cil
	 * structure atomically with the addition of this sequence to the
	 * committing list. This also ensures that we can do unlocked checks
	 * against the current sequence in log forces without risking
	 * deferencing a freed context pointer.
	 */
	spin_lock(&cil->xc_push_lock);
	/*
	 * 将CIL的xc_current_sequence设置为新关联的checkpoint context的sequence
	 */
	cil->xc_current_sequence = new_ctx->sequence;
	spin_unlock(&cil->xc_push_lock);
	up_write(&cil->xc_ctx_lock);

	/*
	 * Build a checkpoint transaction header and write it to the log to
	 * begin the transaction. We need to account for the space used by the
	 * transaction header here as it is not accounted for in xlog_write().
	 *
	 * The LSN we need to pass to the log items on transaction commit is
	 * the LSN reported by the first log vector write. If we use the commit
	 * record lsn then we can move the tail beyond the grant write head.
	 */
	tic = ctx->ticket;
	thdr.th_magic = XFS_TRANS_HEADER_MAGIC;
	thdr.th_type = XFS_TRANS_CHECKPOINT;
	thdr.th_tid = tic->t_tid;
	thdr.th_num_items = num_iovecs;
	/*
	 * 将这个xfs_trans_header放入xfs_log_iovec的数据区；
	 */
	lhdr.i_addr = &thdr;
	lhdr.i_len = sizeof(xfs_trans_header_t);
	lhdr.i_type = XLOG_REG_TYPE_TRANSHDR;
	tic->t_curr_res -= lhdr.i_len + sizeof(xlog_op_header_t);
	/*
	 * 将上面组装的xfs_log_iovec关联到xfs_log_vec中；
	 */
	lvhdr.lv_niovecs = 1;
	lvhdr.lv_iovecp = &lhdr;
	/*
	 * checkpoint本身的这个header xfs_log_vec要串在ctx->lv_chain链表上所有的
	 * xfs_log_vec之前
	 * - 这里有点巧妙的一点是：iclog写出到disk log space后，会调用回调函数
	 *   xlog_bio_end_io()，其中会依次对ctx->lv_chain上的对象调用释放函数
	 *   xlog_cil_free_logvec()。这里我们并没有将栈上变量lvhdr加入
	 *   ctx->lv_chain链表，因此不存在问题；
	 */
	lvhdr.lv_next = ctx->lv_chain;

	/*
	 * 写CIL到iclog
	 */
	error = xlog_write(log, &lvhdr, tic, &ctx->start_lsn, NULL, 0);
	if (error)
		goto out_abort_free_ticket;

	/*
	 * now that we've written the checkpoint into the log, strictly
	 * order the commit records so replay will get them in the right order.
	 */
restart:
	spin_lock(&cil->xc_push_lock);
	/*
	 * xlog_cil_push()要确保本次xfs_cil_ctx之前的ctx全部push结束了
	 */
	list_for_each_entry(new_ctx, &cil->xc_committing, committing) {
		/*
		 * Avoid getting stuck in this loop because we were woken by the
		 * shutdown, but then went back to sleep once already in the
		 * shutdown state.
		 */
		if (XLOG_FORCED_SHUTDOWN(log)) {
			spin_unlock(&cil->xc_push_lock);
			goto out_abort_free_ticket;
		}

		/*
		 * Higher sequences will wait for this one so skip them.
		 * Don't wait for our own sequence, either.
		 */
		if (new_ctx->sequence >= ctx->sequence)
			continue;
		if (!new_ctx->commit_lsn) {
			/*
			 * It is still being pushed! Wait for the push to
			 * complete, then start again from the beginning.
			 */
			xlog_wait(&cil->xc_commit_wait, &cil->xc_push_lock);
			goto restart;
		}
	}
	spin_unlock(&cil->xc_push_lock);

	/* xfs_log_done always frees the ticket on error. */
	/*
	 * 一个xfs_cil_ctx的数据内容已经写入iclog了，此处写最后的结束标志。
	 * - commit_lsn最终来源时commit log写入的第一个iclog的ic_header.h_lsn
	 */
	commit_lsn = xfs_log_done(log->l_mp, tic, &commit_iclog, false);
	if (commit_lsn == -1)
		goto out_abort;

	spin_lock(&commit_iclog->ic_callback_lock);
	if (commit_iclog->ic_state & XLOG_STATE_IOERROR) {
		spin_unlock(&commit_iclog->ic_callback_lock);
		goto out_abort;
	}
	ASSERT_ALWAYS(commit_iclog->ic_state == XLOG_STATE_ACTIVE ||
		      commit_iclog->ic_state == XLOG_STATE_WANT_SYNC);
	/*
	 * 将xfs_cil_ctx加入iclog，待iclog写入disk后，依次调用回调函数；
	 */
	list_add_tail(&ctx->iclog_entry, &commit_iclog->ic_callbacks);
	spin_unlock(&commit_iclog->ic_callback_lock);

	/*
	 * now the checkpoint commit is complete and we've attached the
	 * callbacks to the iclog we can assign the commit LSN to the context
	 * and wake up anyone who is waiting for the commit to complete.
	 */
	spin_lock(&cil->xc_push_lock);
	/*
	 * 参见上面xfs_log_done() -> xlog_write()中关于start_lsn的注释
	 */
	ctx->commit_lsn = commit_lsn;
	wake_up_all(&cil->xc_commit_wait);
	spin_unlock(&cil->xc_push_lock);

	/*
	 * release the hounds!
	 *
	 * 放弃引用计数
	 * - 获取引用计数的动作在xlog_state_get_iclog_space()
	 */
	return xfs_log_release_iclog(log->l_mp, commit_iclog);

out_skip:
	up_write(&cil->xc_ctx_lock);
	xfs_log_ticket_put(new_ctx->ticket);
	kmem_free(new_ctx);
	return 0;

out_abort_free_ticket:
	xfs_log_ticket_put(tic);
out_abort:
	xlog_cil_committed(ctx, true);
	return -EIO;
}

static void
xlog_cil_push_work(
	struct work_struct	*work)
{
	struct xfs_cil		*cil = container_of(work, struct xfs_cil,
							xc_push_work);
	xlog_cil_push(cil->xc_log);
}

/*
 * We need to push CIL every so often so we don't cache more than we can fit in
 * the log. The limit really is that a checkpoint can't be more than half the
 * log (the current checkpoint is not allowed to overwrite the previous
 * checkpoint), but commit latency and memory usage limit this to a smaller
 * size.
 */
static void
xlog_cil_push_background(
	struct xlog	*log)
{
	struct xfs_cil	*cil = log->l_cilp;

	/*
	 * The cil won't be empty because we are called while holding the
	 * context lock so whatever we added to the CIL will still be there
	 */
	ASSERT(!list_empty(&cil->xc_cil));

	/*
	 * don't do a background push if we haven't used up all the
	 * space available yet.
	 *
	 * 如果CIL上已有的log size小于log buffer的一半，则返回，不继续做从CIL
	 * 到log buffer的push操作；
	 */
	if (cil->xc_ctx->space_used < XLOG_CIL_SPACE_LIMIT(log))
		return;

	spin_lock(&cil->xc_push_lock);
	if (cil->xc_push_seq < cil->xc_current_sequence) {
		cil->xc_push_seq = cil->xc_current_sequence;
		/*
		 * 调用的是xlog_cil_push_work() -> xlog_cil_push()
		 */
		queue_work(log->l_mp->m_cil_workqueue, &cil->xc_push_work);
	}
	spin_unlock(&cil->xc_push_lock);

}

/*
 * xlog_cil_push_now() is used to trigger an immediate CIL push to the sequence
 * number that is passed. When it returns, the work will be queued for
 * @push_seq, but it won't be completed. The caller is expected to do any
 * waiting for push_seq to complete if it is required.
 */
static void
xlog_cil_push_now(
	struct xlog	*log,
	xfs_lsn_t	push_seq)
{
	struct xfs_cil	*cil = log->l_cilp;

	if (!cil)
		return;

	ASSERT(push_seq && push_seq <= cil->xc_current_sequence);

	/* start on any pending background push to minimise wait time on it */
	/*
	 * 这里对应 xlog_cil_push_work()
	 * - 参见xlog_cil_init()
	 *
	 * 这里应该等待其他已经开始的xlog_cil_push_work()完成；
	 */
	flush_work(&cil->xc_push_work);

	/*
	 * If the CIL is empty or we've already pushed the sequence then
	 * there's no work we need to do.
	 */
	spin_lock(&cil->xc_push_lock);
	if (list_empty(&cil->xc_cil) || push_seq <= cil->xc_push_seq) {
		spin_unlock(&cil->xc_push_lock);
		return;
	}

	/*
	 * 这里才是本次期望的CIL push
	 */
	cil->xc_push_seq = push_seq;
	queue_work(log->l_mp->m_cil_workqueue, &cil->xc_push_work);
	spin_unlock(&cil->xc_push_lock);
}

bool
xlog_cil_empty(
	struct xlog	*log)
{
	struct xfs_cil	*cil = log->l_cilp;
	bool		empty = false;

	spin_lock(&cil->xc_push_lock);
	if (list_empty(&cil->xc_cil))
		empty = true;
	spin_unlock(&cil->xc_push_lock);
	return empty;
}

/*
 * Commit a transaction with the given vector to the Committed Item List.
 *
 * To do this, we need to format the item, pin it in memory if required and
 * account for the space used by the transaction. Once we have done that we
 * need to release the unused reservation for the transaction, attach the
 * transaction to the checkpoint context so we carry the busy extents through
 * to checkpoint completion, and then unlock all the items in the transaction.
 *
 * Called with the context lock already held in read mode to lock out
 * background commit, returns without it held once background commits are
 * allowed again.
 *
 * 对应文档3.3.8 Life Cycle Chanages中delayed log部分6. Transaction Commit
 */
void
xfs_log_commit_cil(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	xfs_lsn_t		*commit_lsn,
	bool			regrant)
{
	struct xlog		*log = mp->m_log;
	struct xfs_cil		*cil = log->l_cilp;
	struct xfs_log_item	*lip, *next;
	xfs_lsn_t		xc_commit_lsn;

	/*
	 * Do all necessary memory allocation before we lock the CIL.
	 * This ensures the allocation does not deadlock with a CIL
	 * push in memory reclaim (e.g. from kswapd).
	 *
	 * 预分配xfs_log_vec/xfs_log_iovec，防止持锁后分配内存时引发reclaim并写
	 * 日志，那么就要再次到这里获取这把锁；
	 */
	xlog_cil_alloc_shadow_bufs(log, tp);

	/*
	 * lock out background commit
	 * - 互斥端在xlog_cil_push()
	 */
	down_read(&cil->xc_ctx_lock);

	/*
	 * 将本transaction管理的xfs_log_item插入CIL的链表；
	 */
	xlog_cil_insert_items(log, tp);

	xc_commit_lsn = cil->xc_ctx->sequence;
	if (commit_lsn)
		*commit_lsn = xc_commit_lsn;

	xfs_log_done(mp, tp->t_ticket, NULL, regrant);
	tp->t_ticket = NULL;
	xfs_trans_unreserve_and_mod_sb(tp);

	/*
	 * Once all the items of the transaction have been copied to the CIL,
	 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
	 * the items can be unlocked and possibly freed.
	 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
	 *
	 * This needs to be done before we drop the CIL context lock because we
	 * have to update state in the log items and unlock them before they go
	 * to disk. If we don't, then the CIL checkpoint can race with us and
	 * we can run checkpoint completion before we've updated and unlocked
	 * the log items. This affects (at least) processing of stale buffers,
	 * inodes and EFIs.
	 */
	trace_xfs_trans_commit_items(tp, _RET_IP_);
	list_for_each_entry_safe(lip, next, &tp->t_items, li_trans) {
		/*
		 * 将xfs_log_item从xfs_trans->t_items链表上摘除；
		 */
		xfs_trans_del_item(lip);
		/*
		 * 解锁item（这个item指的是object本身，比如inode）
		 * - xfs_inode_log_item -> xfs_inode_item_committing()
		 */
		if (lip->li_ops->iop_committing)
			lip->li_ops->iop_committing(lip, xc_commit_lsn);
	}
	/*
	 * 如果CIL上日志足够多，则写入iclog
	 */
	xlog_cil_push_background(log);

	up_read(&cil->xc_ctx_lock);
}

/*
 * Conditionally push the CIL based on the sequence passed in.
 *
 * We only need to push if we haven't already pushed the sequence
 * number given. Hence the only time we will trigger a push here is
 * if the push sequence is the same as the current context.
 *
 * We return the current commit lsn to allow the callers to determine if a
 * iclog flush is necessary following this call.
 */
xfs_lsn_t
xlog_cil_force_lsn(
	struct xlog	*log,
	xfs_lsn_t	sequence)
{
	struct xfs_cil		*cil = log->l_cilp;
	struct xfs_cil_ctx	*ctx;
	xfs_lsn_t		commit_lsn = NULLCOMMITLSN;

	ASSERT(sequence <= cil->xc_current_sequence);

	/*
	 * check to see if we need to force out the current context.
	 * xlog_cil_push() handles racing pushes for the same sequence,
	 * so no need to deal with it here.
	 */
restart:
	xlog_cil_push_now(log, sequence);

	/*
	 * See if we can find a previous sequence still committing.
	 * We need to wait for all previous sequence commits to complete
	 * before allowing the force of push_seq to go ahead. Hence block
	 * on commits for those as well.
	 */
	spin_lock(&cil->xc_push_lock);
	list_for_each_entry(ctx, &cil->xc_committing, committing) {
		/*
		 * Avoid getting stuck in this loop because we were woken by the
		 * shutdown, but then went back to sleep once already in the
		 * shutdown state.
		 */
		if (XLOG_FORCED_SHUTDOWN(log))
			goto out_shutdown;
		if (ctx->sequence > sequence)
			continue;
		if (!ctx->commit_lsn) {
		/*
		 * xfs_cil_ctx->commit_lsn会在xfs_cil_ctx写入iclog之后才会赋值
		 */
			/*
			 * It is still being pushed! Wait for the push to
			 * complete, then start again from the beginning.
			 */
			xlog_wait(&cil->xc_commit_wait, &cil->xc_push_lock);
			goto restart;
		}
		if (ctx->sequence != sequence)
			continue;
		/* found it! */
		commit_lsn = ctx->commit_lsn;
	}

	/*
	 * The call to xlog_cil_push_now() executes the push in the background.
	 * Hence by the time we have got here it our sequence may not have been
	 * pushed yet. This is true if the current sequence still matches the
	 * push sequence after the above wait loop and the CIL still contains
	 * dirty objects. This is guaranteed by the push code first adding the
	 * context to the committing list before emptying the CIL.
	 *
	 * Hence if we don't find the context in the committing list and the
	 * current sequence number is unchanged then the CIL contents are
	 * significant.  If the CIL is empty, if means there was nothing to push
	 * and that means there is nothing to wait for. If the CIL is not empty,
	 * it means we haven't yet started the push, because if it had started
	 * we would have found the context on the committing list.
	 */
	if (sequence == cil->xc_current_sequence &&
	    !list_empty(&cil->xc_cil)) {
		spin_unlock(&cil->xc_push_lock);
		goto restart;
	}

	spin_unlock(&cil->xc_push_lock);
	return commit_lsn;

	/*
	 * We detected a shutdown in progress. We need to trigger the log force
	 * to pass through it's iclog state machine error handling, even though
	 * we are already in a shutdown state. Hence we can't return
	 * NULLCOMMITLSN here as that has special meaning to log forces (i.e.
	 * LSN is already stable), so we return a zero LSN instead.
	 */
out_shutdown:
	spin_unlock(&cil->xc_push_lock);
	return 0;
}

/*
 * Check if the current log item was first committed in this sequence.
 * We can't rely on just the log item being in the CIL, we have to check
 * the recorded commit sequence number.
 *
 * Note: for this to be used in a non-racy manner, it has to be called with
 * CIL flushing locked out. As a result, it should only be used during the
 * transaction commit process when deciding what to format into the item.
 */
bool
xfs_log_item_in_current_chkpt(
	struct xfs_log_item *lip)
{
	struct xfs_cil_ctx *ctx;

	if (list_empty(&lip->li_cil))
		return false;

	ctx = lip->li_mountp->m_log->l_cilp->xc_ctx;

	/*
	 * li_seq is written on the first commit of a log item to record the
	 * first checkpoint it is written to. Hence if it is different to the
	 * current sequence, we're in a new checkpoint.
	 */
	if (XFS_LSN_CMP(lip->li_seq, ctx->sequence) != 0)
		return false;
	return true;
}

/*
 * Perform initial CIL structure initialisation.
 */
int
xlog_cil_init(
	struct xlog	*log)
{
	struct xfs_cil	*cil;
	struct xfs_cil_ctx *ctx;

	cil = kmem_zalloc(sizeof(*cil), KM_MAYFAIL);
	if (!cil)
		return -ENOMEM;

	ctx = kmem_zalloc(sizeof(*ctx), KM_MAYFAIL);
	if (!ctx) {
		kmem_free(cil);
		return -ENOMEM;
	}

	INIT_WORK(&cil->xc_push_work, xlog_cil_push_work);
	INIT_LIST_HEAD(&cil->xc_cil);
	INIT_LIST_HEAD(&cil->xc_committing);
	spin_lock_init(&cil->xc_cil_lock);
	spin_lock_init(&cil->xc_push_lock);
	init_rwsem(&cil->xc_ctx_lock);
	init_waitqueue_head(&cil->xc_commit_wait);

	INIT_LIST_HEAD(&ctx->committing);
	INIT_LIST_HEAD(&ctx->busy_extents);
	ctx->sequence = 1;
	ctx->cil = cil;
	cil->xc_ctx = ctx;
	cil->xc_current_sequence = ctx->sequence;

	cil->xc_log = log;
	log->l_cilp = cil;
	return 0;
}

void
xlog_cil_destroy(
	struct xlog	*log)
{
	if (log->l_cilp->xc_ctx) {
		if (log->l_cilp->xc_ctx->ticket)
			xfs_log_ticket_put(log->l_cilp->xc_ctx->ticket);
		kmem_free(log->l_cilp->xc_ctx);
	}

	ASSERT(list_empty(&log->l_cilp->xc_cil));
	kmem_free(log->l_cilp);
}

