// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __XFS_DEFER_H__
#define	__XFS_DEFER_H__

struct xfs_defer_op_type;

/*
 * Header for deferred operation list.
 */
enum xfs_defer_ops_type {
	XFS_DEFER_OPS_TYPE_BMAP,
	XFS_DEFER_OPS_TYPE_REFCOUNT,
	XFS_DEFER_OPS_TYPE_RMAP,
	XFS_DEFER_OPS_TYPE_FREE,
	XFS_DEFER_OPS_TYPE_AGFL_FREE,
	XFS_DEFER_OPS_TYPE_MAX,
};

/*
 * Save a log intent item and a list of extents, so that we can replay
 * whatever action had to happen to the extent list and file the log done
 * item.
 */
struct xfs_defer_pending {
	/*
	 * 作为链表元素加入xfs_trans->t_dfops
	 */
	struct list_head		dfp_list;	/* pending items */
	/*
	 * 作为链表头
	 * - 在xfs_defer_pending本身保序的前提下，相同类型的xfs_rmap_intent链
	 *   接到同一个xfs_defer_pending
	 *
	 * 链表元素：
	 * - xfs_extent_free_item->xefi_list
	 * - xfs_rmap_intent->ri_list
	 */
	struct list_head		dfp_work;	/* work items */
	/*
	 * - xfs_efi_log_item
	 * - ... ...
	 */
	void				*dfp_intent;	/* log intent item */
	/*
	 * - xfs_efd_log_item
	 * - ... ...
	 */
	void				*dfp_done;	/* log done item */
	unsigned int			dfp_count;	/* # extent items */
	enum xfs_defer_ops_type		dfp_type;
};

void xfs_defer_add(struct xfs_trans *tp, enum xfs_defer_ops_type type,
		struct list_head *h);
int xfs_defer_finish_noroll(struct xfs_trans **tp);
int xfs_defer_finish(struct xfs_trans **tp);
void xfs_defer_cancel(struct xfs_trans *);
void xfs_defer_move(struct xfs_trans *dtp, struct xfs_trans *stp);

/* Description of a deferred type. */
struct xfs_defer_op_type {
	void (*abort_intent)(void *);
	/*
	 * 创建一个intent item对应的done item
	 * - 要注意的是这里虽然将其挂到xfs_trans->t_items链表上，但并没有设置
	 *   XFS_LI_DIRTY标志，没有该标志的话，xlog_cil_push是不会写入iclog的
	 */
	void *(*create_done)(struct xfs_trans *, void *, unsigned int);
	/*
	 * 这里会设置XFS_LI_DIRTY，此时该done item会被写入iclog了
	 */
	int (*finish_item)(struct xfs_trans *, struct list_head *, void *,
			void **);
	void (*finish_cleanup)(struct xfs_trans *, void *, int);
	void (*cancel_item)(struct list_head *);
	int (*diff_items)(void *, struct list_head *, struct list_head *);
	/*
	 * 创建intent item，并挂入xfs_trans->t_items链表的尾部
	 * - 这里挂入尾部，表明了虽然xfs_defer_finish()的调用在xfs_trans_roll()
	 *   之前，但defer item还是在前面已经发生的log之后发生；
	 * - 这里没有设置intent item的XFS_LI_DIRTY标志
	 */
	void *(*create_intent)(struct xfs_trans *, uint);
	/*
	 * 这里会设置intent item的XFS_LI_DIRTY标志
	 */
	void (*log_item)(struct xfs_trans *, void *, struct list_head *);
	unsigned int		max_items;
};

extern const struct xfs_defer_op_type xfs_bmap_update_defer_type;
extern const struct xfs_defer_op_type xfs_refcount_update_defer_type;
extern const struct xfs_defer_op_type xfs_rmap_update_defer_type;
extern const struct xfs_defer_op_type xfs_extent_free_defer_type;
extern const struct xfs_defer_op_type xfs_agfl_free_defer_type;

#endif /* __XFS_DEFER_H__ */
