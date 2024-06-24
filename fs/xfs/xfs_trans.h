// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__XFS_TRANS_H__
#define	__XFS_TRANS_H__

/* kernel only transaction subsystem defines */

struct xfs_buf;
struct xfs_buftarg;
struct xfs_efd_log_item;
struct xfs_efi_log_item;
struct xfs_inode;
struct xfs_item_ops;
struct xfs_log_iovec;
struct xfs_mount;
struct xfs_trans;
struct xfs_trans_res;
struct xfs_dquot_acct;
struct xfs_rud_log_item;
struct xfs_rui_log_item;
struct xfs_btree_cur;
struct xfs_cui_log_item;
struct xfs_cud_log_item;
struct xfs_bui_log_item;
struct xfs_bud_log_item;

/*
 * log item的内存数据结构
 * - 磁盘数据结构呢？
 */
struct xfs_log_item {
	/*
	 * 链接进AIL
	 */
	struct list_head		li_ail;		/* AIL pointers */
	/*
	 * 作为链表元素加入xfs_trans->t_items
	 */
	struct list_head		li_trans;	/* transaction list */
	/*
	 * 在插入AIL时获得具体值
	 * - xfs_trans_ail_update_bulk()
	 *
	 * 在xfs_log_item被插入AIL之前，确定其li_lsn
	 * - lsn来源于xfs_cil_ctx->start_lsn
	 *   > xlog_cil_committed() -> call xfs_trans_committed_bulk()
	 * - xfs_cil_ctx->start_lsn又来源于其写入的第一个iclog的h_lsn
	 *   > xlog_state_get_iclog_space
	 *
	 * 这个值主要是用于在AIL上对xfs_log_item进行排序，所以我觉得用start_lsn
	 * 或者commit_lsn问题都不大；
	 */
	xfs_lsn_t			li_lsn;		/* last on-disk lsn */
	struct xfs_mount		*li_mountp;	/* ptr to fs mount */
	/*
	 * 直接拷贝的xfs_mount->m_ail
	 * - 参见xfs_log_item_init()
	 *
	 * 这里保存一下的作用和必要性？
	 * 为什么没有li_cilp？
	 */
	struct xfs_ail			*li_ailp;	/* ptr to AIL */
	uint				li_type;	/* item type */
	unsigned long			li_flags;	/* misc flags */
	struct xfs_buf			*li_buf;	/* real buffer pointer */
	/*
	 * 作为链表元素链入xfs_buf->b_li_list
	 * - 当xfs_buf的io操作完成后，依次调用该链表上xfs_log_item的回调
	 */
	struct list_head		li_bio_list;	/* buffer item list */
	/*
	 * 当AIL中的log item写入metadata space完成后的回调
	 * - 实际上是xfs_buf->b_iodone/xfs_buf_do_callbacks()调过来的
	 */
	void				(*li_cb)(struct xfs_buf *,
						 struct xfs_log_item *);
							/* buffer item iodone */
							/* callback func */
	const struct xfs_item_ops	*li_ops;	/* function list */

	/* delayed logging */

	/*
	 * 作为链表元素链接进xfs_cil->xc_cil链表
	 */
	struct list_head		li_cil;		/* CIL pointers */
	/*
	 * li_lv和li_lv_shadow的关系见xlog_cil_alloc_shadow_bufs()的注释；
	 * - 最后一次使用是什么时候？
	 */
	struct xfs_log_vec		*li_lv;		/* active log vector */
	struct xfs_log_vec		*li_lv_shadow;	/* standby vector */
	/*
	 * 第一次提交到CIL checkpoint context时所对应的log->l_cilp->xc_ctx->sequence
	 */
	xfs_lsn_t			li_seq;		/* CIL commit seq */
};

/*
 * li_flags use the (set/test/clear)_bit atomic interfaces because updates can
 * race with each other and we don't want to have to use the AIL lock to
 * serialise all updates.
 */
#define	XFS_LI_IN_AIL	0
#define	XFS_LI_ABORTED	1
#define	XFS_LI_FAILED	2
#define	XFS_LI_DIRTY	3	/* log item dirty in transaction */

#define XFS_LI_FLAGS \
	{ (1 << XFS_LI_IN_AIL),		"IN_AIL" }, \
	{ (1 << XFS_LI_ABORTED),	"ABORTED" }, \
	{ (1 << XFS_LI_FAILED),		"FAILED" }, \
	{ (1 << XFS_LI_DIRTY),		"DIRTY" }

struct xfs_item_ops {
	unsigned flags;
	void (*iop_size)(struct xfs_log_item *, int *, int *);
	/*
	 * 将object的修改format到memory buffer/log vector中
	 */
	void (*iop_format)(struct xfs_log_item *, struct xfs_log_vec *);
	void (*iop_pin)(struct xfs_log_item *);
	void (*iop_unpin)(struct xfs_log_item *, int remove);
	/*
	 * 将AIL上的xfs_log_item回写的数据挂到入参list_head中，等待后面回写
	 * - deferred intent item不配置此方法，导致xfsaild_push_item()返回
	 *   XFS_ITEM_PINNED从而在AIL链表上保留。
	 *   > deferred intent item会在deferred done item调用iop_release()方法
	 *     时被摘下；
	 * - 非deferred：
	 *   > xfs_inode_item_push()
	 */
	uint (*iop_push)(struct xfs_log_item *, struct list_head *);
	/*
	 * 将xfs_log_item提交到CIL后调用本回调
	 * - 可以用来做6. Transaction commit中的unlock item这一步
	 */
	void (*iop_committing)(struct xfs_log_item *, xfs_lsn_t commit_lsn);
	/*
	 * 用于释放object
	 * - 一般而言是unlock，对应文档中Item Unlock
	 */
	void (*iop_release)(struct xfs_log_item *);
	/*
	 * 用于在xfs_trans_committed_bulk()中获取xfs_log_item对应的commit lsn
	 * - 一般而言，是直接返回第二个参数；
	 * - 但对某些类型的xfs_log_item有特殊处理
	 *   > xfs_inode_item_committed()
	 *   > xfs_buf_item_committed()
	 */
	xfs_lsn_t (*iop_committed)(struct xfs_log_item *, xfs_lsn_t);
	void (*iop_error)(struct xfs_log_item *, xfs_buf_t *);
};

/*
 * Release the log item as soon as committed.  This is for items just logging
 * intents that never need to be written back in place.
 */
#define XFS_ITEM_RELEASE_WHEN_COMMITTED	(1 << 0)

void	xfs_log_item_init(struct xfs_mount *mp, struct xfs_log_item *item,
			  int type, const struct xfs_item_ops *ops);

/*
 * Return values for the iop_push() routines.
 */
#define XFS_ITEM_SUCCESS	0
#define XFS_ITEM_PINNED		1
#define XFS_ITEM_LOCKED		2
#define XFS_ITEM_FLUSHING	3

/*
 * Deferred operation item relogging limits.
 */
#define XFS_DEFER_OPS_NR_INODES	2	/* join up to two inodes */
#define XFS_DEFER_OPS_NR_BUFS	2	/* join up to two buffers */

/*
 * This is the structure maintained for every active transaction.
 */
typedef struct xfs_trans {
	unsigned int		t_magic;	/* magic number */
	unsigned int		t_log_res;	/* amt of log space resvd */
	unsigned int		t_log_count;	/* count for perm log res */
	unsigned int		t_blk_res;	/* # of blocks resvd */
	unsigned int		t_blk_res_used;	/* # of resvd blocks used */
	unsigned int		t_rtx_res;	/* # of rt extents resvd */
	unsigned int		t_rtx_res_used;	/* # of resvd rt extents used */
	unsigned int		t_flags;	/* misc flags */
	xfs_fsblock_t		t_firstblock;	/* first block allocated */
	struct xlog_ticket	*t_ticket;	/* log mgr ticket */
	struct xfs_mount	*t_mountp;	/* ptr to fs mount struct */
	struct xfs_dquot_acct   *t_dqinfo;	/* acctg info for dquots */
	int64_t			t_icount_delta;	/* superblock icount change */
	int64_t			t_ifree_delta;	/* superblock ifree change */
	int64_t			t_fdblocks_delta; /* superblock fdblocks chg */
	int64_t			t_res_fdblocks_delta; /* on-disk only chg */
	int64_t			t_frextents_delta;/* superblock freextents chg*/
	int64_t			t_res_frextents_delta; /* on-disk only chg */
#if defined(DEBUG) || defined(XFS_WARN)
	int64_t			t_ag_freeblks_delta; /* debugging counter */
	int64_t			t_ag_flist_delta; /* debugging counter */
	int64_t			t_ag_btree_delta; /* debugging counter */
#endif
	int64_t			t_dblocks_delta;/* superblock dblocks change */
	int64_t			t_agcount_delta;/* superblock agcount change */
	int64_t			t_imaxpct_delta;/* superblock imaxpct change */
	int64_t			t_rextsize_delta;/* superblock rextsize chg */
	int64_t			t_rbmblocks_delta;/* superblock rbmblocks chg */
	int64_t			t_rblocks_delta;/* superblock rblocks change */
	int64_t			t_rextents_delta;/* superblocks rextents chg */
	int64_t			t_rextslog_delta;/* superblocks rextslog chg */
	/*
	 * 链表元素是xfs_log_item->li_trans
	 */
	struct list_head	t_items;	/* log item descriptors */
	struct list_head	t_busy;		/* list of busy extents */
	/*
	 * 链表元素是xfs_defer_pending->dfp_list；
	 * - 参见 xfs_defer_add()
	 */
	struct list_head	t_dfops;	/* deferred operations */
	/*
	 * 参见xfs_trans_alloc()
	 *     -> xfs_trans_reserve()
	 *       -> current_set_flags_nested()
	 */
	unsigned long		t_pflags;	/* saved process flags state */
} xfs_trans_t;

/*
 * XFS transaction mechanism exported interfaces that are
 * actually macros.
 */
#define	xfs_trans_set_sync(tp)		((tp)->t_flags |= XFS_TRANS_SYNC)

#if defined(DEBUG) || defined(XFS_WARN)
#define	xfs_trans_agblocks_delta(tp, d)	((tp)->t_ag_freeblks_delta += (int64_t)d)
#define	xfs_trans_agflist_delta(tp, d)	((tp)->t_ag_flist_delta += (int64_t)d)
#define	xfs_trans_agbtree_delta(tp, d)	((tp)->t_ag_btree_delta += (int64_t)d)
#else
#define	xfs_trans_agblocks_delta(tp, d)
#define	xfs_trans_agflist_delta(tp, d)
#define	xfs_trans_agbtree_delta(tp, d)
#endif

/*
 * XFS transaction mechanism exported interfaces.
 */
int		xfs_trans_alloc(struct xfs_mount *mp, struct xfs_trans_res *resp,
			uint blocks, uint rtextents, uint flags,
			struct xfs_trans **tpp);
int		xfs_trans_alloc_empty(struct xfs_mount *mp,
			struct xfs_trans **tpp);
void		xfs_trans_mod_sb(xfs_trans_t *, uint, int64_t);

struct xfs_buf	*xfs_trans_get_buf_map(struct xfs_trans *tp,
				       struct xfs_buftarg *target,
				       struct xfs_buf_map *map, int nmaps,
				       uint flags);

static inline struct xfs_buf *
xfs_trans_get_buf(
	struct xfs_trans	*tp,
	struct xfs_buftarg	*target,
	xfs_daddr_t		blkno,
	int			numblks,
	uint			flags)
{
	DEFINE_SINGLE_BUF_MAP(map, blkno, numblks);
	return xfs_trans_get_buf_map(tp, target, &map, 1, flags);
}

int		xfs_trans_read_buf_map(struct xfs_mount *mp,
				       struct xfs_trans *tp,
				       struct xfs_buftarg *target,
				       struct xfs_buf_map *map, int nmaps,
				       xfs_buf_flags_t flags,
				       struct xfs_buf **bpp,
				       const struct xfs_buf_ops *ops);

static inline int
xfs_trans_read_buf(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	struct xfs_buftarg	*target,
	xfs_daddr_t		blkno,
	int			numblks,
	xfs_buf_flags_t		flags,
	struct xfs_buf		**bpp,
	const struct xfs_buf_ops *ops)
{
	/*
	 * 这里的blkno和numblks都是basic block，512块
	 */
	DEFINE_SINGLE_BUF_MAP(map, blkno, numblks);
	return xfs_trans_read_buf_map(mp, tp, target, &map, 1,
				      flags, bpp, ops);
}

struct xfs_buf	*xfs_trans_getsb(xfs_trans_t *, struct xfs_mount *);

void		xfs_trans_brelse(xfs_trans_t *, struct xfs_buf *);
void		xfs_trans_bjoin(xfs_trans_t *, struct xfs_buf *);
void		xfs_trans_bhold(xfs_trans_t *, struct xfs_buf *);
void		xfs_trans_bhold_release(xfs_trans_t *, struct xfs_buf *);
void		xfs_trans_binval(xfs_trans_t *, struct xfs_buf *);
void		xfs_trans_inode_buf(xfs_trans_t *, struct xfs_buf *);
void		xfs_trans_stale_inode_buf(xfs_trans_t *, struct xfs_buf *);
bool		xfs_trans_ordered_buf(xfs_trans_t *, struct xfs_buf *);
void		xfs_trans_dquot_buf(xfs_trans_t *, struct xfs_buf *, uint);
void		xfs_trans_inode_alloc_buf(xfs_trans_t *, struct xfs_buf *);
void		xfs_trans_ichgtime(struct xfs_trans *, struct xfs_inode *, int);
void		xfs_trans_ijoin(struct xfs_trans *, struct xfs_inode *, uint);
void		xfs_trans_log_buf(struct xfs_trans *, struct xfs_buf *, uint,
				  uint);
void		xfs_trans_dirty_buf(struct xfs_trans *, struct xfs_buf *);
bool		xfs_trans_buf_is_dirty(struct xfs_buf *bp);
void		xfs_trans_log_inode(xfs_trans_t *, struct xfs_inode *, uint);

int		xfs_trans_commit(struct xfs_trans *);
int		xfs_trans_roll(struct xfs_trans **);
int		xfs_trans_roll_inode(struct xfs_trans **, struct xfs_inode *);
void		xfs_trans_cancel(xfs_trans_t *);
int		xfs_trans_ail_init(struct xfs_mount *);
void		xfs_trans_ail_destroy(struct xfs_mount *);

void		xfs_trans_buf_set_type(struct xfs_trans *, struct xfs_buf *,
				       enum xfs_blft);
void		xfs_trans_buf_copy_type(struct xfs_buf *dst_bp,
					struct xfs_buf *src_bp);

extern kmem_zone_t	*xfs_trans_zone;

#endif	/* __XFS_TRANS_H__ */
