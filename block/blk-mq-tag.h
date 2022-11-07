/* SPDX-License-Identifier: GPL-2.0 */
#ifndef INT_BLK_MQ_TAG_H
#define INT_BLK_MQ_TAG_H

#include "blk-mq.h"

/*
 * Tag address space map.
 *
 * 用于tag空间管理。tags中包含了对request及payload的分配, page_list就是用于链接
 * 分配出的page; blk_mq_tags与硬件队列blk_mq_hw_ctx一一对应，它管理了硬队列的
 *               ^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^oooooooo
 * tag bitmap和request，其中每一个tag bit代表了一个request
 */
struct blk_mq_tags {
	/*
	 * tag和保留tag的数量。
	 *
	 * 一般情况下tag数量等于最大队列深度（QD），保留tag数量为0。
	 */
	unsigned int nr_tags;
	unsigned int nr_reserved_tags;

	/*
	 * 活跃队列数量。
	 *
	 * blk-mq中一个tag set可以是多个request queue共享的（tag set是对应硬件
	 * 队列的，每个硬件队列可以对应多个软件队列），记录当前活跃队列数量是为
	 * 了均匀分配tag到每个request queue
	 */
	atomic_t active_queues;

	/*
	 * tag和保留tag的位图
	 */
	struct sbitmap_queue bitmap_tags;
	struct sbitmap_queue breserved_tags;

	/*
	 * 提前分配的request
	 */
	struct request **rqs;
	struct request **static_rqs;
	/*
 	 * 用于链接分配出的page
 	 */ 
	struct list_head page_list;
};


extern struct blk_mq_tags *blk_mq_init_tags(unsigned int nr_tags, unsigned int reserved_tags, int node, int alloc_policy);
extern void blk_mq_free_tags(struct blk_mq_tags *tags);

extern unsigned int blk_mq_get_tag(struct blk_mq_alloc_data *data);
extern void blk_mq_put_tag(struct blk_mq_hw_ctx *hctx, struct blk_mq_tags *tags,
			   struct blk_mq_ctx *ctx, unsigned int tag);
extern bool blk_mq_has_free_tags(struct blk_mq_tags *tags);
extern int blk_mq_tag_update_depth(struct blk_mq_hw_ctx *hctx,
					struct blk_mq_tags **tags,
					unsigned int depth, bool can_grow);
extern void blk_mq_tag_wakeup_all(struct blk_mq_tags *tags, bool);
void blk_mq_queue_tag_busy_iter(struct request_queue *q, busy_iter_fn *fn,
		void *priv);

static inline struct sbq_wait_state *bt_wait_ptr(struct sbitmap_queue *bt,
						 struct blk_mq_hw_ctx *hctx)
{
	if (!hctx)
		return &bt->ws[0];
	return sbq_wait_ptr(bt, &hctx->wait_index);
}

enum {
	BLK_MQ_TAG_FAIL		= -1U,
	BLK_MQ_TAG_MIN		= 1,
	BLK_MQ_TAG_MAX		= BLK_MQ_TAG_FAIL - 1,
};

extern bool __blk_mq_tag_busy(struct blk_mq_hw_ctx *);
extern void __blk_mq_tag_idle(struct blk_mq_hw_ctx *);

static inline bool blk_mq_tag_busy(struct blk_mq_hw_ctx *hctx)
{
	if (!(hctx->flags & BLK_MQ_F_TAG_SHARED))
		return false;

	return __blk_mq_tag_busy(hctx);
}

static inline void blk_mq_tag_idle(struct blk_mq_hw_ctx *hctx)
{
	if (!(hctx->flags & BLK_MQ_F_TAG_SHARED))
		return;

	__blk_mq_tag_idle(hctx);
}

/*
 * This helper should only be used for flush request to share tag
 * with the request cloned from, and both the two requests can't be
 * in flight at the same time. The caller has to make sure the tag
 * can't be freed.
 */
static inline void blk_mq_tag_set_rq(struct blk_mq_hw_ctx *hctx,
		unsigned int tag, struct request *rq)
{
	hctx->tags->rqs[tag] = rq;
}

static inline bool blk_mq_tag_is_reserved(struct blk_mq_tags *tags,
					  unsigned int tag)
{
	return tag < tags->nr_reserved_tags;
}

#endif
