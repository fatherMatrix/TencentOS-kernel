// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2005-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __XFS_AOPS_H__
#define __XFS_AOPS_H__

extern struct bio_set xfs_ioend_bioset;

/*
 * Structure for buffered I/O completions.
 * - 描述一段在磁盘上连续的pagecache回写所产生的bios
 */
struct xfs_ioend {
	/*
	 * 分时复用
	 * - 在io发起前，作为链表元素在xfs_add_to_ioend()中加入submit_list临时链
	 *   表，等待在其调用者中遍历该链表并submit_bio()
	 * - 在io完成后，作为链表元素在xfs_end_bio()中加入xfs_inode->i_ioend_list
	 *   链表，等待xfs_inode->i_ioend_work中使用
	 * - 在xfs_inode->i_ioend_work中，如果多个xfs_ioend可以合并时，将后面合
	 *   并的xfs_ioend->io_list链入前面的xfs_ioend->io_list中
	 */
	struct list_head	io_list;	/* next ioend in chain */
	int			io_fork;	/* inode fork written back */
	xfs_exntst_t		io_state;	/* extent state */
	struct inode		*io_inode;	/* file being written to */
	size_t			io_size;	/* size of the extent */
	/*
	 * 文件偏移
	 */
	xfs_off_t		io_offset;	/* offset in the file */
	struct xfs_trans	*io_append_trans;/* xact. for size update */
	/*
	 * bi_end_io的设置在xfs_submit_ioend()
	 * - 回调函数为xfs_end_bio()
	 * io_bio一开始指向io_inline_bio，如果一个page中包含多个文件块，且多个
	 * 文件块需要多个bio来完成，那么新的bio被io_inline_bio->bi_private指向，
	 * io_bio指向最新的bio，最新的bio->bi_private指向本结构体xfs_ioend
	 */
	struct bio		*io_bio;	/* bio being built */
	struct bio		io_inline_bio;	/* MUST BE LAST! */
};

extern const struct address_space_operations xfs_address_space_operations;
extern const struct address_space_operations xfs_dax_aops;

int	xfs_setfilesize(struct xfs_inode *ip, xfs_off_t offset, size_t size);

extern struct block_device *xfs_find_bdev_for_inode(struct inode *);
extern struct dax_device *xfs_find_daxdev_for_inode(struct inode *);

#endif /* __XFS_AOPS_H__ */
