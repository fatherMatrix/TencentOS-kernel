// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (c) 2016-2018 Christoph Hellwig.
 */
#include <linux/module.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/iomap.h>

/*
 * Execute a iomap write on a segment of the mapping that spans a
 *                                                        ^^^^^^^
 * contiguous range of pages that have identical block mapping state.
 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 *
 * This avoids the need to map pages individually, do individual allocations
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * for each page and most importantly avoid the need for filesystem specific
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * locking per page. Instead, all the operations are amortised over the entire
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * range of pages. It is assumed that the filesystems will lock whatever
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * resources they require in the iomap_begin call, and release them in the
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * iomap_end call.
 * ^^^^^^^^^^^^^^^
 */
loff_t
iomap_apply(struct inode *inode, loff_t pos, loff_t length, unsigned flags,
		const struct iomap_ops *ops, void *data, iomap_actor_t actor)
{
	/*
	 * 用于保存数据的文件偏移到磁盘偏移间的映射
	 */
	struct iomap iomap = { 0 };
	loff_t written = 0, ret;

	/*
	 * Need to map a range from start position for length bytes. This can
	 *                                                           ^^^^^^^^
	 * span multiple pages - it is only guaranteed to return a range of a
	 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
	 * single type of pages (e.g. all into a hole, all mapped or all
	 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
	 * unwritten). Failure at this point has nothing to undo.
	 * ^^^^^^^^^^^
	 *
	 * If allocation is required for this range, reserve the space now so
	 * that the allocation is guaranteed to succeed later on. Once we copy
	 * the data into the page cache pages, then we cannot fail otherwise we
	 * expose transient stale data. If the reserve fails, we can safely
	 * back out at this point as there is nothing to undo.
	 *
	 * 对xfs，对应函数 xfs_file_iomap_begin()
	 * - 该接口主要作用是构建文件块和磁盘块的地址映射；
	 * - 如果文件块在磁盘上没有对应的地址，则分配新的地址（相当于分配了磁盘块）；
	 * - 里面通过xfs_trans_alloc() -> xfs_trans_commit()提交日志；
	 */
	ret = ops->iomap_begin(inode, pos, length, flags, &iomap);
	if (ret)
		return ret;
	if (WARN_ON(iomap.offset > pos))
		return -EIO;
	if (WARN_ON(iomap.length == 0))
		return -EIO;

	/*
	 * Cut down the length to the one actually provided by the filesystem,
	 * as it might not be able to give us the whole size that we requested.
	 */
	if (iomap.offset + iomap.length < pos + length)
		length = iomap.offset + iomap.length - pos;

	/*
	 * Now that we have guaranteed that the space allocation will succeed.
	 * we can do the copy-in page by page without having to worry about
	 * failures exposing transient data.
	 *
	 * xfs中buffer io对应 iomap_write_actor()
	 * - 
	 * xfs中direct io对应 iomap_dio_actor()
	 * - 该函数内部调用iomap_dio_bio_actor()，对iomap中的数据创建bio并调用
	 *   submit_bio()将其提交到块层；
	 * 对于zero区域对应 iomap_zero_range_actor()
	 *
	 * 从这里相对上面xfs_trans_commit()的位置可以得出结论：
	 * - xfs中的日志仅作用于metadata
	 * - 又由于其日志是异步的，所以在user data落盘之前，并不能保证metadata
	 *   持久化（log落盘或metadata本身落盘）了。即user data和metadata持久化
	 *   的先后顺序不保证。对应ext4中的data=writeback
	 */
	written = actor(inode, pos, length, data, &iomap);

	/*
	 * Now the data has been copied, commit the range we've copied.  This
	 * should not fail unless the filesystem has had a fatal error.
	 *
	 * 对xfs，对应函数 xfs_file_iomap_end()
	 * - 猜测：对于写操作，且有磁盘上空间的释放需求时，在这里做；
	 */
	if (ops->iomap_end) {
		ret = ops->iomap_end(inode, pos, length,
				     written > 0 ? written : 0,
				     flags, &iomap);
	}

	return written ? written : ret;
}
