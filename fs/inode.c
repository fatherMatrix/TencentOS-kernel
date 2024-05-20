// SPDX-License-Identifier: GPL-2.0-only
/*
 * (C) 1997 Linus Torvalds
 * (C) 1999 Andrea Arcangeli <andrea@suse.de> (dynamic inode allocation)
 */
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/hash.h>
#include <linux/swap.h>
#include <linux/security.h>
#include <linux/cdev.h>
#include <linux/memblock.h>
#include <linux/fsnotify.h>
#include <linux/mount.h>
#include <linux/posix_acl.h>
#include <linux/prefetch.h>
#include <linux/buffer_head.h> /* for inode_has_buffers */
#include <linux/ratelimit.h>
#include <linux/list_lru.h>
#include <linux/iversion.h>
#include <trace/events/writeback.h>
#include "internal.h"

/*
 * Inode locking rules:
 *
 * inode->i_lock protects:
 *   inode->i_state, inode->i_hash, __iget()
 * Inode LRU list locks protect:
 *   inode->i_sb->s_inode_lru, inode->i_lru
 * inode->i_sb->s_inode_list_lock protects:
 *   inode->i_sb->s_inodes, inode->i_sb_list
 * bdi->wb.list_lock protects:
 *   bdi->wb.b_{dirty,io,more_io,dirty_time}, inode->i_io_list
 * inode_hash_lock protects:
 *   inode_hashtable, inode->i_hash
 *
 * Lock ordering:
 *
 * inode->i_sb->s_inode_list_lock
 *   inode->i_lock
 *     Inode LRU list locks
 *
 * bdi->wb.list_lock
 *   inode->i_lock
 *
 * inode_hash_lock
 *   inode->i_sb->s_inode_list_lock
 *   inode->i_lock
 *
 * iunique_lock
 *   inode_hash_lock
 */

static unsigned int i_hash_mask __read_mostly;
static unsigned int i_hash_shift __read_mostly;
/*
 * 哈希键为superblock和inode_no
 */
static struct hlist_head *inode_hashtable __read_mostly;
static __cacheline_aligned_in_smp DEFINE_SPINLOCK(inode_hash_lock);

/*
 * Empty aops. Can be used for the cases where the user does not
 * define any of the address_space operations.
 */
const struct address_space_operations empty_aops = {
};
EXPORT_SYMBOL(empty_aops);

/*
 * Statistics gathering..
 */
struct inodes_stat_t inodes_stat;

static DEFINE_PER_CPU(unsigned long, nr_inodes);
static DEFINE_PER_CPU(unsigned long, nr_unused);

static struct kmem_cache *inode_cachep __read_mostly;

static long get_nr_inodes(void)
{
	int i;
	long sum = 0;
	for_each_possible_cpu(i)
		sum += per_cpu(nr_inodes, i);
	return sum < 0 ? 0 : sum;
}

static inline long get_nr_inodes_unused(void)
{
	int i;
	long sum = 0;
	for_each_possible_cpu(i)
		sum += per_cpu(nr_unused, i);
	return sum < 0 ? 0 : sum;
}

long get_nr_dirty_inodes(void)
{
	/* not actually dirty inodes, but a wild approximation */
	long nr_dirty = get_nr_inodes() - get_nr_inodes_unused();
	return nr_dirty > 0 ? nr_dirty : 0;
}

/*
 * Handle nr_inode sysctl
 */
#ifdef CONFIG_SYSCTL
int proc_nr_inodes(struct ctl_table *table, int write,
		   void __user *buffer, size_t *lenp, loff_t *ppos)
{
	inodes_stat.nr_inodes = get_nr_inodes();
	inodes_stat.nr_unused = get_nr_inodes_unused();
	return proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
}
#endif

static int no_open(struct inode *inode, struct file *file)
{
	return -ENXIO;
}

/**
 * inode_init_always - perform inode structure initialisation
 * @sb: superblock inode belongs to
 * @inode: inode to initialise
 *
 * These are initializations that need to be done on every inode
 * allocation as the fields are not initialised by slab allocation.
 */
int inode_init_always(struct super_block *sb, struct inode *inode)
{
	static const struct inode_operations empty_iops;
	static const struct file_operations no_open_fops = {.open = no_open};
	struct address_space *const mapping = &inode->i_data;

	inode->i_sb = sb;
	inode->i_blkbits = sb->s_blocksize_bits;
	inode->i_flags = 0;
	atomic64_set(&inode->i_sequence, 0);
	/*
	 * 引用计数设置为1
	 */
	atomic_set(&inode->i_count, 1);
	/*
	 * 此处只是对新分配的inode进行一般化的初始化，所以设置的i_ops及i_fops都
	 * 是不可用的（但不会导致内核crash，只是返回给调用者失败）。
	 *
	 * 真正赋值可用的操作结构体是在各文件系统拿到init inode后，再进行相应的
	 * 设置。比如：ext4_iget()、kernfs_init_inode()、xfs_setup_iops()等
	 */
	inode->i_op = &empty_iops;
	inode->i_fop = &no_open_fops;
	/*
	 * __i_nlink和i_nlink是一个union
	 */ 
	inode->__i_nlink = 1;
	inode->i_opflags = 0;
	if (sb->s_xattr)
		inode->i_opflags |= IOP_XATTR;
	/*
	 * 这里给inode->i_uid,i_gid都设置了0，那么什么时候去设置正确的用户呢？
	 * - 这里是公共的初始化函数，所以这里只能初始化为0，在本函数返回后，会在
	 *   上层函数__ext4_new_inode()中设置指定的uid,gid；
	 */
	i_uid_write(inode, 0);
	i_gid_write(inode, 0);
	atomic_set(&inode->i_writecount, 0);
	inode->i_size = 0;
	inode->i_write_hint = WRITE_LIFE_NOT_SET;
	inode->i_blocks = 0;
	inode->i_bytes = 0;
	inode->i_generation = 0;
	inode->i_pipe = NULL;
	inode->i_bdev = NULL;
	inode->i_cdev = NULL;
	inode->i_link = NULL;
	inode->i_dir_seq = 0;
	inode->i_rdev = 0;
	inode->dirtied_when = 0;

#ifdef CONFIG_CGROUP_WRITEBACK
	inode->i_wb_frn_winner = 0;
	inode->i_wb_frn_avg_time = 0;
	inode->i_wb_frn_history = 0;
#endif

	/*
	 * 在inode_init_always中调用的security竟然是security_inode_alloc
	 *
	 * security_inode_init反倒是在create中调用的
	 */
	if (security_inode_alloc(inode))
		goto out;
	spin_lock_init(&inode->i_lock);
	lockdep_set_class(&inode->i_lock, &sb->s_type->i_lock_key);

	init_rwsem(&inode->i_rwsem);
	lockdep_set_class(&inode->i_rwsem, &sb->s_type->i_mutex_key);

	atomic_set(&inode->i_dio_count, 0);

	mapping->a_ops = &empty_aops;
	mapping->host = inode;
	mapping->flags = 0;
	mapping->wb_err = 0;
	atomic_set(&mapping->i_mmap_writable, 0);
#ifdef CONFIG_READ_ONLY_THP_FOR_FS
	atomic_set(&mapping->nr_thps, 0);
#endif
	mapping_set_gfp_mask(mapping, GFP_HIGHUSER_MOVABLE);
	mapping->private_data = NULL;
	mapping->writeback_index = 0;
	inode->i_private = NULL;
	/*
	 * 所有inode的i_mapping字段默认都指向自己内嵌的i_data字段；
	 * - 但对于设备文件，在blkdev_open()中有可能被修改；
	 */
	inode->i_mapping = mapping;
	INIT_HLIST_HEAD(&inode->i_dentry);	/* buggered by rcu freeing */
#ifdef CONFIG_FS_POSIX_ACL
	inode->i_acl = inode->i_default_acl = ACL_NOT_CACHED;
#endif

#ifdef CONFIG_FSNOTIFY
	inode->i_fsnotify_mask = 0;
#endif
	inode->i_flctx = NULL;
	this_cpu_inc(nr_inodes);

	return 0;
out:
	return -ENOMEM;
}
EXPORT_SYMBOL(inode_init_always);

void free_inode_nonrcu(struct inode *inode)
{
	kmem_cache_free(inode_cachep, inode);
}
EXPORT_SYMBOL(free_inode_nonrcu);

static void i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	if (inode->free_inode)
		inode->free_inode(inode);
	else
		free_inode_nonrcu(inode);
}

static struct inode *alloc_inode(struct super_block *sb)
{
	const struct super_operations *ops = sb->s_op;
	struct inode *inode;

	if (ops->alloc_inode)
		/*
		 * 对于ext4文件系统来说，这里调用的是 ext4_alloc_inode()，其中
		 * 分配的是ext4_inode_info，并指定了部分初始值，返回的是其中的
		 * vfs inode部分。
		 *
		 * 对于sockfs，这里调用的是sock_alloc_inode()，其中分配的结构体
		 * 是socket_alloc，返回其中内嵌的inode；
		 *
		 * 对xfs来说，该回调定义了，但会直接调用BUG()；
		 * - 也就是说，xfs不会调用alloc_inode；
		 * - 其inode的分配在xfs_dir_inode_operations.create()方法中；
		 *
		 * 所以，这里结束时我们有了一个ext4_inode_info
		 */
		inode = ops->alloc_inode(sb);
	else
		/*
		 * kernfs没有定义此方法，所以是直接分配一个内存中的inode
		 * xfs也没有定义此方法。
		 */
		inode = kmem_cache_alloc(inode_cachep, GFP_KERNEL);

	if (!inode)
		return NULL;

	/*
	 * 这里面会将新分配的inode的引用计数设置为1
	 *
	 * 在里面执行了security_inode_alloc
	 */
	if (unlikely(inode_init_always(sb, inode))) {
		if (ops->destroy_inode) {
			ops->destroy_inode(inode);
			if (!ops->free_inode)
				return NULL;
		}
		inode->free_inode = ops->free_inode;
		/*
		 * TODO: inode的删除似乎就是用了延迟的机制 
		 */
		i_callback(&inode->i_rcu);
		return NULL;
	}

	return inode;
}

void __destroy_inode(struct inode *inode)
{
	BUG_ON(inode_has_buffers(inode));
	inode_detach_wb(inode);
	security_inode_free(inode);
	fsnotify_inode_delete(inode);
	locks_free_lock_context(inode);
	if (!inode->i_nlink) {
		WARN_ON(atomic_long_read(&inode->i_sb->s_remove_count) == 0);
		atomic_long_dec(&inode->i_sb->s_remove_count);
	}

#ifdef CONFIG_FS_POSIX_ACL
	if (inode->i_acl && !is_uncached_acl(inode->i_acl))
		posix_acl_release(inode->i_acl);
	if (inode->i_default_acl && !is_uncached_acl(inode->i_default_acl))
		posix_acl_release(inode->i_default_acl);
#endif
	this_cpu_dec(nr_inodes);
}
EXPORT_SYMBOL(__destroy_inode);

static void destroy_inode(struct inode *inode)
{
	const struct super_operations *ops = inode->i_sb->s_op;

	BUG_ON(!list_empty(&inode->i_lru));
	/*
	 * 释放inode的其他资源
	 * - 包括writeback等
	 *   > 这些资源回收之后，->destroy_inode()中的io操作怎么办？
	 *     - ext4中，__destroy_inode()后不再有io操作；
	 *     - xfs中，还有io操作
	 */
	__destroy_inode(inode);
	if (ops->destroy_inode) {
		/*
		 * xfs: xfs_fs_destroy_inode()
		 * ext4: ext4_destroy_inode()
		 */
		ops->destroy_inode(inode);
		/*
		 * xfs: NULL
		 * ext4: ext4_free_in_core_inode()
		 */
		if (!ops->free_inode)
			return;
	}
	inode->free_inode = ops->free_inode;
	call_rcu(&inode->i_rcu, i_callback);
}

/**
 * drop_nlink - directly drop an inode's link count
 * @inode: inode
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.  In cases
 * where we are attempting to track writes to the
 * filesystem, a decrement to zero means an imminent
 * write when the file is truncated and actually unlinked
 * on the filesystem.
 */
void drop_nlink(struct inode *inode)
{
	WARN_ON(inode->i_nlink == 0);
	inode->__i_nlink--;
	if (!inode->i_nlink)
		atomic_long_inc(&inode->i_sb->s_remove_count);
}
EXPORT_SYMBOL(drop_nlink);

/**
 * clear_nlink - directly zero an inode's link count
 * @inode: inode
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.  See
 * drop_nlink() for why we care about i_nlink hitting zero.
 */
void clear_nlink(struct inode *inode)
{
	if (inode->i_nlink) {
		inode->__i_nlink = 0;
		atomic_long_inc(&inode->i_sb->s_remove_count);
	}
}
EXPORT_SYMBOL(clear_nlink);

/**
 * set_nlink - directly set an inode's link count
 * @inode: inode
 * @nlink: new nlink (should be non-zero)
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.
 */
void set_nlink(struct inode *inode, unsigned int nlink)
{
	if (!nlink) {
		clear_nlink(inode);
	} else {
		/* Yes, some filesystems do change nlink from zero to one */
		if (inode->i_nlink == 0)
			atomic_long_dec(&inode->i_sb->s_remove_count);

		inode->__i_nlink = nlink;
	}
}
EXPORT_SYMBOL(set_nlink);

/**
 * inc_nlink - directly increment an inode's link count
 * @inode: inode
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.  Currently,
 * it is only here for parity with dec_nlink().
 */
void inc_nlink(struct inode *inode)
{
	if (unlikely(inode->i_nlink == 0)) {
		WARN_ON(!(inode->i_state & I_LINKABLE));
		atomic_long_dec(&inode->i_sb->s_remove_count);
	}

	inode->__i_nlink++;
}
EXPORT_SYMBOL(inc_nlink);

static void __address_space_init_once(struct address_space *mapping)
{
	xa_init_flags(&mapping->i_pages, XA_FLAGS_LOCK_IRQ | XA_FLAGS_ACCOUNT);
	init_rwsem(&mapping->i_mmap_rwsem);
	INIT_LIST_HEAD(&mapping->private_list);
	spin_lock_init(&mapping->private_lock);
	mapping->i_mmap = RB_ROOT_CACHED;
}

void address_space_init_once(struct address_space *mapping)
{
	memset(mapping, 0, sizeof(*mapping));
	__address_space_init_once(mapping);
}
EXPORT_SYMBOL(address_space_init_once);

/*
 * These are initializations that only need to be done
 * once, because the fields are idempotent across use
 * of the inode, so let the slab aware of that.
 */
void inode_init_once(struct inode *inode)
{
	memset(inode, 0, sizeof(*inode));
	INIT_HLIST_NODE(&inode->i_hash);
	INIT_LIST_HEAD(&inode->i_devices);
	INIT_LIST_HEAD(&inode->i_io_list);
	INIT_LIST_HEAD(&inode->i_wb_list);
	INIT_LIST_HEAD(&inode->i_lru);
	__address_space_init_once(&inode->i_data);
	i_size_ordered_init(inode);
}
EXPORT_SYMBOL(inode_init_once);

static void init_once(void *foo)
{
	struct inode *inode = (struct inode *) foo;

	inode_init_once(inode);
}

/*
 * inode->i_lock must be held
 */
void __iget(struct inode *inode)
{
	atomic_inc(&inode->i_count);
}

/*
 * get additional reference to inode; caller must already hold one.
 */
void ihold(struct inode *inode)
{
	WARN_ON(atomic_inc_return(&inode->i_count) < 2);
}
EXPORT_SYMBOL(ihold);

static void inode_lru_list_add(struct inode *inode)
{
	if (list_lru_add(&inode->i_sb->s_inode_lru, &inode->i_lru))
		this_cpu_inc(nr_unused);
	else
		inode->i_state |= I_REFERENCED;
}

/*
 * Add inode to LRU if needed (inode is unused and clean).
 *
 * Needs inode->i_lock held.
 */
void inode_add_lru(struct inode *inode)
{
	if (!(inode->i_state & (I_DIRTY_ALL | I_SYNC |
				I_FREEING | I_WILL_FREE)) &&
	    !atomic_read(&inode->i_count) && inode->i_sb->s_flags & SB_ACTIVE)
		inode_lru_list_add(inode);
}


static void inode_lru_list_del(struct inode *inode)
{

	if (list_lru_del(&inode->i_sb->s_inode_lru, &inode->i_lru))
		this_cpu_dec(nr_unused);
}

/**
 * inode_sb_list_add - add inode to the superblock list of inodes
 * @inode: inode to add
 */
void inode_sb_list_add(struct inode *inode)
{
	spin_lock(&inode->i_sb->s_inode_list_lock);
	list_add(&inode->i_sb_list, &inode->i_sb->s_inodes);
	spin_unlock(&inode->i_sb->s_inode_list_lock);
}
EXPORT_SYMBOL_GPL(inode_sb_list_add);

static inline void inode_sb_list_del(struct inode *inode)
{
	if (!list_empty(&inode->i_sb_list)) {
		spin_lock(&inode->i_sb->s_inode_list_lock);
		list_del_init(&inode->i_sb_list);
		spin_unlock(&inode->i_sb->s_inode_list_lock);
	}
}

static unsigned long hash(struct super_block *sb, unsigned long hashval)
{
	unsigned long tmp;

	tmp = (hashval * (unsigned long)sb) ^ (GOLDEN_RATIO_PRIME + hashval) /
			L1_CACHE_BYTES;
	tmp = tmp ^ ((tmp ^ GOLDEN_RATIO_PRIME) >> i_hash_shift);
	return tmp & i_hash_mask;
}

/**
 *	__insert_inode_hash - hash an inode
 *	@inode: unhashed inode
 *	@hashval: unsigned long value used to locate this object in the
 *		inode_hashtable.
 *
 *	Add an inode to the inode hash for this superblock.
 */
void __insert_inode_hash(struct inode *inode, unsigned long hashval)
{
	struct hlist_head *b = inode_hashtable + hash(inode->i_sb, hashval);

	spin_lock(&inode_hash_lock);
	spin_lock(&inode->i_lock);
	hlist_add_head(&inode->i_hash, b);
	spin_unlock(&inode->i_lock);
	spin_unlock(&inode_hash_lock);
}
EXPORT_SYMBOL(__insert_inode_hash);

/**
 *	__remove_inode_hash - remove an inode from the hash
 *	@inode: inode to unhash
 *
 *	Remove an inode from the superblock.
 */
void __remove_inode_hash(struct inode *inode)
{
	spin_lock(&inode_hash_lock);
	spin_lock(&inode->i_lock);
	hlist_del_init(&inode->i_hash);
	spin_unlock(&inode->i_lock);
	spin_unlock(&inode_hash_lock);
}
EXPORT_SYMBOL(__remove_inode_hash);

void clear_inode(struct inode *inode)
{
	/*
	 * We have to cycle the i_pages lock here because reclaim can be in the
	 * process of removing the last page (in __delete_from_page_cache())
	 * and we must not free the mapping under it.
	 */
	xa_lock_irq(&inode->i_data.i_pages);
	BUG_ON(inode->i_data.nrpages);
	BUG_ON(inode->i_data.nrexceptional);
	xa_unlock_irq(&inode->i_data.i_pages);
	BUG_ON(!list_empty(&inode->i_data.private_list));
	BUG_ON(!(inode->i_state & I_FREEING));
	BUG_ON(inode->i_state & I_CLEAR);
	BUG_ON(!list_empty(&inode->i_wb_list));
	/* don't need i_lock here, no concurrent mods to i_state */
	inode->i_state = I_FREEING | I_CLEAR;
}
EXPORT_SYMBOL(clear_inode);

/*
 * Free the inode passed in, removing it from the lists it is still connected
 * to. We remove any pages still attached to the inode and wait for any IO that
 * is still in progress before finally destroying the inode.
 *
 * An inode must already be marked I_FREEING so that we avoid the inode being
 * moved back onto lists if we race with other code that manipulates the lists
 * (e.g. writeback_single_inode). The caller is responsible for setting this.
 *
 * An inode must already be removed from the LRU list before being evicted from
 * the cache. This should occur atomically with setting the I_FREEING state
 * flag, so no inodes here should ever be on the LRU when being evicted.
 */
static void evict(struct inode *inode)
{
	const struct super_operations *op = inode->i_sb->s_op;

	BUG_ON(!(inode->i_state & I_FREEING));
	BUG_ON(!list_empty(&inode->i_lru));

	if (!list_empty(&inode->i_io_list))
		inode_io_list_del(inode);

	inode_sb_list_del(inode);

	/*
	 * Wait for flusher thread to be done with the inode so that filesystem
	 * does not start destroying it while writeback is still running. Since
	 * the inode has I_FREEING set, flusher thread won't start new work on
	 * the inode.  We just have to wait for running writeback to finish.
	 *
	 * 既然决定要删除了？还在这里等他写完，是不是没有什么意义？
	 * - 这里是释放内存中的inode，不是在磁盘上删除
	 *   > 如果是do_unlinkat() ~> evict_inode()这样调用过来的呢？
	 *
	 * - prune_icache_sb()路径上似乎没有对inode本身做回写操作？
	 *   > 首先，xfs本身是不需要回写inode的，这从其super_operations中没有设
	 *     置.write_inode函数指针即可猜测。实际上，xfs的inode元数据回写是由
	 *     AIL机制完成的。
	 *   > 对于其他的文件系统，比如ext4，猜测其在evict_inode()中进行了某些
	 *     操作。
	 * --------------------------------------------------------------------
	 * 要明白一点，对于有日志系统的文件系统来说，是不需要回写inode metadata
	 * 操作的，因为日志系统中，事务提交后，inode metadata区域已经被更新了；
	 * 比如，在xfs中，inode metadata的回写就是通过AIL部分自动完成的；
	 */
	inode_wait_for_writeback(inode);

	if (op->evict_inode) {
		/*
		 * xfs: NULL
		 * ext4: ext4_evict_inode()
		 */
		op->evict_inode(inode);
	} else {
		/*
		 * xfs走这里 -- iput()路径
		 * x 如果这个inode没有在磁盘上被删除，那么在调用evict()之前是调
		 *   用了write_inode_now()且同步等待了的；那么这里再调用这个的意
		 *   义是什么呢？
		 * x 如果这个inode已经在磁盘上被删除了，那么我们应该直接将page
		 *   cache释放即可，为什么还要回写呢？
		 *
		 * ---------------------------  ANS  --------------------------
		 *
		 * - 这里并不是回写页，回写页已经在前面做好了，这里是将这些页从
		 *   pagecahe中删除；
		 *
		 * ============================================================
		 *
		 * xfs走这里 -- prune_icache_sb()路径
		 *
		 */
		truncate_inode_pages_final(&inode->i_data);
		/*
		 * 设置inode的I_FREEING | I_CLEAR标志
		 * - 其实在进入evict()之前，inode就已经被标记上I_FREEING标志了
		 */
		clear_inode(inode);
	}
	if (S_ISBLK(inode->i_mode) && inode->i_bdev)
		bd_forget(inode);
	if (S_ISCHR(inode->i_mode) && inode->i_cdev)
		cd_forget(inode);

	/*
	 * 将inode从hash表上摘下来
	 */
	remove_inode_hash(inode);

	spin_lock(&inode->i_lock);
	/*
	 * 这个wakeup的作用？
	 * - 参见：ext4_iget() -> iget_locked() -> wait_on_inode()
	 */
	wake_up_bit(&inode->i_state, __I_NEW);
	BUG_ON(inode->i_state != (I_FREEING | I_CLEAR));
	spin_unlock(&inode->i_lock);

	/*
	 * 调用.destory_inode()和.free_inode()
	 */
	destroy_inode(inode);
}

/*
 * dispose_list - dispose of the contents of a local list
 * @head: the head of the list to free
 *
 * Dispose-list gets a local list with local inodes in it, so it doesn't
 * need to worry about list corruption and SMP locks.
 */
static void dispose_list(struct list_head *head)
{
	while (!list_empty(head)) {
		struct inode *inode;

		inode = list_first_entry(head, struct inode, i_lru);
		list_del_init(&inode->i_lru);

		/*
		 * 对于正常的iput()流程，在调用evict()之前是有机会被拦截从而防
		 * 入icache的；在这里就直接调用evict()了；
		 */
		evict(inode);
		cond_resched();
	}
}

/**
 * evict_inodes	- evict all evictable inodes for a superblock
 * @sb:		superblock to operate on
 *
 * Make sure that no inodes with zero refcount are retained.  This is
 * called by superblock shutdown after having SB_ACTIVE flag removed,
 * so any inode reaching zero refcount during or after that call will
 * be immediately evicted.
 */
void evict_inodes(struct super_block *sb)
{
	struct inode *inode, *next;
	LIST_HEAD(dispose);

again:
	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry_safe(inode, next, &sb->s_inodes, i_sb_list) {
		if (atomic_read(&inode->i_count))
			continue;

		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_NEW | I_FREEING | I_WILL_FREE)) {
			spin_unlock(&inode->i_lock);
			continue;
		}

		inode->i_state |= I_FREEING;
		inode_lru_list_del(inode);
		spin_unlock(&inode->i_lock);
		list_add(&inode->i_lru, &dispose);

		/*
		 * We can have a ton of inodes to evict at unmount time given
		 * enough memory, check to see if we need to go to sleep for a
		 * bit so we don't livelock.
		 */
		if (need_resched()) {
			spin_unlock(&sb->s_inode_list_lock);
			cond_resched();
			dispose_list(&dispose);
			goto again;
		}
	}
	spin_unlock(&sb->s_inode_list_lock);

	dispose_list(&dispose);
}
EXPORT_SYMBOL_GPL(evict_inodes);

/**
 * invalidate_inodes	- attempt to free all inodes on a superblock
 * @sb:		superblock to operate on
 * @kill_dirty: flag to guide handling of dirty inodes
 *
 * Attempts to free all inodes for a given superblock.  If there were any
 * busy inodes return a non-zero value, else zero.
 * If @kill_dirty is set, discard dirty inodes too, otherwise treat
 * them as busy.
 */
int invalidate_inodes(struct super_block *sb, bool kill_dirty)
{
	int busy = 0;
	struct inode *inode, *next;
	LIST_HEAD(dispose);

again:
	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry_safe(inode, next, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_NEW | I_FREEING | I_WILL_FREE)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		if (inode->i_state & I_DIRTY_ALL && !kill_dirty) {
			spin_unlock(&inode->i_lock);
			busy = 1;
			continue;
		}
		if (atomic_read(&inode->i_count)) {
			spin_unlock(&inode->i_lock);
			busy = 1;
			continue;
		}

		inode->i_state |= I_FREEING;
		inode_lru_list_del(inode);
		spin_unlock(&inode->i_lock);
		list_add(&inode->i_lru, &dispose);
		if (need_resched()) {
			spin_unlock(&sb->s_inode_list_lock);
			cond_resched();
			dispose_list(&dispose);
			goto again;
		}
	}
	spin_unlock(&sb->s_inode_list_lock);

	dispose_list(&dispose);

	return busy;
}

/*
 * Isolate the inode from the LRU in preparation for freeing it.
 *
 * Any inodes which are pinned purely because of attached pagecache have their
 * pagecache removed.  If the inode has metadata buffers attached to
 * mapping->private_list then try to remove them.
 *
 * If the inode has the I_REFERENCED flag set, then it means that it has been
 * used recently - the flag is set in iput_final(). When we encounter such an
 * inode, clear the flag and move it to the back of the LRU so it gets another
 * pass through the LRU before it gets reclaimed. This is necessary because of
 * the fact we are doing lazy LRU updates to minimise lock contention so the
 * LRU does not have strict ordering. Hence we don't want to reclaim inodes
 * with this flag set because they are the inodes that are out of order.
 */
static enum lru_status inode_lru_isolate(struct list_head *item,
		struct list_lru_one *lru, spinlock_t *lru_lock, void *arg)
{
	struct list_head *freeable = arg;
	struct inode	*inode = container_of(item, struct inode, i_lru);

	/*
	 * we are inverting the lru lock/inode->i_lock here, so use a trylock.
	 * If we fail to get the lock, just skip it.
	 */
	if (!spin_trylock(&inode->i_lock))
		return LRU_SKIP;

	/*
	 * Referenced or dirty inodes are still in use. Give them another pass
	 * through the LRU as we canot reclaim them now.
	 */
	if (atomic_read(&inode->i_count) ||
	    (inode->i_state & ~I_REFERENCED)) {
		list_lru_isolate(lru, &inode->i_lru);
		spin_unlock(&inode->i_lock);
		this_cpu_dec(nr_unused);
		return LRU_REMOVED;
	}

	/* recently referenced inodes get one more pass */
	if (inode->i_state & I_REFERENCED) {
		inode->i_state &= ~I_REFERENCED;
		spin_unlock(&inode->i_lock);
		return LRU_ROTATE;
	}

	if (inode_has_buffers(inode) || inode->i_data.nrpages) {
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(lru_lock);
		if (remove_inode_buffers(inode)) {
			unsigned long reap;
			/*
			 * 这里和evict()中的truncate_inode_pages_final()关系是？
			 */
			reap = invalidate_mapping_pages(&inode->i_data, 0, -1);
			if (current_is_kswapd())
				__count_vm_events(KSWAPD_INODESTEAL, reap);
			else
				__count_vm_events(PGINODESTEAL, reap);
			if (current->reclaim_state)
				current->reclaim_state->reclaimed_slab += reap;
		}
		iput(inode);
		spin_lock(lru_lock);
		return LRU_RETRY;
	}

	WARN_ON(inode->i_state & I_NEW);
	/*
	 * 这里设置上之后，vfs对fs的要求是要等inode被完全释放后才能分配新的
	 * inode；
	 * - 参见I_CLEAR的注释
	 */
	inode->i_state |= I_FREEING;
	list_lru_isolate_move(lru, &inode->i_lru, freeable);
	spin_unlock(&inode->i_lock);

	this_cpu_dec(nr_unused);
	return LRU_REMOVED;
}

/*
 * Walk the superblock inode LRU for freeable inodes and attempt to free them.
 * This is called from the superblock shrinker function with a number of inodes
 * to trim from the LRU. Inodes to be freed are moved to a temporary list and
 * then are freed outside inode_lock by dispose_list().
 */
long prune_icache_sb(struct super_block *sb, struct shrink_control *sc)
{
	LIST_HEAD(freeable);
	long freed;

	freed = list_lru_shrink_walk(&sb->s_inode_lru, sc,
				     inode_lru_isolate, &freeable);
	dispose_list(&freeable);
	return freed;
}

static void __wait_on_freeing_inode(struct inode *inode);
/*
 * Called with the inode lock held.
 */
static struct inode *find_inode(struct super_block *sb,
				struct hlist_head *head,
				int (*test)(struct inode *, void *),
				void *data)
{
	struct inode *inode = NULL;

repeat:
	hlist_for_each_entry(inode, head, i_hash) {
		if (inode->i_sb != sb)
			continue;
		if (!test(inode, data))
			continue;
		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_FREEING|I_WILL_FREE)) {
			__wait_on_freeing_inode(inode);
			goto repeat;
		}
		if (unlikely(inode->i_state & I_CREATING)) {
			spin_unlock(&inode->i_lock);
			return ERR_PTR(-ESTALE);
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		return inode;
	}
	return NULL;
}

/*
 * find_inode_fast is the fast path version of find_inode, see the comment at
 * iget_locked for details.
 */
static struct inode *find_inode_fast(struct super_block *sb,
				struct hlist_head *head, unsigned long ino)
{
	struct inode *inode = NULL;

repeat:
	hlist_for_each_entry(inode, head, i_hash) {
		if (inode->i_ino != ino)
			continue;
		if (inode->i_sb != sb)
			continue;
		/*
		 * 此处的spin_lock成功时的分析：
		 * 1. 此时会导致下面的__iget()成功，从而iput()侧的
		 *    atomic_dec_and_lock()不可能使引用计数减小到0，iput()立即
		 *    退出；
		 * 2. 此时本处观测的inode->i_state中有FREEING标记，等待__I_NEW
		 *    并repeat，直到iput()端执行到remove_inode_hash()，导致哈希
		 *    表里再也差不到，本处退出；
		 * 3. 与2相同
		 * 4. 不可能。因为在整个find_inode_fast()中我们都持有
		 *    inode_hash_lock，走到这里时，iput()侧没有机会将inode从哈
		 *    希表里删除；
		 * 5. 与4相同。
		 *
		 * 关键点：inode_hash_lock保证整个find_inode_fast()逻辑要么在
		 * remove_inode_hash之前，要么在remove_inode_hash之后。
		 *
		 * iput
		 *   --------------------------------------- 1
		 *   atomic_dec_and_lock
		 *     iput_final
		 *       inode->i_state |= I_FREEING
		 *       spin_unlock
		 *       ----------------------------------- 2
		 *       evict
		 *         --------------------------------- 3
		 *         remove_inode_hash
		 *         --------------------------------- 4
		 *         spin_lock
		 *         wake_up_bit(__I_NEW)
		 *         spin_unlock
		 *         --------------------------------- 5
		 */
		spin_lock(&inode->i_lock);
		/*
		 * 诶，所以非xfs也是要等待I_FREEING|I_WILL_FREE标志的，只不过下
		 * 面的__wait_on_freeing_inode()是使用__I_NEW这个标志来等的；
		 *
		 * 运行到这里的时候，会不会evict()中已经把wake_up_bit(__I_NEW)执
		 * 行过了，导致下面的wait永远醒不了呢？
		 * - 不可能，如果wake_up_bit()都已经走过了，那么肯定也运行了
		 *   remove_inode_hash()，从而我们就不可能在哈希表里找到该inode
		 *   了，也就不会进入本处的循环了；
		 */
		if (inode->i_state & (I_FREEING|I_WILL_FREE)) {
			__wait_on_freeing_inode(inode);
			goto repeat;
		}
		if (unlikely(inode->i_state & I_CREATING)) {
			spin_unlock(&inode->i_lock);
			return ERR_PTR(-ESTALE);
		}
		/*
		 * 增加计数
		 */
		__iget(inode);
		spin_unlock(&inode->i_lock);
		return inode;
	}
	return NULL;
}

/*
 * Each cpu owns a range of LAST_INO_BATCH numbers.
 * 'shared_last_ino' is dirtied only once out of LAST_INO_BATCH allocations,
 * to renew the exhausted range.
 *
 * This does not significantly increase overflow rate because every CPU can
 * consume at most LAST_INO_BATCH-1 unused inode numbers. So there is
 * NR_CPUS*(LAST_INO_BATCH-1) wastage. At 4096 and 1024, this is ~0.1% of the
 * 2^32 range, and is a worst-case. Even a 50% wastage would only increase
 * overflow rate by 2x, which does not seem too significant.
 *
 * On a 32bit, non LFS stat() call, glibc will generate an EOVERFLOW
 * error if st_ino won't fit in target struct field. Use 32bit counter
 * here to attempt to avoid that.
 */
#define LAST_INO_BATCH 1024
static DEFINE_PER_CPU(unsigned int, last_ino);

unsigned int get_next_ino(void)
{
	unsigned int *p = &get_cpu_var(last_ino);
	unsigned int res = *p;

#ifdef CONFIG_SMP
	if (unlikely((res & (LAST_INO_BATCH-1)) == 0)) {
		static atomic_t shared_last_ino;
		int next = atomic_add_return(LAST_INO_BATCH, &shared_last_ino);

		res = next - LAST_INO_BATCH;
	}
#endif

	res++;
	/* get_next_ino should not provide a 0 inode number */
	if (unlikely(!res))
		res++;
	*p = res;
	put_cpu_var(last_ino);
	return res;
}
EXPORT_SYMBOL(get_next_ino);

/**
 *	new_inode_pseudo 	- obtain an inode
 *	@sb: superblock
 *
 *	Allocates a new inode for given superblock.
 *	Inode wont be chained in superblock s_inodes list
 *	This means :
 *	- fs can't be unmount
 *	- quotas, fsnotify, writeback can't work
 */
struct inode *new_inode_pseudo(struct super_block *sb)
{
	struct inode *inode = alloc_inode(sb);

	if (inode) {
		spin_lock(&inode->i_lock);
		inode->i_state = 0;
		spin_unlock(&inode->i_lock);
		INIT_LIST_HEAD(&inode->i_sb_list);
	}
	return inode;
}

/**
 *	new_inode 	- obtain an inode
 *	@sb: superblock
 *
 *	Allocates a new inode for given superblock. The default gfp_mask
 *	for allocations related to inode->i_mapping is GFP_HIGHUSER_MOVABLE.
 *	If HIGHMEM pages are unsuitable or it is known that pages allocated
 *	for the page cache are not reclaimable or migratable,
 *	mapping_set_gfp_mask() must be called with suitable flags on the
 *	newly created inode's mapping
 *
 */
struct inode *new_inode(struct super_block *sb)
{
	struct inode *inode;

	spin_lock_prefetch(&sb->s_inode_list_lock);

	inode = new_inode_pseudo(sb);
	if (inode)
		inode_sb_list_add(inode);
	return inode;
}
EXPORT_SYMBOL(new_inode);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
void lockdep_annotate_inode_mutex_key(struct inode *inode)
{
	if (S_ISDIR(inode->i_mode)) {
		struct file_system_type *type = inode->i_sb->s_type;

		/* Set new key only if filesystem hasn't already changed it */
		if (lockdep_match_class(&inode->i_rwsem, &type->i_mutex_key)) {
			/*
			 * ensure nobody is actually holding i_mutex
			 */
			// mutex_destroy(&inode->i_mutex);
			init_rwsem(&inode->i_rwsem);
			lockdep_set_class(&inode->i_rwsem,
					  &type->i_mutex_dir_key);
		}
	}
}
EXPORT_SYMBOL(lockdep_annotate_inode_mutex_key);
#endif

/**
 * unlock_new_inode - clear the I_NEW state and wake up any waiters
 * @inode:	new inode to unlock
 *
 * Called when the inode is fully initialised to clear the new state of the
 * inode and wake up anyone waiting for the inode to finish initialisation.
 */
void unlock_new_inode(struct inode *inode)
{
	lockdep_annotate_inode_mutex_key(inode);
	spin_lock(&inode->i_lock);
	WARN_ON(!(inode->i_state & I_NEW));
	inode->i_state &= ~I_NEW & ~I_CREATING;
	smp_mb();
	wake_up_bit(&inode->i_state, __I_NEW);
	spin_unlock(&inode->i_lock);
}
EXPORT_SYMBOL(unlock_new_inode);

void discard_new_inode(struct inode *inode)
{
	lockdep_annotate_inode_mutex_key(inode);
	spin_lock(&inode->i_lock);
	WARN_ON(!(inode->i_state & I_NEW));
	inode->i_state &= ~I_NEW;
	smp_mb();
	wake_up_bit(&inode->i_state, __I_NEW);
	spin_unlock(&inode->i_lock);
	iput(inode);
}
EXPORT_SYMBOL(discard_new_inode);

/**
 * lock_two_nondirectories - take two i_mutexes on non-directory objects
 *
 * Lock any non-NULL argument that is not a directory.
 * Zero, one or two objects may be locked by this function.
 *
 * @inode1: first inode to lock
 * @inode2: second inode to lock
 */
void lock_two_nondirectories(struct inode *inode1, struct inode *inode2)
{
	if (inode1 > inode2)
		swap(inode1, inode2);

	if (inode1 && !S_ISDIR(inode1->i_mode))
		inode_lock(inode1);
	if (inode2 && !S_ISDIR(inode2->i_mode) && inode2 != inode1)
		inode_lock_nested(inode2, I_MUTEX_NONDIR2);
}
EXPORT_SYMBOL(lock_two_nondirectories);

/**
 * unlock_two_nondirectories - release locks from lock_two_nondirectories()
 * @inode1: first inode to unlock
 * @inode2: second inode to unlock
 */
void unlock_two_nondirectories(struct inode *inode1, struct inode *inode2)
{
	if (inode1 && !S_ISDIR(inode1->i_mode))
		inode_unlock(inode1);
	if (inode2 && !S_ISDIR(inode2->i_mode) && inode2 != inode1)
		inode_unlock(inode2);
}
EXPORT_SYMBOL(unlock_two_nondirectories);

/**
 * inode_insert5 - obtain an inode from a mounted file system
 * @inode:	pre-allocated inode to use for insert to cache
 * @hashval:	hash value (usually inode number) to get
 * @test:	callback used for comparisons between inodes
 * @set:	callback used to initialize a new struct inode
 * @data:	opaque data pointer to pass to @test and @set
 *
 * Search for the inode specified by @hashval and @data in the inode cache,
 * and if present it is return it with an increased reference count. This is
 * a variant of iget5_locked() for callers that don't want to fail on memory
 * allocation of inode.
 *
 * If the inode is not in cache, insert the pre-allocated inode to cache and
 * return it locked, hashed, and with the I_NEW flag set. The file system gets
 * to fill it in before unlocking it via unlock_new_inode().
 *
 * Note both @test and @set are called with the inode_hash_lock held, so can't
 * sleep.
 */
struct inode *inode_insert5(struct inode *inode, unsigned long hashval,
			    int (*test)(struct inode *, void *),
			    int (*set)(struct inode *, void *), void *data)
{
	struct hlist_head *head = inode_hashtable + hash(inode->i_sb, hashval);
	struct inode *old;
	bool creating = inode->i_state & I_CREATING;

again:
	spin_lock(&inode_hash_lock);
	old = find_inode(inode->i_sb, head, test, data);
	if (unlikely(old)) {
		/*
		 * Uhhuh, somebody else created the same inode under us.
		 * Use the old inode instead of the preallocated one.
		 */
		spin_unlock(&inode_hash_lock);
		if (IS_ERR(old))
			return NULL;
		wait_on_inode(old);
		if (unlikely(inode_unhashed(old))) {
			iput(old);
			goto again;
		}
		return old;
	}

	if (set && unlikely(set(inode, data))) {
		inode = NULL;
		goto unlock;
	}

	/*
	 * Return the locked inode with I_NEW set, the
	 * caller is responsible for filling in the contents
	 */
	spin_lock(&inode->i_lock);
	inode->i_state |= I_NEW;
	hlist_add_head(&inode->i_hash, head);
	spin_unlock(&inode->i_lock);
	if (!creating)
		inode_sb_list_add(inode);
unlock:
	spin_unlock(&inode_hash_lock);

	return inode;
}
EXPORT_SYMBOL(inode_insert5);

/**
 * iget5_locked - obtain an inode from a mounted file system
 * @sb:		super block of file system
 * @hashval:	hash value (usually inode number) to get
 * @test:	callback used for comparisons between inodes
 * @set:	callback used to initialize a new struct inode
 * @data:	opaque data pointer to pass to @test and @set
 *
 * Search for the inode specified by @hashval and @data in the inode cache,
 * and if present it is return it with an increased reference count. This is
 * a generalized version of iget_locked() for file systems where the inode
 * number is not sufficient for unique identification of an inode.
 *
 * If the inode is not in cache, allocate a new inode and return it locked,
 * hashed, and with the I_NEW flag set. The file system gets to fill it in
 * before unlocking it via unlock_new_inode().
 *
 * Note both @test and @set are called with the inode_hash_lock held, so can't
 * sleep.
 */
struct inode *iget5_locked(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *),
		int (*set)(struct inode *, void *), void *data)
{
	struct inode *inode = ilookup5(sb, hashval, test, data);

	if (!inode) {
		/*
		 * bdevfs: bdev_alloc_inode()
		 * - 返回的inode对应的bdev_inode->block_device是全0
		 */
		struct inode *new = alloc_inode(sb);

		if (new) {
			new->i_state = 0;
			inode = inode_insert5(new, hashval, test, set, data);
			if (unlikely(inode != new))
				destroy_inode(new);
		}
	}
	return inode;
}
EXPORT_SYMBOL(iget5_locked);

/**
 * iget_locked - obtain an inode from a mounted file system
 * @sb:		super block of file system
 * @ino:	inode number to get
 *
 * Search for the inode specified by @ino in the inode cache and if present
 * return it with an increased reference count. This is for file systems
 * where the inode number is sufficient for unique identification of an inode.
 *
 * If the inode is not in cache, allocate a new inode and return it locked,
 *                 ^^^^^^^^^^^^  ^^^^^^^^^^^^^^                     ^^^^^^
 * hashed, and with the I_NEW flag set.  The file system gets to fill it in
 * ^^^^^^               ^^^^^
 * before unlocking it via unlock_new_inode().
 */
struct inode *iget_locked(struct super_block *sb, unsigned long ino)
{
	struct hlist_head *head = inode_hashtable + hash(sb, ino);
	struct inode *inode;
again:
	/*
	 * 对inode哈希表加锁，然后在其中搜索目标inode
	 */ 
	spin_lock(&inode_hash_lock);
	/*
	 * 在inode_hashtable中查找目标inode，在返回前会增加其引用计数
	 * - 如果成功增加引用计数并返回，那么evict路径是不可能继续释放的；
	 */
	inode = find_inode_fast(sb, head, ino);
	spin_unlock(&inode_hash_lock);
	/*
	 * 如果在哈希表中找到了，则返回找到的inode。
	 * NOTE: 要等待并确保返回的inode是将磁盘上inode信息加载完毕的，因为找到
	 *       的inode有可能是另一个内核路径刚刚分配、将其加入hash表但未读取
	 *       磁盘数据的（带I_NEW的）
	 */ 
	if (inode) {
		if (IS_ERR(inode))
			return NULL;
		wait_on_inode(inode);
		if (unlikely(inode_unhashed(inode))) {
			iput(inode);
			goto again;
		}
		return inode;
	}

	/*
	 * 调用文件系统自定义的inode分配方法，然后执行具有共性的初始化部分
	 */
	inode = alloc_inode(sb);
	if (inode) {
		struct inode *old;

		spin_lock(&inode_hash_lock);
		/* 
		 * We released the lock, so.. 
		 *
		 * alloc_inode()执行的过程中，有可能其他内核路径也执行了
		 * alloc_inode()，并向inode_hashtable中插入了另一个inode，所以
		 * 此处要进行一次检查。
		 */
		old = find_inode_fast(sb, head, ino);
		if (!old) {
			/* 运行到这里，说明没有其他inode被创建，我们创建的inode
			 * 要被插入到inode_hashtable中。
			 *
			 * inode终于有了索引节点号
			 */
			inode->i_ino = ino;
			spin_lock(&inode->i_lock);
			/*
			 * 对于新创建的inode，设置其标志的I_NEW位
			 */
			inode->i_state = I_NEW;
			/*
			 * 将我们的inode插入全局哈希表中
			 *
			 * TODO: 这里明明可以不用全局哈希表，而是每个namespace
			 *       建立一个哈希表的
			 */
			hlist_add_head(&inode->i_hash, head);
			spin_unlock(&inode->i_lock);
			/*
			 * 将inode放入对应超级块的inode链表中
			 */
			inode_sb_list_add(inode);
			spin_unlock(&inode_hash_lock);

			/* Return the locked inode with I_NEW set, the
			 * caller is responsible for filling in the contents
			 */
			return inode;
		}

		/*
		 * Uhhuh, somebody else created the same inode under
		 * us. Use the old inode instead of the one we just
		 * allocated.
		 *
		 * 别人创建的相同inode先一步被插入到了inode_hashtable中，我们就
		 * 使用别人创建的就好了
		 */
		spin_unlock(&inode_hash_lock);
		destroy_inode(inode);
		if (IS_ERR(old))
			return NULL;
		inode = old;
		/*
		 * 等待inode的I_NEW位被清除
		 */
		wait_on_inode(inode);
		if (unlikely(inode_unhashed(inode))) {
			iput(inode);
			goto again;
		}
	}
	return inode;
}
EXPORT_SYMBOL(iget_locked);

/*
 * search the inode cache for a matching inode number.
 * If we find one, then the inode number we are trying to
 * allocate is not unique and so we should not use it.
 *
 * Returns 1 if the inode number is unique, 0 if it is not.
 */
static int test_inode_iunique(struct super_block *sb, unsigned long ino)
{
	struct hlist_head *b = inode_hashtable + hash(sb, ino);
	struct inode *inode;

	spin_lock(&inode_hash_lock);
	hlist_for_each_entry(inode, b, i_hash) {
		if (inode->i_ino == ino && inode->i_sb == sb) {
			spin_unlock(&inode_hash_lock);
			return 0;
		}
	}
	spin_unlock(&inode_hash_lock);

	return 1;
}

/**
 *	iunique - get a unique inode number
 *	@sb: superblock
 *	@max_reserved: highest reserved inode number
 *
 *	Obtain an inode number that is unique on the system for a given
 *	superblock. This is used by file systems that have no natural
 *	permanent inode numbering system. An inode number is returned that
 *	is higher than the reserved limit but unique.
 *
 *	BUGS:
 *	With a large number of inodes live on the file system this function
 *	currently becomes quite slow.
 */
ino_t iunique(struct super_block *sb, ino_t max_reserved)
{
	/*
	 * On a 32bit, non LFS stat() call, glibc will generate an EOVERFLOW
	 * error if st_ino won't fit in target struct field. Use 32bit counter
	 * here to attempt to avoid that.
	 */
	static DEFINE_SPINLOCK(iunique_lock);
	static unsigned int counter;
	ino_t res;

	spin_lock(&iunique_lock);
	do {
		if (counter <= max_reserved)
			counter = max_reserved + 1;
		res = counter++;
	} while (!test_inode_iunique(sb, res));
	spin_unlock(&iunique_lock);

	return res;
}
EXPORT_SYMBOL(iunique);

struct inode *igrab(struct inode *inode)
{
	spin_lock(&inode->i_lock);
	if (!(inode->i_state & (I_FREEING|I_WILL_FREE))) {
		__iget(inode);
		spin_unlock(&inode->i_lock);
	} else {
	/*
	 * 走到这里，说明inode->i_state被设置了I_FREEING或者I_WILL_FREE
	 */
		spin_unlock(&inode->i_lock);
		/*
		 * Handle the case where s_op->clear_inode is not been
		 * called yet, and somebody is calling igrab
		 * while the inode is getting freed.
		 */
		inode = NULL;
	}
	return inode;
}
EXPORT_SYMBOL(igrab);

/**
 * ilookup5_nowait - search for an inode in the inode cache
 * @sb:		super block of file system to search
 * @hashval:	hash value (usually inode number) to search for
 * @test:	callback used for comparisons between inodes
 * @data:	opaque data pointer to pass to @test
 *
 * Search for the inode specified by @hashval and @data in the inode cache.
 * If the inode is in the cache, the inode is returned with an incremented
 * reference count.
 *
 * Note: I_NEW is not waited upon so you have to be very careful what you do
 * with the returned inode.  You probably should be using ilookup5() instead.
 *
 * Note2: @test is called with the inode_hash_lock held, so can't sleep.
 */
struct inode *ilookup5_nowait(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data)
{
	/*
	 * 有一些文件系统的inode根本就没有插入到inode_hashtable中
	 * - 比如xfs
	 */
	struct hlist_head *head = inode_hashtable + hash(sb, hashval);
	struct inode *inode;

	spin_lock(&inode_hash_lock);
	inode = find_inode(sb, head, test, data);
	spin_unlock(&inode_hash_lock);

	return IS_ERR(inode) ? NULL : inode;
}
EXPORT_SYMBOL(ilookup5_nowait);

/**
 * ilookup5 - search for an inode in the inode cache
 * @sb:		super block of file system to search
 * @hashval:	hash value (usually inode number) to search for
 * @test:	callback used for comparisons between inodes
 * @data:	opaque data pointer to pass to @test
 *
 * Search for the inode specified by @hashval and @data in the inode cache,
 * and if the inode is in the cache, return the inode with an incremented
 * reference count.  Waits on I_NEW before returning the inode.
 * returned with an incremented reference count.
 *
 * This is a generalized version of ilookup() for file systems where the
 * inode number is not sufficient for unique identification of an inode.
 *
 * Note: @test is called with the inode_hash_lock held, so can't sleep.
 */
struct inode *ilookup5(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data)
{
	struct inode *inode;
again:
	inode = ilookup5_nowait(sb, hashval, test, data);
	if (inode) {
		/**
 		 * 等待inode的__I_NEW位被清除
 		 */ 
		wait_on_inode(inode);
		if (unlikely(inode_unhashed(inode))) {
			iput(inode);
			goto again;
		}
	}
	return inode;
}
EXPORT_SYMBOL(ilookup5);

/**
 * ilookup - search for an inode in the inode cache
 * @sb:		super block of file system to search
 * @ino:	inode number to search for
 *
 * Search for the inode @ino in the inode cache, and if the inode is in the
 * cache, the inode is returned with an incremented reference count.
 */
struct inode *ilookup(struct super_block *sb, unsigned long ino)
{
	struct hlist_head *head = inode_hashtable + hash(sb, ino);
	struct inode *inode;
again:
	spin_lock(&inode_hash_lock);
	inode = find_inode_fast(sb, head, ino);
	spin_unlock(&inode_hash_lock);

	if (inode) {
		if (IS_ERR(inode))
			return NULL;
		wait_on_inode(inode);
		if (unlikely(inode_unhashed(inode))) {
			iput(inode);
			goto again;
		}
	}
	return inode;
}
EXPORT_SYMBOL(ilookup);

/**
 * find_inode_nowait - find an inode in the inode cache
 * @sb:		super block of file system to search
 * @hashval:	hash value (usually inode number) to search for
 * @match:	callback used for comparisons between inodes
 * @data:	opaque data pointer to pass to @match
 *
 * Search for the inode specified by @hashval and @data in the inode
 * cache, where the helper function @match will return 0 if the inode
 * does not match, 1 if the inode does match, and -1 if the search
 * should be stopped.  The @match function must be responsible for
 * taking the i_lock spin_lock and checking i_state for an inode being
 * freed or being initialized, and incrementing the reference count
 * before returning 1.  It also must not sleep, since it is called with
 * the inode_hash_lock spinlock held.
 *
 * This is a even more generalized version of ilookup5() when the
 * function must never block --- find_inode() can block in
 * __wait_on_freeing_inode() --- or when the caller can not increment
 * the reference count because the resulting iput() might cause an
 * inode eviction.  The tradeoff is that the @match funtion must be
 * very carefully implemented.
 */
struct inode *find_inode_nowait(struct super_block *sb,
				unsigned long hashval,
				int (*match)(struct inode *, unsigned long,
					     void *),
				void *data)
{
	struct hlist_head *head = inode_hashtable + hash(sb, hashval);
	struct inode *inode, *ret_inode = NULL;
	int mval;

	spin_lock(&inode_hash_lock);
	hlist_for_each_entry(inode, head, i_hash) {
		if (inode->i_sb != sb)
			continue;
		mval = match(inode, hashval, data);
		if (mval == 0)
			continue;
		if (mval == 1)
			ret_inode = inode;
		goto out;
	}
out:
	spin_unlock(&inode_hash_lock);
	return ret_inode;
}
EXPORT_SYMBOL(find_inode_nowait);

int insert_inode_locked(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	ino_t ino = inode->i_ino;
	struct hlist_head *head = inode_hashtable + hash(sb, ino);

	while (1) {
		struct inode *old = NULL;
		spin_lock(&inode_hash_lock);
		hlist_for_each_entry(old, head, i_hash) {
			if (old->i_ino != ino)
				continue;
			if (old->i_sb != sb)
				continue;
			spin_lock(&old->i_lock);
			if (old->i_state & (I_FREEING|I_WILL_FREE)) {
				spin_unlock(&old->i_lock);
				continue;
			}
			break;
		}
		if (likely(!old)) {
			spin_lock(&inode->i_lock);
			inode->i_state |= I_NEW | I_CREATING;
			hlist_add_head(&inode->i_hash, head);
			spin_unlock(&inode->i_lock);
			spin_unlock(&inode_hash_lock);
			return 0;
		}
		if (unlikely(old->i_state & I_CREATING)) {
			spin_unlock(&old->i_lock);
			spin_unlock(&inode_hash_lock);
			return -EBUSY;
		}
		__iget(old);
		spin_unlock(&old->i_lock);
		spin_unlock(&inode_hash_lock);
		wait_on_inode(old);
		if (unlikely(!inode_unhashed(old))) {
			iput(old);
			return -EBUSY;
		}
		iput(old);
	}
}
EXPORT_SYMBOL(insert_inode_locked);

int insert_inode_locked4(struct inode *inode, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data)
{
	struct inode *old;

	inode->i_state |= I_CREATING;
	old = inode_insert5(inode, hashval, test, NULL, data);

	if (old != inode) {
		iput(old);
		return -EBUSY;
	}
	return 0;
}
EXPORT_SYMBOL(insert_inode_locked4);


int generic_delete_inode(struct inode *inode)
{
	return 1;
}
EXPORT_SYMBOL(generic_delete_inode);

/*
 * Called when we're dropping the last reference
 * to an inode.
 *
 * Call the FS "drop_inode()" function, defaulting to
 * the legacy UNIX filesystem behaviour.  If it tells
 * us to evict inode, do so.  Otherwise, retain inode
 * in cache if fs is alive, sync and evict if fs is
 * shutting down.
 *
 * 进来之前，是持有inode->i_lock的；
 */
static void iput_final(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	const struct super_operations *op = inode->i_sb->s_op;
	int drop;

	WARN_ON(inode->i_state & I_NEW);

	/*
	 * 调用文件系统超级块的drop_inode()方法。
	 * - xfs: xfs_fs_drop_inode()
	 *
	 * drop_inode()主要是用来判断是否应该evict本inode
	 */
	if (op->drop_inode)
		drop = op->drop_inode(inode);
	else
		/* 
		 * 如果i_nlink == 0或者unhashed，返回1
		 */
		drop = generic_drop_inode(inode);

	if (!drop && (sb->s_flags & SB_ACTIVE)) {
	/*
	 * 进到这里，说明两点：
	 * - drop是0，即inode->i_nlink != 0，且inode本身是hashed状态
	 * - super_block还带有SB_ACTIVE标志
	 *
	 * --------------------------------------------------------------------
	 *
	 * - 哦，inode最后一次iput()时如果文件没有被删除，那么会将其放入icache；
	 *   但前提是该文件没有被删除。
	 * - 如果文件已经被删除（i_nlink == 0）导致的iput()，才会走到后面的
	 *   evict流程。
	 *
	 * 此时如果没有了dentry，那么怎么再找回？
	 * - dentry_hashtable的key是{parent dentry地址, dname}
	 * - inode_hashtable的key是{super_block地址, ino}，所以不需要dentry存在
	 */
		inode_add_lru(inode);
		spin_unlock(&inode->i_lock);
		return;
	}

	/*
	 * 进入到这里，说明：
	 * - drop是0，即inode->i_nlink != 0，且inode本身是hashed状态
	 * - 但super_block没有了SB_ACTIVE标志
	 */
	if (!drop) {
		inode->i_state |= I_WILL_FREE;
		spin_unlock(&inode->i_lock);
		/*
		 * 回写
		 * - 同步等待，返回前已经将inode回写到盘上
		 * - 如果是从prune_icache_sb()中调用evict()，那么什么时候去回写
		 *   inode本身呢？
		 */
		write_inode_now(inode, 1);
		spin_lock(&inode->i_lock);
		WARN_ON(inode->i_state & I_NEW);
		inode->i_state &= ~I_WILL_FREE;
	}

	/*
	 * 上面把inode回写完了，这里要释放掉inode了，在持有inode->i_lock的前提
	 * 下置位I_FREEING。
	 */
	inode->i_state |= I_FREEING;
	/*
	 * 将inode从lru链表上取下来
	 */
	if (!list_empty(&inode->i_lru))
		inode_lru_list_del(inode);
	/*
	 * 释放掉inode->i_lock自旋锁
	 */
	spin_unlock(&inode->i_lock);

	/*
	 * 取下来后其他人就不可见了？所以释放了inode->i_lock？
	 *
	 * 真正对inode进行释放
	 */
	evict(inode);
}

/**
 *	iput	- put an inode
 *	@inode: inode to put
 *
 *	Puts an inode, dropping its usage count. If the inode use count hits
 *	zero, the inode is then freed and may also be destroyed.
 *
 *	Consequently, iput() can sleep.
 */
void iput(struct inode *inode)
{
	if (!inode)
		return;
	BUG_ON(inode->i_state & I_CLEAR);
retry:
	/*
	 * 只有当inode->i_count减为0时，才会进入if内部
	 * - inode->i_count减为0对xfs则意味着调用了prune_dcache_sb()
	 * - 如果i_count减为0，则会获取inode->i_lock
	 */
	if (atomic_dec_and_lock(&inode->i_count, &inode->i_lock)) {
		/*
		 * 只有当inode->i_nlink不为0时，即没有被删除，需要刷回磁盘时进
		 * 入下面的if。
		 * - 如果文件都要被删除了，也就没有必要将inode回写了
		 */
		if (inode->i_nlink && (inode->i_state & I_DIRTY_TIME)) {
			/*
			 * 保证回写过程中inode不会被从内存中释放
			 * - 那对应的引用计数释放是在哪里呢？
			 *   > goto retry后会重新减，这里是恢复上面的减法。
			 */
			atomic_inc(&inode->i_count);
			spin_unlock(&inode->i_lock);
			trace_writeback_lazytime_iput(inode);
			/*
			 * - ext4: 调用了ext4_dirty_inode()，生成了jbd2日志，唤
			 *   醒了对应的回写线程
			 * - xfs: xfs_fs_dirty_inode()
			 * - 并不等待回写完成
			 */
			mark_inode_dirty_sync(inode);
			goto retry;
		}
		/*
		 * 走到这里的话，inode->i_lock是保持着的
		 * - 且必定没有I_DIRTY_TIME
		 */
		iput_final(inode);
	}
}
EXPORT_SYMBOL(iput);

/**
 *	bmap	- find a block number in a file
 *	@inode: inode of file
 *	@block: block to find
 *
 *	Returns the block number on the device holding the inode that
 *	is the disk block number for the block of the file requested.
 *	That is, asked for block 4 of inode 1 the function will return the
 *	disk block relative to the disk start that holds that block of the
 *	file.
 */
sector_t bmap(struct inode *inode, sector_t block)
{
	sector_t res = 0;
	if (inode->i_mapping->a_ops->bmap)
		res = inode->i_mapping->a_ops->bmap(inode->i_mapping, block);
	return res;
}
EXPORT_SYMBOL(bmap);

/*
 * With relative atime, only update atime if the previous atime is
 * earlier than either the ctime or mtime or if at least a day has
 * passed since the last atime update.
 */
static int relatime_need_update(struct vfsmount *mnt, struct inode *inode,
			     struct timespec64 now)
{

	if (!(mnt->mnt_flags & MNT_RELATIME))
		return 1;
	/*
	 * Is mtime younger than atime? If yes, update atime:
	 */
	if (timespec64_compare(&inode->i_mtime, &inode->i_atime) >= 0)
		return 1;
	/*
	 * Is ctime younger than atime? If yes, update atime:
	 */
	if (timespec64_compare(&inode->i_ctime, &inode->i_atime) >= 0)
		return 1;

	/*
	 * Is the previous atime value older than a day? If yes,
	 * update atime:
	 */
	if ((long)(now.tv_sec - inode->i_atime.tv_sec) >= 24*60*60)
		return 1;
	/*
	 * Good, we can skip the atime update:
	 */
	return 0;
}

int generic_update_time(struct inode *inode, struct timespec64 *time, int flags)
{
	int iflags = I_DIRTY_TIME;
	bool dirty = false;

	if (flags & S_ATIME)
		inode->i_atime = *time;
	if (flags & S_VERSION)
		dirty = inode_maybe_inc_iversion(inode, false);
	if (flags & S_CTIME)
		inode->i_ctime = *time;
	if (flags & S_MTIME)
		inode->i_mtime = *time;
	if ((flags & (S_ATIME | S_CTIME | S_MTIME)) &&
	/*
	 * 如果设置了SB_LAZYTIME（mount选项lazytime），则不单独更新[a|c|m]time，
	 * 而是当有其他写操作的时候顺路更新；
	 */
	    !(inode->i_sb->s_flags & SB_LAZYTIME))
		dirty = true;

	if (dirty)
		iflags |= I_DIRTY_SYNC;
	/*
	 * 这里会把inode置为脏的
	 */
	__mark_inode_dirty(inode, iflags);
	return 0;
}
EXPORT_SYMBOL(generic_update_time);

/*
 * This does the actual work of updating an inodes time or version.  Must have
 * had called mnt_want_write() before calling this.
 */
static int update_time(struct inode *inode, struct timespec64 *time, int flags)
{
	int (*update_time)(struct inode *, struct timespec64 *, int);

	/*
	 * xfs: xfs_vn_update_time()
	 */
	update_time = inode->i_op->update_time ? inode->i_op->update_time :
		generic_update_time;

	return update_time(inode, time, flags);
}

/**
 *	touch_atime	-	update the access time
 *	@path: the &struct path to update
 *	@inode: inode to update
 *
 *	Update the accessed time on an inode and mark it for writeback.
 *	This function automatically handles read only file systems and media,
 *	as well as the "noatime" flag and inode specific "noatime" markers.
 */
bool atime_needs_update(const struct path *path, struct inode *inode)
{
	struct vfsmount *mnt = path->mnt;
	struct timespec64 now;

	if (inode->i_flags & S_NOATIME)
		return false;

	/* Atime updates will likely cause i_uid and i_gid to be written
	 * back improprely if their true value is unknown to the vfs.
	 */
	if (HAS_UNMAPPED_ID(inode))
		return false;

	if (IS_NOATIME(inode))
		return false;
	if ((inode->i_sb->s_flags & SB_NODIRATIME) && S_ISDIR(inode->i_mode))
		return false;

	if (mnt->mnt_flags & MNT_NOATIME)
		return false;
	if ((mnt->mnt_flags & MNT_NODIRATIME) && S_ISDIR(inode->i_mode))
		return false;

	now = current_time(inode);

	if (!relatime_need_update(mnt, inode, now))
		return false;

	if (timespec64_equal(&inode->i_atime, &now))
		return false;

	return true;
}

void touch_atime(const struct path *path)
{
	struct vfsmount *mnt = path->mnt;
	struct inode *inode = d_inode(path->dentry);
	struct timespec64 now;

	if (!atime_needs_update(path, inode))
		return;

	/*
	 * 没锁住就直接返回了？
	 */
	if (!sb_start_write_trylock(inode->i_sb))
		return;

	if (__mnt_want_write(mnt) != 0)
		goto skip_update;
	/*
	 * File systems can error out when updating inodes if they need to
	 * allocate new space to modify an inode (such is the case for
	 * Btrfs), but since we touch atime while walking down the path we
	 * really don't care if we failed to update the atime of the file,
	 * so just ignore the return value.
	 * We may also fail on filesystems that have the ability to make parts
	 * of the fs read only, e.g. subvolumes in Btrfs.
	 */
	now = current_time(inode);
	update_time(inode, &now, S_ATIME);
	__mnt_drop_write(mnt);
skip_update:
	sb_end_write(inode->i_sb);
}
EXPORT_SYMBOL(touch_atime);

/*
 * The logic we want is
 *
 *	if suid or (sgid and xgrp)
 *		remove privs
 */
int should_remove_suid(struct dentry *dentry)
{
	umode_t mode = d_inode(dentry)->i_mode;
	int kill = 0;

	/* suid always must be killed */
	if (unlikely(mode & S_ISUID))
		kill = ATTR_KILL_SUID;

	/*
	 * sgid without any exec bits is just a mandatory locking mark; leave
	 * it alone.  If some exec bits are set, it's a real sgid; kill it.
	 */
	if (unlikely((mode & S_ISGID) && (mode & S_IXGRP)))
		kill |= ATTR_KILL_SGID;

	if (unlikely(kill && !capable(CAP_FSETID) && S_ISREG(mode)))
		return kill;

	return 0;
}
EXPORT_SYMBOL(should_remove_suid);

/*
 * Return mask of changes for notify_change() that need to be done as a
 * response to write or truncate. Return 0 if nothing has to be changed.
 * Negative value on error (change should be denied).
 */
int dentry_needs_remove_privs(struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	int mask = 0;
	int ret;

	if (IS_NOSEC(inode))
		return 0;

	mask = should_remove_suid(dentry);
	ret = security_inode_need_killpriv(dentry);
	if (ret < 0)
		return ret;
	if (ret)
		mask |= ATTR_KILL_PRIV;
	return mask;
}

static int __remove_privs(struct dentry *dentry, int kill)
{
	struct iattr newattrs;

	newattrs.ia_valid = ATTR_FORCE | kill;
	/*
	 * Note we call this on write, so notify_change will not
	 * encounter any conflicting delegations:
	 */
	return notify_change(dentry, &newattrs, NULL);
}

/*
 * Remove special file priviledges (suid, capabilities) when file is written
 * to or truncated.
 */
int file_remove_privs(struct file *file)
{
	struct dentry *dentry = file_dentry(file);
	struct inode *inode = file_inode(file);
	int kill;
	int error = 0;

	/*
	 * Fast path for nothing security related.
	 * As well for non-regular files, e.g. blkdev inodes.
	 * For example, blkdev_write_iter() might get here
	 * trying to remove privs which it is not allowed to.
	 */
	if (IS_NOSEC(inode) || !S_ISREG(inode->i_mode))
		return 0;

	kill = dentry_needs_remove_privs(dentry);
	if (kill < 0)
		return kill;
	if (kill)
		error = __remove_privs(dentry, kill);
	if (!error)
		inode_has_no_xattr(inode);

	return error;
}
EXPORT_SYMBOL(file_remove_privs);

/**
 *	file_update_time	-	update mtime and ctime time
 *	@file: file accessed
 *
 *	Update the mtime and ctime members of an inode and mark the inode
 *	for writeback.  Note that this function is meant exclusively for
 *	usage in the file write path of filesystems, and filesystems may
 *	choose to explicitly ignore update via this function with the
 *	S_NOCMTIME inode flag, e.g. for network filesystem where these
 *	timestamps are handled by the server.  This can return an error for
 *	file systems who need to allocate space in order to update an inode.
 */

int file_update_time(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct timespec64 now;
	int sync_it = 0;
	int ret;

	/* First try to exhaust all avenues to not sync */
	if (IS_NOCMTIME(inode))
		return 0;

	now = current_time(inode);
	if (!timespec64_equal(&inode->i_mtime, &now))
		sync_it = S_MTIME;

	if (!timespec64_equal(&inode->i_ctime, &now))
		sync_it |= S_CTIME;

	if (IS_I_VERSION(inode) && inode_iversion_need_inc(inode))
		sync_it |= S_VERSION;

	if (!sync_it)
		return 0;

	/* Finally allowed to write? Takes lock. */
        /* 
 	 * 对mount结构体中的writers字段加一
 	 */
	if (__mnt_want_write_file(file))
		return 0;

	/*
	 * 内部会触发journal操作
	 */
	ret = update_time(inode, &now, sync_it);
	/*
 	 * 对mount结构体中的writers字段减一
 	 */
	__mnt_drop_write_file(file);

	return ret;
}
EXPORT_SYMBOL(file_update_time);

/* Caller must hold the file's inode lock */
int file_modified(struct file *file)
{
	int err;

	/*
	 * Clear the security bits if the process is not being run by root.
	 * This keeps people from modifying setuid and setgid binaries.
	 */
	err = file_remove_privs(file);
	if (err)
		return err;

	if (unlikely(file->f_mode & FMODE_NOCMTIME))
		return 0;

	return file_update_time(file);
}
EXPORT_SYMBOL(file_modified);

int inode_needs_sync(struct inode *inode)
{
	if (IS_SYNC(inode))
		return 1;
	if (S_ISDIR(inode->i_mode) && IS_DIRSYNC(inode))
		return 1;
	return 0;
}
EXPORT_SYMBOL(inode_needs_sync);

/*
 * If we try to find an inode in the inode hash while it is being
 * deleted, we have to wait until the filesystem completes its
 * deletion before reporting that it isn't found.  This function waits
 * until the deletion _might_ have completed.  Callers are responsible
 * to recheck inode state.
 *
 * It doesn't matter if I_NEW is not set initially, a call to
 * wake_up_bit(&inode->i_state, __I_NEW) after removing from the hash list
 * will DTRT.
 *
 * 不管这个时候I_NEW到底有没有，我强行睡眠等待其消除，那么只有下一个
 * wake_up_bit(__I_NEW)可以唤醒我；
 */
static void __wait_on_freeing_inode(struct inode *inode)
{
	wait_queue_head_t *wq;
	DEFINE_WAIT_BIT(wait, &inode->i_state, __I_NEW);
	wq = bit_waitqueue(&inode->i_state, __I_NEW);
	prepare_to_wait(wq, &wait.wq_entry, TASK_UNINTERRUPTIBLE);
	spin_unlock(&inode->i_lock);
	spin_unlock(&inode_hash_lock);
	schedule();
	finish_wait(wq, &wait.wq_entry);
	spin_lock(&inode_hash_lock);
}

static __initdata unsigned long ihash_entries;
static int __init set_ihash_entries(char *str)
{
	if (!str)
		return 0;
	ihash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("ihash_entries=", set_ihash_entries);

/*
 * Initialize the waitqueues and inode hash table.
 */
void __init inode_init_early(void)
{
	/* If hashes are distributed across NUMA nodes, defer
	 * hash allocation until vmalloc space is available.
	 */
	if (hashdist)
		return;

	inode_hashtable =
		alloc_large_system_hash("Inode-cache",
					sizeof(struct hlist_head),
					ihash_entries,
					14,
					HASH_EARLY | HASH_ZERO,
					&i_hash_shift,
					&i_hash_mask,
					0,
					0);
}

void __init inode_init(void)
{
	/* inode slab cache */
	inode_cachep = kmem_cache_create("inode_cache",
					 sizeof(struct inode),
					 0,
					 (SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|
					 SLAB_MEM_SPREAD|SLAB_ACCOUNT),
					 init_once);

	/* Hash may have been set up in inode_init_early */
	if (!hashdist)
		return;

	inode_hashtable =
		alloc_large_system_hash("Inode-cache",
					sizeof(struct hlist_head),
					ihash_entries,
					14,
					HASH_ZERO,
					&i_hash_shift,
					&i_hash_mask,
					0,
					0);
}

void init_special_inode(struct inode *inode, umode_t mode, dev_t rdev)
{
	inode->i_mode = mode;
	if (S_ISCHR(mode)) {
		inode->i_fop = &def_chr_fops;
		inode->i_rdev = rdev;
	} else if (S_ISBLK(mode)) {
		inode->i_fop = &def_blk_fops;
		inode->i_rdev = rdev;
	} else if (S_ISFIFO(mode))
		inode->i_fop = &pipefifo_fops;
	else if (S_ISSOCK(mode))
		;	/* leave it no_open_fops */
	else
		printk(KERN_DEBUG "init_special_inode: bogus i_mode (%o) for"
				  " inode %s:%lu\n", mode, inode->i_sb->s_id,
				  inode->i_ino);
}
EXPORT_SYMBOL(init_special_inode);

/**
 * inode_init_owner - Init uid,gid,mode for new inode according to posix standards
 * @inode: New inode
 * @dir: Directory inode
 * @mode: mode of the new inode
 */
void inode_init_owner(struct inode *inode, const struct inode *dir,
			umode_t mode)
{
	inode->i_uid = current_fsuid();
	if (dir && dir->i_mode & S_ISGID) {
		inode->i_gid = dir->i_gid;

		/* Directories are special, and always inherit S_ISGID */
		if (S_ISDIR(mode))
			mode |= S_ISGID;
		else if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP) &&
			 !in_group_p(inode->i_gid) &&
			 !capable_wrt_inode_uidgid(dir, CAP_FSETID))
			mode &= ~S_ISGID;
	} else
		inode->i_gid = current_fsgid();
	inode->i_mode = mode;
}
EXPORT_SYMBOL(inode_init_owner);

/**
 * inode_owner_or_capable - check current task permissions to inode
 * @inode: inode being checked
 *
 * Return true if current either has CAP_FOWNER in a namespace with the
 * inode owner uid mapped, or owns the file.
 */
bool inode_owner_or_capable(const struct inode *inode)
{
	struct user_namespace *ns;

	if (uid_eq(current_fsuid(), inode->i_uid))
		return true;

	ns = current_user_ns();
	/*
	 * 首先要求inode->i_uid在current_user_ns()中有映射；
	 * 然后要求当前用户在current_user_ns()中有CAP_FOWNER能力；
	 */
	if (kuid_has_mapping(ns, inode->i_uid) && ns_capable(ns, CAP_FOWNER))
		return true;
	return false;
}
EXPORT_SYMBOL(inode_owner_or_capable);

/*
 * Direct i/o helper functions
 */
static void __inode_dio_wait(struct inode *inode)
{
	/*
	 * 找到应该睡眠到的wait_queue_head
	 */
	wait_queue_head_t *wq = bit_waitqueue(&inode->i_state, __I_DIO_WAKEUP);
	/*
	 * 定义在wait_queue_head上睡眠的wait_queue_entry
	 */
	DEFINE_WAIT_BIT(q, &inode->i_state, __I_DIO_WAKEUP);

	do {
		prepare_to_wait(wq, &q.wq_entry, TASK_UNINTERRUPTIBLE);
		if (atomic_read(&inode->i_dio_count))
			schedule();
	} while (atomic_read(&inode->i_dio_count));
	finish_wait(wq, &q.wq_entry);
}

/**
 * inode_dio_wait - wait for outstanding DIO requests to finish
 * @inode: inode to wait for
 *
 * Waits for all pending direct I/O requests to finish so that we can
 * proceed with a truncate or equivalent operation.
 *
 * Must be called under a lock that serializes taking new references
 * to i_dio_count, usually by inode->i_mutex.
 */
void inode_dio_wait(struct inode *inode)
{
	if (atomic_read(&inode->i_dio_count))
		__inode_dio_wait(inode);
}
EXPORT_SYMBOL(inode_dio_wait);

/*
 * inode_set_flags - atomically set some inode flags
 *
 * Note: the caller should be holding i_mutex, or else be sure that
 * they have exclusive access to the inode structure (i.e., while the
 * inode is being instantiated).  The reason for the cmpxchg() loop
 * --- which wouldn't be necessary if all code paths which modify
 * i_flags actually followed this rule, is that there is at least one
 * code path which doesn't today so we use cmpxchg() out of an abundance
 * of caution.
 *
 * In the long run, i_mutex is overkill, and we should probably look
 * at using the i_lock spinlock to protect i_flags, and then make sure
 * it is so documented in include/linux/fs.h and that all code follows
 * the locking convention!!
 */
void inode_set_flags(struct inode *inode, unsigned int flags,
		     unsigned int mask)
{
	WARN_ON_ONCE(flags & ~mask);
	set_mask_bits(&inode->i_flags, mask, flags);
}
EXPORT_SYMBOL(inode_set_flags);

void inode_nohighmem(struct inode *inode)
{
	mapping_set_gfp_mask(inode->i_mapping, GFP_USER);
}
EXPORT_SYMBOL(inode_nohighmem);

/**
 * timespec64_trunc - Truncate timespec64 to a granularity
 * @t: Timespec64
 * @gran: Granularity in ns.
 *
 * Truncate a timespec64 to a granularity. Always rounds down. gran must
 * not be 0 nor greater than a second (NSEC_PER_SEC, or 10^9 ns).
 */
struct timespec64 timespec64_trunc(struct timespec64 t, unsigned gran)
{
	/* Avoid division in the common cases 1 ns and 1 s. */
	if (gran == 1) {
		/* nothing */
	} else if (gran == NSEC_PER_SEC) {
		t.tv_nsec = 0;
	} else if (gran > 1 && gran < NSEC_PER_SEC) {
		t.tv_nsec -= t.tv_nsec % gran;
	} else {
		WARN(1, "illegal file time granularity: %u", gran);
	}
	return t;
}
EXPORT_SYMBOL(timespec64_trunc);

/**
 * timestamp_truncate - Truncate timespec to a granularity
 * @t: Timespec
 * @inode: inode being updated
 *
 * Truncate a timespec to the granularity supported by the fs
 * containing the inode. Always rounds down. gran must
 * not be 0 nor greater than a second (NSEC_PER_SEC, or 10^9 ns).
 */
struct timespec64 timestamp_truncate(struct timespec64 t, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	unsigned int gran = sb->s_time_gran;

	t.tv_sec = clamp(t.tv_sec, sb->s_time_min, sb->s_time_max);
	if (unlikely(t.tv_sec == sb->s_time_max || t.tv_sec == sb->s_time_min))
		t.tv_nsec = 0;

	/* Avoid division in the common cases 1 ns and 1 s. */
	if (gran == 1)
		; /* nothing */
	else if (gran == NSEC_PER_SEC)
		t.tv_nsec = 0;
	else if (gran > 1 && gran < NSEC_PER_SEC)
		t.tv_nsec -= t.tv_nsec % gran;
	else
		WARN(1, "invalid file time granularity: %u", gran);
	return t;
}
EXPORT_SYMBOL(timestamp_truncate);

/**
 * current_time - Return FS time
 * @inode: inode.
 *
 * Return the current time truncated to the time granularity supported by
 * the fs.
 *
 * Note that inode and inode->sb cannot be NULL.
 * Otherwise, the function warns and returns time without truncation.
 */
struct timespec64 current_time(struct inode *inode)
{
	struct timespec64 now;

	ktime_get_coarse_real_ts64(&now);

	if (unlikely(!inode->i_sb)) {
		WARN(1, "current_time() called with uninitialized super_block in the inode");
		return now;
	}

	return timestamp_truncate(now, inode);
}
EXPORT_SYMBOL(current_time);

/*
 * Generic function to check FS_IOC_SETFLAGS values and reject any invalid
 * configurations.
 *
 * Note: the caller should be holding i_mutex, or else be sure that they have
 * exclusive access to the inode structure.
 */
int vfs_ioc_setflags_prepare(struct inode *inode, unsigned int oldflags,
			     unsigned int flags)
{
	/*
	 * The IMMUTABLE and APPEND_ONLY flags can only be changed by
	 * the relevant capability.
	 *
	 * This test looks nicer. Thanks to Pauline Middelink
	 */
	if ((flags ^ oldflags) & (FS_APPEND_FL | FS_IMMUTABLE_FL) &&
	    !capable(CAP_LINUX_IMMUTABLE))
		return -EPERM;

	return 0;
}
EXPORT_SYMBOL(vfs_ioc_setflags_prepare);

/*
 * Generic function to check FS_IOC_FSSETXATTR values and reject any invalid
 * configurations.
 *
 * Note: the caller should be holding i_mutex, or else be sure that they have
 * exclusive access to the inode structure.
 */
int vfs_ioc_fssetxattr_check(struct inode *inode, const struct fsxattr *old_fa,
			     struct fsxattr *fa)
{
	/*
	 * Can't modify an immutable/append-only file unless we have
	 * appropriate permission.
	 */
	if ((old_fa->fsx_xflags ^ fa->fsx_xflags) &
			(FS_XFLAG_IMMUTABLE | FS_XFLAG_APPEND) &&
	    !capable(CAP_LINUX_IMMUTABLE))
		return -EPERM;

	/*
	 * Project Quota ID state is only allowed to change from within the init
	 * namespace. Enforce that restriction only if we are trying to change
	 * the quota ID state. Everything else is allowed in user namespaces.
	 */
	if (current_user_ns() != &init_user_ns) {
		if (old_fa->fsx_projid != fa->fsx_projid)
			return -EINVAL;
		if ((old_fa->fsx_xflags ^ fa->fsx_xflags) &
				FS_XFLAG_PROJINHERIT)
			return -EINVAL;
	}

	/* Check extent size hints. */
	if ((fa->fsx_xflags & FS_XFLAG_EXTSIZE) && !S_ISREG(inode->i_mode))
		return -EINVAL;

	if ((fa->fsx_xflags & FS_XFLAG_EXTSZINHERIT) &&
			!S_ISDIR(inode->i_mode))
		return -EINVAL;

	if ((fa->fsx_xflags & FS_XFLAG_COWEXTSIZE) &&
	    !S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
		return -EINVAL;

	/*
	 * It is only valid to set the DAX flag on regular files and
	 * directories on filesystems.
	 */
	if ((fa->fsx_xflags & FS_XFLAG_DAX) &&
	    !(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)))
		return -EINVAL;

	/* Extent size hints of zero turn off the flags. */
	if (fa->fsx_extsize == 0)
		fa->fsx_xflags &= ~(FS_XFLAG_EXTSIZE | FS_XFLAG_EXTSZINHERIT);
	if (fa->fsx_cowextsize == 0)
		fa->fsx_xflags &= ~FS_XFLAG_COWEXTSIZE;

	return 0;
}
EXPORT_SYMBOL(vfs_ioc_fssetxattr_check);
