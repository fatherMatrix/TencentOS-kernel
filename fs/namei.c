// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * Some corrections by tytso.
 */

/* [Feb 1997 T. Schoebel-Theuer] Complete rewrite of the pathname
 * lookup logic.
 */
/* [Feb-Apr 2000, AV] Rewrite to the new namespace architecture.
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/fsnotify.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/ima.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/device_cgroup.h>
#include <linux/fs_struct.h>
#include <linux/posix_acl.h>
#include <linux/hash.h>
#include <linux/bitops.h>
#include <linux/init_task.h>
#include <linux/uaccess.h>

#include "internal.h"
#include "mount.h"

/* [Feb-1997 T. Schoebel-Theuer]
 * Fundamental changes in the pathname lookup mechanisms (namei)
 * were necessary because of omirr.  The reason is that omirr needs
 * to know the _real_ pathname, not the user-supplied one, in case
 * of symlinks (and also when transname replacements occur).
 *
 * The new code replaces the old recursive symlink resolution with
 * an iterative one (in case of non-nested symlink chains).  It does
 * this with calls to <fs>_follow_link().
 * As a side effect, dir_namei(), _namei() and follow_link() are now 
 * replaced with a single function lookup_dentry() that can handle all 
 * the special cases of the former code.
 *
 * With the new dcache, the pathname is stored at each inode, at least as
 * long as the refcount of the inode is positive.  As a side effect, the
 * size of the dcache depends on the inode cache and thus is dynamic.
 *
 * [29-Apr-1998 C. Scott Ananian] Updated above description of symlink
 * resolution to correspond with current state of the code.
 *
 * Note that the symlink resolution is not *completely* iterative.
 * There is still a significant amount of tail- and mid- recursion in
 * the algorithm.  Also, note that <fs>_readlink() is not used in
 * lookup_dentry(): lookup_dentry() on the result of <fs>_readlink()
 * may return different results than <fs>_follow_link().  Many virtual
 * filesystems (including /proc) exhibit this behavior.
 */

/* [24-Feb-97 T. Schoebel-Theuer] Side effects caused by new implementation:
 * New symlink semantics: when open() is called with flags O_CREAT | O_EXCL
 * and the name already exists in form of a symlink, try to create the new
 * name indicated by the symlink. The old code always complained that the
 * name already exists, due to not following the symlink even if its target
 * is nonexistent.  The new semantics affects also mknod() and link() when
 * the name is a symlink pointing to a non-existent name.
 *
 * I don't know which semantics is the right one, since I have no access
 * to standards. But I found by trial that HP-UX 9.0 has the full "new"
 * semantics implemented, while SunOS 4.1.1 and Solaris (SunOS 5.4) have the
 * "old" one. Personally, I think the new semantics is much more logical.
 * Note that "ln old new" where "new" is a symlink pointing to a non-existing
 * file does succeed in both HP-UX and SunOs, but not in Solaris
 * and in the old Linux semantics.
 */

/* [16-Dec-97 Kevin Buhr] For security reasons, we change some symlink
 * semantics.  See the comments in "open_namei" and "do_link" below.
 *
 * [10-Sep-98 Alan Modra] Another symlink change.
 */

/* [Feb-Apr 2000 AV] Complete rewrite. Rules for symlinks:
 *	inside the path - always follow.
 *	in the last component in creation/removal/renaming - never follow.
 *	if LOOKUP_FOLLOW passed - follow.
 *	if the pathname has trailing slashes - follow.
 *	otherwise - don't follow.
 * (applied in that order).
 *
 * [Jun 2000 AV] Inconsistent behaviour of open() in case if flags==O_CREAT
 * restored for 2.4. This is the last surviving part of old 4.2BSD bug.
 * During the 2.4 we need to fix the userland stuff depending on it -
 * hopefully we will be able to get rid of that wart in 2.5. So far only
 * XEmacs seems to be relying on it...
 */
/*
 * [Sep 2001 AV] Single-semaphore locking scheme (kudos to David Holland)
 * implemented.  Let's see if raised priority of ->s_vfs_rename_mutex gives
 * any extra contention...
 */

/* In order to reduce some races, while at the same time doing additional
 * checking and hopefully speeding things up, we copy filenames to the
 * kernel data space before using them..
 *
 * POSIX.1 2.4: an empty pathname is invalid (ENOENT).
 * PATH_MAX includes the nul terminator --RR.
 */

#define EMBEDDED_NAME_MAX	(PATH_MAX - offsetof(struct filename, iname))

struct filename *
getname_flags(const char __user *filename, int flags, int *empty)
{
	struct filename *result;
	char *kname;
	int len;

	/*
 	 * 在audit_context()->name_list链表中，查找是否有相同的filename，如果有
 	 * 的话，增加引用计数后直接返回
 	 */ 
	result = audit_reusename(filename);
	if (result)
		return result;

	result = __getname();
	if (unlikely(!result))
		return ERR_PTR(-ENOMEM);

	/*
	 * First, try to embed the struct filename inside the names_cache
	 * allocation
	 */
	kname = (char *)result->iname;
	result->name = kname;

	len = strncpy_from_user(kname, filename, EMBEDDED_NAME_MAX);
	if (unlikely(len < 0)) {
		__putname(result);
		return ERR_PTR(len);
	}

	/*
	 * Uh-oh. We have a name that's approaching PATH_MAX. Allocate a
	 * separate struct filename so we can dedicate the entire
	 * names_cache allocation for the pathname, and re-do the copy from
	 * userland.
	 */
	if (unlikely(len == EMBEDDED_NAME_MAX)) {
		const size_t size = offsetof(struct filename, iname[1]);
		/* kname此时指向上面分配的第一个struct filename */
		kname = (char *)result;

		/*
		 * size is chosen that way we to guarantee that
		 * result->iname[0] is within the same object and that
		 * kname can't be equal to result->iname, no matter what.
		 */
		/* 分配第二个struct filename */
		result = kzalloc(size, GFP_KERNEL);
		if (unlikely(!result)) {
			__putname(kname);
			return ERR_PTR(-ENOMEM);
		}
		/* 将第二个struct filename的name指向第一个struct filename */
		result->name = kname;
		/* 将分配的第一个struct filename完全用来存放filename */
		len = strncpy_from_user(kname, filename, PATH_MAX);
		if (unlikely(len < 0)) {
			__putname(kname);
			kfree(result);
			return ERR_PTR(len);
		}
		if (unlikely(len == PATH_MAX)) {
			__putname(kname);
			kfree(result);
			return ERR_PTR(-ENAMETOOLONG);
		}
	}

	result->refcnt = 1;
	/* The empty path is special. */
	if (unlikely(!len)) {
		if (empty)
			*empty = 1;
		if (!(flags & LOOKUP_EMPTY)) {
			putname(result);
			return ERR_PTR(-ENOENT);
		}
	}

	result->uptr = filename;
	result->aname = NULL;
	audit_getname(result);
	return result;
}

struct filename *
getname(const char __user * filename)
{
	return getname_flags(filename, 0, NULL);
}

struct filename *
getname_kernel(const char * filename)
{
	struct filename *result;
	int len = strlen(filename) + 1;

	result = __getname();
	if (unlikely(!result))
		return ERR_PTR(-ENOMEM);

	if (len <= EMBEDDED_NAME_MAX) {
		result->name = (char *)result->iname;
	} else if (len <= PATH_MAX) {
		const size_t size = offsetof(struct filename, iname[1]);
		struct filename *tmp;

		tmp = kmalloc(size, GFP_KERNEL);
		if (unlikely(!tmp)) {
			__putname(result);
			return ERR_PTR(-ENOMEM);
		}
		tmp->name = (char *)result;
		result = tmp;
	} else {
		__putname(result);
		return ERR_PTR(-ENAMETOOLONG);
	}
	memcpy((char *)result->name, filename, len);
	result->uptr = NULL;
	result->aname = NULL;
	result->refcnt = 1;
	audit_getname(result);

	return result;
}

void putname(struct filename *name)
{
	BUG_ON(name->refcnt <= 0);

	if (--name->refcnt > 0)
		return;

	if (name->name != name->iname) {
		__putname(name->name);
		kfree(name);
	} else
		__putname(name);
}

/*
 * @mask: Right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 */
static int check_acl(struct inode *inode, int mask)
{
#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl *acl;

	if (mask & MAY_NOT_BLOCK) {
		acl = get_cached_acl_rcu(inode, ACL_TYPE_ACCESS);
	        if (!acl)
	                return -EAGAIN;
		/* no ->get_acl() calls in RCU mode... */
		if (is_uncached_acl(acl))
			return -ECHILD;
	        return posix_acl_permission(inode, acl, mask & ~MAY_NOT_BLOCK);
	}

	acl = get_acl(inode, ACL_TYPE_ACCESS);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl) {
	        int error = posix_acl_permission(inode, acl, mask);
	        posix_acl_release(acl);
	        return error;
	}
#endif

	return -EAGAIN;
}

/*
 * This does the basic permission checking
 */
static int acl_permission_check(struct inode *inode, int mask)
{
	unsigned int mode = inode->i_mode;

	/*
	 * 这里使用的都是全局user namespace中的id;
	 * - UGO在不同user namespace中不是独立的，所以比较UGO时总是使用全局ID；
	 * - Capability在不同user namespace中是独立管理的；
	 *   x 小level和大level间的Capability的充分/必要关系是怎样的？
	 */
	if (likely(uid_eq(current_fsuid(), inode->i_uid)))
		/* 
 		 * 同一个用户，使用User的rwx标志
 		 * - 注意，/root目录本身是dr-xr-x---，其对自己home目录的写操作是
 		 *   经由后面DAC_OVERRIDE放过的；
 		 */ 
		mode >>= 6;
	else {
		/*
		 * 当inode设置了ACL权限后，UGO权限中G部分表示ACL_MASK的权限。而
		 * ACL_MASK权限表示ACL_USER、ACL_GROUP和ACL_OTHER权限的合集。
		 * - 简单说，UGO中G部分并不是只用来表示Group的权限，在设置了某些
		 *   ACL权限后可能显示其他的东西，参见：
		 *   x https://www.cnblogs.com/sparkdev/p/9694015.html
		 *
		 * 此处如果(mode & S_IRWXG) == 0，意味着ACL_USER、ACL_GROUP和
		 * ACL_OTHER都是空白，也无需继续进行check_acl()
		 */
		if (IS_POSIXACL(inode) && (mode & S_IRWXG)) {
			int error = check_acl(inode, mask);
			if (error != -EAGAIN)
				return error;
		}

		/* 
		 * 只有当inode中没有acl规则或者有acl规则但check_acl()返回-EAGAIN
		 * 后，才会运行到这个位置。如果没有开启ACL，那么check_acl()直接
		 * 返回-EAGAIN。
		 */
		if (in_group_p(inode->i_gid))
			/* 
 			 * 同一个组，使用Group的rwx标志
 			 */ 
			mode >>= 3;

		/*
 		 * 运行到这里，说明是other，使用Other的rwx标志。
 		 * 此时不用做移位操作
 		 */ 
	}

	/*
	 * If the DACs are ok we don't need any capability check.
	 *
	 * 上面对mode的移位操作只是为了选出适合角色的3bit权限，并将其放到mode中
	 * 的最低3bit。
	 *
	 * 如果mode中没有允许某个权限，那么~mode中这一位就为1。此时~mode & mask
	 * 中这一位即为1。此时与(MAY_READ | MAY_WRITE | MAY_EXEC)位与后这一位即
	 * 为1。
	 *
	 * 这种情况下，最终结果不为0。总结就是，如果mode中没有设置mask中需要的
	 * 某种权限，那么返回值不为0。
	 */
	if ((mask & ~mode & (MAY_READ | MAY_WRITE | MAY_EXEC)) == 0)
		return 0;
	return -EACCES;
}

/**
 * generic_permission -  check for access rights on a Posix-like filesystem
 * @inode:	inode to check access rights for
 * @mask:	right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC, ...)
 *
 * Used to check for read/write/execute permissions on a file.
 * We use "fsuid" for this, letting us set arbitrary permissions
 * for filesystem access without changing the "normal" uids which
 * are used for other things.
 *
 * generic_permission is rcu-walk aware. It returns -ECHILD in case an rcu-walk
 * request cannot be satisfied (eg. requires blocking or too much complexity).
 * It would then be called again in ref-walk mode.
 */
int generic_permission(struct inode *inode, int mask)
{
	int ret;

	/*
	 * Do the basic permission checks.
	 *
	 * ugo和acl权限检查；
	 */
	ret = acl_permission_check(inode, mask);
	/*
	 * acl检查如果返回：
	 * x 0：说明检查通过，直接返回即可；
	 * x -EACCES，说明是权限错误，这时候不退出；因为有可能后面的capability检
	 *   查通过；
	 * x 否则说明是其他异常错误，返回给上层处理；
	 */ 
	if (ret != -EACCES)
		return ret;

	if (S_ISDIR(inode->i_mode)) {
		/* DACs are overridable for directories */
		if (!(mask & MAY_WRITE))
			if (capable_wrt_inode_uidgid(inode,
						     CAP_DAC_READ_SEARCH))
				return 0;
		if (capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE))
			return 0;
		return -EACCES;
	}

	/*
	 * Searching includes executable on directories, else just read.
	 */
	mask &= MAY_READ | MAY_WRITE | MAY_EXEC;
	if (mask == MAY_READ)
		if (capable_wrt_inode_uidgid(inode, CAP_DAC_READ_SEARCH))
			return 0;
	/*
	 * Read/write DACs are always overridable.
	 * Executable DACs are overridable when there is
	 * at least one exec bit set.
	 */
	if (!(mask & MAY_EXEC) || (inode->i_mode & S_IXUGO))
		if (capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE))
			return 0;

	return -EACCES;
}
EXPORT_SYMBOL(generic_permission);

/*
 * We _really_ want to just do "generic_permission()" without
 * even looking at the inode->i_op values. So we keep a cache
 * flag in inode->i_opflags, that says "this has not special
 * permission function, use the fast case".
 *
 * @mask: Right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 */
static inline int do_inode_permission(struct inode *inode, int mask)
{
	if (unlikely(!(inode->i_opflags & IOP_FASTPERM))) {
		if (likely(inode->i_op->permission))
			return inode->i_op->permission(inode, mask);

		/* This gets set once for the inode lifetime */
		spin_lock(&inode->i_lock);
		inode->i_opflags |= IOP_FASTPERM;
		spin_unlock(&inode->i_lock);
	}
	return generic_permission(inode, mask);
}

/**
 * sb_permission - Check superblock-level permissions
 * @sb: Superblock of inode to check permission on
 * @inode: Inode to check permission on
 * @mask: Right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 *
 * Separate out file-system wide checks from inode-specific permission checks.
 */
static int sb_permission(struct super_block *sb, struct inode *inode, int mask)
{
	if (unlikely(mask & MAY_WRITE)) {
		umode_t mode = inode->i_mode;

		/* Nobody gets write access to a read-only fs. */
		if (sb_rdonly(sb) && (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			return -EROFS;
	}
	return 0;
}

/**
 * inode_permission - Check for access rights to a given inode
 * @inode: Inode to check permission on
 * @mask: Right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 *
 * Check for read/write/execute permissions on an inode.  We use fs[ug]id for
 * this, letting us set arbitrary permissions for filesystem access without
 * changing the "normal" UIDs which are used for other things.
 *
 * When checking for MAY_APPEND, MAY_WRITE must also be set in @mask.
 */
int inode_permission(struct inode *inode, int mask)
{
	int retval;

	retval = sb_permission(inode->i_sb, inode, mask);
	if (retval)
		return retval;

	if (unlikely(mask & MAY_WRITE)) {
		/*
		 * Nobody gets write access to an immutable file.
		 */
		if (IS_IMMUTABLE(inode))
			return -EPERM;

		/*
		 * Updating mtime will likely cause i_uid and i_gid to be
		 * written back improperly if their true value is unknown
		 * to the vfs.
		 */
		if (HAS_UNMAPPED_ID(inode))
			return -EACCES;
	}

	retval = do_inode_permission(inode, mask);
	if (retval)
		return retval;

	retval = devcgroup_inode_permission(inode, mask);
	if (retval)
		return retval;

	/*
	 * LSM SELinux
	 */
	return security_inode_permission(inode, mask);
}
EXPORT_SYMBOL(inode_permission);

/**
 * path_get - get a reference to a path
 * @path: path to get the reference to
 *
 * Given a path increment the reference count to the dentry and the vfsmount.
 */
void path_get(const struct path *path)
{
	mntget(path->mnt);
	dget(path->dentry);
}
EXPORT_SYMBOL(path_get);

/**
 * path_put - put a reference to a path
 * @path: path to put the reference to
 *
 * Given a path decrement the reference count to the dentry and the vfsmount.
 */
void path_put(const struct path *path)
{
	dput(path->dentry);
	mntput(path->mnt);
}
EXPORT_SYMBOL(path_put);

#define EMBEDDED_LEVELS 2
struct nameidata {
	struct path	path; 			/* 已解析路径(未解析分量的父目录) */
	struct qstr	last; 			/* 需要解析的文件路径分量 */
	struct path	root; 			/* 根目录，可能是为了更换根目录？*/
	struct inode	*inode; 		/* path.dentry.d_inode */
	unsigned int	flags;
	unsigned	seq, m_seq; 		/* 顺序锁
						 * seq保护path.dentry，即保护last的parent
						 * m_seq保护mount_lock
						 */
	int		last_type; 		/* 下一个要解析的路径单元类型 */
	unsigned	depth; 			/* 符号连接深度 */
	int		total_link_count;	/* ？*/
	struct saved {
		struct path link;		/* 表示一个符号链接的path */
		struct delayed_call done;
		const char *name;		/* 跳转到path的目标前，要把当前待解析的路径存到这里 */
		unsigned seq;
	} *stack, internal[EMBEDDED_LEVELS];
	struct filename	*name; 			/* 指向文件路径名 */
	struct nameidata *saved;
	struct inode	*link_inode;
	unsigned	root_seq;		/* 根目录对应的dentry的d_sep字段，在set_root()中设置 */
	int		dfd; 			/* 基准目录对应的文件描述符 */
} __randomize_layout;

static void set_nameidata(struct nameidata *p, int dfd, struct filename *name)
{
	struct nameidata *old = current->nameidata;
	p->stack = p->internal;
	p->dfd = dfd;
	p->name = name;
	p->total_link_count = old ? old->total_link_count : 0;
	p->saved = old;
	current->nameidata = p;
}

static void restore_nameidata(void)
{
	struct nameidata *now = current->nameidata, *old = now->saved;

	current->nameidata = old;
	if (old)
		old->total_link_count = now->total_link_count;
	if (now->stack != now->internal)
		kfree(now->stack);
}

static int __nd_alloc_stack(struct nameidata *nd)
{
	struct saved *p;

	if (nd->flags & LOOKUP_RCU) {
		p= kmalloc_array(MAXSYMLINKS, sizeof(struct saved),
				  GFP_ATOMIC);
		if (unlikely(!p))
			return -ECHILD;
	} else {
		p= kmalloc_array(MAXSYMLINKS, sizeof(struct saved),
				  GFP_KERNEL);
		if (unlikely(!p))
			return -ENOMEM;
	}
	memcpy(p, nd->internal, sizeof(nd->internal));
	nd->stack = p;
	return 0;
}

/**
 * path_connected - Verify that a path->dentry is below path->mnt.mnt_root
 * @path: nameidate to verify
 *
 * Rename can sometimes move a file or directory outside of a bind
 * mount, path_connected allows those cases to be detected.
 */
static bool path_connected(const struct path *path)
{
	struct vfsmount *mnt = path->mnt;
	struct super_block *sb = mnt->mnt_sb;

	/* Bind mounts and multi-root filesystems can have disconnected paths */
	if (!(sb->s_iflags & SB_I_MULTIROOT) && (mnt->mnt_root == sb->s_root))
		return true;

	return is_subdir(path->dentry, mnt->mnt_root);
}

static inline int nd_alloc_stack(struct nameidata *nd)
{
	if (likely(nd->depth != EMBEDDED_LEVELS))
		return 0;
	if (likely(nd->stack != nd->internal))
		return 0;
	return __nd_alloc_stack(nd);
}

static void drop_links(struct nameidata *nd)
{
	int i = nd->depth;
	while (i--) {
		struct saved *last = nd->stack + i;
		do_delayed_call(&last->done);
		clear_delayed_call(&last->done);
	}
}

static void terminate_walk(struct nameidata *nd)
{
	drop_links(nd);
	if (!(nd->flags & LOOKUP_RCU)) {
		int i;
		/*
		 * 这里对应ref-walk模式，分两种上下文环境：
		 *
		 * 如果是从kern_path() -> path_lookupat()调用进来，那么正常情况
		 * 下，path里都是NULL了（在调用前进行了移动语义）。此时返回给
		 * kern_path()调用者的dentry和vfsmount还是处于引用计数增加的状
		 * 态
		 *
		 * 如果是从path_openat()调用进来，那么正常情况下，path里保存了
		 * 要返回的dentry（在调用前没有进行移动语义）。此时返回给调用者
		 * 的dentry和vfsmount时处于引用计数减少过后的状态
		 * TODO: 我记得这里当时是看错了，应该也是增加状态才对，后面继续
		 *       看一下
		 */
		path_put(&nd->path);
		for (i = 0; i < nd->depth; i++)
			path_put(&nd->stack[i].link);
		if (nd->flags & LOOKUP_ROOT_GRABBED) {
			path_put(&nd->root);
			nd->flags &= ~LOOKUP_ROOT_GRABBED;
		}
	} else {
		/*
		 * 这里对应rcu-walk模式，分两种上下文环境：
		 *
		 * 如果是从kern_path() -> path_lookupat()调用进来，那么在调用本
		 * 函数前，path_lookupat()是调用了complete_walk()的，其中会对
		 * rcu-walk得到的path进行path_get()操作。此时返回给kern_path()
		 * 调用者的dentry和vfsmount是处于引用计数增加状态的
		 *
		 * 如果是从do_filp_open() -> path_openat()调用进来，那么在调用
		 * 本函数前，经过do_last() -> complete_walk()执行了path_get()操
		 * 作，因此返回给do_filp_open()调用者的dentry和vfsmount也是处于
		 * 引用计数增加状态的
		 */
		nd->flags &= ~LOOKUP_RCU;
		/* 对应path_init()中的rcu_read_lock() */
		rcu_read_unlock();
	}
	nd->depth = 0;
}

/* path_put is needed afterwards regardless of success or failure */
static bool legitimize_path(struct nameidata *nd,
			    struct path *path, unsigned seq)
{
	int res = __legitimize_mnt(path->mnt, nd->m_seq);
	if (unlikely(res)) {
		if (res > 0)
			path->mnt = NULL;
		path->dentry = NULL;
		return false;
	}
	/* 
	 * 增加引用计数，因为要切换到ref-walk模式了
	 */
	if (unlikely(!lockref_get_not_dead(&path->dentry->d_lockref))) {
		path->dentry = NULL;
		return false;
	}
	return !read_seqcount_retry(&path->dentry->d_seq, seq);
}

static bool legitimize_links(struct nameidata *nd)
{
	int i;
	for (i = 0; i < nd->depth; i++) {
		struct saved *last = nd->stack + i;
		if (unlikely(!legitimize_path(nd, &last->link, last->seq))) {
			drop_links(nd);
			nd->depth = i + 1;
			return false;
		}
	}
	return true;
}

static bool legitimize_root(struct nameidata *nd)
{
	if (!nd->root.mnt || (nd->flags & LOOKUP_ROOT))
		return true;
	nd->flags |= LOOKUP_ROOT_GRABBED;
	return legitimize_path(nd, &nd->root, nd->root_seq);
}

/*
 * Path walking has 2 modes, rcu-walk and ref-walk (see
 * Documentation/filesystems/path-lookup.txt).  In situations when we can't
 * continue in RCU mode, we attempt to drop out of rcu-walk mode and grab
 * normal reference counts on dentries and vfsmounts to transition to ref-walk
 * mode.  Refcounts are grabbed at the last known good point before rcu-walk
 * got stuck, so ref-walk may continue from there. If this is not successful
 * (eg. a seqcount has changed), then failure is returned and it's up to caller
 * to restart the path walk from the beginning in ref-walk mode.
 */

/**
 * unlazy_walk - try to switch to ref-walk mode.
 * @nd: nameidata pathwalk data
 * Returns: 0 on success, -ECHILD on failure
 *
 * unlazy_walk attempts to legitimize(合法化) the current nd->path and nd->root
 * for ref-walk mode.
 * Must be called from rcu-walk context.
 * Nothing should touch nameidata between unlazy_walk() failure and
 * terminate_walk().
 */
static int unlazy_walk(struct nameidata *nd)
{
	struct dentry *parent = nd->path.dentry;

	BUG_ON(!(nd->flags & LOOKUP_RCU));

	/*
	 * 取消LOOKUP_RCU标记，表示切换到ref-walk模式
	 */
	nd->flags &= ~LOOKUP_RCU;
	if (unlikely(!legitimize_links(nd)))
		goto out1;
	if (unlikely(!legitimize_path(nd, &nd->path, nd->seq)))
		goto out;
	if (unlikely(!legitimize_root(nd)))
		goto out;
	/* 这里出了rcu的临界区 */
	rcu_read_unlock();
	BUG_ON(nd->inode != parent->d_inode);
	return 0;

out1:
	nd->path.mnt = NULL;
	nd->path.dentry = NULL;
out:
	rcu_read_unlock();
	return -ECHILD;
}

/**
 * unlazy_child - try to switch to ref-walk mode.
 * @nd: nameidata pathwalk data
 * @dentry: child of nd->path.dentry
 * @seq: seq number to check dentry against
 * Returns: 0 on success, -ECHILD on failure
 *
 * unlazy_child attempts to legitimize the current nd->path, nd->root and dentry
 * for ref-walk mode.  @dentry must be a path found by a do_lookup call on
 * @nd.  Must be called from rcu-walk context.
 * Nothing should touch nameidata between unlazy_child() failure and
 * terminate_walk().
 */
static int unlazy_child(struct nameidata *nd, struct dentry *dentry, unsigned seq)
{
	BUG_ON(!(nd->flags & LOOKUP_RCU));

	nd->flags &= ~LOOKUP_RCU;
	if (unlikely(!legitimize_links(nd)))
		goto out2;
	if (unlikely(!legitimize_mnt(nd->path.mnt, nd->m_seq)))
		goto out2;
	if (unlikely(!lockref_get_not_dead(&nd->path.dentry->d_lockref)))
		goto out1;

	/*
	 * We need to move both the parent and the dentry from the RCU domain
	 * to be properly refcounted. And the sequence number in the dentry
	 * validates *both* dentry counters, since we checked the sequence
	 * number of the parent after we got the child sequence number. So we
	 * know the parent must still be valid if the child sequence number is
	 */
	if (unlikely(!lockref_get_not_dead(&dentry->d_lockref)))
		goto out;
	if (unlikely(read_seqcount_retry(&dentry->d_seq, seq)))
		goto out_dput;
	/*
	 * Sequence counts matched. Now make sure that the root is
	 * still valid and get it if required.
	 */
	if (unlikely(!legitimize_root(nd)))
		goto out_dput;
	rcu_read_unlock();
	return 0;

out2:
	nd->path.mnt = NULL;
out1:
	nd->path.dentry = NULL;
out:
	rcu_read_unlock();
	return -ECHILD;
out_dput:
	rcu_read_unlock();
	dput(dentry);
	return -ECHILD;
}

static inline int d_revalidate(struct dentry *dentry, unsigned int flags)
{
	if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE))
		return dentry->d_op->d_revalidate(dentry, flags);
	else
		return 1;
}

/**
 * complete_walk - successful completion of path walk
 * @nd:  pointer nameidata
 *
 * If we had been in RCU mode, drop out of it and legitimize nd->path.
 * Revalidate the final result, unless we'd already done that during
 * the path walk or the filesystem doesn't ask for it.  Return 0 on
 * success, -error on failure.  In case of failure caller does not
 * need to drop nd->path.
 */
static int complete_walk(struct nameidata *nd)
{
	struct dentry *dentry = nd->path.dentry;
	int status;

	if (nd->flags & LOOKUP_RCU) {
		if (!(nd->flags & LOOKUP_ROOT))
			nd->root.mnt = NULL;
		/*
		 * 草，对于rcu-walk模式，在这里最后增加了一次引用计数。
		 * 目的是和ref-walk返回的dentry进行语义上的对齐，因为ref-walk是
		 * 增加了引用计数的
		 *
		 * 所以，可以得出结论：通过path_lookup()或path_openat()返回的
		 * dentry都是增加了引用计数的!
		 */
		if (unlikely(unlazy_walk(nd)))
			return -ECHILD;
	}

	if (likely(!(nd->flags & LOOKUP_JUMPED)))
		return 0;

	if (likely(!(dentry->d_flags & DCACHE_OP_WEAK_REVALIDATE)))
		return 0;

	status = dentry->d_op->d_weak_revalidate(dentry, nd->flags);
	if (status > 0)
		return 0;

	if (!status)
		status = -ESTALE;

	return status;
}

static void set_root(struct nameidata *nd)
{
	struct fs_struct *fs = current->fs;

	if (nd->flags & LOOKUP_RCU) {
		unsigned seq;

		/*
		 * 下面的get_fs_root是直接加了自旋锁
		 */
		do {
			seq = read_seqcount_begin(&fs->seq);
			nd->root = fs->root;
			nd->root_seq = __read_seqcount_begin(&nd->root.dentry->d_seq);
			/* 如果不想等，则重试 */
		} while (read_seqcount_retry(&fs->seq, seq));
	} else {
		/*
		 * 增加引用计数
		 */
		get_fs_root(fs, &nd->root);
		nd->flags |= LOOKUP_ROOT_GRABBED;
	}
}

static void path_put_conditional(struct path *path, struct nameidata *nd)
{
	dput(path->dentry);
	if (path->mnt != nd->path.mnt)
		mntput(path->mnt);
}

static inline void path_to_nameidata(const struct path *path,
					struct nameidata *nd)
{
	if (!(nd->flags & LOOKUP_RCU)) {
		/*
		 * 在这里释放了原来所站目录的引用计数
		 * - 相当于除了父dentry的临界区
		 * - 对于rcu模式：
		 *   > “不被删除”控制在一个巨大的rcu临界区中
		 *   > “不被更改”控制在父dentry的d_seq中
		 */
		dput(nd->path.dentry);
		if (nd->path.mnt != path->mnt)
			mntput(nd->path.mnt);
	}
	/*
	 * 迈入新的挂载点
	 */
	nd->path.mnt = path->mnt;
	/*
	 * 迈入新的目录
	 */
	nd->path.dentry = path->dentry;
}

static int nd_jump_root(struct nameidata *nd)
{
	if (nd->flags & LOOKUP_RCU) {
		struct dentry *d;
		nd->path = nd->root;
		d = nd->path.dentry;
		nd->inode = d->d_inode;
		nd->seq = nd->root_seq;
		if (unlikely(read_seqcount_retry(&d->d_seq, nd->seq)))
			return -ECHILD;
	} else {
		path_put(&nd->path);
		nd->path = nd->root;
		path_get(&nd->path);
		nd->inode = nd->path.dentry->d_inode;
	}
	nd->flags |= LOOKUP_JUMPED;
	return 0;
}

/*
 * Helper to directly jump to a known parsed path from ->get_link,
 * caller must have taken a reference to path beforehand.
 */
void nd_jump_link(struct path *path)
{
	struct nameidata *nd = current->nameidata;
	path_put(&nd->path);

	nd->path = *path;
	nd->inode = nd->path.dentry->d_inode;
	nd->flags |= LOOKUP_JUMPED;
}

static inline void put_link(struct nameidata *nd)
{
	/*
	 * depth指向的是第一个未使用的格子，这里的last得到的是当前的
	 * 符号链接；
	 */
	struct saved *last = nd->stack + --nd->depth;
	do_delayed_call(&last->done);
	if (!(nd->flags & LOOKUP_RCU))
		path_put(&last->link);
}

int sysctl_protected_symlinks __read_mostly = 0;
int sysctl_protected_hardlinks __read_mostly = 0;
int sysctl_protected_fifos __read_mostly;
int sysctl_protected_regular __read_mostly;

/**
 * may_follow_link - Check symlink following for unsafe situations
 * @nd: nameidata pathwalk data
 *
 * In the case of the sysctl_protected_symlinks sysctl being enabled,
 * CAP_DAC_OVERRIDE needs to be specifically ignored if the symlink is
 * in a sticky world-writable directory. This is to protect privileged
 * processes from failing races against path names that may change out
 * from under them by way of other users creating malicious symlinks.
 * It will permit symlinks to be followed only when outside a sticky
 * world-writable directory, or when the uid of the symlink and follower
 * match, or when the directory owner matches the symlink's owner.
 *
 * Returns 0 if following the symlink is allowed, -ve on error.
 */
static inline int may_follow_link(struct nameidata *nd)
{
	const struct inode *inode;
	const struct inode *parent;
	kuid_t puid;

	if (!sysctl_protected_symlinks)
		return 0;

	/* Allowed if owner and follower match. */
	inode = nd->link_inode;
	if (uid_eq(current_cred()->fsuid, inode->i_uid))
		return 0;

	/* Allowed if parent directory not sticky and world-writable. */
	parent = nd->inode;
	if ((parent->i_mode & (S_ISVTX|S_IWOTH)) != (S_ISVTX|S_IWOTH))
		return 0;

	/* Allowed if parent directory and link owner match. */
	puid = parent->i_uid;
	if (uid_valid(puid) && uid_eq(puid, inode->i_uid))
		return 0;

	if (nd->flags & LOOKUP_RCU)
		return -ECHILD;

	audit_inode(nd->name, nd->stack[0].link.dentry, 0);
	audit_log_link_denied("follow_link");
	return -EACCES;
}

/**
 * safe_hardlink_source - Check for safe hardlink conditions
 * @inode: the source inode to hardlink from
 *
 * Return false if at least one of the following conditions:
 *    - inode is not a regular file
 *    - inode is setuid
 *    - inode is setgid and group-exec
 *    - access failure for read and write
 *
 * Otherwise returns true.
 */
static bool safe_hardlink_source(struct inode *inode)
{
	umode_t mode = inode->i_mode;

	/* Special files should not get pinned to the filesystem. */
	if (!S_ISREG(mode))
		return false;

	/* Setuid files should not get pinned to the filesystem. */
	if (mode & S_ISUID)
		return false;

	/* Executable setgid files should not get pinned to the filesystem. */
	if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))
		return false;

	/* Hardlinking to unreadable or unwritable sources is dangerous. */
	if (inode_permission(inode, MAY_READ | MAY_WRITE))
		return false;

	return true;
}

/**
 * may_linkat - Check permissions for creating a hardlink
 * @link: the source to hardlink from
 *
 * Block hardlink when all of:
 *  - sysctl_protected_hardlinks enabled
 *  - fsuid does not match inode
 *  - hardlink source is unsafe (see safe_hardlink_source() above)
 *  - not CAP_FOWNER in a namespace with the inode owner uid mapped
 *
 * Returns 0 if successful, -ve on error.
 */
static int may_linkat(struct path *link)
{
	struct inode *inode = link->dentry->d_inode;

	/* Inode writeback is not safe when the uid or gid are invalid. */
	if (!uid_valid(inode->i_uid) || !gid_valid(inode->i_gid))
		return -EOVERFLOW;

	if (!sysctl_protected_hardlinks)
		return 0;

	/* Source inode owner (or CAP_FOWNER) can hardlink all they like,
	 * otherwise, it must be a safe source.
	 */
	if (safe_hardlink_source(inode) || inode_owner_or_capable(inode))
		return 0;

	audit_log_link_denied("linkat");
	return -EPERM;
}

/**
 * may_create_in_sticky - Check whether an O_CREAT open in a sticky directory
 *			  should be allowed, or not, on files that already
 *			  exist.
 * @dir_mode: mode bits of directory
 * @dir_uid: owner of directory
 * @inode: the inode of the file to open
 *
 * Block an O_CREAT open of a FIFO (or a regular file) when:
 *   - sysctl_protected_fifos (or sysctl_protected_regular) is enabled
 *   - the file already exists
 *   - we are in a sticky directory
 *   - we don't own the file
 *   - the owner of the directory doesn't own the file
 *   - the directory is world writable
 * If the sysctl_protected_fifos (or sysctl_protected_regular) is set to 2
 * the directory doesn't have to be world writable: being group writable will
 * be enough.
 *
 * Returns 0 if the open is allowed, -ve on error.
 */
static int may_create_in_sticky(umode_t dir_mode, kuid_t dir_uid,
				struct inode * const inode)
{
	if ((!sysctl_protected_fifos && S_ISFIFO(inode->i_mode)) ||
	    (!sysctl_protected_regular && S_ISREG(inode->i_mode)) ||
	    likely(!(dir_mode & S_ISVTX)) ||
	    uid_eq(inode->i_uid, dir_uid) ||
	    /*
	     * 因为d_alloc_parallel()的并发，所以这里拿到的新的inode并不一定真
	     * 的属于current；
	     * - 但是不属于又如何呢？反正sticky文件都是可以创建的；
	     */
	    uid_eq(current_fsuid(), inode->i_uid))
		return 0;

	if (likely(dir_mode & 0002) ||
	    (dir_mode & 0020 &&
	     ((sysctl_protected_fifos >= 2 && S_ISFIFO(inode->i_mode)) ||
	      (sysctl_protected_regular >= 2 && S_ISREG(inode->i_mode))))) {
		return -EACCES;
	}
	return 0;
}

static __always_inline
const char *get_link(struct nameidata *nd)
{
	/* 
	 * 在walk_component -> step_into -> pick_link中向stack中存放的符号链接
	 * 信息。但那个时候只是存放了stack[depth - 1]->link字段，没有解析对应
	 * 的name字段
	 */
	struct saved *last = nd->stack + nd->depth - 1;
	struct dentry *dentry = last->link.dentry;
	struct inode *inode = nd->link_inode;
	int error;
	const char *res;

	if (!(nd->flags & LOOKUP_RCU)) {
		touch_atime(&last->link);
		cond_resched();
	} else if (atime_needs_update(&last->link, inode)) {
		if (unlikely(unlazy_walk(nd)))
			return ERR_PTR(-ECHILD);
		touch_atime(&last->link);
	}

	error = security_inode_follow_link(dentry, inode,
					   nd->flags & LOOKUP_RCU);
	if (unlikely(error))
		return ERR_PTR(error);

	nd->last_type = LAST_BIND;
	res = READ_ONCE(inode->i_link);
	if (!res) {
		const char * (*get)(struct dentry *, struct inode *,
				struct delayed_call *);
		get = inode->i_op->get_link;
		if (nd->flags & LOOKUP_RCU) {
			res = get(NULL, inode, &last->done);
			if (res == ERR_PTR(-ECHILD)) {
				if (unlikely(unlazy_walk(nd)))
					return ERR_PTR(-ECHILD);
				res = get(dentry, inode, &last->done);
			}
		} else {
			res = get(dentry, inode, &last->done);
		}
		if (IS_ERR_OR_NULL(res))
			return res;
	}
	if (*res == '/') {
		if (!nd->root.mnt)
			set_root(nd);
		if (unlikely(nd_jump_root(nd)))
			return ERR_PTR(-ECHILD);
		while (unlikely(*++res == '/'))
			;
	}
	if (!*res)
		res = NULL;
	return res;
}

/*
 * follow_up - Find the mountpoint of path's vfsmount
 *
 * Given a path, find the mountpoint of its source file system.
 * Replace @path with the path of the mountpoint in the parent mount.
 * Up is towards /.
 *
 * Return 1 if we went up a level and 0 if we were already at the
 * root.
 */
int follow_up(struct path *path)
{
	struct mount *mnt = real_mount(path->mnt);
	struct mount *parent;
	struct dentry *mountpoint;

	read_seqlock_excl(&mount_lock);
	parent = mnt->mnt_parent;
	if (parent == mnt) {
		read_sequnlock_excl(&mount_lock);
		return 0;
	}
	mntget(&parent->mnt);
	mountpoint = dget(mnt->mnt_mountpoint);
	read_sequnlock_excl(&mount_lock);
	dput(path->dentry);
	path->dentry = mountpoint;
	mntput(path->mnt);
	path->mnt = &parent->mnt;
	return 1;
}
EXPORT_SYMBOL(follow_up);

/*
 * Perform an automount
 * - return -EISDIR to tell follow_managed() to stop and return the path we
 *   were called with.
 */
static int follow_automount(struct path *path, struct nameidata *nd,
			    bool *need_mntput)
{
	struct vfsmount *mnt;
	int err;

	if (!path->dentry->d_op || !path->dentry->d_op->d_automount)
		return -EREMOTE;

	/* We don't want to mount if someone's just doing a stat -
	 * unless they're stat'ing a directory and appended a '/' to
	 * the name.
	 *
	 * We do, however, want to mount if someone wants to open or
	 * create a file of any type under the mountpoint, wants to
	 * traverse through the mountpoint or wants to open the
	 * mounted directory.  Also, autofs may mark negative dentries
	 * as being automount points.  These will need the attentions
	 * of the daemon to instantiate them before they can be used.
	 */
	if (!(nd->flags & (LOOKUP_PARENT | LOOKUP_DIRECTORY |
			   LOOKUP_OPEN | LOOKUP_CREATE | LOOKUP_AUTOMOUNT)) &&
	    path->dentry->d_inode)
		return -EISDIR;

	nd->total_link_count++;
	if (nd->total_link_count >= 40)
		return -ELOOP;

	mnt = path->dentry->d_op->d_automount(path);
	if (IS_ERR(mnt)) {
		/*
		 * The filesystem is allowed to return -EISDIR here to indicate
		 * it doesn't want to automount.  For instance, autofs would do
		 * this so that its userspace daemon can mount on this dentry.
		 *
		 * However, we can only permit this if it's a terminal point in
		 * the path being looked up; if it wasn't then the remainder of
		 * the path is inaccessible and we should say so.
		 */
		if (PTR_ERR(mnt) == -EISDIR && (nd->flags & LOOKUP_PARENT))
			return -EREMOTE;
		return PTR_ERR(mnt);
	}

	if (!mnt) /* mount collision */
		return 0;

	if (!*need_mntput) {
		/* lock_mount() may release path->mnt on error */
		mntget(path->mnt);
		*need_mntput = true;
	}
	err = finish_automount(mnt, path);

	switch (err) {
	case -EBUSY:
		/* Someone else made a mount here whilst we were busy */
		return 0;
	case 0:
		path_put(path);
		path->mnt = mnt;
		path->dentry = dget(mnt->mnt_root);
		return 0;
	default:
		return err;
	}

}

/*
 * Handle a dentry that is managed in some way.
 * - Flagged for transit management (autofs)
 * - Flagged as mountpoint
 * - Flagged as automount point
 *
 * This may only be called in refwalk mode.
 *
 * Serialization is taken care of in namespace.c
 */
static int follow_managed(struct path *path, struct nameidata *nd)
{
	struct vfsmount *mnt = path->mnt; /* held by caller, must be left alone */
	unsigned managed;
	bool need_mntput = false;
	int ret = 0;

	/* Given that we're not holding a lock here, we retain the value in a
	 * local variable for each dentry as we look at it so that we don't see
	 * the components of that value change under us */
	while (managed = READ_ONCE(path->dentry->d_flags),
	       managed &= DCACHE_MANAGED_DENTRY,
	       unlikely(managed != 0)) {
		/* Allow the filesystem to manage the transit without i_mutex
		 * being held. */
		if (managed & DCACHE_MANAGE_TRANSIT) {
			BUG_ON(!path->dentry->d_op);
			BUG_ON(!path->dentry->d_op->d_manage);
			ret = path->dentry->d_op->d_manage(path, false);
			if (ret < 0)
				break;
		}

		/* Transit to a mounted filesystem. 
		 *
		 * dentry->d_flags中有DCACHE_MOUNTED表示这是一个挂载点，所以要
		 * 自动向下跨越挂载点，走到被挂载操作系统的根目录上去
		 */
		if (managed & DCACHE_MOUNTED) {
			/*
			 * 增加了vfsmount的引用计数的
			 */
			struct vfsmount *mounted = lookup_mnt(path);
			if (mounted) {
				dput(path->dentry);
				if (need_mntput)
					mntput(path->mnt);
				path->mnt = mounted;
				path->dentry = dget(mounted->mnt_root);
				need_mntput = true;
				continue;
			}

			/* Something is mounted on this dentry in another
			 * namespace and/or whatever was mounted there in this
			 * namespace got unmounted before lookup_mnt() could
			 * get it */
		}

		/* Handle an automount point */
		if (managed & DCACHE_NEED_AUTOMOUNT) {
			ret = follow_automount(path, nd, &need_mntput);
			if (ret < 0)
				break;
			continue;
		}

		/* We didn't change the current path point */
		break;
	}

	if (need_mntput && path->mnt == mnt)
		mntput(path->mnt);
	if (ret == -EISDIR || !ret)
		ret = 1;
	if (need_mntput)
		nd->flags |= LOOKUP_JUMPED;
	if (unlikely(ret < 0))
		path_put_conditional(path, nd);
	return ret;
}

int follow_down_one(struct path *path)
{
	struct vfsmount *mounted;

	mounted = lookup_mnt(path);
	if (mounted) {
		dput(path->dentry);
		mntput(path->mnt);
		path->mnt = mounted;
		path->dentry = dget(mounted->mnt_root);
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL(follow_down_one);

static inline int managed_dentry_rcu(const struct path *path)
{
	return (path->dentry->d_flags & DCACHE_MANAGE_TRANSIT) ?
		path->dentry->d_op->d_manage(path, true) : 0;
}

/*
 * Try to skip to top of mountpoint pile in rcuwalk mode.  Fail if
 * we meet a managed dentry that would need blocking.
 */
static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
			       struct inode **inode, unsigned *seqp)
{
	for (;;) {
		struct mount *mounted;
		/*
		 * Don't forget we might have a non-mountpoint managed dentry
		 * that wants to block transit.
		 */
		switch (managed_dentry_rcu(path)) {
		case -ECHILD:
		default:
			return false;
		case -EISDIR:
			return true;
		case 0:
			break;
		}

		if (!d_mountpoint(path->dentry))
			return !(path->dentry->d_flags & DCACHE_NEED_AUTOMOUNT);

		mounted = __lookup_mnt(path->mnt, path->dentry);
		if (!mounted)
			break;
		path->mnt = &mounted->mnt;
		path->dentry = mounted->mnt.mnt_root;
		nd->flags |= LOOKUP_JUMPED;
		*seqp = read_seqcount_begin(&path->dentry->d_seq);
		/*
		 * Update the inode too. We don't need to re-check the
		 * dentry sequence number here after this d_inode read,
		 * because a mount-point is always pinned.
		 */
		*inode = path->dentry->d_inode;
	}
	return !read_seqretry(&mount_lock, nd->m_seq) &&
		!(path->dentry->d_flags & DCACHE_NEED_AUTOMOUNT);
}

static int follow_dotdot_rcu(struct nameidata *nd)
{
	struct inode *inode = nd->inode;

	while (1) {
		/*
		 * 当前路径已经是预设根目录了，所以就直接退出，什么都不用做。
		 * 因为已经是根目录了，再"cd .."也没什么用了
		 */
		if (path_equal(&nd->path, &nd->root))
			break;

		/* 
		 * 走到这里，说明当前路径不是预设根目录
		 */
		if (nd->path.dentry != nd->path.mnt->mnt_root) {
			/*
			 * 当前目录不是所在文件系统的根目录，即"cd .."未跨过安
			 * 装点
			 */
			/* 当前所在目录 */
			struct dentry *old = nd->path.dentry;
			/* 所在目录的上层目录，即../ */
			struct dentry *parent = old->d_parent;
			unsigned seq;

			inode = parent->d_inode;
			seq = read_seqcount_begin(&parent->d_seq);
			if (unlikely(read_seqcount_retry(&old->d_seq, nd->seq)))
				return -ECHILD;
			/* 直接把当前目录path.dentry赋值为parent，即../ */
			nd->path.dentry = parent;
			nd->seq = seq;
			if (unlikely(!path_connected(&nd->path)))
				return -ECHILD;
			break;
		} else {
			/* 
			 * 跨越了安装点
			 */
			/* 当前文件系统的mount实例 */
			struct mount *mnt = real_mount(nd->path.mnt);
			/* 父文件系统的mount实例 */
			struct mount *mparent = mnt->mnt_parent;
			/*
			 * 安装点对应的被覆盖文件系统的目录，即挂载点
			 */
			struct dentry *mountpoint = mnt->mnt_mountpoint;
			struct inode *inode2 = mountpoint->d_inode;
			unsigned seq = read_seqcount_begin(&mountpoint->d_seq);
			if (unlikely(read_seqretry(&mount_lock, nd->m_seq)))
				return -ECHILD;
			/*
			 * 这个判断成立的话，说明已经是根文件系统了。因为只有根
			 * 文件系统的父mount和自己才相同
			 */
			if (&mparent->mnt == nd->path.mnt)
				break;

			/* 
			 * 走到这里，说明当前文件系统不是根文件系统。
			 *
			 * 此时跨越安装点的操作就是取得挂载点就可以了
			 */
			/* we know that mountpoint was pinned */
			nd->path.dentry = mountpoint;
			/* type(nd->path.mnt) == vfsmount */
			nd->path.mnt = &mparent->mnt;
			inode = inode2;
			nd->seq = seq;

			/* 
			 * 仅仅取得挂载点后还没完，因为"cd .."最终是要走到挂载
			 * 点的父目录才对。
			 * 这里不再处理，而是再次进入while循环。此时进入while
			 * 循环中第一个大的if分支
			 */
		}
	}
	/*
	 * 这个循环又是干什么的呢？
	 *
	 * 如果说我们在上边的循环中一直退出到了根文件系统上，就需要再反方向往下
	 * 走，因为我们不能站在根文件系统上。
	 * 之所以是个while循环，是因为有可能fs1挂载在了根文件系统上，然后fs2又
	 * 挂载在了fs1上，然后fs3又挂载在了fs2上，然后...
	 */
	while (unlikely(d_mountpoint(nd->path.dentry))) {
		struct mount *mounted;
		mounted = __lookup_mnt(nd->path.mnt, nd->path.dentry);
		if (unlikely(read_seqretry(&mount_lock, nd->m_seq)))
			return -ECHILD;
		if (!mounted)
			break;
		nd->path.mnt = &mounted->mnt;
		nd->path.dentry = mounted->mnt.mnt_root;
		inode = nd->path.dentry->d_inode;
		nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
	}
	nd->inode = inode;
	return 0;
}

/*
 * Follow down to the covering mount currently visible to userspace.  At each
 * point, the filesystem owning that dentry may be queried as to whether the
 * caller is permitted to proceed or not.
 */
int follow_down(struct path *path)
{
	unsigned managed;
	int ret;

	while (managed = READ_ONCE(path->dentry->d_flags),
	       unlikely(managed & DCACHE_MANAGED_DENTRY)) {
		/* Allow the filesystem to manage the transit without i_mutex
		 * being held.
		 *
		 * We indicate to the filesystem if someone is trying to mount
		 * something here.  This gives autofs the chance to deny anyone
		 * other than its daemon the right to mount on its
		 * superstructure.
		 *
		 * The filesystem may sleep at this point.
		 */
		if (managed & DCACHE_MANAGE_TRANSIT) {
			BUG_ON(!path->dentry->d_op);
			BUG_ON(!path->dentry->d_op->d_manage);
			ret = path->dentry->d_op->d_manage(path, false);
			if (ret < 0)
				return ret == -EISDIR ? 0 : ret;
		}

		/* Transit to a mounted filesystem. */
		if (managed & DCACHE_MOUNTED) {
			struct vfsmount *mounted = lookup_mnt(path);
			if (!mounted)
				break;
			dput(path->dentry);
			mntput(path->mnt);
			path->mnt = mounted;
			path->dentry = dget(mounted->mnt_root);
			continue;
		}

		/* Don't handle automount points here */
		break;
	}
	return 0;
}
EXPORT_SYMBOL(follow_down);

/*
 * Skip to top of mountpoint pile in refwalk mode for follow_dotdot()
 *
 * 当前(path->dentry)是一个挂载点，那么需要walk到被挂载的文件系统上
 */
static void follow_mount(struct path *path)
{
	while (d_mountpoint(path->dentry)) {
		struct vfsmount *mounted = lookup_mnt(path);
		if (!mounted)
			break;
		dput(path->dentry);
		mntput(path->mnt);
		/*
		 * path中保存的是已解析路径，即待解析路径的父目录
		 *
		 * walk到被挂载的文件系统上的实质就是将path->dentry替换成被挂载
		 * 文件系统根目录所对应的dentry
		 */
		path->mnt = mounted;
		path->dentry = dget(mounted->mnt_root);
	}
}

static int path_parent_directory(struct path *path)
{
	struct dentry *old = path->dentry;
	/* rare case of legitimate dget_parent()... */
	path->dentry = dget_parent(path->dentry);
	dput(old);
	if (unlikely(!path_connected(path)))
		return -ENOENT;
	return 0;
}

static int follow_dotdot(struct nameidata *nd)
{
	while(1) {
		if (path_equal(&nd->path, &nd->root))
			break;
		if (nd->path.dentry != nd->path.mnt->mnt_root) {
			int ret = path_parent_directory(&nd->path);
			if (ret)
				return ret;
			break;
		}
		if (!follow_up(&nd->path))
			break;
	}
	follow_mount(&nd->path);
	nd->inode = nd->path.dentry->d_inode;
	return 0;
}

/*
 * This looks up the name in dcache and possibly revalidates the found dentry.
 * NULL is returned if the dentry does not exist in the cache.
 */
static struct dentry *lookup_dcache(const struct qstr *name,
				    struct dentry *dir,
				    unsigned int flags)
{
	struct dentry *dentry = d_lookup(dir, name);
	if (dentry) {
		int error = d_revalidate(dentry, flags);
		if (unlikely(error <= 0)) {
			if (!error)
				d_invalidate(dentry);
			dput(dentry);
			return ERR_PTR(error);
		}
	}
	return dentry;
}

/*
 * Parent directory has inode locked exclusive.  This is one
 * and only case when ->lookup() gets called on non in-lookup
 * dentries - as the matter of fact, this only gets called
 * when directory is guaranteed to have no in-lookup children
 * at all.
 */
static struct dentry *__lookup_hash(const struct qstr *name,
		struct dentry *base, unsigned int flags)
{
	struct dentry *dentry = lookup_dcache(name, base, flags);
	struct dentry *old;
	struct inode *dir = base->d_inode;

	if (dentry)
		return dentry;

	/* Don't create child dentry for a dead directory. */
	if (unlikely(IS_DEADDIR(dir)))
		return ERR_PTR(-ENOENT);

	dentry = d_alloc(base, name);
	if (unlikely(!dentry))
		return ERR_PTR(-ENOMEM);

	/*
	 * xfs: xfs_vn_lookup()
	 * - 出来后dentry的lockref没有改变；
	 */
	old = dir->i_op->lookup(dir, dentry, flags);
	if (unlikely(old)) {
		dput(dentry);
		dentry = old;
	}
	return dentry;
}

/*
 * 返回值：
 * ret >  0	表示成功找到
 * ret == 0	表示内存中没有，且成功切换到ref-walk模式
 * ret <  0	表示错误
 */
static int lookup_fast(struct nameidata *nd,
		       struct path *path, struct inode **inode,
		       unsigned *seqp)
{
	struct vfsmount *mnt = nd->path.mnt;
	struct dentry *dentry, *parent = nd->path.dentry;
	int status = 1;
	int err;

	/*
	 * Rename seqlock is not required here because in the off chance
	 * of a false negative due to a concurrent rename, the caller is
	 * going to fall back to non-racy lookup.
	 */
	if (nd->flags & LOOKUP_RCU) {
		unsigned seq;
		bool negative;
		/* 
		 * 在dentry_hashtable中查找分量
		 *
		 * 在什么时候将dentry放入dentry_hashtable中的呢？
		 * - lookup_slow
		 *     ext4_lookup
		 *       d_splice_alias
		 *         __d_add
		 */
		dentry = __d_lookup_rcu(parent, &nd->last, &seq);
		if (unlikely(!dentry)) {
			/*
			 * 如果哈希表查找失败了，则要切换到ref-walk模式
			 * - 哈希表查找失败了，后面的slow path可能要面临内存分配，
			 *   而rcu临界区内是没办法睡眠的；
			 *
			 * 内部对当前已经解析好的dentry加了引用计数（因为正站在
			 * 的dentry的引用计数+1是ref-walk的要求）
			 */
			if (unlazy_walk(nd))
				return -ECHILD;
			return 0;
		}

		/*
		 * This sequence count validates that the inode matches
		 * the dentry name information from lookup.
		 */
		*inode = d_backing_inode(dentry);
		negative = d_is_negative(dentry);
		/*
		 * seq来源于上面__d_lookup_rcu()中找到该子dentry时刻的dentry->d_seq；
		 * 此时要检查dentry是否有变化；
		 * - 之所以这里需要检查，因为要保证获取到的inode是一致的
		 */
		if (unlikely(read_seqcount_retry(&dentry->d_seq, seq)))
			return -ECHILD;

		/*
		 * This sequence count validates that the parent had no
		 * changes while we did the lookup of the dentry above.
		 *
		 * The memory barrier in read_seqcount_begin of child is
		 *  enough, we can use __read_seqcount_retry here.
		 *
		 * 保证在查找子dentry时，父dentry没有发生变化；
		 * - 这里结束了父dentry的seqlock临界区
		 */
		if (unlikely(__read_seqcount_retry(&parent->d_seq, nd->seq)))
			return -ECHILD;

		/*
		 * seq是查找到的子dentry的d_seq字段
		 */
		*seqp = seq;
		status = d_revalidate(dentry, nd->flags);
		if (likely(status > 0)) {
			/*
			 * Note: do negative dentry check after revalidation in
			 * case that drops it.
			 */
			if (unlikely(negative))
				return -ENOENT;
			path->mnt = mnt;
			path->dentry = dentry;
			if (likely(__follow_mount_rcu(nd, path, inode, seqp)))
				return 1;
			/*
			 * rcu-walk成功的话，会在上面返回
			 */
		}
		/* 
		 * 上面的快速查找出问题了，要切换到ref-walk模式再尝试了。
		 * 增加引用计数，与上面的unlazy_walk()只会执行成功一个
		 */
		if (unlazy_child(nd, dentry, seq))
			return -ECHILD;
		if (unlikely(status == -ECHILD))
			/* we'd been told to redo it in non-rcu mode */
			status = d_revalidate(dentry, nd->flags);
	} else {
		/* 
		 * 这里是一种ref-walk
		 * 内部增加了dentry的引用计数，没有增加对应inode的引用计数
		 */
		dentry = __d_lookup(parent, &nd->last);
		if (unlikely(!dentry))
			return 0;
		status = d_revalidate(dentry, nd->flags);
	}
	if (unlikely(status <= 0)) {
		if (!status)
			d_invalidate(dentry);
		dput(dentry);
		return status;
	}
	if (unlikely(d_is_negative(dentry))) {
		dput(dentry);
		return -ENOENT;
	}

	/*
	 * 这个path是调用者自己的局部变量，不是nd.path。所以这里并没有覆盖父目录
	 */
	path->mnt = mnt;
	path->dentry = dentry;
	/*
	 * 向下跨越挂载点等
	 */
	err = follow_managed(path, nd);
	if (likely(err > 0))
		*inode = d_backing_inode(path->dentry);
	return err;
}

/* Fast lookup failed, do it the slow way */
static struct dentry *__lookup_slow(const struct qstr *name,
				    struct dentry *dir,
				    unsigned int flags)
{
	struct dentry *dentry, *old;
	struct inode *inode = dir->d_inode;
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

	/* Don't go there if it's already dead */
	if (unlikely(IS_DEADDIR(inode)))
		return ERR_PTR(-ENOENT);
again:
	/*
	 * 要创建dentry了，返回的dentry已经和parent dentry建立了父子关系。
	 *
	 * - 如果返回的dentry是由本d_alloc_parallel创建的，则中将新创建的dentry
	 *   放入了inlookup_hashtable中
	 * - 如果返回的dentry是由其他d_alloc_parallel创建的，则返回前等待dentry
	 *   在inlookup_hashtable中摘除。值得注意的是，dentry在从
	 *   inlookup_hashtable中摘除之前，会插入到dentry_hashtable中。也就是如
	 *   此返回的dentry，已经成熟（但这里面包括负状态的dentry，即去磁盘上转
	 *   了一圈，发现没有对应的inode，也算是成熟了，因为至少确定了此dentry
	 *   就是不应该对应inode）
	 */
	dentry = d_alloc_parallel(dir, name, &wq);
	if (IS_ERR(dentry))
		return dentry;
	if (unlikely(!d_in_lookup(dentry))) {
		/*
		 * 走到这里，说明dentry不是由本d_alloc_parallel创建的
		 * - 因为如果是本d_alloc_parallel创建的，那么此时dentry的状态肯
		 *   定是in_lookup的
		 */
		if (!(flags & LOOKUP_NO_REVAL)) {
			int error = d_revalidate(dentry, flags);
			if (unlikely(error <= 0)) {
				if (!error) {
					d_invalidate(dentry);
					dput(dentry);
					goto again;
				}
				dput(dentry);
				dentry = ERR_PTR(error);
			}
		}
	} else {
		/* 
		 * 调用具体文件系统的lookup方法来查找对应的inode节点
		 *
		 * 根据Documentation/filesystems/vfs.txt中的要求，此回调函数内
		 * 1. 必须调用d_add()将inode与dentry建立联系
		 * 2. 必须对inode->i_count加一
		 * 3. 必须调用d_add将找到的inode和dentry建立联系。如果目标inode
		 *    不存在，则插入一个NULL inode。
		 *
		 * ext4_lookup中通过调用d_splice_alias -> __d_add将dentry放到了
		 * dentry_hashtable中
		 *
		 * xfs中是： xfs_vn_lookup()
		 * ext4: ext4_lookup()
		 *
		 * 会有多个内核路径同时走到这里，这个函数是可以并发的吗？
		 * - 猜测：该函数内使用了bh cache和inode cache，这两个cache会保
		 *   整真正的读盘操作只会由一个内核路径执行，其他的同目标的内核
		 *   路径会在这两个cache中睡眠等待
		 * 更正：
		 * - 好像只会有一个内核路径进入到这里，就是真正创建了dentry
		 *   的内核路径。
		 * - 如果dentry是由其他内核路径创建的，那么在退出
		 *   d_alloc_parallel之前，该dentry就已经加入了dentry_hashtable
		 *   且离开了inlookup_hashtable。此时应该进入上面的if分支。
		 */
		old = inode->i_op->lookup(inode, dentry, flags);
		/*
		 * 将处于inlookup_hashtable中的dentry摘下来，并唤醒前面在函数
		 * d_alloc_parallel()中等待这一事实的其他内核路径；
		 *
		 * 但其实在->lookup中的d_splice_alias -> __d_add中就调用过一次
		 * __d_lookup_done了呀？
		 * - 有可能走不到__d_add这个分支上
		 */
		d_lookup_done(dentry);
		if (unlikely(old)) {
			/*
			 * 这里面会将dentry从其parent的children list中摘除，其
			 * 对称动作在上面的d_alloc_parallel中
			 *
			 * 如果上面的几个d_lookup_done使得最上面的
			 * d_alloc_parallel返回了本内核路径创建的dentry，但此
			 * dentry又在此处dput，会如何？
			 * - 不会出现这种情况：
			 *   o 对于文件，上面返回的old之可能是NULL，根本不会进
			 *     入当前的if分支
			 *   o 对于目录，如果old不会NULL，那么本内核路径创建的
			 *     dentry也根本不会插入到dentry_hashtable中，所以也
			 *     不会被其他内核路径的d_alloc_parallel返回
			 */
			dput(dentry);
			dentry = old;
		}
		/*
		 * 这里应该可以用来插入inode_attach_security?
		 */
	}
	return dentry;
}

static struct dentry *lookup_slow(const struct qstr *name,
				  struct dentry *dir,
				  unsigned int flags)
{
	/* 父目录对应的inode */
	struct inode *inode = dir->d_inode;
	struct dentry *res;
	/*
	 * 获取了inode->i_rwsem的读锁，不过这里加锁对象是parent dir
	 */
	inode_lock_shared(inode);
	res = __lookup_slow(name, dir, flags);
	/*
	 * 释放了inode->i_rwsem的读锁
	 */
	inode_unlock_shared(inode);
	return res;
}

static inline int may_lookup(struct nameidata *nd)
{
	if (nd->flags & LOOKUP_RCU) {
		/*
 		 * nd->inode指向了nd->path.dentry.d_inode，即将要解析的下一个
 		 *                ^^^^^^^^^^^^^^^^^^^^^^^ - 谁负责更新nd->inode
 		 * 分量所在的目录。此处是用来检查父目录的访问权限。
 		 */ 
		int err = inode_permission(nd->inode, MAY_EXEC|MAY_NOT_BLOCK);
		if (err != -ECHILD)
			return err;
		if (unlazy_walk(nd))
			return -ECHILD;
	}
	return inode_permission(nd->inode, MAY_EXEC);
}

static inline int handle_dots(struct nameidata *nd, int type)
{
	if (type == LAST_DOTDOT) {
		/* 
		 * 如果是相对目录起步，那么nd->root字段在path_init()中是没有被
		 * 设置过的，此时要对其进行赋值。
		 *
		 * 之所以path_init()中对相对目录情况不设置nd->root，是出于性能
		 * 考虑，因为有可能用不上。
		 * 之所以这里对nd->root字段设置就是因为马上就要用到了。因为这
		 * 里是要"cd .."了
		 */
		if (!nd->root.mnt)
			set_root(nd);
		if (nd->flags & LOOKUP_RCU) {
			return follow_dotdot_rcu(nd);
		} else
			return follow_dotdot(nd);
	}
	return 0;
}

static int pick_link(struct nameidata *nd, struct path *link,
		     struct inode *inode, unsigned seq)
{
	int error;
	struct saved *last;
	if (unlikely(nd->total_link_count++ >= MAXSYMLINKS)) {
		path_to_nameidata(link, nd);
		return -ELOOP;
	}
	if (!(nd->flags & LOOKUP_RCU)) {
		if (link->mnt == nd->path.mnt)
			mntget(link->mnt);
	}
	/*
	 * 如果embedded stack不够用了，则分配一个新的
	 */
	error = nd_alloc_stack(nd);
	if (unlikely(error)) {
		if (error == -ECHILD) {
			if (unlikely(!legitimize_path(nd, link, seq))) {
				drop_links(nd);
				nd->depth = 0;
				nd->flags &= ~LOOKUP_RCU;
				nd->path.mnt = NULL;
				nd->path.dentry = NULL;
				rcu_read_unlock();
			} else if (likely(unlazy_walk(nd)) == 0)
				error = nd_alloc_stack(nd);
		}
		if (error) {
			path_put(link);
			return error;
		}
	}

	/*
	 * depth指向的是未使用的格子
	 */
	last = nd->stack + nd->depth++;
	last->link = *link;
	clear_delayed_call(&last->done);
	nd->link_inode = inode;
	last->seq = seq;
	return 1;
}

enum {WALK_FOLLOW = 1, WALK_MORE = 2};

/*
 * Do we need to follow links? We _really_ want to be able
 * to do this check without having to look at inode->i_op,
 * so we keep a cache of "no, this doesn't need follow_link"
 * for the common case.
 */
static inline int step_into(struct nameidata *nd, struct path *path,
			    int flags, struct inode *inode, unsigned seq)
{
	/*
	 * 非do_last()，lookup_last()，xxx_last()时都会设置WALK_MORE标志
	 */
	if (!(flags & WALK_MORE) && nd->depth)
		put_link(nd);

	/*
	 * 走到这里说明需要继续向下一个路径分量迈进
	 */
	if (likely(!d_is_symlink(path->dentry)) ||
	   !(flags & WALK_FOLLOW || nd->flags & LOOKUP_FOLLOW)) {
		/* not a symlink or should not follow */
		/*
		 * 不是符号链接或者不需要follow符号链接，则直接将path移进
		 * 到nd中，完成一次分量跨越；
		 */
		path_to_nameidata(path, nd);
		nd->inode = inode;
		/*
		 * 此时已经移进了一步，子dentry变成了新的父dentry，更新
		 * nd->seq表示后面查找时，父dentry的seq的新值；
		 */
		nd->seq = seq;
		return 0;
	}

	/*
	 * 走到这里，说明path表示一个符号链接，且需要follow该符号链接
	 */

	/* make sure that d_is_symlink above matches inode */
	if (nd->flags & LOOKUP_RCU) {
		if (read_seqcount_retry(&path->dentry->d_seq, seq))
			return -ECHILD;
	}
	/*
	 * 将path这个符号链接放到nd->stack中；
	 * - 成功放入的话，返回1
	 */
	return pick_link(nd, path, inode, seq);
}

static int walk_component(struct nameidata *nd, int flags)
{
	struct path path;
	struct inode *inode;
	unsigned seq;
	int err;
	/*
	 * "." and ".." are special - ".." especially so because it has
	 * to be able to know about the current root directory and
	 * parent relationships.
	 */
	if (unlikely(nd->last_type != LAST_NORM)) {
		err = handle_dots(nd, nd->last_type);
		/*
		 * 非last component在调用walk_component时才传入WALK_MORE参数。
		 * 因此，只有last component才有可能进入到下面的if语句。
		 *
		 * 这里的意思是：我们此时要处理的是"cd ."或者"cd .."，所以原来
		 * 解析好的符号链接此时不需要了，所以要put_link()来放弃对符号
		 * 连接的引用计数
		 */
		if (!(flags & WALK_MORE) && nd->depth)
			put_link(nd);
		return err;
	}
	/*
	 * 快速查找————依赖于缓存。根据「父目录、名称」查找
	 * 疑问：为什么不直接通过parent dentry的d_subdirs链表来查找呢？
	 * - 这样的话需要给每个dentry都建立一个hash表才能保证O(1)的时间复杂度；
	 *   但每个dentry一个哈希表的话，尺寸不好定，不容易平衡；
	 *
 	 * 进行路径名的查找，目标存放在nd->last中，查找结果存放在inode和path中
 	 * 返回出来
	 *
	 * 对于ref-walk，是增加了引用计数的
	 * 对于rcu-walk，seq返回子dentry查找到时的d_seq或者follow_mount_rcu()中
	 * 更新的子dentry的d_seq
 	 */ 
	err = lookup_fast(nd, &path, &inode, &seq);
	if (unlikely(err <= 0)) {
		/*
		 * 小于0的话表示从rcu-walk到ref-walk的切换出了问题，需要回到上
		 * 层来解决；
		 * - ENOENT会返回
		 */
		if (err < 0)
			return err;

		/*
		 * 走到这里，说明err为0，即成功切换到了ref-walk模式
		 */
		
		/* 
 		 * nd->last是将要检索的路径分量
 		 * nd->path.dentry是当前目录
		 *
		 * 内部会调用文件系统特定的方法。此函数返回后，path.dentry中保
		 * 存目标文件的dentry项指针
		 *
		 * 内部会将找到的dentry到到dentry_hashtable中（期间经历了一次放
		 * 到inlookup_hashtable，然后从里面拿出来的过程），将dentry放入
		 * dentry_hashtable的动作是在__d_add(->lookup的最后一步）中完成
		 * 的：
		 * 
		 * d_alloc
		 * list_add(inlookup_hashtable)
		 * ->lookup
		 *     d_add
		 *       list_add(dentry_hashtable)
		 * list_del(inlookup_hashtable)
 		 */ 
		path.dentry = lookup_slow(&nd->last, nd->path.dentry,
					  nd->flags);
		if (IS_ERR(path.dentry))
			return PTR_ERR(path.dentry);

		path.mnt = nd->path.mnt;
		/*
		 * 处理按某种方式管理的目录：
		 * - 如果自动挂载工具autofs管理这个目录的跳转，那么调用具体文件
		 *   系统的目录项操作集合的d_manage方法来处理；
		 * - 如果目录是挂载点，那么在挂载描述符散列表中查找挂载的文件系
		 *   统，然后跳转到这个文件系统的根目录；
		 * - 如果目录是自动挂载点，那么调用函数follow_automount自动挂载
		 *   文件系统
		 *
		 * 所以向下跨越挂载点是在这个函数中完成的
		 */
		err = follow_managed(&path, nd);
		if (unlikely(err < 0))
			return err;

		/*
		 * 如果上面返回的dentry是负状态的，则返回错误
		 */
		if (unlikely(d_is_negative(path.dentry))) {
			/*
			 * 在负状态的dentry返回错误前，nd迈入了负状态的dentry，
			 * 这意味着即便是负状态的dentry，也不会在查找操作返回失
			 * 败前free掉，而是cache了起来。这有助于下次目录查找时
			 * 的加速
			 */
			path_to_nameidata(&path, nd);
			return -ENOENT;
		}

		seq = 0;	/* we are already out of RCU mode */
		inode = d_backing_inode(path.dentry);
	}

	/*
	 * 走到这里，说明找到了dentry，且不为负状态
	 */

	/*
	 * 如果目录是符号链接，那么调用step_into()来加以处理：如果符号链接的嵌
	 * 套层次超过40，返回错误；nameidata结构体的成员stack指向一个栈，如果栈
	 * 的最大深度是初始值2，那么把栈的最大深度扩大到40；把解析分量得到的路
	 * 径信息保存到栈中，接下来解析符号链接的目标。
	 *
	 * 返回0说明不是符号链接或者不应该被follow
	 */
	return step_into(nd, &path, flags, inode, seq);
}

/*
 * We can do the critical dentry name comparison and hashing
 * operations one word at a time, but we are limited to:
 *
 * - Architectures with fast unaligned word accesses. We could
 *   do a "get_unaligned()" if this helps and is sufficiently
 *   fast.
 *
 * - non-CONFIG_DEBUG_PAGEALLOC configurations (so that we
 *   do not trap on the (extremely unlikely) case of a page
 *   crossing operation.
 *
 * - Furthermore, we need an efficient 64-bit compile for the
 *   64-bit case in order to generate the "number of bytes in
 *   the final mask". Again, that could be replaced with a
 *   efficient population count instruction or similar.
 */
#ifdef CONFIG_DCACHE_WORD_ACCESS

#include <asm/word-at-a-time.h>

#ifdef HASH_MIX

/* Architecture provides HASH_MIX and fold_hash() in <asm/hash.h> */

#elif defined(CONFIG_64BIT)
/*
 * Register pressure in the mixing function is an issue, particularly
 * on 32-bit x86, but almost any function requires one state value and
 * one temporary.  Instead, use a function designed for two state values
 * and no temporaries.
 *
 * This function cannot create a collision in only two iterations, so
 * we have two iterations to achieve avalanche.  In those two iterations,
 * we have six layers of mixing, which is enough to spread one bit's
 * influence out to 2^6 = 64 state bits.
 *
 * Rotate constants are scored by considering either 64 one-bit input
 * deltas or 64*63/2 = 2016 two-bit input deltas, and finding the
 * probability of that delta causing a change to each of the 128 output
 * bits, using a sample of random initial states.
 *
 * The Shannon entropy of the computed probabilities is then summed
 * to produce a score.  Ideally, any input change has a 50% chance of
 * toggling any given output bit.
 *
 * Mixing scores (in bits) for (12,45):
 * Input delta: 1-bit      2-bit
 * 1 round:     713.3    42542.6
 * 2 rounds:   2753.7   140389.8
 * 3 rounds:   5954.1   233458.2
 * 4 rounds:   7862.6   256672.2
 * Perfect:    8192     258048
 *            (64*128) (64*63/2 * 128)
 */
#define HASH_MIX(x, y, a)	\
	(	x ^= (a),	\
	y ^= x,	x = rol64(x,12),\
	x += y,	y = rol64(y,45),\
	y *= 9			)

/*
 * Fold two longs into one 32-bit hash value.  This must be fast, but
 * latency isn't quite as critical, as there is a fair bit of additional
 * work done before the hash value is used.
 */
static inline unsigned int fold_hash(unsigned long x, unsigned long y)
{
	y ^= x * GOLDEN_RATIO_64;
	y *= GOLDEN_RATIO_64;
	return y >> 32;
}

#else	/* 32-bit case */

/*
 * Mixing scores (in bits) for (7,20):
 * Input delta: 1-bit      2-bit
 * 1 round:     330.3     9201.6
 * 2 rounds:   1246.4    25475.4
 * 3 rounds:   1907.1    31295.1
 * 4 rounds:   2042.3    31718.6
 * Perfect:    2048      31744
 *            (32*64)   (32*31/2 * 64)
 */
#define HASH_MIX(x, y, a)	\
	(	x ^= (a),	\
	y ^= x,	x = rol32(x, 7),\
	x += y,	y = rol32(y,20),\
	y *= 9			)

static inline unsigned int fold_hash(unsigned long x, unsigned long y)
{
	/* Use arch-optimized multiply if one exists */
	return __hash_32(y ^ __hash_32(x));
}

#endif

/*
 * Return the hash of a string of known length.  This is carfully
 * designed to match hash_name(), which is the more critical function.
 * In particular, we must end by hashing a final word containing 0..7
 * payload bytes, to match the way that hash_name() iterates until it
 * finds the delimiter after the name.
 */
unsigned int full_name_hash(const void *salt, const char *name, unsigned int len)
{
	unsigned long a, x = 0, y = (unsigned long)salt;

	for (;;) {
		if (!len)
			goto done;
		a = load_unaligned_zeropad(name);
		if (len < sizeof(unsigned long))
			break;
		HASH_MIX(x, y, a);
		name += sizeof(unsigned long);
		len -= sizeof(unsigned long);
	}
	x ^= a & bytemask_from_count(len);
done:
	return fold_hash(x, y);
}
EXPORT_SYMBOL(full_name_hash);

/* Return the "hash_len" (hash and length) of a null-terminated string */
u64 hashlen_string(const void *salt, const char *name)
{
	unsigned long a = 0, x = 0, y = (unsigned long)salt;
	unsigned long adata, mask, len;
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;

	len = 0;
	goto inside;

	do {
		HASH_MIX(x, y, a);
		len += sizeof(unsigned long);
inside:
		a = load_unaligned_zeropad(name+len);
	} while (!has_zero(a, &adata, &constants));

	adata = prep_zero_mask(a, adata, &constants);
	mask = create_zero_mask(adata);
	x ^= a & zero_bytemask(mask);

	return hashlen_create(fold_hash(x, y), len + find_zero(mask));
}
EXPORT_SYMBOL(hashlen_string);

/*
 * Calculate the length and hash of the path component, and
 * return the "hash_len" as the result.
 */
static inline u64 hash_name(const void *salt, const char *name)
{
	unsigned long a = 0, b, x = 0, y = (unsigned long)salt;
	unsigned long adata, bdata, mask, len;
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;

	len = 0;
	goto inside;

	do {
		HASH_MIX(x, y, a);
		len += sizeof(unsigned long);
inside:
		a = load_unaligned_zeropad(name+len);
		b = a ^ REPEAT_BYTE('/');
	} while (!(has_zero(a, &adata, &constants) | has_zero(b, &bdata, &constants)));

	adata = prep_zero_mask(a, adata, &constants);
	bdata = prep_zero_mask(b, bdata, &constants);
	mask = create_zero_mask(adata | bdata);
	x ^= a & zero_bytemask(mask);

	return hashlen_create(fold_hash(x, y), len + find_zero(mask));
}

#else	/* !CONFIG_DCACHE_WORD_ACCESS: Slow, byte-at-a-time version */

/* Return the hash of a string of known length */
unsigned int full_name_hash(const void *salt, const char *name, unsigned int len)
{
	unsigned long hash = init_name_hash(salt);
	while (len--)
		hash = partial_name_hash((unsigned char)*name++, hash);
	return end_name_hash(hash);
}
EXPORT_SYMBOL(full_name_hash);

/* Return the "hash_len" (hash and length) of a null-terminated string */
u64 hashlen_string(const void *salt, const char *name)
{
	unsigned long hash = init_name_hash(salt);
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	while (c) {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	}
	return hashlen_create(end_name_hash(hash), len);
}
EXPORT_SYMBOL(hashlen_string);

/*
 * We know there's a real path component here of at least
 * one character.
 */
static inline u64 hash_name(const void *salt, const char *name)
{
	unsigned long hash = init_name_hash(salt);
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	do {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	} while (c && c != '/');
	return hashlen_create(end_name_hash(hash), len);
}

#endif

/*
 * Name resolution.
 * This is the basic name resolution function, turning a pathname into
 * the final dentry. We expect 'base' to be positive and a directory.
 *
 * Returns 0 and nd will have valid dentry and mnt on success.
 * Returns error and drops reference to input namei data on failure.
 */
static int link_path_walk(const char *name, struct nameidata *nd)
{
	int err;

	if (IS_ERR(name))
		return PTR_ERR(name);
	while (*name=='/')
		name++;
	if (!*name)
		return 0;

	/* At this point we know we have a real path component. */
	for(;;) {
		u64 hash_len;
		int type;

		/* 检查下一个路径分量所在父目录的访问权限 */
		err = may_lookup(nd);
		if (err)
			return err;

		/* 
		 * hash_len高32位是路径长度，低32位是hash值。用于在dentry哈希表
		 * 中搜索dentry
		 *
		 * nd->path.dentry是当前正站在的目录，name是此目录下的一个分量
		 */
		hash_len = hash_name(nd->path.dentry, name);

		type = LAST_NORM;
		/* 判断文件名是否使用了"."或者".."，并标明type */
		if (name[0] == '.') switch (hashlen_len(hash_len)) {
			case 2:
				if (name[1] == '.') {
					type = LAST_DOTDOT;
					nd->flags |= LOOKUP_JUMPED;
				}
				break;
			case 1:
				type = LAST_DOT;
		}
		/* 普通文件和目录 */
		if (likely(type == LAST_NORM)) {
			/*
			 * nameidata->path中存储的是当前最新的已解析路径，
			 * 即当前待解析路径的父目录
			 */
			struct dentry *parent = nd->path.dentry;
			nd->flags &= ~LOOKUP_JUMPED;
			/*
			 * 如果文件系统定义了自己的d_hash()方法，则使用文件系统
			 * 的d_hash()方法，得到新的hash_len，覆盖上面通用
			 * hash_name()得到的hash_len
			 */
			if (unlikely(parent->d_flags & DCACHE_OP_HASH)) {
				struct qstr this = { { .hash_len = hash_len }, .name = name };
				err = parent->d_op->d_hash(parent, &this);
				if (err < 0)
					return err;
				hash_len = this.hash_len;
				name = this.name;
			}
		}

		/*
		 * 当前要解析的分量保存在nd->last中
		 */
		nd->last.hash_len = hash_len;
		nd->last.name = name;
		nd->last_type = type;

		/* 
 		 * 此处name要后移，指向下一个路径分量。当前路径分量已经保存
 		 * 在了nd->last.name中
 		 *
 		 * hash_len中编码了当前这一段路径分量的长度
 		 */
		name += hashlen_len(hash_len);
		/*
		 * 此函数本身并不要求将所有路径解析完成，当发现待解析的路径已经
		 * 是最后一个路径分量时即可退出本函数，交由lookup_last或do_last
		 * 操作
		 */ 
		if (!*name)
			goto OK;
		/*
		 * If it wasn't NUL, we know it was '/'. Skip that
		 * slash, and continue until no more slashes.
		 *
		 * 过滤掉多余的/
		 */
		do {
			name++;
		} while (unlikely(*name == '/'));
		if (unlikely(!*name)) {
OK:
			/* 
 			 * pathname body, done 
 			 *
 			 * name指针指向NUL了，name解析结束。
 			 * 但此时最后一个分量还没有被解析，即本函数只处理路径，
 			 * 不处理最后一个代表文件的分量
 			 */

			/*
			 * 此时判断是否还在处理符号链接
			 *
			 * 如果nd->depth == 0，表示没有要处理的符号连接，返回0
			 */
			if (!nd->depth)
				return 0;
			/* 
			 * 运行到这里说明有符号链接要处理，将name指向这个符号链
			 * 接。name表示下一步要处理的路径
			 */
			name = nd->stack[nd->depth - 1].name;
			/* trailing symlink, done */
			if (!name)
				return 0;
			/*
			 * 走到这里，说明nd->last还是一个符号链接的结尾，此时继续
			 * 解析；
			 * 如果在上面返回了，表示nd->last是真正路径的最后，此时本
			 * 函数返回，将最后一个路径分量交给xxx_last()处理；
			 */
			/* last component of nested symlink */
			err = walk_component(nd, WALK_FOLLOW);
		} else {
			/* not the last component */
			err = walk_component(nd, WALK_FOLLOW | WALK_MORE);
		}
		if (err < 0)
			return err;

		/* 
		 * 是符号连接
		 *
		 * walk_component返回0说明不是符号链接或者不应该被follow
		 * 返回1表示是符号链接且需要follow，并已经将表示符号链接的path放
		 * 入了nd->stack中；
		 */
		if (err) {
			/* 
			 * 读取符号连接的目标路径，因为在walk_component -> 
			 * step_into -> pick_link中只存放了符号连接的dentry字段
			 * 而没有解析其具体的name字段；
			 * 这里通过get_link()方法得到该符号链接inode的目标路径；
			 */
			const char *s = get_link(nd);

			if (IS_ERR(s))
				return PTR_ERR(s);
			err = 0;
			if (unlikely(!s)) {
				/* 如果符号连接的目标是空的，则弹出这个符号链接丢掉 */
				/* jumped */
				put_link(nd);
			} else {
				/* 
				 * 符号链接的目标非空，把当前【正在】【待】解析
				 * 路径压栈。转而先去处理符号链接。
				 *
				 * 当符号链接处理完后，再继续处理现在保存的路径
				 */
				nd->stack[nd->depth - 1].name = name;
				name = s;
				continue;
			}
		}
		if (unlikely(!d_can_lookup(nd->path.dentry))) {
			if (nd->flags & LOOKUP_RCU) {
				if (unlazy_walk(nd))
					return -ECHILD;
			}
			return -ENOTDIR;
		}
	}
}

/* must be paired with terminate_walk() */
static const char *path_init(struct nameidata *nd, unsigned flags)
{
	/* 
	 * nameidata->name 是个一个 struct filename * 类型
	 * nameidata->name->name 是一个 char * 类型
	 */
	const char *s = nd->name->name;

	/*
	 * 如果s现在是个空字符串，那么取消掉LOOKUP_RCU
	 */
	if (!*s)
		flags &= ~LOOKUP_RCU;
	/* 
	 * 对应的rcu_read_unlock()在terminate_walk()中
	 * path_init和terminate_walk必须成对使用
	 */
	if (flags & LOOKUP_RCU)
		rcu_read_lock();

	nd->last_type = LAST_ROOT; /* if there are only slashes... */
	/* 对应lookup_flag */
	nd->flags = flags | LOOKUP_JUMPED | LOOKUP_PARENT;
	nd->depth = 0;
	if (flags & LOOKUP_ROOT) {
		struct dentry *root = nd->root.dentry;
		struct inode *inode = root->d_inode;
		if (*s && unlikely(!d_can_lookup(root)))
			return ERR_PTR(-ENOTDIR);
		/*
		 * nd->path和nd->root都是struct path, 内部只有两个指针，所以可以直接赋值；
		 */
		nd->path = nd->root;
		/* 当前所站在dentry的inode */
		nd->inode = inode;
		if (flags & LOOKUP_RCU) {
			/* 使用RCU的情况 */
			nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			nd->root_seq = nd->seq;
			nd->m_seq = read_seqbegin(&mount_lock);
		} else {
			/* 
			 * 使用reflock的情况
			 * 在terminate_walk()中调用了path_put()
			 */
			path_get(&nd->path);
		}
		return s;
	}

	/*
	 * 根文件系统的挂载点是强制为NULL吗？
	 */ 
	nd->root.mnt = NULL;
	/*
	 * 暂时还未知，下面多个地方都对其进行了设置
	 */
	nd->path.mnt = NULL;
	nd->path.dentry = NULL;

	/*
	 * 为什么是mount_lock？这个全局锁是用来干嘛的？
	 */
	nd->m_seq = read_seqbegin(&mount_lock);
	if (*s == '/') {
		/* 
		 * 后面的两个if分支都没有设置nd->root的值，这是处于性能考虑，因为很有可
		 * 能用不到nd->root。但是如果在路径中遇到了/../，即向上一层目录walk，则
		 * 会在handle_dotdot之前进行set_root()
		 *
		 * 设置根目录
		 * - rcu方式
		 * - ref方式
		 */
		set_root(nd);
		if (likely(!nd_jump_root(nd)))
			return s;
		return ERR_PTR(-ECHILD);
	} else if (nd->dfd == AT_FDCWD) {
		/*
		 * 当前目录
		 */
		if (flags & LOOKUP_RCU) {
			struct fs_struct *fs = current->fs;
			unsigned seq;

			do {
				seq = read_seqcount_begin(&fs->seq);
				/*
				 * 上面nd->path.mnt和nd->path.dentry都被置为NULL了，这里
				 * 就不是NULL了
				 */
				nd->path = fs->pwd;
				nd->inode = nd->path.dentry->d_inode;
				/*
				 * 开启父节点的顺序锁临界区
				 */
				nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			} while (read_seqcount_retry(&fs->seq, seq));
		} else {
			/* 
			 * 获取fs->pwd(struct path)，并对其进行path_get()，
			 * 因为这是ref-walk，所以要增加引用计数。
			 *
			 * 这里里面也是要设置nd->path
			 */
			get_fs_pwd(current->fs, &nd->path);
			nd->inode = nd->path.dentry->d_inode;
		}
		return s;
	} else {
		/* Caller must check execute permissions on the starting path component */
		struct fd f = fdget_raw(nd->dfd);
		struct dentry *dentry;

		if (!f.file)
			return ERR_PTR(-EBADF);

		dentry = f.file->f_path.dentry;

		if (*s && unlikely(!d_can_lookup(dentry))) {
			fdput(f);
			return ERR_PTR(-ENOTDIR);
		}

		nd->path = f.file->f_path;
		if (flags & LOOKUP_RCU) {
			nd->inode = nd->path.dentry->d_inode;
			nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
		} else {
			/*
			 * ref-walk模式，要对dentry引用计数+1
			 */
			path_get(&nd->path);
			nd->inode = nd->path.dentry->d_inode;
		}
		fdput(f);
		return s;
	}
}

static const char *trailing_symlink(struct nameidata *nd)
{
	const char *s;
	int error = may_follow_link(nd);
	if (unlikely(error))
		return ERR_PTR(error);
	nd->flags |= LOOKUP_PARENT;
	nd->stack[0].name = NULL;
	s = get_link(nd);
	return s ? s : "";
}

static inline int lookup_last(struct nameidata *nd)
{
	if (nd->last_type == LAST_NORM && nd->last.name[nd->last.len])
		nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;

	nd->flags &= ~LOOKUP_PARENT;
	return walk_component(nd, 0);
}

static int handle_lookup_down(struct nameidata *nd)
{
	struct path path = nd->path;
	struct inode *inode = nd->inode;
	unsigned seq = nd->seq;
	int err;

	if (nd->flags & LOOKUP_RCU) {
		/*
		 * don't bother with unlazy_walk on failure - we are
		 * at the very beginning of walk, so we lose nothing
		 * if we simply redo everything in non-RCU mode
		 */
		if (unlikely(!__follow_mount_rcu(nd, &path, &inode, &seq)))
			return -ECHILD;
	} else {
		dget(path.dentry);
		err = follow_managed(&path, nd);
		if (unlikely(err < 0))
			return err;
		inode = d_backing_inode(path.dentry);
		seq = 0;
	}
	path_to_nameidata(&path, nd);
	nd->inode = inode;
	nd->seq = seq;
	return 0;
}

/* 
 * Returns 0 and nd will be valid on success; Retuns error, otherwise.
 *
 * 本函数要和path_openat()对比着看，path的引用计数部分非常微妙
 */
static int path_lookupat(struct nameidata *nd, unsigned flags, struct path *path)
{
	/* 
	 * 如果是rcu-walk模式，在path_init()中就进行了rcu_read_lock()
	 * 如果是ref-walk模式，在path_init()中就进行了path_get()
	 *
	 * 此函数的重点就是设置nd->path的起始状态
	 */
	const char *s = path_init(nd, flags);
	int err;

	/*
	 * 在路径开始的点就检查是否是挂载点并walk上去
	 */
	if (unlikely(flags & LOOKUP_DOWN) && !IS_ERR(s)) {
		err = handle_lookup_down(nd);
		if (unlikely(err < 0))
			s = ERR_PTR(err);
	}

	/*
	 * link_path_walk()成功后返回0，意味着已经解析完了。
	 * link_path_walk()返回0后才会执行lookup_last()
	 *
	 * lookup_last()返回值大于0意味着是个符号链接
	 * lookup_last()等于0意味着已经解析完成
	 */
	while (!(err = link_path_walk(s, nd))
		/*
		 * ref-walk模式下是增加了引用计数的
		 *
		 * rcu-walk模式下没有增加引用计数
		 */
		&& ((err = lookup_last(nd)) > 0)) {
		/*
		 * 进入到这里，说明最后一项是个符号链接，所以要重新进入while循
		 * 环中的link_path_walk()和lookup_last。
		 *
		 * 如果最后一项不是符号链接，则整个while循环直接结束了
		 */ 
		s = trailing_symlink(nd);
	}
	if (!err)
		/* 
		 * 在这里对rcu-walk模式得到的结果进行了引用计数增加，目的是对齐
		 * ref-walk模式返回的结果
		 */
		err = complete_walk(nd);

	if (!err && nd->flags & LOOKUP_DIRECTORY)
		if (!d_can_lookup(nd->path.dentry))
			err = -ENOTDIR;
	if (!err) {
		*path = nd->path;
		nd->path.mnt = NULL;
		nd->path.dentry = NULL;
	}
	/*
	 * 如果是rcu-walk模式，内部会调用rcu_read_unlock()；
	 *
	 * 内部调用了path_put()，对应path_init()中的path_get()
	 *
	 * 但此时nd->path中的值都已经被赋值为NULL了， 所以这里是没有真正减小引
	 * 用计数的
	 */
	terminate_walk(nd);
	return err;
}

int filename_lookup(int dfd, struct filename *name, unsigned flags,
		    struct path *path, struct path *root)
{
	int retval;
	struct nameidata nd;
	if (IS_ERR(name))
		return PTR_ERR(name);
	if (unlikely(root)) {
		nd.root = *root;
		flags |= LOOKUP_ROOT;
	}
	set_nameidata(&nd, dfd, name);
	retval = path_lookupat(&nd, flags | LOOKUP_RCU, path);
	if (unlikely(retval == -ECHILD))
		retval = path_lookupat(&nd, flags, path);
	if (unlikely(retval == -ESTALE))
		retval = path_lookupat(&nd, flags | LOOKUP_REVAL, path);

	if (likely(!retval))
		audit_inode(name, path->dentry, 0);
	restore_nameidata();
	putname(name);
	return retval;
}

/* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
static int path_parentat(struct nameidata *nd, unsigned flags,
				struct path *parent)
{
	const char *s = path_init(nd, flags);
	int err = link_path_walk(s, nd);
	if (!err)
		err = complete_walk(nd);
	if (!err) {
		*parent = nd->path;
		nd->path.mnt = NULL;
		nd->path.dentry = NULL;
	}
	terminate_walk(nd);
	return err;
}

static struct filename *filename_parentat(int dfd, struct filename *name,
				unsigned int flags, struct path *parent,
				struct qstr *last, int *type)
{
	int retval;
	struct nameidata nd;

	if (IS_ERR(name))
		return name;
	set_nameidata(&nd, dfd, name);
	retval = path_parentat(&nd, flags | LOOKUP_RCU, parent);
	if (unlikely(retval == -ECHILD))
		retval = path_parentat(&nd, flags, parent);
	if (unlikely(retval == -ESTALE))
		retval = path_parentat(&nd, flags | LOOKUP_REVAL, parent);
	if (likely(!retval)) {
		*last = nd.last;
		*type = nd.last_type;
		audit_inode(name, parent->dentry, AUDIT_INODE_PARENT);
	} else {
		putname(name);
		name = ERR_PTR(retval);
	}
	restore_nameidata();
	return name;
}

/* does lookup, returns the object with parent locked */
struct dentry *kern_path_locked(const char *name, struct path *path)
{
	struct filename *filename;
	struct dentry *d;
	struct qstr last;
	int type;

	filename = filename_parentat(AT_FDCWD, getname_kernel(name), 0, path,
				    &last, &type);
	if (IS_ERR(filename))
		return ERR_CAST(filename);
	if (unlikely(type != LAST_NORM)) {
		path_put(path);
		putname(filename);
		return ERR_PTR(-EINVAL);
	}
	inode_lock_nested(path->dentry->d_inode, I_MUTEX_PARENT);
	d = __lookup_hash(&last, path->dentry, 0);
	if (IS_ERR(d)) {
		inode_unlock(path->dentry->d_inode);
		path_put(path);
	}
	putname(filename);
	return d;
}

int kern_path(const char *name, unsigned int flags, struct path *path)
{
	/*
	 * 此时path中的vfsmount和dentry都是加了引用计数的
	 */
	return filename_lookup(AT_FDCWD, getname_kernel(name),
			       flags, path, NULL);
}
EXPORT_SYMBOL(kern_path);

/**
 * vfs_path_lookup - lookup a file path relative to a dentry-vfsmount pair
 * @dentry:  pointer to dentry of the base directory
 * @mnt: pointer to vfs mount of the base directory
 * @name: pointer to file name
 * @flags: lookup flags
 * @path: pointer to struct path to fill
 */
int vfs_path_lookup(struct dentry *dentry, struct vfsmount *mnt,
		    const char *name, unsigned int flags,
		    struct path *path)
{
	struct path root = {.mnt = mnt, .dentry = dentry};
	/* the first argument of filename_lookup() is ignored with root */
	return filename_lookup(AT_FDCWD, getname_kernel(name),
			       flags , path, &root);
}
EXPORT_SYMBOL(vfs_path_lookup);

static int lookup_one_len_common(const char *name, struct dentry *base,
				 int len, struct qstr *this)
{
	this->name = name;
	this->len = len;
	this->hash = full_name_hash(base, name, len);
	if (!len)
		return -EACCES;

	if (unlikely(name[0] == '.')) {
		if (len < 2 || (len == 2 && name[1] == '.'))
			return -EACCES;
	}

	while (len--) {
		unsigned int c = *(const unsigned char *)name++;
		if (c == '/' || c == '\0')
			return -EACCES;
	}
	/*
	 * See if the low-level filesystem might want
	 * to use its own hash..
	 */
	if (base->d_flags & DCACHE_OP_HASH) {
		int err = base->d_op->d_hash(base, this);
		if (err < 0)
			return err;
	}

	return inode_permission(base->d_inode, MAY_EXEC);
}

/**
 * try_lookup_one_len - filesystem helper to lookup single pathname component
 * @name:	pathname component to lookup
 * @base:	base directory to lookup from
 * @len:	maximum length @len should be interpreted to
 *
 * Look up a dentry by name in the dcache, returning NULL if it does not
 * currently exist.  The function does not try to create a dentry.
 *
 * Note that this routine is purely a helper for filesystem usage and should
 * not be called by generic code.
 *
 * The caller must hold base->i_mutex.
 */
struct dentry *try_lookup_one_len(const char *name, struct dentry *base, int len)
{
	struct qstr this;
	int err;

	WARN_ON_ONCE(!inode_is_locked(base->d_inode));

	err = lookup_one_len_common(name, base, len, &this);
	if (err)
		return ERR_PTR(err);

	return lookup_dcache(&this, base, 0);
}
EXPORT_SYMBOL(try_lookup_one_len);

/**
 * lookup_one_len - filesystem helper to lookup single pathname component
 * @name:	pathname component to lookup
 * @base:	base directory to lookup from
 * @len:	maximum length @len should be interpreted to
 *
 * Note that this routine is purely a helper for filesystem usage and should
 * not be called by generic code.
 *
 * The caller must hold base->i_mutex.
 */
struct dentry *lookup_one_len(const char *name, struct dentry *base, int len)
{
	struct dentry *dentry;
	struct qstr this;
	int err;

	WARN_ON_ONCE(!inode_is_locked(base->d_inode));

	err = lookup_one_len_common(name, base, len, &this);
	if (err)
		return ERR_PTR(err);

	dentry = lookup_dcache(&this, base, 0);
	return dentry ? dentry : __lookup_slow(&this, base, 0);
}
EXPORT_SYMBOL(lookup_one_len);

/**
 * lookup_one_len_unlocked - filesystem helper to lookup single pathname component
 * @name:	pathname component to lookup
 * @base:	base directory to lookup from
 * @len:	maximum length @len should be interpreted to
 *
 * Note that this routine is purely a helper for filesystem usage and should
 * not be called by generic code.
 *
 * Unlike lookup_one_len, it should be called without the parent
 * i_mutex held, and will take the i_mutex itself if necessary.
 */
struct dentry *lookup_one_len_unlocked(const char *name,
				       struct dentry *base, int len)
{
	struct qstr this;
	int err;
	struct dentry *ret;

	err = lookup_one_len_common(name, base, len, &this);
	if (err)
		return ERR_PTR(err);

	ret = lookup_dcache(&this, base, 0);
	if (!ret)
		ret = lookup_slow(&this, base, 0);
	return ret;
}
EXPORT_SYMBOL(lookup_one_len_unlocked);

#ifdef CONFIG_UNIX98_PTYS
int path_pts(struct path *path)
{
	/* Find something mounted on "pts" in the same directory as
	 * the input path.
	 */
	struct dentry *child, *parent;
	struct qstr this;
	int ret;

	ret = path_parent_directory(path);
	if (ret)
		return ret;

	parent = path->dentry;
	this.name = "pts";
	this.len = 3;
	child = d_hash_and_lookup(parent, &this);
	if (!child)
		return -ENOENT;

	path->dentry = child;
	dput(parent);
	follow_mount(path);
	return 0;
}
#endif

int user_path_at_empty(int dfd, const char __user *name, unsigned flags,
		 struct path *path, int *empty)
{
	return filename_lookup(dfd, getname_flags(name, flags, empty),
			       flags, path, NULL);
}
EXPORT_SYMBOL(user_path_at_empty);

/**
 * mountpoint_last - look up last component for umount
 * @nd:   pathwalk nameidata - currently pointing at parent directory of "last"
 *
 * This is a special lookup_last function just for umount. In this case, we
 * need to resolve the path without doing any revalidation.
 *
 * The nameidata should be the result of doing a LOOKUP_PARENT pathwalk. Since
 * mountpoints are always pinned in the dcache, their ancestors are too. Thus,
 * in almost all cases, this lookup will be served out of the dcache. The only
 * cases where it won't are if nd->last refers to a symlink or the path is
 * bogus and it doesn't exist.
 *
 * Returns:
 * -error: if there was an error during lookup. This includes -ENOENT if the
 *         lookup found a negative dentry.
 *
 * 0:      if we successfully resolved nd->last and found it to not to be a
 *         symlink that needs to be followed.
 *
 * 1:      if we successfully resolved nd->last and found it to be a symlink
 *         that needs to be followed.
 */
static int
mountpoint_last(struct nameidata *nd)
{
	int error = 0;
	struct dentry *dir = nd->path.dentry;
	struct path path;

	/* If we're in rcuwalk, drop out of it to handle last component */
	if (nd->flags & LOOKUP_RCU) {
		if (unlazy_walk(nd))
			return -ECHILD;
	}

	nd->flags &= ~LOOKUP_PARENT;

	if (unlikely(nd->last_type != LAST_NORM)) {
		error = handle_dots(nd, nd->last_type);
		if (error)
			return error;
		path.dentry = dget(nd->path.dentry);
	} else {
		path.dentry = d_lookup(dir, &nd->last);
		if (!path.dentry) {
			/*
			 * No cached dentry. Mounted dentries are pinned in the
			 * cache, so that means that this dentry is probably
			 * a symlink or the path doesn't actually point
			 * to a mounted dentry.
			 */
			path.dentry = lookup_slow(&nd->last, dir,
					     nd->flags | LOOKUP_NO_REVAL);
			if (IS_ERR(path.dentry))
				return PTR_ERR(path.dentry);
		}
	}
	if (d_is_negative(path.dentry)) {
		dput(path.dentry);
		return -ENOENT;
	}
	path.mnt = nd->path.mnt;
	return step_into(nd, &path, 0, d_backing_inode(path.dentry), 0);
}

/**
 * path_mountpoint - look up a path to be umounted
 * @nd:		lookup context
 * @flags:	lookup flags
 * @path:	pointer to container for result
 *
 * Look up the given name, but don't attempt to revalidate the last component.
 * Returns 0 and "path" will be valid on success; Returns error otherwise.
 */
static int
path_mountpoint(struct nameidata *nd, unsigned flags, struct path *path)
{
	const char *s = path_init(nd, flags);
	int err;

	while (!(err = link_path_walk(s, nd)) &&
		(err = mountpoint_last(nd)) > 0) {
		s = trailing_symlink(nd);
	}
	if (!err) {
		*path = nd->path;
		nd->path.mnt = NULL;
		nd->path.dentry = NULL;
		follow_mount(path);
	}
	terminate_walk(nd);
	return err;
}

static int
filename_mountpoint(int dfd, struct filename *name, struct path *path,
			unsigned int flags)
{
	struct nameidata nd;
	int error;
	if (IS_ERR(name))
		return PTR_ERR(name);
	set_nameidata(&nd, dfd, name);
	error = path_mountpoint(&nd, flags | LOOKUP_RCU, path);
	if (unlikely(error == -ECHILD))
		error = path_mountpoint(&nd, flags, path);
	if (unlikely(error == -ESTALE))
		error = path_mountpoint(&nd, flags | LOOKUP_REVAL, path);
	if (likely(!error))
		audit_inode(name, path->dentry, AUDIT_INODE_NOEVAL);
	restore_nameidata();
	putname(name);
	return error;
}

/**
 * user_path_mountpoint_at - lookup a path from userland in order to umount it
 * @dfd:	directory file descriptor
 * @name:	pathname from userland
 * @flags:	lookup flags
 * @path:	pointer to container to hold result
 *
 * A umount is a special case for path walking. We're not actually interested
 * in the inode in this situation, and ESTALE errors can be a problem. We
 * simply want track down the dentry and vfsmount attached at the mountpoint
 * and avoid revalidating the last component.
 *
 * Returns 0 and populates "path" on success.
 */
int
user_path_mountpoint_at(int dfd, const char __user *name, unsigned int flags,
			struct path *path)
{
	return filename_mountpoint(dfd, getname(name), path, flags);
}

int
kern_path_mountpoint(int dfd, const char *name, struct path *path,
			unsigned int flags)
{
	return filename_mountpoint(dfd, getname_kernel(name), path, flags);
}
EXPORT_SYMBOL(kern_path_mountpoint);

int __check_sticky(struct inode *dir, struct inode *inode)
{
	kuid_t fsuid = current_fsuid();

	if (uid_eq(inode->i_uid, fsuid))
		return 0;
	if (uid_eq(dir->i_uid, fsuid))
		return 0;
	return !capable_wrt_inode_uidgid(inode, CAP_FOWNER);
}
EXPORT_SYMBOL(__check_sticky);

/*
 *	Check whether we can remove a link victim from directory dir, check
 *  whether the type of victim is right.
 *  1. We can't do it if dir is read-only (done in permission())
 *  2. We should have write and exec permissions on dir
 *  3. We can't remove anything from append-only dir
 *  4. We can't do anything with immutable dir (done in permission())
 *  5. If the sticky bit on dir is set we should either
 *	a. be owner of dir, or
 *	b. be owner of victim, or
 *	c. have CAP_FOWNER capability
 *  6. If the victim is append-only or immutable we can't do antyhing with
 *     links pointing to it.
 *  7. If the victim has an unknown uid or gid we can't change the inode.
 *  8. If we were asked to remove a directory and victim isn't one - ENOTDIR.
 *  9. If we were asked to remove a non-directory and victim isn't one - EISDIR.
 * 10. We can't remove a root or mountpoint.
 * 11. We don't allow removal of NFS sillyrenamed files; it's handled by
 *     nfs_async_unlink().
 *
 * 值得注意的是：删除文件只需要拥有该文件父目录的MAY_WRITE和MAY_EXEC权限即可，
 * 不要求拥有被删除文件的权限（sticky dir下的文件除外）；
 */
static int may_delete(struct inode *dir, struct dentry *victim, bool isdir)
{
	struct inode *inode = d_backing_inode(victim);
	int error;

	if (d_is_negative(victim))
		return -ENOENT;
	BUG_ON(!inode);

	BUG_ON(victim->d_parent->d_inode != dir);

	/* Inode writeback is not safe when the uid or gid are invalid. */
	if (!uid_valid(inode->i_uid) || !gid_valid(inode->i_gid))
		return -EOVERFLOW;

	audit_inode_child(dir, victim, AUDIT_TYPE_CHILD_DELETE);

	error = inode_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;
	if (IS_APPEND(dir))
		return -EPERM;

	if (check_sticky(dir, inode) || IS_APPEND(inode) ||
	    IS_IMMUTABLE(inode) || IS_SWAPFILE(inode) || HAS_UNMAPPED_ID(inode))
		return -EPERM;
	if (isdir) {
		if (!d_is_dir(victim))
			return -ENOTDIR;
		if (IS_ROOT(victim))
			return -EBUSY;
	} else if (d_is_dir(victim))
		return -EISDIR;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	if (victim->d_flags & DCACHE_NFSFS_RENAMED)
		return -EBUSY;
	return 0;
}

/*	Check whether we can create an object with dentry child in directory
 *  dir.
 *  1. We can't do it if child already exists (open has special treatment for
 *     this case, but since we are inlined it's OK)
 *  2. We can't do it if dir is read-only (done in permission())
 *  3. We can't do it if the fs can't represent the fsuid or fsgid.
 *  4. We should have write and exec permissions on dir
 *  5. We can't do it if dir is immutable (done in permission())
 */
static inline int may_create(struct inode *dir, struct dentry *child)
{
	struct user_namespace *s_user_ns;
	audit_inode_child(dir, child, AUDIT_TYPE_CHILD_CREATE);
	if (child->d_inode)
		return -EEXIST;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	s_user_ns = dir->i_sb->s_user_ns;
	if (!kuid_has_mapping(s_user_ns, current_fsuid()) ||
	    !kgid_has_mapping(s_user_ns, current_fsgid()))
		return -EOVERFLOW;
	return inode_permission(dir, MAY_WRITE | MAY_EXEC);
}

/*
 * p1 and p2 should be directories on the same fs.
 * 如果在同一个文件系统间使用mv，则使用的是renameat系统调用。
 * 如果在两个不同的文件系统（同类型不同实例也算）间使用mv，则使用的是open、
 * read、write、unlink等组合（其实就是拷贝并删除了）。
 *
 * 但实际上，在第二种情况中，mv还是会先尝试使用renameat，如果返回错误(EXDEV)则
 * 说明时跨设备的，此时再尝试拷贝并删除的方式。
 */
struct dentry *lock_rename(struct dentry *p1, struct dentry *p2)
{
	struct dentry *p;

	if (p1 == p2) {
		/*
		 * 等价于down_write(d_inode->i_rwsem)
		 */
		inode_lock_nested(p1->d_inode, I_MUTEX_PARENT);
		return NULL;
	}

	mutex_lock(&p1->d_sb->s_vfs_rename_mutex);

	p = d_ancestor(p2, p1);
	if (p) {
		inode_lock_nested(p2->d_inode, I_MUTEX_PARENT);
		inode_lock_nested(p1->d_inode, I_MUTEX_CHILD);
		return p;
	}

	p = d_ancestor(p1, p2);
	if (p) {
		inode_lock_nested(p1->d_inode, I_MUTEX_PARENT);
		inode_lock_nested(p2->d_inode, I_MUTEX_CHILD);
		return p;
	}

	inode_lock_nested(p1->d_inode, I_MUTEX_PARENT);
	inode_lock_nested(p2->d_inode, I_MUTEX_PARENT2);
	return NULL;
}
EXPORT_SYMBOL(lock_rename);

void unlock_rename(struct dentry *p1, struct dentry *p2)
{
	inode_unlock(p1->d_inode);
	if (p1 != p2) {
		inode_unlock(p2->d_inode);
		mutex_unlock(&p1->d_sb->s_vfs_rename_mutex);
	}
}
EXPORT_SYMBOL(unlock_rename);

int vfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool want_excl)
{
	int error = may_create(dir, dentry);
	if (error)
		return error;

	if (!dir->i_op->create)
		return -EACCES;	/* shouldn't it be ENOSYS? */
	mode &= S_IALLUGO;
	mode |= S_IFREG;
	error = security_inode_create(dir, dentry, mode);
	if (error)
		return error;
	error = dir->i_op->create(dir, dentry, mode, want_excl);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}
EXPORT_SYMBOL(vfs_create);

int vfs_mkobj(struct dentry *dentry, umode_t mode,
		int (*f)(struct dentry *, umode_t, void *),
		void *arg)
{
	struct inode *dir = dentry->d_parent->d_inode;
	int error = may_create(dir, dentry);
	if (error)
		return error;

	mode &= S_IALLUGO;
	mode |= S_IFREG;
	error = security_inode_create(dir, dentry, mode);
	if (error)
		return error;
	error = f(dentry, mode, arg);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}
EXPORT_SYMBOL(vfs_mkobj);

bool may_open_dev(const struct path *path)
{
	return !(path->mnt->mnt_flags & MNT_NODEV) &&
		!(path->mnt->mnt_sb->s_iflags & SB_I_NODEV);
}

static int may_open(const struct path *path, int acc_mode, int flag)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = dentry->d_inode;
	int error;

	if (!inode)
		return -ENOENT;

	switch (inode->i_mode & S_IFMT) {
	case S_IFLNK:
		return -ELOOP;
	case S_IFDIR:
		if (acc_mode & MAY_WRITE)
			return -EISDIR;
		break;
	case S_IFBLK:
	case S_IFCHR:
		if (!may_open_dev(path))
			return -EACCES;
		/*FALLTHRU*/
	case S_IFIFO:
	case S_IFSOCK:
		flag &= ~O_TRUNC;
		break;
	}

	error = inode_permission(inode, MAY_OPEN | acc_mode);
	if (error)
		return error;

	/*
	 * An append-only file must be opened in append mode for writing.
	 */
	if (IS_APPEND(inode)) {
		if  ((flag & O_ACCMODE) != O_RDONLY && !(flag & O_APPEND))
			return -EPERM;
		if (flag & O_TRUNC)
			return -EPERM;
	}

	/* O_NOATIME can only be set by the owner or superuser */
	if (flag & O_NOATIME && !inode_owner_or_capable(inode))
		return -EPERM;

	return 0;
}

static int handle_truncate(struct file *filp)
{
	const struct path *path = &filp->f_path;
	struct inode *inode = path->dentry->d_inode;
	int error = get_write_access(inode);
	if (error)
		return error;
	/*
	 * Refuse to truncate files with mandatory locks held on them.
	 */
	error = locks_verify_locked(filp);
	if (!error)
		error = security_path_truncate(path);
	if (!error) {
		error = do_truncate(path->dentry, 0,
				    ATTR_MTIME|ATTR_CTIME|ATTR_OPEN,
				    filp);
	}
	put_write_access(inode);
	return error;
}

static inline int open_to_namei_flags(int flag)
{
	if ((flag & O_ACCMODE) == 3)
		flag--;
	return flag;
}

static int may_o_create(const struct path *dir, struct dentry *dentry, umode_t mode)
{
	struct user_namespace *s_user_ns;
	int error = security_path_mknod(dir, dentry, mode, 0);
	if (error)
		return error;

	s_user_ns = dir->dentry->d_sb->s_user_ns;
	if (!kuid_has_mapping(s_user_ns, current_fsuid()) ||
	    !kgid_has_mapping(s_user_ns, current_fsgid()))
		return -EOVERFLOW;

	error = inode_permission(dir->dentry->d_inode, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;

	return security_inode_create(dir->dentry->d_inode, dentry, mode);
}

/*
 * Attempt to atomically look up, create and open a file from a negative
 * dentry.
 *
 * Returns 0 if successful.  The file will have been created and attached to
 * @file by the filesystem calling finish_open().
 *
 * If the file was looked up only or didn't need creating, FMODE_OPENED won't
 * be set.  The caller will need to perform the open themselves.  @path will
 * have been updated to point to the new dentry.  This may be negative.
 *
 * Returns an error code otherwise.
 */
static int atomic_open(struct nameidata *nd, struct dentry *dentry,
			struct path *path, struct file *file,
			const struct open_flags *op,
			int open_flag, umode_t mode)
{
	struct dentry *const DENTRY_NOT_SET = (void *) -1UL;
	struct inode *dir =  nd->path.dentry->d_inode;
	int error;

	if (!(~open_flag & (O_EXCL | O_CREAT)))	/* both O_EXCL and O_CREAT */
		open_flag &= ~O_TRUNC;

	if (nd->flags & LOOKUP_DIRECTORY)
		open_flag |= O_DIRECTORY;

	file->f_path.dentry = DENTRY_NOT_SET;
	file->f_path.mnt = nd->path.mnt;
	error = dir->i_op->atomic_open(dir, dentry, file,
				       open_to_namei_flags(open_flag), mode);
	d_lookup_done(dentry);
	if (!error) {
		if (file->f_mode & FMODE_OPENED) {
			/*
			 * We didn't have the inode before the open, so check open
			 * permission here.
			 */
			int acc_mode = op->acc_mode;
			if (file->f_mode & FMODE_CREATED) {
				WARN_ON(!(open_flag & O_CREAT));
				fsnotify_create(dir, dentry);
				acc_mode = 0;
			}
			error = may_open(&file->f_path, acc_mode, open_flag);
			if (WARN_ON(error > 0))
				error = -EINVAL;
		} else if (WARN_ON(file->f_path.dentry == DENTRY_NOT_SET)) {
			error = -EIO;
		} else {
			if (file->f_path.dentry) {
				dput(dentry);
				dentry = file->f_path.dentry;
			}
			if (file->f_mode & FMODE_CREATED)
				fsnotify_create(dir, dentry);
			if (unlikely(d_is_negative(dentry))) {
				error = -ENOENT;
			} else {
				path->dentry = dentry;
				path->mnt = nd->path.mnt;
				return 0;
			}
		}
	}
	dput(dentry);
	return error;
}

/*
 * Look up and maybe create and open the last component.
 *
 * Must be called with parent locked (exclusive in O_CREAT case).
 *
 * Returns 0 on success, that is, if
 *  the file was successfully atomically created (if necessary) and opened, or
 *  the file was not completely opened at this time, though lookups and
 *  creations were performed.
 * These case are distinguished by presence of FMODE_OPENED on file->f_mode.
 * In the latter case dentry returned in @path might be negative if O_CREAT
 * hadn't been specified.
 *
 * An error code is returned on failure.
 */
static int lookup_open(struct nameidata *nd, struct path *path,
			struct file *file,
			const struct open_flags *op,
			bool got_write)
{
	/*
	 * dir是父目录的dentry
	 * - dir_inode是上了锁的；
	 *   - 如果有O_CREAT，则上了写锁
	 *   - 如果没有，则上了写锁
	 */
	struct dentry *dir = nd->path.dentry;
	struct inode *dir_inode = dir->d_inode;
	int open_flag = op->open_flag;
	struct dentry *dentry;
	int error, create_error = 0;
	umode_t mode = op->mode;
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

	if (unlikely(IS_DEADDIR(dir_inode)))
		return -ENOENT;

	file->f_mode &= ~FMODE_CREATED;
	/*
	 * dentry是待查找目标的dentry
	 */
	dentry = d_lookup(dir, &nd->last);
	for (;;) {
		if (!dentry) {
			/*
			 * 如果dentry_hashtable中没有找到目标dentry：
			 *
			 * 内部将分配好的dentry放入了inlookup_hashtable
			 * 在后面的d_lookup_done中将其从inlookup_hashtable中取
			 * 下来
			 */
			dentry = d_alloc_parallel(dir, &nd->last, &wq);
			/*
			 * d_alloc_parallel返回时，dentry已经存在于
			 * dentry_hashtable中
			 */
			if (IS_ERR(dentry))
				return PTR_ERR(dentry);
		}

		/*
		 * 只有真正分配了此dentry的内核路径d_in_lookup判断才为真。
		 */
		if (d_in_lookup(dentry))
			break;

		/*
		 * 其他内核路径分配了dentry，本内核路径才会走到这里
		 * - 返回值大于0表示dentry依旧合法
		 */
		error = d_revalidate(dentry, nd->flags);
		if (likely(error > 0))
			break;
		/*
		 * 走到这里，说明dentry经d_revalidate()判断后发现不合法了，
		 * 则做好收尾工作后重新循环一遍
		 */
		if (error)
			goto out_dput;
		d_invalidate(dentry);
		dput(dentry);
		dentry = NULL;
	}
	if (dentry->d_inode) {
		/* Cached positive dentry: will open in f_op->open 
		 *
		 * 说明已经有对应的inode了，发生在返回的dentry为非本内核路径创
		 * 建的情况中。
		 *
		 * 因为如果返回的是其他内核路径创建的dentry，那么这个dentry在返
		 * 回之前，dentry和对应inode已经成熟(成熟包括在磁盘上查了一圈后
		 * 发现确实没有对应的inode，此时会将一个负状态的dentry进行插入
		 * 到dentry_hashtable中)
		 */
		goto out_no_open;
	}

	/*
	 * Checking write permission is tricky, bacuse we don't know if we are
	 * going to actually need it: O_CREAT opens should work as long as the
	 * file exists.  But checking existence breaks atomicity.  The trick is
	 * to check access and if not granted clear O_CREAT from the flags.
	 *
	 * Another problem is returing the "right" error value (e.g. for an
	 * O_EXCL open we want to return EEXIST not EROFS).
	 */
	if (open_flag & O_CREAT) {
		if (!IS_POSIXACL(dir->d_inode))
			mode &= ~current_umask();
		if (unlikely(!got_write)) {
			create_error = -EROFS;
			open_flag &= ~O_CREAT;
			if (open_flag & (O_EXCL | O_TRUNC))
				goto no_open;
			/* No side effects, safe to clear O_CREAT */
		} else {
			/*
			 * 检查当前用户是否有父目录的写权限；
			 */
			create_error = may_o_create(&nd->path, dentry, mode);
			if (create_error) {
				open_flag &= ~O_CREAT;
				if (open_flag & O_EXCL)
					goto no_open;
			}
		}
	} else if ((open_flag & (O_TRUNC|O_WRONLY|O_RDWR)) &&
		   unlikely(!got_write)) {
		/*
		 * No O_CREATE -> atomicity not a requirement -> fall
		 * back to lookup + open
		 */
		goto no_open;
	}

	if (dir_inode->i_op->atomic_open) {
		error = atomic_open(nd, dentry, path, file, op, open_flag,
				    mode);
		if (unlikely(error == -ENOENT) && create_error)
			error = create_error;
		return error;
	}

no_open:
	if (d_in_lookup(dentry)) {
		/*
		 * 同时搜索一个目标dentry的并发线程中，只有一个内核路径可以进入到这里
		 * - 此时其他的内核路径应该正在d_alloc_parallel()中睡眠
		 */

		/*
		 * 文件系统的查找inode操作
		 *
		 * dentry是返回的最重要的东西。相反，返回值res并没有那么重要，
		 * 其与d_splice_alias相关。对于非目录的文件，返回的res总是为
		 * NULL
		 *
		 * 返回的dentry有可能是负状态的，即dentry不对应inode
		 *
		 * 里面的d_splice_alias()会唤醒d_alloc_parallel()中的睡眠，并使其通过
		 * unhash()等检查并返回；
		 */
		struct dentry *res = dir_inode->i_op->lookup(dir_inode, dentry,
							     nd->flags);
		/*
		 * 将找到的dentry从inlookup_hashtable中摘下来
		 */
		d_lookup_done(dentry);
		if (unlikely(res)) {
			if (IS_ERR(res)) {
				error = PTR_ERR(res);
				goto out_dput;
			}
			dput(dentry);
			dentry = res;
		}
		/*
		 * 走到这里的dentry有可能是负状态的
		 */
	}

	/* Negative dentry, just create the file */

	/*
	 * 如果current_fsuid()在当前父目录没有创建文件的权限，那么O_CREAT在上面
	 * 被清除掉了，这个分支就会被跳过；
	 *
	 * 如果有O_CREAT标志，那么本函数的调用者需要首先获取dir_inode的写锁，那么
	 * 肯定只有一个内核路径可以进入到本函数，进而只有一个内核路径可以进入到下
	 * 面的分支；
	 */
	if (!dentry->d_inode && (open_flag & O_CREAT)) {
		file->f_mode |= FMODE_CREATED;
		audit_inode_child(dir_inode, dentry, AUDIT_TYPE_CHILD_CREATE);
		if (!dir_inode->i_op->create) {
			error = -EACCES;
			goto out_dput;
		}
		/*
		 * 文件系统的创建inode操作
		 * 创建新的inode
		 *
		 * 其中会调用d_instantiate_new将dentry和inode联系起来
		 *
		 * 对于xfs: xfs_vn_create()
		 * 对于ext4： ext4_create() -> ext4_new_inode() -> super_block.sops.alloc_inode()
		 */
		error = dir_inode->i_op->create(dir_inode, dentry, mode,
						open_flag & O_EXCL);
		if (error)
			goto out_dput;
		fsnotify_create(dir_inode, dentry);
	}
	if (unlikely(create_error) && !dentry->d_inode) {
		error = create_error;
		goto out_dput;
	}
out_no_open:
	path->dentry = dentry;
	path->mnt = nd->path.mnt;
	return 0;

out_dput:
	dput(dentry);
	return error;
}

/*
 * Handle the last step of open()
 */
static int do_last(struct nameidata *nd,
		   struct file *file, const struct open_flags *op)
{
	struct dentry *dir = nd->path.dentry;
	kuid_t dir_uid = nd->inode->i_uid;
	umode_t dir_mode = nd->inode->i_mode;
	int open_flag = op->open_flag;
	bool will_truncate = (open_flag & O_TRUNC) != 0;
	bool got_write = false;
	int acc_mode = op->acc_mode;
	unsigned seq;
	struct inode *inode;
	struct path path;
	int error;

	nd->flags &= ~LOOKUP_PARENT;
	nd->flags |= op->intent;

	if (nd->last_type != LAST_NORM) {
		error = handle_dots(nd, nd->last_type);
		if (unlikely(error))
			return error;
		goto finish_open;
	}

	if (!(open_flag & O_CREAT)) {
		/*
		 * 无O_CREAT标志，正常的open过程
		 */
		if (nd->last.name[nd->last.len])
			nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
		/* 
		 * we _can_ be in RCU mode here
		 *
		 * ref_walk内部对path增加了一次引用计数
		 * rcu-walk内部没有对path增加引用计数（后边会有complete_walk来
		 * 将引用计数对齐的）
		 *
		 * 这里只有lookup_fast吗？如果内存的哈希表中没有呢？不需要通过
		 * lookup_slow去磁盘上查找吗？
		 * - 没有的话会走到下面的lookup_open
		 */
		error = lookup_fast(nd, &path, &inode, &seq);
		if (likely(error > 0))
			goto finish_lookup;

		if (error < 0)
			return error;

		BUG_ON(nd->inode != dir->d_inode);
		BUG_ON(nd->flags & LOOKUP_RCU);
	} else {
		/*
		 * 有O_CREAT标志，需要创建目标文件
		 */
		/* create side of things */
		/*
		 * This will *only* deal with leaving RCU mode - LOOKUP_JUMPED
		 * has been cleared when we got to the last component we are
		 * about to look up
		 */
		error = complete_walk(nd);
		if (error)
			return error;

		audit_inode(nd->name, dir, AUDIT_INODE_PARENT);
		/* trailing slashes? */
		if (unlikely(nd->last.name[nd->last.len]))
			return -EISDIR;
	}

	if (open_flag & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR)) {
		error = mnt_want_write(nd->path.mnt);
		if (!error)
			got_write = true;
		/*
		 * do _not_ fail yet - we might not need that or fail with
		 * a different error; let lookup_open() decide; we'll be
		 * dropping this one anyway.
		 */
	}
	/*
	 * 如果确定要创建新的inode，需要对父inode加锁
	 */
	if (open_flag & O_CREAT)
		inode_lock(dir->d_inode);
	else
		inode_lock_shared(dir->d_inode);
	/*
	 * 查找对应的inode，如果没有就创建一个新的
	 *
	 * 如果确实没有这个文件，且没有O_CREAT标志，那么这里会将一个NULL
	 * inode和对应的dentry连接，即返回之后dentry是个负状态的
	 */
	error = lookup_open(nd, &path, file, op, got_write);
	if (open_flag & O_CREAT)
		inode_unlock(dir->d_inode);
	else
		inode_unlock_shared(dir->d_inode);

	if (error)
		goto out;

	if (file->f_mode & FMODE_OPENED) {
		if ((file->f_mode & FMODE_CREATED) ||
		    !S_ISREG(file_inode(file)->i_mode))
			will_truncate = false;

		audit_inode(nd->name, file->f_path.dentry, 0);
		goto opened;
	}

	if (file->f_mode & FMODE_CREATED) {
		/* Don't check for write permission, don't truncate */
		open_flag &= ~O_TRUNC;
		will_truncate = false;
		acc_mode = 0;
		path_to_nameidata(&path, nd);
		goto finish_open_created;
	}

	/*
	 * If atomic_open() acquired write access it is dropped now due to
	 * possible mount and symlink following (this might be optimized away if
	 * necessary...)
	 */
	if (got_write) {
		mnt_drop_write(nd->path.mnt);
		got_write = false;
	}

	error = follow_managed(&path, nd);
	if (unlikely(error < 0))
		return error;

	if (unlikely(d_is_negative(path.dentry))) {
		path_to_nameidata(&path, nd);
		return -ENOENT;
	}

	/*
	 * create/update audit record if it already exists.
	 */
	audit_inode(nd->name, path.dentry, 0);

	if (unlikely((open_flag & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT))) {
		path_to_nameidata(&path, nd);
		return -EEXIST;
	}

	seq = 0;	/* out of RCU mode, so the value doesn't matter */
	inode = d_backing_inode(path.dentry);
finish_lookup:
	error = step_into(nd, &path, 0, inode, seq);
	if (unlikely(error))
		return error;
	/*
	 * 到这里，nd->path中保存的应该是open目标文件的信息了？
	 */
finish_open:
	/* Why this, you ask?  _Now_ we might have grown LOOKUP_JUMPED... */
	error = complete_walk(nd);
	if (error)
		return error;
	audit_inode(nd->name, nd->path.dentry, 0);
	if (open_flag & O_CREAT) {
		error = -EISDIR;
		if (d_is_dir(nd->path.dentry))
			goto out;
		error = may_create_in_sticky(dir_mode, dir_uid,
					     d_backing_inode(nd->path.dentry));
		if (unlikely(error))
			goto out;
	}
	error = -ENOTDIR;
	if ((nd->flags & LOOKUP_DIRECTORY) && !d_can_lookup(nd->path.dentry))
		goto out;
	if (!d_is_reg(nd->path.dentry))
		will_truncate = false;

	if (will_truncate) {
		error = mnt_want_write(nd->path.mnt);
		if (error)
			goto out;
		got_write = true;
	}
finish_open_created:
	/*
	 * 检查是否有打开权限
	 *
	 * 如果是个负状态的dentry，会在这里面返回-ENOENT
	 */
	error = may_open(&nd->path, acc_mode, open_flag);
	if (error)
		goto out;
	BUG_ON(file->f_mode & FMODE_OPENED); /* once it's opened, it's opened */
	/* 
	 * 这里调用vfs_open()执行真正的文件打开操作 
	 * 其中会对nd->path增加引用计数
	 */
	error = vfs_open(&nd->path, file);
	if (error)
		goto out;
opened:
	error = ima_file_check(file, op->acc_mode);
	if (!error && will_truncate)
		error = handle_truncate(file);
out:
	if (unlikely(error > 0)) {
		WARN_ON(1);
		error = -EINVAL;
	}
	if (got_write)
		mnt_drop_write(nd->path.mnt);
	return error;
}

struct dentry *vfs_tmpfile(struct dentry *dentry, umode_t mode, int open_flag)
{
	struct dentry *child = NULL;
	struct inode *dir = dentry->d_inode;
	struct inode *inode;
	int error;

	/* we want directory to be writable */
	error = inode_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		goto out_err;
	error = -EOPNOTSUPP;
	if (!dir->i_op->tmpfile)
		goto out_err;
	error = -ENOMEM;
	child = d_alloc(dentry, &slash_name);
	if (unlikely(!child))
		goto out_err;
	error = dir->i_op->tmpfile(dir, child, mode);
	if (error)
		goto out_err;
	error = -ENOENT;
	inode = child->d_inode;
	if (unlikely(!inode))
		goto out_err;
	if (!(open_flag & O_EXCL)) {
		spin_lock(&inode->i_lock);
		inode->i_state |= I_LINKABLE;
		spin_unlock(&inode->i_lock);
	}
	ima_post_create_tmpfile(inode);
	return child;

out_err:
	dput(child);
	return ERR_PTR(error);
}
EXPORT_SYMBOL(vfs_tmpfile);

static int do_tmpfile(struct nameidata *nd, unsigned flags,
		const struct open_flags *op,
		struct file *file)
{
	struct dentry *child;
	struct path path;
	int error = path_lookupat(nd, flags | LOOKUP_DIRECTORY, &path);
	if (unlikely(error))
		return error;
	error = mnt_want_write(path.mnt);
	if (unlikely(error))
		goto out;
	child = vfs_tmpfile(path.dentry, op->mode, op->open_flag);
	error = PTR_ERR(child);
	if (IS_ERR(child))
		goto out2;
	dput(path.dentry);
	path.dentry = child;
	audit_inode(nd->name, child, 0);
	/* Don't check for other permissions, the inode was just created */
	error = may_open(&path, 0, op->open_flag);
	if (error)
		goto out2;
	file->f_path.mnt = path.mnt;
	error = finish_open(file, child, NULL);
out2:
	mnt_drop_write(path.mnt);
out:
	path_put(&path);
	return error;
}

static int do_o_path(struct nameidata *nd, unsigned flags, struct file *file)
{
	struct path path;
	int error = path_lookupat(nd, flags, &path);
	if (!error) {
		audit_inode(nd->name, path.dentry, 0);
		error = vfs_open(&path, file);
		path_put(&path);
	}
	return error;
}

/*
 * 本函数要和path_lookupat()对比着看，path的引用计数部分很微妙
 * 注视要一起看！
 */
static struct file *path_openat(struct nameidata *nd,
			const struct open_flags *op, unsigned flags)
{
	/*
	 * 入参中的flags为open_flags中的lookup_flags，而不是open_flag
	 */
	struct file *file;
	int error;

	/* 获取一个未使用的struct file结构体 */
	file = alloc_empty_file(op->open_flag, current_cred());
	if (IS_ERR(file))
		return file;

	if (unlikely(file->f_flags & __O_TMPFILE)) {
		error = do_tmpfile(nd, flags, op, file);
	} else if (unlikely(file->f_flags & O_PATH)) {
		error = do_o_path(nd, flags, file);
	} else {
		/*
 		 * 对struct nameidata中的各个域进行设置，包括：
 		 *  - path
 		 *  - root
 		 *  - inode
 		 *  - seq, m_seq, root_seq
 		 *  - etc.
		 *
		 *  此处的flags为open_flags中的lookup_flag
 		 */ 
		const char *s = path_init(nd, flags);
		/*
 		 * 根据短路原理，link_path_walk()返回0才会执行do_last()。其中，
 		 * link_path_walk()负责解析路径分量，do_last()用来解析最后一个
 		 * 分量并执行打开文件的操作。
 		 *
 		 * 不过既然link_path_walk()会循环解析多个路径分量，那么这里为
 		 * 什么还需要循环解析呢？
 		 *  - do_last()有可能返回1，表示需要跟随符号连接。此时需要再次
		 *    进入while循环，继续处理相关路径
 		 */ 
		while (!(error = link_path_walk(s, nd)) &&
			/*
			 * path_lookupat()中这里调用的是lookup_last()
			 * 
			 * ++++++++++++ 关于do_last和lookup_last ++++++++++++++
			 *
			 * 在do_last中，调用了lookup_last和complete_walk，
			 * 所以本函数在调用terminate_walk之前，是没有调用
			 * complete_walk的。
			 *
			 * 总结：
			 *   do_last - vfs_open = lookup_last + complete_walk
			 *
			 * ++++++++++++++++++ 关于引用计数 ++++++++++++++++++++
			 *
			 * 在do_last中，没有nd={NULL, NULL}的操作，所以下面的
			 * terminate_walk操作确实会减少nd->path的引用计数。但是
			 * 在do_last中，调用了vfs_open，在其中又增加了一次nd的
			 * 引用计数。
			 *
			 * 总结来说，就是do_last中增加了两次引用计数，
			 * terminiate_walk中减少了一次引用计数，所以返回时dentry
			 * 是有一个引用计数增量的
			 *
			 * 对比path_lookupat，因为lookup_last + complete_walk中
			 * 没有vfs_open，所以在lookup_last + complete_walk中仅
			 * 仅增加了一次引用计数，但它在调用terminate_walk前执行
			 * 了nd={NULL, NULL}的移动语义，所以terminiate_walk中没
			 * 有减掉dentry的引用计数。所以还是有一个引用计数的增量
			 */
			(error = do_last(nd, file, op)) > 0) {
			nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
			s = trailing_symlink(nd);
		}

		/*
		 * path_lookupat中在terminate_walk之前有一个complete_walk和
		 * nd={NULL, NULL}的过程
		 */
		terminate_walk(nd);
	}
	if (likely(!error)) {
		if (likely(file->f_mode & FMODE_OPENED))
			return file;
		WARN_ON(1);
		error = -EINVAL;
	}
	fput(file);
	if (error == -EOPENSTALE) {
		if (flags & LOOKUP_RCU)
			error = -ECHILD;
		else
			error = -ESTALE;
	}
	return ERR_PTR(error);
}

struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op)
{
	/*
	 * 参数dfd表示起始目录
	 */
	struct nameidata nd;
	int flags = op->lookup_flags;
	struct file *filp;

	/*
	 * 设置name、dfd、stack等字段
	 */
	set_nameidata(&nd, dfd, pathname);

	/* 
 	 * 第一次使用rcu-walk方式搜索dentry cache。在散列表中根据{父目录，
 	 * 名称}查找目录的过程中，使用RCU保护散列桶的链表，使用序列号保护
 	 * 目录，其他处理器可以并行地修改目录。RCU查找方式速度最快。
 	 */
	filp = path_openat(&nd, op, flags | LOOKUP_RCU);
	/* 
 	 * 第二次使用ref-walk方式搜索dentry cache。在散列表中根据{父目录，
 	 * 名称}查找目录的过程中，使用RCU保护散列桶的链表，使用自旋锁保护
 	 * 目录，并且把目录的引用计数加1。引用查找方式速度比较慢。
 	 */
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = path_openat(&nd, op, flags);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		/* 第三次不使用dentry cache */
		filp = path_openat(&nd, op, flags | LOOKUP_REVAL);

	/*
	 * 恢复stack等
	 */
	restore_nameidata();
	return filp;
}

struct file *do_file_open_root(struct dentry *dentry, struct vfsmount *mnt,
		const char *name, const struct open_flags *op)
{
	struct nameidata nd;
	struct file *file;
	struct filename *filename;
	int flags = op->lookup_flags | LOOKUP_ROOT;

	nd.root.mnt = mnt;
	nd.root.dentry = dentry;

	if (d_is_symlink(dentry) && op->intent & LOOKUP_OPEN)
		return ERR_PTR(-ELOOP);

	filename = getname_kernel(name);
	if (IS_ERR(filename))
		return ERR_CAST(filename);

	set_nameidata(&nd, -1, filename);
	file = path_openat(&nd, op, flags | LOOKUP_RCU);
	if (unlikely(file == ERR_PTR(-ECHILD)))
		file = path_openat(&nd, op, flags);
	if (unlikely(file == ERR_PTR(-ESTALE)))
		file = path_openat(&nd, op, flags | LOOKUP_REVAL);
	restore_nameidata();
	putname(filename);
	return file;
}

static struct dentry *filename_create(int dfd, struct filename *name,
				struct path *path, unsigned int lookup_flags)
{
	struct dentry *dentry = ERR_PTR(-EEXIST);
	struct qstr last;
	int type;
	int err2;
	int error;
	bool is_dir = (lookup_flags & LOOKUP_DIRECTORY);

	/*
	 * Note that only LOOKUP_REVAL and LOOKUP_DIRECTORY matter here. Any
	 * other flags passed in are ignored!
	 */
	lookup_flags &= LOOKUP_REVAL;

	name = filename_parentat(dfd, name, lookup_flags, path, &last, &type);
	if (IS_ERR(name))
		return ERR_CAST(name);

	/*
	 * Yucky last component or no last component at all?
	 * (foo/., foo/.., /////)
	 */
	if (unlikely(type != LAST_NORM))
		goto out;

	/* don't fail immediately if it's r/o, at least try to report other errors */
	err2 = mnt_want_write(path->mnt);
	/*
	 * Do the final lookup.
	 */
	lookup_flags |= LOOKUP_CREATE | LOOKUP_EXCL;
	inode_lock_nested(path->dentry->d_inode, I_MUTEX_PARENT);
	dentry = __lookup_hash(&last, path->dentry, lookup_flags);
	if (IS_ERR(dentry))
		goto unlock;

	error = -EEXIST;
	if (d_is_positive(dentry))
		goto fail;

	/*
	 * Special case - lookup gave negative, but... we had foo/bar/
	 * From the vfs_mknod() POV we just have a negative dentry -
	 * all is fine. Let's be bastards - you had / on the end, you've
	 * been asking for (non-existent) directory. -ENOENT for you.
	 */
	if (unlikely(!is_dir && last.name[last.len])) {
		error = -ENOENT;
		goto fail;
	}
	if (unlikely(err2)) {
		error = err2;
		goto fail;
	}
	putname(name);
	return dentry;
fail:
	dput(dentry);
	dentry = ERR_PTR(error);
unlock:
	inode_unlock(path->dentry->d_inode);
	if (!err2)
		mnt_drop_write(path->mnt);
out:
	path_put(path);
	putname(name);
	return dentry;
}

struct dentry *kern_path_create(int dfd, const char *pathname,
				struct path *path, unsigned int lookup_flags)
{
	return filename_create(dfd, getname_kernel(pathname),
				path, lookup_flags);
}
EXPORT_SYMBOL(kern_path_create);

void done_path_create(struct path *path, struct dentry *dentry)
{
	dput(dentry);
	inode_unlock(path->dentry->d_inode);
	mnt_drop_write(path->mnt);
	path_put(path);
}
EXPORT_SYMBOL(done_path_create);

inline struct dentry *user_path_create(int dfd, const char __user *pathname,
				struct path *path, unsigned int lookup_flags)
{
	return filename_create(dfd, getname(pathname), path, lookup_flags);
}
EXPORT_SYMBOL(user_path_create);

int vfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int error = may_create(dir, dentry);

	if (error)
		return error;

	if ((S_ISCHR(mode) || S_ISBLK(mode)) && !capable(CAP_MKNOD))
		return -EPERM;

	if (!dir->i_op->mknod)
		return -EPERM;

	error = devcgroup_inode_mknod(mode, dev);
	if (error)
		return error;

	error = security_inode_mknod(dir, dentry, mode, dev);
	if (error)
		return error;

	error = dir->i_op->mknod(dir, dentry, mode, dev);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}
EXPORT_SYMBOL(vfs_mknod);

static int may_mknod(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
	case 0: /* zero mode translates to S_IFREG */
		return 0;
	case S_IFDIR:
		return -EPERM;
	default:
		return -EINVAL;
	}
}

long do_mknodat(int dfd, const char __user *filename, umode_t mode,
		unsigned int dev)
{
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags = 0;

	error = may_mknod(mode);
	if (error)
		return error;
retry:
	dentry = user_path_create(dfd, filename, &path, lookup_flags);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();
	error = security_path_mknod(&path, dentry, mode, dev);
	if (error)
		goto out;
	switch (mode & S_IFMT) {
		case 0: case S_IFREG:
			error = vfs_create(path.dentry->d_inode,dentry,mode,true);
			if (!error)
				ima_post_path_mknod(dentry);
			break;
		case S_IFCHR: case S_IFBLK:
			error = vfs_mknod(path.dentry->d_inode,dentry,mode,
					new_decode_dev(dev));
			break;
		case S_IFIFO: case S_IFSOCK:
			error = vfs_mknod(path.dentry->d_inode,dentry,mode,0);
			break;
	}
out:
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE4(mknodat, int, dfd, const char __user *, filename, umode_t, mode,
		unsigned int, dev)
{
	return do_mknodat(dfd, filename, mode, dev);
}

SYSCALL_DEFINE3(mknod, const char __user *, filename, umode_t, mode, unsigned, dev)
{
	return do_mknodat(AT_FDCWD, filename, mode, dev);
}

int vfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int error = may_create(dir, dentry);
	unsigned max_links = dir->i_sb->s_max_links;

	if (error)
		return error;

	if (!dir->i_op->mkdir)
		return -EPERM;

	mode &= (S_IRWXUGO|S_ISVTX);
	error = security_inode_mkdir(dir, dentry, mode);
	if (error)
		return error;

	if (max_links && dir->i_nlink >= max_links)
		return -EMLINK;

	error = dir->i_op->mkdir(dir, dentry, mode);
	if (!error)
		fsnotify_mkdir(dir, dentry);
	return error;
}
EXPORT_SYMBOL(vfs_mkdir);

long do_mkdirat(int dfd, const char __user *pathname, umode_t mode)
{
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_DIRECTORY;

retry:
	dentry = user_path_create(dfd, pathname, &path, lookup_flags);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();
	error = security_path_mkdir(&path, dentry, mode);
	if (!error)
		error = vfs_mkdir(path.dentry->d_inode, dentry, mode);
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE3(mkdirat, int, dfd, const char __user *, pathname, umode_t, mode)
{
	return do_mkdirat(dfd, pathname, mode);
}

SYSCALL_DEFINE2(mkdir, const char __user *, pathname, umode_t, mode)
{
	return do_mkdirat(AT_FDCWD, pathname, mode);
}

int vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int error = may_delete(dir, dentry, 1);

	if (error)
		return error;

	if (!dir->i_op->rmdir)
		return -EPERM;

	dget(dentry);
	inode_lock(dentry->d_inode);

	error = -EBUSY;
	if (is_local_mountpoint(dentry))
		goto out;

	error = security_inode_rmdir(dir, dentry);
	if (error)
		goto out;

	error = dir->i_op->rmdir(dir, dentry);
	if (error)
		goto out;

	shrink_dcache_parent(dentry);
	dentry->d_inode->i_flags |= S_DEAD;
	dont_mount(dentry);
	detach_mounts(dentry);
	fsnotify_rmdir(dir, dentry);

out:
	inode_unlock(dentry->d_inode);
	dput(dentry);
	if (!error)
		d_delete(dentry);
	return error;
}
EXPORT_SYMBOL(vfs_rmdir);

long do_rmdir(int dfd, const char __user *pathname)
{
	int error = 0;
	struct filename *name;
	struct dentry *dentry;
	struct path path;
	struct qstr last;
	int type;
	unsigned int lookup_flags = 0;
retry:
	name = filename_parentat(dfd, getname(pathname), lookup_flags,
				&path, &last, &type);
	if (IS_ERR(name))
		return PTR_ERR(name);

	switch (type) {
	case LAST_DOTDOT:
		error = -ENOTEMPTY;
		goto exit1;
	case LAST_DOT:
		error = -EINVAL;
		goto exit1;
	case LAST_ROOT:
		error = -EBUSY;
		goto exit1;
	}

	error = mnt_want_write(path.mnt);
	if (error)
		goto exit1;

	inode_lock_nested(path.dentry->d_inode, I_MUTEX_PARENT);
	dentry = __lookup_hash(&last, path.dentry, lookup_flags);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto exit2;
	if (!dentry->d_inode) {
		error = -ENOENT;
		goto exit3;
	}
	error = security_path_rmdir(&path, dentry);
	if (error)
		goto exit3;
	error = vfs_rmdir(path.dentry->d_inode, dentry);
exit3:
	dput(dentry);
exit2:
	inode_unlock(path.dentry->d_inode);
	mnt_drop_write(path.mnt);
exit1:
	path_put(&path);
	putname(name);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE1(rmdir, const char __user *, pathname)
{
	return do_rmdir(AT_FDCWD, pathname);
}

/**
 * vfs_unlink - unlink a filesystem object
 * @dir:	parent directory
 * @dentry:	victim
 * @delegated_inode: returns victim inode, if the inode is delegated.
 *
 * The caller must hold dir->i_mutex.
 *
 * If vfs_unlink discovers a delegation, it will return -EWOULDBLOCK and
 * return a reference to the inode in delegated_inode.  The caller
 * should then break the delegation on that inode and retry.  Because
 * breaking a delegation may take a long time, the caller should drop
 * dir->i_mutex before doing so.
 *
 * Alternatively, a caller may pass NULL for delegated_inode.  This may
 * be appropriate for callers that expect the underlying filesystem not
 * to be NFS exported.
 */
int vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
{
	struct inode *target = dentry->d_inode;
	int error = may_delete(dir, dentry, 0);

	if (error)
		return error;

	if (!dir->i_op->unlink)
		return -EPERM;

	/*
	 * 锁定待删除的inode
	 */
	inode_lock(target);
	if (is_local_mountpoint(dentry))
		error = -EBUSY;
	else {
		error = security_inode_unlink(dir, dentry);
		if (!error) {
			error = try_break_deleg(target, delegated_inode);
			if (error)
				goto out;
			/*
			 * xfs: xfs_vn_unlink()
			 */
			error = dir->i_op->unlink(dir, dentry);
			if (!error) {
				dont_mount(dentry);
				detach_mounts(dentry);
				fsnotify_unlink(dir, dentry);
			}
		}
	}
out:
	/*
	 * 解锁待删除的inode
	 */
	inode_unlock(target);

	/* We don't d_delete() NFS sillyrenamed files--they still exist. */
	if (!error && !(dentry->d_flags & DCACHE_NFSFS_RENAMED)) {
		fsnotify_link_count(target);
		/*
		 * 减少dentry对inode的引用计数
		 * - 只是根据lockref判断要不要操作inode，但并未真正减小dentry自己的引用计数；
		 */
		d_delete(dentry);
	}

	return error;
}
EXPORT_SYMBOL(vfs_unlink);

/*
 * Make sure that the actual truncation of the file will occur outside its
 * directory's i_mutex.  Truncate can take a long time if there is a lot of
 * writeout happening, and we don't want to prevent access to the directory
 * while waiting on the I/O.
 */
long do_unlinkat(int dfd, struct filename *name)
{
	int error;
	struct dentry *dentry;
	struct path path;
	struct qstr last;
	int type;
	struct inode *inode = NULL;
	struct inode *delegated_inode = NULL;
	unsigned int lookup_flags = 0;
retry:
	/*
	 * 返回要删除文件的父目录的name
	 *
	 * path中保存已经解析完成的文件路径，在这里就是待删除文件的父目录
	 * last中保存未解析的文件路径，在这里就是要删除的文件
	 */
	name = filename_parentat(dfd, name, lookup_flags, &path, &last, &type);
	if (IS_ERR(name))
		return PTR_ERR(name);

	error = -EISDIR;
	if (type != LAST_NORM)
		goto exit1;

	error = mnt_want_write(path.mnt);
	if (error)
		goto exit1;
retry_deleg:
	inode_lock_nested(path.dentry->d_inode, I_MUTEX_PARENT);
	/*
	 * 查找待删除文件的dentry，返回时引用计数已经加一
	 */
	dentry = __lookup_hash(&last, path.dentry, lookup_flags);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		/* Why not before? Because we want correct error value */
		if (last.name[last.len])
			goto slashes;
		/*
		 * 待删除文件的inode
		 * - 这里的dentry需要锁互斥访问吗？
		 */
		inode = dentry->d_inode;
		if (d_is_negative(dentry))
			goto slashes;
		/*
		 * 待删除文件inode引用计数加一，将该inode保持在内存中；
		 */
		ihold(inode);
		error = security_path_unlink(&path, dentry);
		if (error)
			goto exit2;
		/*
		 * unlink，在文件系统中减少inode对应的nlink计数，表示删除此文件；
		 */
		error = vfs_unlink(path.dentry->d_inode, dentry, &delegated_inode);
exit2:
		/*
		 * 减少待删除文件的dentry引用计数
		 * - 进入里面后不考虑释放关联的inode，因为上面的ihold()保
		 *   证inode的引用计数肯定不为0；
		 * - 在后面的iput()中对inode做操作；
		 *
		 * 这次引用计数的减小对应的是上面__lookup_hash()中增加的引用计数；
		 */
		dput(dentry);
	}
	inode_unlock(path.dentry->d_inode);
	/*
	 * 释放内存中的inode，在里面会进行文件系统上数据的清理工作；
	 */
	if (inode)
		iput(inode);	/* truncate the inode here */
	inode = NULL;
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	mnt_drop_write(path.mnt);
exit1:
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		inode = NULL;
		goto retry;
	}
	putname(name);
	return error;

slashes:
	if (d_is_negative(dentry))
		error = -ENOENT;
	else if (d_is_dir(dentry))
		error = -EISDIR;
	else
		error = -ENOTDIR;
	goto exit2;
}

/*
 * 这个系统调用可以删除目录，也可以删除文件；
 */
SYSCALL_DEFINE3(unlinkat, int, dfd, const char __user *, pathname, int, flag)
{
	if ((flag & ~AT_REMOVEDIR) != 0)
		return -EINVAL;

	if (flag & AT_REMOVEDIR)
		return do_rmdir(dfd, pathname);

	return do_unlinkat(dfd, getname(pathname));
}

/*
 * 这个系统调用只能用于删除普通文件，不能删除目录；
 */
SYSCALL_DEFINE1(unlink, const char __user *, pathname)
{
	return do_unlinkat(AT_FDCWD, getname(pathname));
}

int vfs_symlink(struct inode *dir, struct dentry *dentry, const char *oldname)
{
	int error = may_create(dir, dentry);

	if (error)
		return error;

	if (!dir->i_op->symlink)
		return -EPERM;

	error = security_inode_symlink(dir, dentry, oldname);
	if (error)
		return error;

	error = dir->i_op->symlink(dir, dentry, oldname);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}
EXPORT_SYMBOL(vfs_symlink);

long do_symlinkat(const char __user *oldname, int newdfd,
		  const char __user *newname)
{
	int error;
	struct filename *from;
	struct dentry *dentry;
	struct path path;
	unsigned int lookup_flags = 0;

	from = getname(oldname);
	if (IS_ERR(from))
		return PTR_ERR(from);
retry:
	dentry = user_path_create(newdfd, newname, &path, lookup_flags);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto out_putname;

	error = security_path_symlink(&path, dentry, from->name);
	if (!error)
		error = vfs_symlink(path.dentry->d_inode, dentry, from->name);
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out_putname:
	putname(from);
	return error;
}

SYSCALL_DEFINE3(symlinkat, const char __user *, oldname,
		int, newdfd, const char __user *, newname)
{
	return do_symlinkat(oldname, newdfd, newname);
}

SYSCALL_DEFINE2(symlink, const char __user *, oldname, const char __user *, newname)
{
	return do_symlinkat(oldname, AT_FDCWD, newname);
}

/**
 * vfs_link - create a new link
 * @old_dentry:	object to be linked
 * @dir:	new parent
 * @new_dentry:	where to create the new link
 * @delegated_inode: returns inode needing a delegation break
 *
 * The caller must hold dir->i_mutex
 *
 * If vfs_link discovers a delegation on the to-be-linked file in need
 * of breaking, it will return -EWOULDBLOCK and return a reference to the
 * inode in delegated_inode.  The caller should then break the delegation
 * and retry.  Because breaking a delegation may take a long time, the
 * caller should drop the i_mutex before doing so.
 *
 * Alternatively, a caller may pass NULL for delegated_inode.  This may
 * be appropriate for callers that expect the underlying filesystem not
 * to be NFS exported.
 */
int vfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry, struct inode **delegated_inode)
{
	struct inode *inode = old_dentry->d_inode;
	unsigned max_links = dir->i_sb->s_max_links;
	int error;

	if (!inode)
		return -ENOENT;

	error = may_create(dir, new_dentry);
	if (error)
		return error;

	if (dir->i_sb != inode->i_sb)
		return -EXDEV;

	/*
	 * A link to an append-only or immutable file cannot be created.
	 */
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;
	/*
	 * Updating the link count will likely cause i_uid and i_gid to
	 * be writen back improperly if their true value is unknown to
	 * the vfs.
	 */
	if (HAS_UNMAPPED_ID(inode))
		return -EPERM;
	if (!dir->i_op->link)
		return -EPERM;
	if (S_ISDIR(inode->i_mode))
		return -EPERM;

	error = security_inode_link(old_dentry, dir, new_dentry);
	if (error)
		return error;

	inode_lock(inode);
	/* Make sure we don't allow creating hardlink to an unlinked file */
	if (inode->i_nlink == 0 && !(inode->i_state & I_LINKABLE))
		error =  -ENOENT;
	else if (max_links && inode->i_nlink >= max_links)
		error = -EMLINK;
	else {
		error = try_break_deleg(inode, delegated_inode);
		if (!error)
			error = dir->i_op->link(old_dentry, dir, new_dentry);
	}

	if (!error && (inode->i_state & I_LINKABLE)) {
		spin_lock(&inode->i_lock);
		inode->i_state &= ~I_LINKABLE;
		spin_unlock(&inode->i_lock);
	}
	inode_unlock(inode);
	if (!error)
		fsnotify_link(dir, inode, new_dentry);
	return error;
}
EXPORT_SYMBOL(vfs_link);

/*
 * Hardlinks are often used in delicate situations.  We avoid
 * security-related surprises by not following symlinks on the
 * newname.  --KAB
 *
 * We don't follow them on the oldname either to be compatible
 * with linux 2.0, and to avoid hard-linking to directories
 * and other special files.  --ADM
 */
int do_linkat(int olddfd, const char __user *oldname, int newdfd,
	      const char __user *newname, int flags)
{
	struct dentry *new_dentry;
	struct path old_path, new_path;
	struct inode *delegated_inode = NULL;
	int how = 0;
	int error;

	if ((flags & ~(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH)) != 0)
		return -EINVAL;
	/*
	 * To use null names we require CAP_DAC_READ_SEARCH
	 * This ensures that not everyone will be able to create
	 * handlink using the passed filedescriptor.
	 */
	if (flags & AT_EMPTY_PATH) {
		if (!capable(CAP_DAC_READ_SEARCH))
			return -ENOENT;
		how = LOOKUP_EMPTY;
	}

	if (flags & AT_SYMLINK_FOLLOW)
		how |= LOOKUP_FOLLOW;
retry:
	error = user_path_at(olddfd, oldname, how, &old_path);
	if (error)
		return error;

	new_dentry = user_path_create(newdfd, newname, &new_path,
					(how & LOOKUP_REVAL));
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto out;

	error = -EXDEV;
	if (old_path.mnt != new_path.mnt)
		goto out_dput;
	error = may_linkat(&old_path);
	if (unlikely(error))
		goto out_dput;
	error = security_path_link(old_path.dentry, &new_path, new_dentry);
	if (error)
		goto out_dput;
	error = vfs_link(old_path.dentry, new_path.dentry->d_inode, new_dentry, &delegated_inode);
out_dput:
	done_path_create(&new_path, new_dentry);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error) {
			path_put(&old_path);
			goto retry;
		}
	}
	if (retry_estale(error, how)) {
		path_put(&old_path);
		how |= LOOKUP_REVAL;
		goto retry;
	}
out:
	path_put(&old_path);

	return error;
}

SYSCALL_DEFINE5(linkat, int, olddfd, const char __user *, oldname,
		int, newdfd, const char __user *, newname, int, flags)
{
	return do_linkat(olddfd, oldname, newdfd, newname, flags);
}

SYSCALL_DEFINE2(link, const char __user *, oldname, const char __user *, newname)
{
	return do_linkat(AT_FDCWD, oldname, AT_FDCWD, newname, 0);
}

/**
 * vfs_rename - rename a filesystem object
 * @old_dir:	parent of source
 * @old_dentry:	source
 * @new_dir:	parent of destination
 * @new_dentry:	destination
 * @delegated_inode: returns an inode needing a delegation break
 * @flags:	rename flags
 *
 * The caller must hold multiple mutexes--see lock_rename()).
 *
 * If vfs_rename discovers a delegation in need of breaking at either
 * the source or destination, it will return -EWOULDBLOCK and return a
 * reference to the inode in delegated_inode.  The caller should then
 * break the delegation and retry.  Because breaking a delegation may
 * take a long time, the caller should drop all locks before doing
 * so.
 *
 * Alternatively, a caller may pass NULL for delegated_inode.  This may
 * be appropriate for callers that expect the underlying filesystem not
 * to be NFS exported.
 *
 * The worst of all namespace operations - renaming directory. "Perverted"
 * doesn't even start to describe it. Somebody in UCB had a heck of a trip...
 * Problems:
 *
 *	a) we can get into loop creation.
 *	b) race potential - two innocent renames can create a loop together.
 *	   That's where 4.4 screws up. Current fix: serialization on
 *	   sb->s_vfs_rename_mutex. We might be more accurate, but that's another
 *	   story.
 *	c) we have to lock _four_ objects - parents and victim (if it exists),
 *	   and source (if it is not a directory).
 *	   And that - after we got ->i_mutex on parents (until then we don't know
 *	   whether the target exists).  Solution: try to be smart with locking
 *	   order for inodes.  We rely on the fact that tree topology may change
 *	   only under ->s_vfs_rename_mutex _and_ that parent of the object we
 *	   move will be locked.  Thus we can rank directories by the tree
 *	   (ancestors first) and rank all non-directories after them.
 *	   That works since everybody except rename does "lock parent, lookup,
 *	   lock child" and rename is under ->s_vfs_rename_mutex.
 *	   HOWEVER, it relies on the assumption that any object with ->lookup()
 *	   has no more than 1 dentry.  If "hybrid" objects will ever appear,
 *	   we'd better make sure that there's no link(2) for them.
 *	d) conversion from fhandle to dentry may come in the wrong moment - when
 *	   we are removing the target. Solution: we will have to grab ->i_mutex
 *	   in the fhandle_to_dentry code. [FIXME - current nfsfh.c relies on
 *	   ->i_mutex on parents, which works but leads to some truly excessive
 *	   locking].
 */
int vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry,
	       struct inode **delegated_inode, unsigned int flags)
{
	int error;
	bool is_dir = d_is_dir(old_dentry);
	struct inode *source = old_dentry->d_inode;
	struct inode *target = new_dentry->d_inode;
	bool new_is_dir = false;
	unsigned max_links = new_dir->i_sb->s_max_links;
	struct name_snapshot old_name;

	if (source == target)
		return 0;

	error = may_delete(old_dir, old_dentry, is_dir);
	if (error)
		return error;

	if (!target) {
		error = may_create(new_dir, new_dentry);
	} else {
		new_is_dir = d_is_dir(new_dentry);

		if (!(flags & RENAME_EXCHANGE))
			error = may_delete(new_dir, new_dentry, is_dir);
		else
			error = may_delete(new_dir, new_dentry, new_is_dir);
	}
	if (error)
		return error;

	if (!old_dir->i_op->rename)
		return -EPERM;

	/*
	 * If we are going to change the parent - check write permissions,
	 * we'll need to flip '..'.
	 */
	if (new_dir != old_dir) {
		if (is_dir) {
			error = inode_permission(source, MAY_WRITE);
			if (error)
				return error;
		}
		if ((flags & RENAME_EXCHANGE) && new_is_dir) {
			error = inode_permission(target, MAY_WRITE);
			if (error)
				return error;
		}
	}

	error = security_inode_rename(old_dir, old_dentry, new_dir, new_dentry,
				      flags);
	if (error)
		return error;

	take_dentry_name_snapshot(&old_name, old_dentry);
	dget(new_dentry);
	if (!is_dir || (flags & RENAME_EXCHANGE))
		lock_two_nondirectories(source, target);
	else if (target)
		inode_lock(target);

	error = -EBUSY;
	if (is_local_mountpoint(old_dentry) || is_local_mountpoint(new_dentry))
		goto out;

	if (max_links && new_dir != old_dir) {
		error = -EMLINK;
		if (is_dir && !new_is_dir && new_dir->i_nlink >= max_links)
			goto out;
		if ((flags & RENAME_EXCHANGE) && !is_dir && new_is_dir &&
		    old_dir->i_nlink >= max_links)
			goto out;
	}
	if (!is_dir) {
		error = try_break_deleg(source, delegated_inode);
		if (error)
			goto out;
	}
	if (target && !new_is_dir) {
		error = try_break_deleg(target, delegated_inode);
		if (error)
			goto out;
	}
	error = old_dir->i_op->rename(old_dir, old_dentry,
				       new_dir, new_dentry, flags);
	if (error)
		goto out;

	if (!(flags & RENAME_EXCHANGE) && target) {
		if (is_dir) {
			shrink_dcache_parent(new_dentry);
			target->i_flags |= S_DEAD;
		}
		dont_mount(new_dentry);
		detach_mounts(new_dentry);
	}
	if (!(old_dir->i_sb->s_type->fs_flags & FS_RENAME_DOES_D_MOVE)) {
		if (!(flags & RENAME_EXCHANGE))
			d_move(old_dentry, new_dentry);
		else
			d_exchange(old_dentry, new_dentry);
	}
out:
	if (!is_dir || (flags & RENAME_EXCHANGE))
		unlock_two_nondirectories(source, target);
	else if (target)
		inode_unlock(target);
	dput(new_dentry);
	if (!error) {
		fsnotify_move(old_dir, new_dir, &old_name.name, is_dir,
			      !(flags & RENAME_EXCHANGE) ? target : NULL, old_dentry);
		if (flags & RENAME_EXCHANGE) {
			fsnotify_move(new_dir, old_dir, &old_dentry->d_name,
				      new_is_dir, NULL, new_dentry);
		}
	}
	release_dentry_name_snapshot(&old_name);

	return error;
}
EXPORT_SYMBOL(vfs_rename);

static int do_renameat2(int olddfd, const char __user *oldname, int newdfd,
			const char __user *newname, unsigned int flags)
{
	struct dentry *old_dentry, *new_dentry;
	struct dentry *trap;
	struct path old_path, new_path;
	struct qstr old_last, new_last;
	int old_type, new_type;
	struct inode *delegated_inode = NULL;
	struct filename *from;
	struct filename *to;
	unsigned int lookup_flags = 0, target_flags = LOOKUP_RENAME_TARGET;
	bool should_retry = false;
	int error;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EINVAL;

	if ((flags & (RENAME_NOREPLACE | RENAME_WHITEOUT)) &&
	    (flags & RENAME_EXCHANGE))
		return -EINVAL;

	if ((flags & RENAME_WHITEOUT) && !capable(CAP_MKNOD))
		return -EPERM;

	if (flags & RENAME_EXCHANGE)
		target_flags = 0;

retry:
	/*
	 * 获取源地址和目的地址的父目录的dentry
	 *                       ^^^^^^
	 */
	from = filename_parentat(olddfd, getname(oldname), lookup_flags,
				&old_path, &old_last, &old_type);
	if (IS_ERR(from)) {
		error = PTR_ERR(from);
		goto exit;
	}

	to = filename_parentat(newdfd, getname(newname), lookup_flags,
				&new_path, &new_last, &new_type);
	if (IS_ERR(to)) {
		error = PTR_ERR(to);
		goto exit1;
	}

	error = -EXDEV;
	if (old_path.mnt != new_path.mnt)
		goto exit2;

	error = -EBUSY;
	if (old_type != LAST_NORM)
		goto exit2;

	if (flags & RENAME_NOREPLACE)
		error = -EEXIST;
	if (new_type != LAST_NORM)
		goto exit2;

	error = mnt_want_write(old_path.mnt);
	if (error)
		goto exit2;

retry_deleg:
	/*
	 * 首先会锁住文件系统的rename锁
	 * 然后会分别锁住两个父目录的inode节点，但这里的锁好没见过，要好好看看
	 *
	 * 其实就是对父目录inode->i_rwsem的写者做了P操作
	 */
	trap = lock_rename(new_path.dentry, old_path.dentry);

	/*
	 * 找到要被rename文件的dentry
	 */
	old_dentry = __lookup_hash(&old_last, old_path.dentry, lookup_flags);
	error = PTR_ERR(old_dentry);
	if (IS_ERR(old_dentry))
		goto exit3;
	/* source must exist */
	error = -ENOENT;
	if (d_is_negative(old_dentry))
		goto exit4;

	/*
	 * 找到或分配目标文件的dentry
	 */
	new_dentry = __lookup_hash(&new_last, new_path.dentry, lookup_flags | target_flags);
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto exit4;
	error = -EEXIST;
	if ((flags & RENAME_NOREPLACE) && d_is_positive(new_dentry))
		goto exit5;
	if (flags & RENAME_EXCHANGE) {
		error = -ENOENT;
		if (d_is_negative(new_dentry))
			goto exit5;

		if (!d_is_dir(new_dentry)) {
			error = -ENOTDIR;
			if (new_last.name[new_last.len])
				goto exit5;
		}
	}
	/* unless the source is a directory trailing slashes give -ENOTDIR */
	if (!d_is_dir(old_dentry)) {
		error = -ENOTDIR;
		if (old_last.name[old_last.len])
			goto exit5;
		if (!(flags & RENAME_EXCHANGE) && new_last.name[new_last.len])
			goto exit5;
	}
	/* source should not be ancestor of target */
	error = -EINVAL;
	if (old_dentry == trap)
		goto exit5;
	/* target should not be an ancestor of source */
	if (!(flags & RENAME_EXCHANGE))
		error = -ENOTEMPTY;
	if (new_dentry == trap)
		goto exit5;

	error = security_path_rename(&old_path, old_dentry,
				     &new_path, new_dentry, flags);
	if (error)
		goto exit5;
	error = vfs_rename(old_path.dentry->d_inode, old_dentry,
			   new_path.dentry->d_inode, new_dentry,
			   &delegated_inode, flags);
exit5:
	dput(new_dentry);
exit4:
	dput(old_dentry);
exit3:
	unlock_rename(new_path.dentry, old_path.dentry);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	mnt_drop_write(old_path.mnt);
exit2:
	if (retry_estale(error, lookup_flags))
		should_retry = true;
	path_put(&new_path);
	putname(to);
exit1:
	path_put(&old_path);
	putname(from);
	if (should_retry) {
		should_retry = false;
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
exit:
	return error;
}

SYSCALL_DEFINE5(renameat2, int, olddfd, const char __user *, oldname,
		int, newdfd, const char __user *, newname, unsigned int, flags)
{
	return do_renameat2(olddfd, oldname, newdfd, newname, flags);
}

SYSCALL_DEFINE4(renameat, int, olddfd, const char __user *, oldname,
		int, newdfd, const char __user *, newname)
{
	return do_renameat2(olddfd, oldname, newdfd, newname, 0);
}

SYSCALL_DEFINE2(rename, const char __user *, oldname, const char __user *, newname)
{
	return do_renameat2(AT_FDCWD, oldname, AT_FDCWD, newname, 0);
}

int vfs_whiteout(struct inode *dir, struct dentry *dentry)
{
	int error = may_create(dir, dentry);
	if (error)
		return error;

	if (!dir->i_op->mknod)
		return -EPERM;

	return dir->i_op->mknod(dir, dentry,
				S_IFCHR | WHITEOUT_MODE, WHITEOUT_DEV);
}
EXPORT_SYMBOL(vfs_whiteout);

int readlink_copy(char __user *buffer, int buflen, const char *link)
{
	int len = PTR_ERR(link);
	if (IS_ERR(link))
		goto out;

	len = strlen(link);
	if (len > (unsigned) buflen)
		len = buflen;
	if (copy_to_user(buffer, link, len))
		len = -EFAULT;
out:
	return len;
}

/**
 * vfs_readlink - copy symlink body into userspace buffer
 * @dentry: dentry on which to get symbolic link
 * @buffer: user memory pointer
 * @buflen: size of buffer
 *
 * Does not touch atime.  That's up to the caller if necessary
 *
 * Does not call security hook.
 */
int vfs_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct inode *inode = d_inode(dentry);
	DEFINE_DELAYED_CALL(done);
	const char *link;
	int res;

	if (unlikely(!(inode->i_opflags & IOP_DEFAULT_READLINK))) {
		if (unlikely(inode->i_op->readlink))
			return inode->i_op->readlink(dentry, buffer, buflen);

		if (!d_is_symlink(dentry))
			return -EINVAL;

		spin_lock(&inode->i_lock);
		inode->i_opflags |= IOP_DEFAULT_READLINK;
		spin_unlock(&inode->i_lock);
	}

	link = READ_ONCE(inode->i_link);
	if (!link) {
		link = inode->i_op->get_link(dentry, inode, &done);
		if (IS_ERR(link))
			return PTR_ERR(link);
	}
	res = readlink_copy(buffer, buflen, link);
	do_delayed_call(&done);
	return res;
}
EXPORT_SYMBOL(vfs_readlink);

/**
 * vfs_get_link - get symlink body
 * @dentry: dentry on which to get symbolic link
 * @done: caller needs to free returned data with this
 *
 * Calls security hook and i_op->get_link() on the supplied inode.
 *
 * It does not touch atime.  That's up to the caller if necessary.
 *
 * Does not work on "special" symlinks like /proc/$$/fd/N
 */
const char *vfs_get_link(struct dentry *dentry, struct delayed_call *done)
{
	const char *res = ERR_PTR(-EINVAL);
	struct inode *inode = d_inode(dentry);

	if (d_is_symlink(dentry)) {
		res = ERR_PTR(security_inode_readlink(dentry));
		if (!res)
			res = inode->i_op->get_link(dentry, inode, done);
	}
	return res;
}
EXPORT_SYMBOL(vfs_get_link);

/* get the link contents into pagecache */
const char *page_get_link(struct dentry *dentry, struct inode *inode,
			  struct delayed_call *callback)
{
	char *kaddr;
	struct page *page;
	struct address_space *mapping = inode->i_mapping;

	if (!dentry) {
		page = find_get_page(mapping, 0);
		if (!page)
			return ERR_PTR(-ECHILD);
		if (!PageUptodate(page)) {
			put_page(page);
			return ERR_PTR(-ECHILD);
		}
	} else {
		page = read_mapping_page(mapping, 0, NULL);
		if (IS_ERR(page))
			return (char*)page;
	}
	set_delayed_call(callback, page_put_link, page);
	BUG_ON(mapping_gfp_mask(mapping) & __GFP_HIGHMEM);
	kaddr = page_address(page);
	nd_terminate_link(kaddr, inode->i_size, PAGE_SIZE - 1);
	return kaddr;
}

EXPORT_SYMBOL(page_get_link);

void page_put_link(void *arg)
{
	put_page(arg);
}
EXPORT_SYMBOL(page_put_link);

int page_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	DEFINE_DELAYED_CALL(done);
	int res = readlink_copy(buffer, buflen,
				page_get_link(dentry, d_inode(dentry),
					      &done));
	do_delayed_call(&done);
	return res;
}
EXPORT_SYMBOL(page_readlink);

/*
 * The nofs argument instructs pagecache_write_begin to pass AOP_FLAG_NOFS
 */
int __page_symlink(struct inode *inode, const char *symname, int len, int nofs)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	void *fsdata;
	int err;
	unsigned int flags = 0;
	if (nofs)
		flags |= AOP_FLAG_NOFS;

retry:
	err = pagecache_write_begin(NULL, mapping, 0, len-1,
				flags, &page, &fsdata);
	if (err)
		goto fail;

	memcpy(page_address(page), symname, len-1);

	err = pagecache_write_end(NULL, mapping, 0, len-1, len-1,
							page, fsdata);
	if (err < 0)
		goto fail;
	if (err < len-1)
		goto retry;

	mark_inode_dirty(inode);
	return 0;
fail:
	return err;
}
EXPORT_SYMBOL(__page_symlink);

int page_symlink(struct inode *inode, const char *symname, int len)
{
	return __page_symlink(inode, symname, len,
			!mapping_gfp_constraint(inode->i_mapping, __GFP_FS));
}
EXPORT_SYMBOL(page_symlink);

const struct inode_operations page_symlink_inode_operations = {
	.get_link	= page_get_link,
};
EXPORT_SYMBOL(page_symlink_inode_operations);
