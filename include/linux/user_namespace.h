/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_USER_NAMESPACE_H
#define _LINUX_USER_NAMESPACE_H

#include <linux/kref.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/rwsem.h>
#include <linux/sysctl.h>
#include <linux/err.h>
#include <linux/kabi.h>

#define UID_GID_MAP_MAX_BASE_EXTENTS 5
#define UID_GID_MAP_MAX_EXTENTS 340

struct uid_gid_extent {
	/*
	 * 本段id映射范围在当前user namespace的起始id
	 */
	u32 first;
	/*
	 * 本段id映射范围在全局user namespace的起始id；
	 * - 当通过/proc/$$/xxx_map配置时，本字段填写的是父user namespace中的起
	 *   始id，但内核会将其自动转换为全局id保存到这里；
	 */
	u32 lower_first;
	/*
	 * 本段id映射范围内id的个数
	 */
	u32 count;
};

/*
 * 本数据结构表示一段id范围的映射，有两种存储形式：
 * - 当nr_extents <= UID_GID_MAP_MAX_BASE_EXTENTS时，直接将uid_gid_extent结构体
 *   保存到本地；
 * - 当nr_extents > UID_GID_MAP_MAX_BASE_EXTENTS时，将uid_gid_extent结构体保存到
 *   指针组成的数组里；需要分配额外的内存；
 */
struct uid_gid_map { /* 64 bytes -- 1 cache line */
	u32 nr_extents;
	union {
		struct uid_gid_extent extent[UID_GID_MAP_MAX_BASE_EXTENTS];
		struct {
			struct uid_gid_extent *forward;
			struct uid_gid_extent *reverse;
		};
	};
};

#define USERNS_SETGROUPS_ALLOWED 1UL

#define USERNS_INIT_FLAGS USERNS_SETGROUPS_ALLOWED

struct ucounts;

enum ucount_type {
	UCOUNT_USER_NAMESPACES,
	UCOUNT_PID_NAMESPACES,
	UCOUNT_UTS_NAMESPACES,
	UCOUNT_IPC_NAMESPACES,
	UCOUNT_NET_NAMESPACES,
	UCOUNT_MNT_NAMESPACES,
	UCOUNT_CGROUP_NAMESPACES,
#ifdef CONFIG_INOTIFY_USER
	UCOUNT_INOTIFY_INSTANCES,
	UCOUNT_INOTIFY_WATCHES,
#endif
	UCOUNT_COUNTS,
};

/*
 * user_namespace遵循以下原则：
 * - user_namespace使用父子关系组成树形结构，进程需要指定树种的某个节点为本进程
 *   所在的user_namespace。即task_struct->real_cred->user_ns
 * - 每个其他类型的namespace（uts/pid/mount/network/cgroup）都需要指定当前ns所属
 *   的user_namespace。即xxx_ns->user_ns
 * - 每个进程使用一个代理结构来指定本进程所属的其他类型的namespace（
 *   task_struct->nsproxy->xxx_ns），这些namespace所属的user_namespace即为2；
 *   1和2种的user_ns可以不一致；
 */
struct user_namespace {
	struct uid_gid_map	uid_map;
	struct uid_gid_map	gid_map;
	struct uid_gid_map	projid_map;
	atomic_t		count;
	struct user_namespace	*parent;
	int			level;
	kuid_t			owner;
	kgid_t			group;
	struct ns_common	ns;
	unsigned long		flags;

#ifdef CONFIG_KEYS
	/* List of joinable keyrings in this namespace.  Modification access of
	 * these pointers is controlled by keyring_sem.  Once
	 * user_keyring_register is set, it won't be changed, so it can be
	 * accessed directly with READ_ONCE().
	 */
	struct list_head	keyring_name_list;
	struct key		*user_keyring_register;
	struct rw_semaphore	keyring_sem;
#endif

	/* Register of per-UID persistent keyrings for this namespace */
#ifdef CONFIG_PERSISTENT_KEYRINGS
	struct key		*persistent_keyring_register;
#endif
	struct work_struct	work;
#ifdef CONFIG_SYSCTL
	struct ctl_table_set	set;
	struct ctl_table_header *sysctls;
#endif
	struct ucounts		*ucounts;

	int ucount_max[UCOUNT_COUNTS];

	KABI_RESERVE(1);
	KABI_RESERVE(2);
	KABI_RESERVE(3);
	KABI_RESERVE(4);
} __randomize_layout;

struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	int count;
	atomic_t ucount[UCOUNT_COUNTS];
};

extern struct user_namespace init_user_ns;

bool setup_userns_sysctls(struct user_namespace *ns);
void retire_userns_sysctls(struct user_namespace *ns);
struct ucounts *inc_ucount(struct user_namespace *ns, kuid_t uid, enum ucount_type type);
void dec_ucount(struct ucounts *ucounts, enum ucount_type type);

#ifdef CONFIG_USER_NS

static inline struct user_namespace *get_user_ns(struct user_namespace *ns)
{
	if (ns)
		atomic_inc(&ns->count);
	return ns;
}

extern int create_user_ns(struct cred *new);
extern int unshare_userns(unsigned long unshare_flags, struct cred **new_cred);
extern void __put_user_ns(struct user_namespace *ns);

static inline void put_user_ns(struct user_namespace *ns)
{
	if (ns && atomic_dec_and_test(&ns->count))
		__put_user_ns(ns);
}

struct seq_operations;
extern const struct seq_operations proc_uid_seq_operations;
extern const struct seq_operations proc_gid_seq_operations;
extern const struct seq_operations proc_projid_seq_operations;
extern ssize_t proc_uid_map_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t proc_gid_map_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t proc_projid_map_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t proc_setgroups_write(struct file *, const char __user *, size_t, loff_t *);
extern int proc_setgroups_show(struct seq_file *m, void *v);
extern bool userns_may_setgroups(const struct user_namespace *ns);
extern bool in_userns(const struct user_namespace *ancestor,
		       const struct user_namespace *child);
extern bool current_in_userns(const struct user_namespace *target_ns);
struct ns_common *ns_get_owner(struct ns_common *ns);
#else

static inline struct user_namespace *get_user_ns(struct user_namespace *ns)
{
	return &init_user_ns;
}

static inline int create_user_ns(struct cred *new)
{
	return -EINVAL;
}

static inline int unshare_userns(unsigned long unshare_flags,
				 struct cred **new_cred)
{
	if (unshare_flags & CLONE_NEWUSER)
		return -EINVAL;
	return 0;
}

static inline void put_user_ns(struct user_namespace *ns)
{
}

static inline bool userns_may_setgroups(const struct user_namespace *ns)
{
	return true;
}

static inline bool in_userns(const struct user_namespace *ancestor,
			     const struct user_namespace *child)
{
	return true;
}

static inline bool current_in_userns(const struct user_namespace *target_ns)
{
	return true;
}

static inline struct ns_common *ns_get_owner(struct ns_common *ns)
{
	return ERR_PTR(-EPERM);
}
#endif

#endif /* _LINUX_USER_H */
