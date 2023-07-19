/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Credentials management - see Documentation/security/credentials.rst
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_CRED_H
#define _LINUX_CRED_H

#include <linux/capability.h>
#include <linux/init.h>
#include <linux/key.h>
#include <linux/atomic.h>
#include <linux/uidgid.h>
#include <linux/sched.h>
#include <linux/sched/user.h>

struct cred;
struct inode;

/*
 * COW Supplementary groups list
 */
struct group_info {
	atomic_t	usage;
	int		ngroups;
	kgid_t		gid[0];
} __randomize_layout;

/**
 * get_group_info - Get a reference to a group info structure
 * @group_info: The group info to reference
 *
 * This gets a reference to a set of supplementary groups.
 *
 * If the caller is accessing a task's credentials, they must hold the RCU read
 * lock when reading.
 */
static inline struct group_info *get_group_info(struct group_info *gi)
{
	atomic_inc(&gi->usage);
	return gi;
}

/**
 * put_group_info - Release a reference to a group info structure
 * @group_info: The group info to release
 */
#define put_group_info(group_info)			\
do {							\
	if (atomic_dec_and_test(&(group_info)->usage))	\
		groups_free(group_info);		\
} while (0)

extern struct group_info init_groups;
#ifdef CONFIG_MULTIUSER
extern struct group_info *groups_alloc(int);
extern void groups_free(struct group_info *);

extern int in_group_p(kgid_t);
extern int in_egroup_p(kgid_t);
extern int groups_search(const struct group_info *, kgid_t);

extern int set_current_groups(struct group_info *);
extern void set_groups(struct cred *, struct group_info *);
extern bool may_setgroups(void);
extern void groups_sort(struct group_info *);
#else
static inline void groups_free(struct group_info *group_info)
{
}

static inline int in_group_p(kgid_t grp)
{
        return 1;
}
static inline int in_egroup_p(kgid_t grp)
{
        return 1;
}
static inline int groups_search(const struct group_info *group_info, kgid_t grp)
{
	return 1;
}
#endif

/*
 * The security context of a task
 *
 * The parts of the context break down into two categories:
 *
 *  (1) The objective context of a task.  These parts are used when some other
 *	task is attempting to affect this one.
 *
 *  (2) The subjective context.  These details are used when the task is acting
 *	upon another object, be that a file, a task, a key or whatever.
 *
 * Note that some members of this structure belong to both categories - the
 * LSM security pointer for instance.
 *
 * A task has two security pointers.  task->real_cred points to the objective
 * context that defines that task's actual details.  The objective part of this
 * context is used whenever that task is acted upon.
 *
 * task->cred points to the subjective context that defines the details of how
 * that task is going to act upon another object.  This may be overridden
 * temporarily to point to another security context, but normally points to the
 * same context as task->real_cred.
 */
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	/*
	 * real user id是真正process执行起来的用户user id，这个是比较清楚的，这
	 * 个进程是哪个用户调用的，或者是哪个父进程发起的，这个都是很明显的。通
	 * 常这个是不更改的，也不需要更改。
	 *
	 * 通过查看getuid/setuid系统调用的代码，这里的id号应该是全局id号，即处于
	 * init_user_namespace中的id号；
	 */ 
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	/*
	 * 在exec启动进程之后，它会从effective user id位拷贝信息到自己;
	 * 
	 * 对于非root用户，可以在未来使用setuid()来将euid设置成为real uid和suid
	 * 中的任何一个。但是非root用户是不允许用setuid()把euid设置成为其他值；
	 * - 这个特性支持了文件的set uid位，比如passwd；当用户态进程执行passwd程
	 *   序时，euid首先由于passwd的set-root-id标志被设置为root，然后后续的
	 *   setuid()会使的suid会被设置为euid(此时是root)，这样一来，后续便可以
	 *   通过seteuid()等再次将euid设置为root，从而再次获取root权限；
	 *
	 * 对于root来说，就没有那么大的意义了。因为root调用setuid()的时候，将会
	 * 同时设置uid/suid/euid三个值；
	 * - 这个特性用于支持root进程将自己永远降级为普通进程；
	 */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	/*
	 * 当判定一个进程是否对于某个文件有权限的时候，要验证的ID是
	 * effective user id，而非real user id。
	 */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	/*
	 * 详细关系及解读参见：
	 * - https://lwn.net/Articles/636533/
	 * 
	 * pA' = (file caps or setuid or setgid ? 0 : pA)
	 * pP' = (X & fP) | (pI & fI) | pA'
	 * pI' = pI
	 * pE' = (fE ? pP' : pA')
	 * X is unchanged (X means bounding set)
	 *
	 * 关系较为复杂，来龙去脉还是得去看lwn；
	 *
	 * ----------------------------------------------
	 *
	 * 这里保存的是进程的capability，文件也有capability，作用类似于suid-root；
	 * 文件的capability存储于文件的拓展属性中，参见:
	 * cap_bprm_set_creds
	 *   get_file_caps
	 */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key	*session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	/*
	 * 进程需要指定user_namespace树中的某个节点作为本进程所在的user_namespace
	 * - user namespace还是比较特殊的，其他的namespace都放到了nsproxy中，就
	 *   只有user namespace搞尼玛特殊；
	 */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	/* RCU deletion */
	union {
		int non_rcu;			/* Can we skip RCU deletion? */
		struct rcu_head	rcu;		/* RCU deletion hook */
	};
} __randomize_layout;

extern void __put_cred(struct cred *);
extern void exit_creds(struct task_struct *);
extern int copy_creds(struct task_struct *, unsigned long);
extern const struct cred *get_task_cred(struct task_struct *);
extern struct cred *cred_alloc_blank(void);
extern struct cred *prepare_creds(void);
extern struct cred *prepare_exec_creds(void);
extern int commit_creds(struct cred *);
extern void abort_creds(struct cred *);
extern const struct cred *override_creds(const struct cred *);
extern void revert_creds(const struct cred *);
extern struct cred *prepare_kernel_cred(struct task_struct *);
extern int change_create_files_as(struct cred *, struct inode *);
extern int set_security_override(struct cred *, u32);
extern int set_security_override_from_ctx(struct cred *, const char *);
extern int set_create_files_as(struct cred *, struct inode *);
extern int cred_fscmp(const struct cred *, const struct cred *);
extern void __init cred_init(void);

/*
 * check for validity of credentials
 */
#ifdef CONFIG_DEBUG_CREDENTIALS
extern void __invalid_creds(const struct cred *, const char *, unsigned);
extern void __validate_process_creds(struct task_struct *,
				     const char *, unsigned);

extern bool creds_are_invalid(const struct cred *cred);

static inline void __validate_creds(const struct cred *cred,
				    const char *file, unsigned line)
{
	if (unlikely(creds_are_invalid(cred)))
		__invalid_creds(cred, file, line);
}

#define validate_creds(cred)				\
do {							\
	__validate_creds((cred), __FILE__, __LINE__);	\
} while(0)

#define validate_process_creds()				\
do {								\
	__validate_process_creds(current, __FILE__, __LINE__);	\
} while(0)

extern void validate_creds_for_do_exit(struct task_struct *);
#else
static inline void validate_creds(const struct cred *cred)
{
}
static inline void validate_creds_for_do_exit(struct task_struct *tsk)
{
}
static inline void validate_process_creds(void)
{
}
#endif

static inline bool cap_ambient_invariant_ok(const struct cred *cred)
{
	return cap_issubset(cred->cap_ambient,
			    cap_intersect(cred->cap_permitted,
					  cred->cap_inheritable));
}

/**
 * get_new_cred - Get a reference on a new set of credentials
 * @cred: The new credentials to reference
 *
 * Get a reference on the specified set of new credentials.  The caller must
 * release the reference.
 */
static inline struct cred *get_new_cred(struct cred *cred)
{
	atomic_inc(&cred->usage);
	return cred;
}

/**
 * get_cred - Get a reference on a set of credentials
 * @cred: The credentials to reference
 *
 * Get a reference on the specified set of credentials.  The caller must
 * release the reference.  If %NULL is passed, it is returned with no action.
 *
 * This is used to deal with a committed set of credentials.  Although the
 * pointer is const, this will temporarily discard the const and increment the
 * usage count.  The purpose of this is to attempt to catch at compile time the
 * accidental alteration of a set of credentials that should be considered
 * immutable.
 */
static inline const struct cred *get_cred(const struct cred *cred)
{
	struct cred *nonconst_cred = (struct cred *) cred;
	if (!cred)
		return cred;
	validate_creds(cred);
	nonconst_cred->non_rcu = 0;
	return get_new_cred(nonconst_cred);
}

static inline const struct cred *get_cred_rcu(const struct cred *cred)
{
	struct cred *nonconst_cred = (struct cred *) cred;
	if (!cred)
		return NULL;
	if (!atomic_inc_not_zero(&nonconst_cred->usage))
		return NULL;
	validate_creds(cred);
	nonconst_cred->non_rcu = 0;
	return cred;
}

/**
 * put_cred - Release a reference to a set of credentials
 * @cred: The credentials to release
 *
 * Release a reference to a set of credentials, deleting them when the last ref
 * is released.  If %NULL is passed, nothing is done.
 *
 * This takes a const pointer to a set of credentials because the credentials
 * on task_struct are attached by const pointers to prevent accidental
 * alteration of otherwise immutable credential sets.
 */
static inline void put_cred(const struct cred *_cred)
{
	struct cred *cred = (struct cred *) _cred;

	if (cred) {
		validate_creds(cred);
		if (atomic_dec_and_test(&(cred)->usage))
			__put_cred(cred);
	}
}

/**
 * current_cred - Access the current task's subjective credentials
 *                                          ^^^^^^^^^^
 *                                             主体
 *
 * Access the subjective credentials of the current task.  RCU-safe,
 * since nobody else can modify it.
 */
#define current_cred() \
	rcu_dereference_protected(current->cred, 1)

/**
 * current_real_cred - Access the current task's objective credentials
 *                                               ^^^^^^^^^
 *                                                  客体
 *
 * Access the objective credentials of the current task.  RCU-safe,
 * since nobody else can modify it.
 */
#define current_real_cred() \
	rcu_dereference_protected(current->real_cred, 1)

/**
 * __task_cred - Access a task's objective credentials
 * @task: The task to query
 *
 * Access the objective credentials of a task.  The caller must hold the RCU
 * readlock.
 *
 * The result of this function should not be passed directly to get_cred();
 * rather get_task_cred() should be used instead.
 */
#define __task_cred(task)	\
	rcu_dereference((task)->real_cred)

/**
 * get_current_cred - Get the current task's subjective credentials
 *
 * Get the subjective credentials of the current task, pinning them so that
 * they can't go away.  Accessing the current task's credentials directly is
 * not permitted.
 */
#define get_current_cred()				\
	(get_cred(current_cred()))

/**
 * get_current_user - Get the current task's user_struct
 *
 * Get the user record of the current task, pinning it so that it can't go
 * away.
 */
#define get_current_user()				\
({							\
	struct user_struct *__u;			\
	const struct cred *__cred;			\
	__cred = current_cred();			\
	__u = get_uid(__cred->user);			\
	__u;						\
})

/**
 * get_current_groups - Get the current task's supplementary group list
 *
 * Get the supplementary group list of the current task, pinning it so that it
 * can't go away.
 */
#define get_current_groups()				\
({							\
	struct group_info *__groups;			\
	const struct cred *__cred;			\
	__cred = current_cred();			\
	__groups = get_group_info(__cred->group_info);	\
	__groups;					\
})

#define task_cred_xxx(task, xxx)			\
({							\
	__typeof__(((struct cred *)NULL)->xxx) ___val;	\
	rcu_read_lock();				\
	___val = __task_cred((task))->xxx;		\
	rcu_read_unlock();				\
	___val;						\
})

#define task_uid(task)		(task_cred_xxx((task), uid))
#define task_euid(task)		(task_cred_xxx((task), euid))

#define current_cred_xxx(xxx)			\
({						\
	current_cred()->xxx;			\
})

#define current_uid()		(current_cred_xxx(uid))
#define current_gid()		(current_cred_xxx(gid))
#define current_euid()		(current_cred_xxx(euid))
#define current_egid()		(current_cred_xxx(egid))
#define current_suid()		(current_cred_xxx(suid))
#define current_sgid()		(current_cred_xxx(sgid))
#define current_fsuid() 	(current_cred_xxx(fsuid))
#define current_fsgid() 	(current_cred_xxx(fsgid))
#define current_cap()		(current_cred_xxx(cap_effective))
#define current_user()		(current_cred_xxx(user))

extern struct user_namespace init_user_ns;
#ifdef CONFIG_USER_NS
#define current_user_ns()	(current_cred_xxx(user_ns))
#else
static inline struct user_namespace *current_user_ns(void)
{
	return &init_user_ns;
}
#endif


#define current_uid_gid(_uid, _gid)		\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_uid) = __cred->uid;			\
	*(_gid) = __cred->gid;			\
} while(0)

#define current_euid_egid(_euid, _egid)		\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_euid) = __cred->euid;		\
	*(_egid) = __cred->egid;		\
} while(0)

#define current_fsuid_fsgid(_fsuid, _fsgid)	\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_fsuid) = __cred->fsuid;		\
	*(_fsgid) = __cred->fsgid;		\
} while(0)

#endif /* _LINUX_CRED_H */
