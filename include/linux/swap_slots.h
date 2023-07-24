/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SWAP_SLOTS_H
#define _LINUX_SWAP_SLOTS_H

#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>

#define SWAP_SLOTS_CACHE_SIZE			SWAP_BATCH
#define THRESHOLD_ACTIVATE_SWAP_SLOTS_CACHE	(5*SWAP_SLOTS_CACHE_SIZE)
#define THRESHOLD_DEACTIVATE_SWAP_SLOTS_CACHE	(2*SWAP_SLOTS_CACHE_SIZE)

/*
 * 为了加快为换出页分配交换槽位的速度，每个处理器有一个交换槽位缓存swp_slots
 */
struct swap_slots_cache {
	bool		lock_initialized;
	struct mutex	alloc_lock; /* protects slots, nr, cur */
	/*
	 * 指向交换槽位数组，数组的大小是宏SWAP_SLOTS_CACHE_SIZE，即64
	 */
	swp_entry_t	*slots;
	/*
	 * 空闲槽位的数量
	 */
	int		nr;
	/*
	 * 当前已分配的槽位数量，也是下次分配的数组索引
	 */
	int		cur;
	spinlock_t	free_lock;  /* protects slots_ret, n_ret */
	swp_entry_t	*slots_ret;
	int		n_ret;
};

void disable_swap_slots_cache_lock(void);
void reenable_swap_slots_cache_unlock(void);
int enable_swap_slots_cache(void);
int free_swap_slot(swp_entry_t entry);

extern bool swap_slot_cache_enabled;

#endif /* _LINUX_SWAP_SLOTS_H */
