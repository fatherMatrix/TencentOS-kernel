/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_PGTABLE_INVERT_H
#define _ASM_PGTABLE_INVERT_H 1

#ifndef __ASSEMBLY__

/*
 * A clear pte value is special, and doesn't get inverted.
 *
 * Note that even users that only pass a pgprot_t (rather
 * than a full pte) won't trigger the special zero case,
 * because even PAGE_NONE has _PAGE_PROTNONE | _PAGE_ACCESSED
 * set. So the all zero case really is limited to just the
 * cleared page table entry case.
 */
static inline bool __pte_needs_invert(u64 val)
{
	return val && !(val & _PAGE_PRESENT);
}

/* Get a mask to xor with the page table entry to get the correct pfn. */
static inline u64 protnone_mask(u64 val)
{
	return __pte_needs_invert(val) ?  ~0ull : 0;
}

static inline u64 flip_protnone_guard(u64 oldval, u64 val, u64 mask)
{
	/*
	 * When a PTE transitions from NONE to !NONE or vice-versa
	 * invert the PFN part to stop speculation.
	 * pte_pfn undoes this when needed.
	 *
	 * 这里要解决的问题是：当pte不是present时，要求无法访问数据。当事实上
	 * 会存在推测执行，即在页表权限检查得到结论之前，就开始数据访问。这会
	 * 引起侧信道攻击。
	 *
	 * 解决方案是，产生present位变化时，将pfn做位反转。这样推测执行得到的
	 * 数据是错误的。
	 *
	 * invert的配对？
	 */
	if (__pte_needs_invert(oldval) != __pte_needs_invert(val))
		val = (val & ~mask) | (~val & mask);
	return val;
}

#endif /* __ASSEMBLY__ */

#endif
