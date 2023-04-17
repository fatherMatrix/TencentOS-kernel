/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/boot/head.S
 *
 *  Copyright (C) 1991, 1992, 1993  Linus Torvalds
 */

/*
 *  head.S contains the 32-bit startup code.
 *
 * NOTE!!! Startup happens at absolute address 0x00001000, which is also where
 * the page directory will exist. The startup code will be overwritten by
 * the page directory. [According to comments etc elsewhere on a compressed
 * kernel it will end up at 0x1000 + 1Mb I hope so as I assume this. - AC]
 *
 * Page 0 is deliberately kept safe, since System Management Mode code in 
 * laptops may need to access the BIOS data stored there.  This is also
 * useful for future device drivers that either access the BIOS via VM86 
 * mode.
 */

/*
 * High loaded stuff by Hans Lermen & Werner Almesberger, Feb. 1996
 */
	.code32
	.text

#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/bootparam.h>
#include "pgtable.h"

/*
 * Locally defined symbols should be marked hidden:
 */
	.hidden _bss
	.hidden _ebss
	.hidden _got
	.hidden _egot
	.hidden _end

	__HEAD
	.code32
ENTRY(startup_32)
	/*
	 * 32bit entry is 0 and it is ABI so immutable!
	 * If we come here directly from a bootloader,
	 * kernel(text+data+bss+brk) ramdisk, zero_page, command line
	 * all need to be under the 4G limit.
	 */
	cld
	/*
	 * Test KEEP_SEGMENTS flag to see if the bootloader is asking
	 * us to not reload segments
	 * 
	 * 决定是否需要reload段寄存器
	 */
	testb $KEEP_SEGMENTS, BP_loadflags(%esi)
	jnz 1f

	/*
	 * 再关一次中断
	 */
	cli
	movl	$(__BOOT_DS), %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
1:

/*
 * Calculate the delta between where we were compiled to run
 * at and where we were actually loaded at.  This can only be done
 * with a short local call on x86.  Nothing  else will tell us what
 * address we are running at.  The reserved chunk of the real-mode
 * data at 0x1e4 (defined as a scratch field) are used as the stack
 * for this calculation. Only 4 bytes are needed.
 * 
 * 在vmlinux.ld.S中，startup_32的LMA及VMA都是0，但是bootloader可能
 * 将其加载到非0的地址上，因此我们需要计算出我们现在到底在哪里
 * 
 * 之所以可以这么做，是因为内核在编译的时候使用了-fPIE选项，生成的
 * 代码都是位置无关的!
 */
	/*
	 * esi中保存着boot_params的地址，是在protected_mode_jump的
	 * 第一行被赋值的
	 */
	leal	(BP_scratch+4)(%esi), %esp
	call	1f		/* call指令会跳到哪里去呢？
				 * 机器码是：e8 00 00 00 00
				 *   near跳转，e8后是rel-ip，跳转到下面的指令
				 */
1:	popl	%ebp		/* call指令会将返回地址压栈，所以call指令执行后，
				 * 栈顶元素是返回地址，即call指令后的指令地址。
				 *
				 * 这个栈空间就是位于boot_params中的一
				 * 个32位的变量(scratch)，因为这里的call调用也
				 * 只会用到4个byte。
				 *
				 * 此时ebp中保存了1f的VMA
				 */
	subl	$1b, %ebp	/* 用上边标签1的VMA减去上边的标签1的LMA，
				 * 得到的差值即为startup_32的VMA：
				 *   delta = VMA_1 - LMA_1
				 *   delta = VMA_s - LMA_s
				 *         = VMA_s - 0
				 *         = VMA_s
				 * 
				 * 其实在vmlinux中，VMA和LMA是相等的;但
				 * 是加载的时候被加载到了其他地址，比如0x100000；
				 * 该值根据bootloader的不同而不同，所以我们需要
				 * 用这种方法将其算出来；
				 */

/* setup a stack and make sure cpu supports long mode. */
	movl	$boot_stack_end, %eax	# eax中保存boot_stack的顶部的VMA（编译时）;
	addl	%ebp, %eax		# 因为vmlinux被加载到了0x100000，所以要加上;
	movl	%eax, %esp		# boot_stack_end指向的是一个编译链接时就准备
					# 好的栈的栈顶;

	call	verify_cpu		# 验证通过返回0，验证失败返回1
	testl	%eax, %eax
	jnz	.Lno_longmode		# 如果eax是1，即验证失败，跳转

/*
 * Compute the delta between where we were compiled to run at
 * and where the code will actually run at.
 *
 * %ebp contains the address we are loaded at by the boot loader and %ebx
 * contains the address where we should move the kernel image temporarily
 * for safe in-place decompression.
 *  
 * %ebp保存内核被boot loader加载到了哪里，%ebx将保存内核应该被移动到哪里。
 * 但两个地址都与内核镜像编译时的地址无关，因为内核的代码是地址无关的。
 */

#ifdef CONFIG_RELOCATABLE
	movl	%ebp, %ebx		        # ebp中存储的是startup_32的平坦物理地址
	movl	BP_kernel_alignment(%esi), %eax	# esi中保存boot_params的地址
	decl	%eax				
	addl	%eax, %ebx
	notl	%eax
	andl	%eax, %ebx			# 到这里是将startup_32的平坦物理地址按
						# BP_kernel_alignment中的值进行对齐；
	cmpl	$LOAD_PHYSICAL_ADDR, %ebx
	jae	1f
#endif
	movl	$LOAD_PHYSICAL_ADDR, %ebx
1:

	/* Target address to relocate to for decompression */
	movl	BP_init_size(%esi), %eax	# BP_init_size保存了压缩镜像和解压
						# 镜像两者尺寸的较大值（肯定是解压
						# 后的镜像更大）-- 0x307200
	subl	$_end, %eax			# $_end -- 0xb26000, __end是ZO的end
	addl	%eax, %ebx

	#
	# 到这里后，应该是这个样子的。说实话，这里是没有看懂的；
	#
	#  +----------+----------------+
	#  |          |    压缩镜像    |
	#  +----------+----------------+
	#  ^          ^
	#  |          |
	# old_ebx    ebx
	#

/*
 * Prepare for entering 64 bit mode
 */

	/* Load new GDT with the 64bit segments using 32bit descriptor */
	addl	%ebp, gdt+2(%ebp)		# 地址gdt+2(%ebp)保存的是gdt的基地址
						# 这里是因为我们把原本应该从0地址开始
						# 的startup_32加载到了%ebp指向的地址，
						# 因此这里要修正
	lgdt	gdt(%ebp)			# 值得注意的是，这里虽然重新加载了GDT，
						# 但是在reload各段寄存器前，其隐藏的缓
						# 存基地址还是不会变化的，参加sdm v3
						# 3.4.3

	/* Enable PAE mode */
	movl	%cr4, %eax			# 开启PAE是开启分页的的必要步骤
	orl	$X86_CR4_PAE, %eax		# 参见sdm v3 9.8.5
	movl	%eax, %cr4

 /*
  * Build early 4G boot pagetable
  */
	/*
	 * If SEV is active then set the encryption mask in the page tables.
	 * This will insure that when the kernel is copied and decompressed
	 * it will be done so encrypted.
	 */
	call	get_sev_encryption_bit
	xorl	%edx, %edx
	testl	%eax, %eax
	jz	1f
	subl	$32, %eax	/* Encryption bit is always above bit 31 */
	bts	%eax, %edx	/* Set encryption mask for page tables */
1:

	/* Initialize Page tables to 0 */
	leal	pgtable(%ebx), %edi		# pgtable这个位置链接时留出了19张页表的空间
	xorl	%eax, %eax
	movl	$(BOOT_INIT_PGT_SIZE/4), %ecx
	rep	stosl				# 这三条指令的作用是前6张页表的内容全部写0

	/* ======================= Build Level 4 ======================= */

	leal	pgtable + 0(%ebx), %edi		# 这四条指令其实是向PML4页表中的第0项写入
	leal	0x1007 (%edi), %eax		# 了数据，使其指向紧挨着的PD表项
						# 0x1007 = 4096 + 7，其中7(0b111)是用来填充
						# PML4中页表项的最低三个标志位（present, r/w,
						# u/s);
	movl	%eax, 0(%edi)			# edi中保存了PML4的基地址，也是其第一个页表
						# 项的地址；这里就是填充第一个页表项；
	addl	%edx, 4(%edi)			# SEV内存加密相关;

	/* ======================= Build Level 3 ======================= */

	leal	pgtable + 0x1000(%ebx), %edi	# edi此时保存了预留的第二张页表的基地址，这
						# 是一个PDP;
	leal	0x1007(%edi), %eax		# eax是要在PDP中某一项填充的内容，包括了低3位
						# 的标志位;
	movl	$4, %ecx			# 循环变量 - 4项
1:	movl	%eax, 0x00(%edi)		# 共计4个页表项
	addl	%edx, 0x04(%edi)
	addl	$0x00001000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b

	/* ======================= Build Level 2 ======================= */

	leal	pgtable + 0x2000(%ebx), %edi	#
	movl	$0x00000183, %eax		# 这个0x183是页表项的标志位，不是地址;
						# 这里的地址是从0开始的;
						# 0x183: 0001 1000 0011
						#             ^
						#           PS=2MB
						#
	movl	$2048, %ecx			# 构建了2048个页表项；2048 * 2MB = 4GB
						# 2048个页表项共需4个page才能放下；
						#
1:	movl	%eax, 0(%edi)			# edi总是指向当前该填充的页表项；
	addl	%edx, 4(%edi)			#
	addl	$0x00200000, %eax		# 移向下一个2MB的页;
						#
	addl	$8, %edi                        #
	decl	%ecx                            # 这里不是4k的页，见SDM Vol3 4-22 Fig4-9
	jnz	1b				#

	/* Enable the boot page tables */
	leal	pgtable(%ebx), %eax
	movl	%eax, %cr3			# 把上边建立的页表装到cr3里

	/* Enable Long mode in EFER (Extended Feature Enable Register) */
	movl	$MSR_EFER, %ecx
	rdmsr
	btsl	$_EFER_LME, %eax		# IA32_EFER中有一个可读可写的LME位，对其
	wrmsr					# 置位说明进入了IA-32e模式。至于是32位兼
						# 容模式还是64位模式取决于段描述符的
						# CS.L位。

	/* After gdt is loaded */
	xorl	%eax, %eax
	lldt	%ax
	movl    $__BOOT_TSS, %eax
	ltr	%ax

	/*
	 * Setup for the jump to 64bit mode
	 *
	 * When the jump is performend we will be in long mode but
	 * in 32bit compatibility mode with EFER.LME = 1, CS.L = 0, CS.D = 1
	 * (and in turn EFER.LMA = 1).	To jump into 64bit mode we use
	 * the new gdt/idt that has __KERNEL_CS with CS.L = 1.
	 * We place all of the values on our mini stack so lret can
	 * used to perform that far jump.
	 */
	pushl	$__KERNEL_CS
	leal	startup_64(%ebp), %eax		# 将startup_64的地址放到eax中
#ifdef CONFIG_EFI_MIXED
	movl	efi32_config(%ebp), %ebx
	cmp	$0, %ebx
	jz	1f
	leal	handover_entry(%ebp), %eax
1:
#endif
	pushl	%eax				# 和上面的pushl $__KERNEL_CS一起将跳转
						# 地址压入栈中，然后利用下面的lret指令
						# 完成跳转过程(假装是返回)；跳转后CS.L
						# 便为1，即为64位模式；

	/* Enter paged protected Mode, activating Long Mode */
	movl	$(X86_CR0_PG | X86_CR0_PE), %eax /* Enable Paging and Protected mode */
	movl	%eax, %cr0			# 开启分页

	/* Jump from 32bit compatibility mode into 64bit mode. */
	lret
ENDPROC(startup_32)

#ifdef CONFIG_EFI_MIXED
	.org 0x190
ENTRY(efi32_stub_entry)
	add	$0x4, %esp		/* Discard return address */
	popl	%ecx
	popl	%edx
	popl	%esi

	leal	(BP_scratch+4)(%esi), %esp
	call	1f
1:	pop	%ebp
	subl	$1b, %ebp

	movl	%ecx, efi32_config(%ebp)
	movl	%edx, efi32_config+8(%ebp)
	sgdtl	efi32_boot_gdt(%ebp)

	leal	efi32_config(%ebp), %eax
	movl	%eax, efi_config(%ebp)

	/* Disable paging */
	movl	%cr0, %eax
	btrl	$X86_CR0_PG_BIT, %eax
	movl	%eax, %cr0

	jmp	startup_32
ENDPROC(efi32_stub_entry)
#endif

	.code64
	.org 0x200
ENTRY(startup_64)
	/*
	 * 64bit entry is 0x200 and it is ABI so immutable!
	 * We come here either from startup_32 or directly from a
	 * 64bit bootloader.
	 * If we come here from a bootloader, kernel(text+data+bss+brk),
	 * ramdisk, zero_page, command line could be above 4G.
	 * We depend on an identity mapped page table being provided
	 * that maps our entire kernel(text+data+bss+brk), zero page
	 * and command line.
	 */

	/* Setup data segments. */
	xorl	%eax, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %fs
	movl	%eax, %gs

	/*
	 * Compute the decompressed kernel start address.  It is where
	 * we were loaded at aligned to a 2M boundary. %rbp contains the
	 * decompressed kernel start address.
	 *
	 * If it is a relocatable kernel then decompress and run the kernel
	 * from load address aligned to 2MB addr, otherwise decompress and
	 * run the kernel from LOAD_PHYSICAL_ADDR
	 *
	 * We cannot rely on the calculation done in 32-bit mode, since we
	 * may have been invoked via the 64-bit entry point.
	 */

	/* Start with the delta to where the kernel will run at. */
#ifdef CONFIG_RELOCATABLE
	leaq	startup_32(%rip) /* - $startup_32 */, %rbp	# 代码是pie方式编译的，
								# 所以startup_32会编译为负值（相对rip的偏移）
	movl	BP_kernel_alignment(%rsi), %eax
	decl	%eax
	addq	%rax, %rbp
	notq	%rax
	andq	%rax, %rbp
	cmpq	$LOAD_PHYSICAL_ADDR, %rbp
	jae	1f						# 这里照样是将加载地址按照kernel_alignment对齐
#endif
	movq	$LOAD_PHYSICAL_ADDR, %rbp
1:

	/* Target address to relocate to for decompression */
	movl	BP_init_size(%rsi), %ebx
	subl	$_end, %ebx
	addq	%rbp, %rbx					# 这一段的逻辑跟前边是一样的
								# 之所以要再算一遍是因为64位bootloader会
								# 直接跳到这里，省略前面的startup_32

	# 到这里时：
	# ebp == 0x1000000 (内核被加载到了哪里）
	# ebx == 0x354c000（解压内核前应该将内核临时备份到哪里）
	 
	/* Set up the stack */
	leaq	boot_stack_end(%rbx), %rsp

	/*
	 * paging_prepare() and cleanup_trampoline() below can have GOT
	 * references. Adjust the table with address we are running at.
	 *
	 * Zero RAX for adjust_got: the GOT was not adjusted before;
	 * there's no adjustment to undo.
	 */
	xorq	%rax, %rax

	/*
	 * Calculate the address the binary is loaded at and use it as
	 * a GOT adjustment.
	 */
	call	1f
1:	popq	%rdi
	subq	$1b, %rdi		# rdi此时保存的是startup_64在平坦地址空间的VMA

	call	.Ladjust_got

	/*
	 * At this point we are in long mode with 4-level paging enabled,
	 * but we might want to enable 5-level paging or vice versa.
	 *
	 * The problem is that we cannot do it directly. Setting or clearing
	 * CR4.LA57 in long mode would trigger #GP. So we need to switch off
	 * long mode and paging first.
	 *
	 * We also need a trampoline in lower memory to switch over from
	 * 4- to 5-level paging for cases when the bootloader puts the kernel
	 * above 4G, but didn't enable 5-level paging for us.
	 *
	 * The same trampoline can be used to switch from 5- to 4-level paging
	 * mode, like when starting 4-level paging kernel via kexec() when
	 * original kernel worked in 5-level paging mode.
	 *
	 * For the trampoline, we need the top page table to reside in lower
	 * memory as we don't have a way to load 64-bit values into CR3 in
	 * 32-bit mode.
	 *
	 * We go though the trampoline even if we don't have to: if we're
	 * already in a desired paging mode. This way the trampoline code gets
	 * tested on every boot.
	 */

	/* Make sure we have GDT with 32-bit code segment */
	leaq	gdt(%rip), %rax
	movq	%rax, gdt64+2(%rip)
	lgdt	gdt64(%rip)		# 这里又把startup_32里的活儿干了一遍
					# 加载的还是同一套gdt
					#
					# 应该是因为有些bootloader会直接跳过
					# 上边的startup_32？

	/*
	 * paging_prepare() sets up the trampoline and checks if we need to
	 * enable 5-level paging.
	 *
	 * paging_prepare() returns a two-quadword structure which lands
	 * into RDX:RAX:
	 *   - Address of the trampoline is returned in RAX.
	 *   - Non zero RDX means trampoline needs to enable 5-level
	 *     paging.
	 *
	 * RSI holds real mode data and needs to be preserved across
	 * this function call.
	 */
	pushq	%rsi
	movq	%rsi, %rdi		/* real mode address */
	call	paging_prepare
	popq	%rsi

	/* Save the trampoline address in RCX */
	movq	%rax, %rcx

	/*
	 * Load the address of trampoline_return() into RDI.
	 * It will be used by the trampoline to return to the main code.
	 */
	leaq	trampoline_return(%rip), %rdi

	/* Switch to compatibility mode (CS.L = 0 CS.D = 1) via far return */
	pushq	$__KERNEL32_CS
	leaq	TRAMPOLINE_32BIT_CODE_OFFSET(%rax), %rax
	pushq	%rax
	lretq
trampoline_return:
	/* Restore the stack, the 32-bit trampoline uses its own stack */
	leaq	boot_stack_end(%rbx), %rsp

	/*
	 * cleanup_trampoline() would restore trampoline memory.
	 *
	 * RDI is address of the page table to use instead of page table
	 * in trampoline memory (if required).
	 *
	 * RSI holds real mode data and needs to be preserved across
	 * this function call.
	 */
	pushq	%rsi
	leaq	top_pgtable(%rbx), %rdi
	call	cleanup_trampoline
	popq	%rsi

	/* Zero EFLAGS */
	pushq	$0
	popfq

	/*
	 * Previously we've adjusted the GOT with address the binary was
	 * loaded at. Now we need to re-adjust for relocation address.
	 *
	 * Calculate the address the binary is loaded at, so that we can
	 * undo the previous GOT adjustment.
	 */
	call	1f
1:	popq	%rax
	subq	$1b, %rax

	/* The new adjustment is the relocation address */
	movq	%rbx, %rdi
	call	.Ladjust_got

/*
 * Copy the compressed kernel to the end of our buffer
 * where decompression in place becomes safe.
 */
	pushq	%rsi				# 拷贝压缩内核到rdi
	leaq	(_bss-8)(%rip), %rsi
	leaq	(_bss-8)(%rbx), %rdi
	movq	$_bss /* - $startup_32 */, %rcx
	shrq	$3, %rcx
	std
	rep	movsq
	cld
	popq	%rsi

/*
 * Jump to the relocated address.
 */
	leaq	.Lrelocated(%rbx), %rax		# 跳到relocated标签处
	jmp	*%rax

#ifdef CONFIG_EFI_STUB

/* The entry point for the PE/COFF executable is efi_pe_entry. */
ENTRY(efi_pe_entry)
	movq	%rcx, efi64_config(%rip)	/* Handle */
	movq	%rdx, efi64_config+8(%rip) /* EFI System table pointer */

	leaq	efi64_config(%rip), %rax
	movq	%rax, efi_config(%rip)

	call	1f
1:	popq	%rbp
	subq	$1b, %rbp

	/*
	 * Relocate efi_config->call().
	 */
	addq	%rbp, efi64_config+40(%rip)

	movq	%rax, %rdi
	call	make_boot_params
	cmpq	$0,%rax
	je	fail
	mov	%rax, %rsi
	leaq	startup_32(%rip), %rax
	movl	%eax, BP_code32_start(%rsi)
	jmp	2f		/* Skip the relocation */

handover_entry:
	call	1f
1:	popq	%rbp
	subq	$1b, %rbp

	/*
	 * Relocate efi_config->call().
	 */
	movq	efi_config(%rip), %rax
	addq	%rbp, 40(%rax)
2:
	movq	efi_config(%rip), %rdi
	call	efi_main
	movq	%rax,%rsi
	cmpq	$0,%rax
	jne	2f
fail:
	/* EFI init failed, so hang. */
	hlt
	jmp	fail
2:
	movl	BP_code32_start(%esi), %eax
	leaq	startup_64(%rax), %rax
	jmp	*%rax
ENDPROC(efi_pe_entry)

	.org 0x390
ENTRY(efi64_stub_entry)
	movq	%rdi, efi64_config(%rip)	/* Handle */
	movq	%rsi, efi64_config+8(%rip) /* EFI System table pointer */

	leaq	efi64_config(%rip), %rax
	movq	%rax, efi_config(%rip)

	movq	%rdx, %rsi
	jmp	handover_entry
ENDPROC(efi64_stub_entry)
#endif

	.text
.Lrelocated:

/*
 * Clear BSS (stack is currently empty)
 */
	xorl	%eax, %eax		# 将bss段全部清0
	leaq    _bss(%rip), %rdi
	leaq    _ebss(%rip), %rcx
	subq	%rdi, %rcx
	shrq	$3, %rcx
	rep	stosq

/*
 * Do the extraction, and jump to the new kernel..
 * 
 * 这里是按照x86_64标准的寄存器使用规则来的
 */
	pushq	%rsi			/* Save the real mode argument */
	movq	%rsi, %rdi		/* real mode address */
	leaq	boot_heap(%rip), %rsi	/* malloc area for uncompression */
	leaq	input_data(%rip), %rdx  /* input_data */
	movl	$z_input_len, %ecx	/* input_len */
	movq	%rbp, %r8		/* output target address */
	movq	$z_output_len, %r9	/* decompressed length, end of relocs */
	call	extract_kernel		/* returns kernel location in %rax */
	popq	%rsi

/*
 * Jump to the decompressed kernel.
 */
	jmp	*%rax			# arch/x86/kernel/head_64.S:startup_64

/*
 * Adjust the global offset table
 *
 * RAX is the previous adjustment of the table to undo (use 0 if it's the
 * first time we touch GOT).
 * RDI is the new adjustment to apply.
 */
.Ladjust_got:
	/* Walk through the GOT adding the address to the entries */
	leaq	_got(%rip), %rdx
	leaq	_egot(%rip), %rcx
1:
	cmpq	%rcx, %rdx
	jae	2f
	subq	%rax, (%rdx)	/* Undo previous adjustment */
	addq	%rdi, (%rdx)	/* Apply the new adjustment */
	addq	$8, %rdx
	jmp	1b
2:
	ret

	.code32
/*
 * This is the 32-bit trampoline that will be copied over to low memory.
 *
 * RDI contains the return address (might be above 4G).
 * ECX contains the base address of the trampoline memory.
 * Non zero RDX means trampoline needs to enable 5-level paging.
 */
ENTRY(trampoline_32bit_src)
	/* Set up data and stack segments */
	movl	$__KERNEL_DS, %eax
	movl	%eax, %ds
	movl	%eax, %ss

	/* Set up new stack */
	leal	TRAMPOLINE_32BIT_STACK_END(%ecx), %esp

	/* Disable paging */
	movl	%cr0, %eax
	btrl	$X86_CR0_PG_BIT, %eax
	movl	%eax, %cr0

	/* Check what paging mode we want to be in after the trampoline */
	cmpl	$0, %edx
	jz	1f

	/* We want 5-level paging: don't touch CR3 if it already points to 5-level page tables */
	movl	%cr4, %eax
	testl	$X86_CR4_LA57, %eax
	jnz	3f
	jmp	2f
1:
	/* We want 4-level paging: don't touch CR3 if it already points to 4-level page tables */
	movl	%cr4, %eax
	testl	$X86_CR4_LA57, %eax
	jz	3f
2:
	/* Point CR3 to the trampoline's new top level page table */
	leal	TRAMPOLINE_32BIT_PGTABLE_OFFSET(%ecx), %eax
	movl	%eax, %cr3
3:
	/* Set EFER.LME=1 as a precaution in case hypervsior pulls the rug */
	pushl	%ecx
	pushl	%edx
	movl	$MSR_EFER, %ecx
	rdmsr
	btsl	$_EFER_LME, %eax
	wrmsr
	popl	%edx
	popl	%ecx

	/* Enable PAE and LA57 (if required) paging modes */
	movl	$X86_CR4_PAE, %eax
	cmpl	$0, %edx
	jz	1f
	orl	$X86_CR4_LA57, %eax
1:
	movl	%eax, %cr4

	/* Calculate address of paging_enabled() once we are executing in the trampoline */
	leal	.Lpaging_enabled - trampoline_32bit_src + TRAMPOLINE_32BIT_CODE_OFFSET(%ecx), %eax

	/* Prepare the stack for far return to Long Mode */
	pushl	$__KERNEL_CS
	pushl	%eax

	/* Enable paging again */
	movl	$(X86_CR0_PG | X86_CR0_PE), %eax
	movl	%eax, %cr0

	lret

	.code64
.Lpaging_enabled:
	/* Return from the trampoline */
	jmp	*%rdi

	/*
         * The trampoline code has a size limit.
         * Make sure we fail to compile if the trampoline code grows
         * beyond TRAMPOLINE_32BIT_CODE_SIZE bytes.
	 */
	.org	trampoline_32bit_src + TRAMPOLINE_32BIT_CODE_SIZE

	.code32
.Lno_longmode:
	/* This isn't an x86-64 CPU, so hang intentionally, we cannot continue */
1:
	hlt
	jmp     1b

#include "../../kernel/verify_cpu.S"

/*
 *  63         56         51   48    45           39        32 
 * ------------------------------------------------------------
 * |             | |B| |A|       | |   | |0|E|W|A|            |
 * | BASE 31:24  |G|/|L|V| LIMIT |P|DPL|S|  TYPE | BASE 23:16 |
 * |             | |D| |L| 19:16 | |   | |1|C|R|A|            |
 * ------------------------------------------------------------
 *
 * 31                         16 15                         0 
 * ------------------------------------------------------------
 * |                             |                            |
 * |        BASE 15:0            |       LIMIT 15:0           |
 * |                             |                            |
 * ------------------------------------------------------------
 */

	.data
gdt64:
	.word	gdt_end - gdt
	.quad   0
	.balign	8
gdt:
	.word	gdt_end - gdt		/* gdt长度, 2字节 */
	.long	gdt			/* gdt基址，4字节 */
	.word	0			/* 从gdt到这个word结束，是gdt表的第0项。
					 * 这里算是借用这个第0项的位置来使用。
					 * 不用担心该gdt entry被使用，因为试图
					 * 使用此gdt entry进行内存访问会导致#GP
					 */
	.quad	0x00cf9a000000ffff	/* __KERNEL32_CS 
					 * G=1, B/D=1, L=0, AVL=0
					 * L=0表明这个时32bit的代码段
					 */
	.quad	0x00af9a000000ffff	/* __KERNEL_CS
					 * G=1, B/D=0, L=1, AVL=0
					 * L=1表明这个是64bit的代码段
					 */
	.quad	0x00cf92000000ffff	/* __KERNEL_DS */
	.quad	0x0080890000000000	/* TS descriptor */
	.quad   0x0000000000000000	/* TS continued */
gdt_end:

#ifdef CONFIG_EFI_STUB
efi_config:
	.quad	0

#ifdef CONFIG_EFI_MIXED
	.global efi32_config
efi32_config:
	.fill	5,8,0
	.quad	efi64_thunk
	.byte	0
#endif

	.global efi64_config
efi64_config:
	.fill	5,8,0
	.quad	efi_call
	.byte	1
#endif /* CONFIG_EFI_STUB */

/*
 * Stack and heap for uncompression
 */
	.bss
	.balign 4
boot_heap:
	.fill BOOT_HEAP_SIZE, 1, 0
boot_stack:
	.fill BOOT_STACK_SIZE, 1, 0
boot_stack_end:

/*
 * Space for page tables (not in .bss so not zeroed)
 */
	.section ".pgtable","a",@nobits
	.balign 4096
pgtable:
	.fill BOOT_PGT_SIZE, 1, 0

/*
 * The page table is going to be used instead of page table in the trampoline
 * memory.
 */
top_pgtable:
	.fill PAGE_SIZE, 1, 0
