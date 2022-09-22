/* SPDX-License-Identifier: GPL-2.0-only */
/* ----------------------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 * ----------------------------------------------------------------------- */

/*
 * The actual transition into protected mode
 */

#include <asm/boot.h>
#include <asm/processor-flags.h>
#include <asm/segment.h>
#include <linux/linkage.h>

	.text
	.code16

/*
 * void protected_mode_jump(u32 entrypoint, u32 bootparams);
 * 
 * 第一个参数在eax
 * 第二个参数在edx
 */
GLOBAL(protected_mode_jump)
	movl	%edx, %esi		# Pointer to boot_params table

	xorl	%ebx, %ebx
	movw	%cs, %bx		# 将real mode下的cs放到bx中
	shll	$4, %ebx
	addl	%ebx, 2f		# movw、shll、addl最终的结果是:
					#   in_pm32 = (%cs << 4) + in_pm32。
					# 目的是：
					#   将2f处的实模式跳转地址转变为保护模
					#   式的偏移即平坦地址空间内的线性地址

	jmp	1f			# Short jump to serialize on 386/486
					# short jump也有这个作用吗？
1:

	movw	$__BOOT_DS, %cx		# ecx保存数据段的段选择子
	movw	$__BOOT_TSS, %di

	movl	%cr0, %edx
	orb	$X86_CR0_PE, %dl	# Protected mode
	movl	%edx, %cr0		# 此刻正式开启保护模式

	# Transition to 32-bit mode
	.byte	0x66, 0xea		# ljmpl opcode
2:	.long	in_pm32			# offset ----------------------+
	.word	__BOOT_CS		# segment                      |  
					# 这个far jump可以起到清空     |
					# 指令流水线的作用             |
ENDPROC(protected_mode_jump)		#                              |
					#                              |
	.code32				#                              |
	.section ".text32","ax"		#                              |
GLOBAL(in_pm32)				# <----------------------------+
	# Set up data segments for flat 32-bit mode
	movl	%ecx, %ds		# 将段寄存器都设置为__BOOT_DS
	movl	%ecx, %es		# cs寄存器通过上面的far jump后已经保存
	movl	%ecx, %fs		# 了__BOOT_CS
	movl	%ecx, %gs
	movl	%ecx, %ss
	# The 32-bit code sets up its own stack, but this way we do have
	# a valid stack if some debugging hack wants to use it.
	addl	%ebx, %esp		# 将实模式下的sp转换成保护模式下的esp
					#   实模式下ss == 0x1000
					#   保护模式下ss.base == 0
					#   所以要将esp加上ebx(值为0x10000)

	# Set up TR to make Intel VT happy
	# 骗一下CPU
	ltr	%di

	# Clear registers to allow for future extensions to the
	# 32-bit boot protocol
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	xorl	%ebx, %ebx
	xorl	%ebp, %ebp
	xorl	%edi, %edi

	# Set up LDTR to make Intel VT happy
	lldt	%cx

	jmpl	*%eax			# Jump to the 32-bit entrypoint
					# eax从protected_mode_jump就没变过，是0x100000
					# 如果使用的是bzImage，则跳转到startup_32
					# 位置是: arch/x86/boot/compressed/head_64.S
ENDPROC(in_pm32)
