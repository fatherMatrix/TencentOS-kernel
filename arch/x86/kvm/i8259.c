/*
 * 8259 interrupt controller emulation
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2007 Intel Corporation
 * Copyright 2009 Red Hat, Inc. and/or its affiliates.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * Authors:
 *   Yaozu (Eddie) Dong <Eddie.dong@intel.com>
 *   Port from Qemu.
 */
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#include "irq.h"

#include <linux/kvm_host.h>
#include "trace.h"

#define pr_pic_unimpl(fmt, ...)	\
	pr_err_ratelimited("kvm: pic: " fmt, ## __VA_ARGS__)

static void pic_irq_request(struct kvm *kvm, int level);

static void pic_lock(struct kvm_pic *s)
	__acquires(&s->lock)
{
	spin_lock(&s->lock);
}

static void pic_unlock(struct kvm_pic *s)
	__releases(&s->lock)
{
	bool wakeup = s->wakeup_needed;
	struct kvm_vcpu *vcpu;
	int i;

	s->wakeup_needed = false;

	spin_unlock(&s->lock);

	/*
	 * 这里被抢占了怎么办？这个时候中断岂不是要乱序到达了？
	 * - pic阶段，guest应该是单核，有可能被抢占吗？
	 *   > host上是多核呀，设备有多个吧？在host上的表现是不是应该是多线程？
	 */
	if (wakeup) {
		kvm_for_each_vcpu(i, vcpu, s->kvm) {
			/*
			 * 这里选出BSP；
			 *
			 * 要注意的是，如果guest中将LVT LINT0给mask掉了，会通过
			 * vmexit -> handle_exit -> kvm_lapic_reg_write修改
			 * kvm_lapic的regs（LVT LINT0）；这将导致下面的判断会返
			 * 回0，从而跳过本分支，不会继续执行kvm_make_request和
			 * kvm_vcpu_kick函数；
			 * - 下面这个检查在其他地方也有做；
			 */
			if (kvm_apic_accept_pic_intr(vcpu)) {
				kvm_make_request(KVM_REQ_EVENT, vcpu);
				kvm_vcpu_kick(vcpu);
				return;
			}
		}
	}
}

static void pic_clear_isr(struct kvm_kpic_state *s, int irq)
{
	s->isr &= ~(1 << irq);
	if (s != &s->pics_state->pics[0])
		irq += 8;
	/*
	 * We are dropping lock while calling ack notifiers since ack
	 * notifier callbacks for assigned devices call into PIC recursively.
	 * Other interrupt may be delivered to PIC while lock is dropped but
	 * it should be safe since PIC state is already updated at this stage.
	 */
	pic_unlock(s->pics_state);
	kvm_notify_acked_irq(s->pics_state->kvm, SELECT_PIC(irq), irq);
	pic_lock(s->pics_state);
}

/*
 * set irq level. If an edge is detected, then the IRR is set to 1
 */
static inline int pic_set_irq1(struct kvm_kpic_state *s, int irq, int level)
{
	int mask, ret = 1;
	mask = 1 << irq;
	if (s->elcr & mask)	/* level triggered */
		if (level) {
			/*
			 * 如果原来irr中对应bit已经为1，则ret为0，表示该中断
			 * still pending；
			 * 如果原来irr中对应bit为0，则ret为1(>0)，表示Number of
			 * CPUs interrupt was delivered to;
			 */
			ret = !(s->irr & mask);
			s->irr |= mask;
			s->last_irr |= mask;
		} else {
			s->irr &= ~mask;
			s->last_irr &= ~mask;
		}
	else	/* edge triggered */
		if (level) {
			if ((s->last_irr & mask) == 0) {
				ret = !(s->irr & mask);
				s->irr |= mask;
			}
			s->last_irr |= mask;
		} else
			s->last_irr &= ~mask;

	/*
	 * 如果中断被imr屏蔽，则返回-1(<0)，表示失败；
	 */
	return (s->imr & mask) ? -1 : ret;
}

/*
 * return the highest priority found in mask (highest = smallest
 * number). Return 8 if no irq
 */
static inline int get_priority(struct kvm_kpic_state *s, int mask)
{
	int priority;
	if (mask == 0)
		return 8;
	priority = 0;
	while ((mask & (1 << ((priority + s->priority_add) & 7))) == 0)
		priority++;
	return priority;
}

/*
 * return the pic wanted interrupt. return -1 if none
 */
static int pic_get_irq(struct kvm_kpic_state *s)
{
	int mask, cur_priority, priority;

	/*
	 * 干掉IMR中屏蔽的位
	 */
	mask = s->irr & ~s->imr;
	priority = get_priority(s, mask);
	/*
	 * get_priority意味着没有中断
	 */ 
	if (priority == 8)
		return -1;
	/*
	 * compute current priority. If special fully nested mode on the
	 * master, the IRQ coming from the slave is not taken into account
	 * for the priority computation.
	 */
	mask = s->isr;
	if (s->special_fully_nested_mode && s == &s->pics_state->pics[0])
		mask &= ~(1 << 2);
	cur_priority = get_priority(s, mask);
	if (priority < cur_priority)
		/*
		 * higher priority found: an irq should be generated
		 */
		return (priority + s->priority_add) & 7;
	else
		return -1;
}

/*
 * raise irq to CPU if necessary. must be called every time the active
 * irq may change
 */
static void pic_update_irq(struct kvm_pic *s)
{
	int irq2, irq;

	irq2 = pic_get_irq(&s->pics[1]);
	if (irq2 >= 0) {
		/*
		 * if irq request by slave pic, signal master PIC
		 */
		pic_set_irq1(&s->pics[0], 2, 1);
		pic_set_irq1(&s->pics[0], 2, 0);
	}
	irq = pic_get_irq(&s->pics[0]);
	pic_irq_request(s->kvm, irq >= 0);
}

void kvm_pic_update_irq(struct kvm_pic *s)
{
	pic_lock(s);
	pic_update_irq(s);
	pic_unlock(s);
}

int kvm_pic_set_irq(struct kvm_pic *s, int irq, int irq_source_id, int level)
{
	int ret, irq_level;

	BUG_ON(irq < 0 || irq >= PIC_NUM_PINS);

	pic_lock(s);
	irq_level = __kvm_irq_line_state(&s->irq_states[irq],
					 irq_source_id, level);
	ret = pic_set_irq1(&s->pics[irq >> 3], irq & 7, irq_level);
	pic_update_irq(s);
	trace_kvm_pic_set_irq(irq >> 3, irq & 7, s->pics[irq >> 3].elcr,
			      s->pics[irq >> 3].imr, ret == 0);
	pic_unlock(s);

	return ret;
}

void kvm_pic_clear_all(struct kvm_pic *s, int irq_source_id)
{
	int i;

	pic_lock(s);
	for (i = 0; i < PIC_NUM_PINS; i++)
		__clear_bit(irq_source_id, &s->irq_states[i]);
	pic_unlock(s);
}

/*
 * acknowledge interrupt 'irq'
 */
static inline void pic_intack(struct kvm_kpic_state *s, int irq)
{
	s->isr |= 1 << irq;
	/*
	 * We don't clear a level sensitive interrupt here
	 *
	 * elcr寄存器对应位为0表示边沿触发；
	 *
	 * 对于边沿触发的中断，在这里清除其irr。那么对于水平触发的中断，在哪里
	 * 清除其irr呢？
	 * - 
	 */
	if (!(s->elcr & (1 << irq)))
		s->irr &= ~(1 << irq);

	if (s->auto_eoi) {
		if (s->rotate_on_auto_eoi)
			s->priority_add = (irq + 1) & 7;
		pic_clear_isr(s, irq);
	}

}

int kvm_pic_read_irq(struct kvm *kvm)
{
	int irq, irq2, intno;
	struct kvm_pic *s = kvm->arch.vpic;

	s->output = 0;

	pic_lock(s);
	/*
	 * 先读取master上的输出，因为这是作为一个整体；
	 */
	irq = pic_get_irq(&s->pics[0]);
	if (irq >= 0) {
		pic_intack(&s->pics[0], irq);
		/*
		 * 如果master上的输出是irq 2，那么说明是由slave触发的
		 */
		if (irq == 2) {
			irq2 = pic_get_irq(&s->pics[1]);
			if (irq2 >= 0)
				pic_intack(&s->pics[1], irq2);
			else
				/*
				 * spurious IRQ on slave controller
				 */
				irq2 = 7;
			intno = s->pics[1].irq_base + irq2;
			irq = irq2 + 8;
		} else
			intno = s->pics[0].irq_base + irq;
	} else {
		/*
		 * spurious IRQ on host controller
		 */
		irq = 7;
		intno = s->pics[0].irq_base + irq;
	}
	pic_update_irq(s);
	pic_unlock(s);

	return intno;
}

static void kvm_pic_reset(struct kvm_kpic_state *s)
{
	int irq, i;
	struct kvm_vcpu *vcpu;
	u8 edge_irr = s->irr & ~s->elcr;
	bool found = false;

	s->last_irr = 0;
	s->irr &= s->elcr;
	s->imr = 0;
	s->priority_add = 0;
	s->special_mask = 0;
	s->read_reg_select = 0;
	if (!s->init4) {
		s->special_fully_nested_mode = 0;
		s->auto_eoi = 0;
	}
	s->init_state = 1;

	kvm_for_each_vcpu(i, vcpu, s->pics_state->kvm)
		if (kvm_apic_accept_pic_intr(vcpu)) {
			found = true;
			break;
		}


	if (!found)
		return;

	/*
	 * 这是在干嘛？
	 */
	for (irq = 0; irq < PIC_NUM_PINS/2; irq++)
		if (edge_irr & (1 << irq))
			pic_clear_isr(s, irq);
}

static void pic_ioport_write(void *opaque, u32 addr, u32 val)
{
	struct kvm_kpic_state *s = opaque;
	int priority, cmd, irq;

	addr &= 1;
	/*
	 * 写的是1号寄存器
	 */
	if (addr == 0) {
		/*
		 * bit4为1，表示这是一个初始化序列，ICW1
		 */
		if (val & 0x10) {
			/*
			 * ICW1的bit0为1，表示此序列中有ICW4；
			 * ICW1的bit0为0，表示次序列中没有ICW4；
			 */
			s->init4 = val & 1;
			/*
			 * ICW1的bit1为0表示集联了2个8259a，这是我们期望的；
			 * 否则，直接报错；
			 */
			if (val & 0x02)
				pr_pic_unimpl("single mode not supported");
			if (val & 0x08)
				pr_pic_unimpl(
						"level sensitive irq not supported");
			/*
			 * 上面配置好之后，这里触发对pic的重置操作；
			 * 诶，不需要等ICW2-ICW4吗？
			 * - 下面的kvm_pic_reset中重置的只是当前得到的信息；而且
			 *   在kvm_pic_reset中将init_state设置为1，用于标识从
			 *   ICW1 -> ICW2 -> ICW3 -> ICW4的状态机；在ICW3或ICW4
			 *   结束后，将init_state重新设置回0，表示ICWx状态机结束；
			 */
			kvm_pic_reset(s);
		} else if (val & 0x08) {
		/*
		 * bit3为1，bit4为0时（bit4为1就不会走到这里了），表示这是一个
		 * OCW3命令字；
		 *
		 *  7 6 5 4 3 2 1 0
		 * +-+-+-+-+-+-+-+-+
		 * |0|E|S|0|1|P|R|R|
		 * | |S|M| | | |R|I|
		 * | |M|M| | | | |S|
		 * | |M| | | | | | |
		 * +-+-+-+-+-+-+-+-+
		 *    | |     | | |
		 *    | |     | | +-- read register command
		 *    | |     | +---- read register command
		 *    | |     +------ poll mode
		 *    | +------------ special mask
		 *    +-------------- special mask
		 */
			/*
			 * 打开poll mode
			 */
			if (val & 0x04)
				s->poll = 1;
			/*
			 * RR为1时，如果RIS为1，则读取ISR；
			 * RR为1时，如果RIS为0，则读取IRR；
			 */ 
			if (val & 0x02)
				s->read_reg_select = val & 1;
			/*
			 * 根据ESMM和SMM决定是否需要开启special mask
			 */
			if (val & 0x40)
				s->special_mask = (val >> 5) & 1;
		} else {
		/*
		 * 如果走到这里，则只剩下了一种可能：OCW2
		 *
		 *  7 6 5 4 3 2 1 0
		 * +-+-+-+-+-+-+-+-+
		 * |R|S|E|0|0| | | |
		 * | |L|O| | | | | |
		 * | | |I| | | | | |
		 * +-+-+-+-+-+-+-+-+
		 *  0 0 1 
		 *  0 1 1
		 *  1 0 1 rotate on non-specific eoi command   \
		 *  1 0 0 rotate in automatic eoi mode (set)    > automatic rotation
		 *  0 0 0 rotate in automatic eoi mode (clear) /
		 *  1 1 1
		 *  1 1 0
		 *  0 1 0
		 */
			/*
			 * 选取OCW2 bit7:5
			 */
			cmd = val >> 5;
			switch (cmd) {
			case 0:
			case 4:
				/*
				 * 这里对应automatic rotation的set和clear
				 */
				s->rotate_on_auto_eoi = cmd >> 2;
				break;
			case 1:	/* end of interrupt */
			case 5:
				/*
				 *
				 */ 
				priority = get_priority(s, s->isr);
				if (priority != 8) {
					irq = (priority + s->priority_add) & 7;
					if (cmd == 5)
						s->priority_add = (irq + 1) & 7;
					pic_clear_isr(s, irq);
					pic_update_irq(s->pics_state);
				}
				break;
			case 3:
				/*
				 * 
				 */ 
				irq = val & 7;
				pic_clear_isr(s, irq);
				pic_update_irq(s->pics_state);
				break;
			case 6:
				/*
				 * R=1, SL=1, 此时OCW2低3位+1是最高优先级
				 */
				s->priority_add = (val + 1) & 7;
				pic_update_irq(s->pics_state);
				break;
			case 7:
				/*
				 * R=1, SL=1, EOL=1, 此时是结合EOI和case 6
				 */
				irq = val & 7;
				s->priority_add = (irq + 1) & 7;
				pic_clear_isr(s, irq);
				pic_update_irq(s->pics_state);
				break;
			default:
				break;	/* no operation */
			}
		}
	} else
	/*
	 * 写的是2号寄存器
	 */
		switch (s->init_state) {
		case 0: { /* normal mode */
			u8 imr_diff = s->imr ^ val,
				off = (s == &s->pics_state->pics[0]) ? 0 : 8;
			s->imr = val;
			for (irq = 0; irq < PIC_NUM_PINS/2; irq++)
				if (imr_diff & (1 << irq))
					kvm_fire_mask_notifiers(
						s->pics_state->kvm,
						SELECT_PIC(irq + off),
						irq + off,
						!!(s->imr & (1 << irq)));
			pic_update_irq(s->pics_state);
			break;
		}
		case 1:
			/* 
			 * ICW2的bit7:3表示起始中断向量号
			 */ 
			s->irq_base = val & 0xf8;
			/*
			 * 推一下状态机
			 */
			s->init_state = 2;
			break;
		case 2:
			/*
			 * ICW3本来是用于表示是否使用了级联方式，但是我们这里肯
			 * 定是级联的，而且还是级联了2片，所以没有必要再去处理
			 * 这个；说实话，就是偷了个懒，相信guest os不是傻逼；
			 */
			if (s->init4)
				s->init_state = 3;
			else
				s->init_state = 0;
			break;
		case 3:
			/*
			 * ICW4
			 */
			s->special_fully_nested_mode = (val >> 4) & 1;
			s->auto_eoi = (val >> 1) & 1;
			s->init_state = 0;
			break;
		}
}

static u32 pic_poll_read(struct kvm_kpic_state *s, u32 addr1)
{
	int ret;

	ret = pic_get_irq(s);
	if (ret >= 0) {
		if (addr1 >> 7) {
		/*
		 * 走进这里，说明addr1是0xA0或0xA1，表示是从片；
		 */
			s->pics_state->pics[0].isr &= ~(1 << 2);
			s->pics_state->pics[0].irr &= ~(1 << 2);
		}
		s->irr &= ~(1 << ret);
		pic_clear_isr(s, ret);
		/*
		 * 从片但是不是2号输出pin
		 */
		if (addr1 >> 7 || ret != 2)
			pic_update_irq(s->pics_state);
	} else {
		ret = 0x07;
		pic_update_irq(s->pics_state);
	}

	return ret;
}

static u32 pic_ioport_read(void *opaque, u32 addr)
{
	struct kvm_kpic_state *s = opaque;
	int ret;

	if (s->poll) {
		ret = pic_poll_read(s, addr);
		s->poll = 0;
	} else
		if ((addr & 1) == 0)
		/*
		 * 奇地址端口复用读取ISR或者IRR
		 */
			if (s->read_reg_select)
				ret = s->isr;
			else
				ret = s->irr;
		else
		/*
		 * 偶地址端口只用来读取IMR
		 */
			ret = s->imr;
	return ret;
}

static void elcr_ioport_write(void *opaque, u32 addr, u32 val)
{
	struct kvm_kpic_state *s = opaque;
	s->elcr = val & s->elcr_mask;
}

static u32 elcr_ioport_read(void *opaque, u32 addr1)
{
	struct kvm_kpic_state *s = opaque;
	return s->elcr;
}

static int picdev_write(struct kvm_pic *s,
			 gpa_t addr, int len, const void *val)
{
	unsigned char data = *(unsigned char *)val;

	if (len != 1) {
		pr_pic_unimpl("non byte write\n");
		return 0;
	}
	switch (addr) {
	case 0x20:
	case 0x21:
		pic_lock(s);
		pic_ioport_write(&s->pics[0], addr, data);
		pic_unlock(s);
		break;
	case 0xa0:
	case 0xa1:
		pic_lock(s);
		pic_ioport_write(&s->pics[1], addr, data);
		pic_unlock(s);
		break;
	case 0x4d0:
	case 0x4d1:
		pic_lock(s);
		elcr_ioport_write(&s->pics[addr & 1], addr, data);
		pic_unlock(s);
		break;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int picdev_read(struct kvm_pic *s,
		       gpa_t addr, int len, void *val)
{
	unsigned char *data = (unsigned char *)val;

	if (len != 1) {
		memset(val, 0, len);
		pr_pic_unimpl("non byte read\n");
		return 0;
	}
	switch (addr) {
	case 0x20:
	case 0x21:
	case 0xa0:
	case 0xa1:
		pic_lock(s);
		*data = pic_ioport_read(&s->pics[addr >> 7], addr);
		pic_unlock(s);
		break;
	case 0x4d0:
	case 0x4d1:
		pic_lock(s);
		*data = elcr_ioport_read(&s->pics[addr & 1], addr);
		pic_unlock(s);
		break;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int picdev_master_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			       gpa_t addr, int len, const void *val)
{
	return picdev_write(container_of(dev, struct kvm_pic, dev_master),
			    addr, len, val);
}

static int picdev_master_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			      gpa_t addr, int len, void *val)
{
	return picdev_read(container_of(dev, struct kvm_pic, dev_master),
			    addr, len, val);
}

static int picdev_slave_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			      gpa_t addr, int len, const void *val)
{
	return picdev_write(container_of(dev, struct kvm_pic, dev_slave),
			    addr, len, val);
}

static int picdev_slave_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			     gpa_t addr, int len, void *val)
{
	return picdev_read(container_of(dev, struct kvm_pic, dev_slave),
			    addr, len, val);
}

static int picdev_eclr_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			     gpa_t addr, int len, const void *val)
{
	return picdev_write(container_of(dev, struct kvm_pic, dev_eclr),
			    addr, len, val);
}

static int picdev_eclr_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			    gpa_t addr, int len, void *val)
{
	return picdev_read(container_of(dev, struct kvm_pic, dev_eclr),
			    addr, len, val);
}

/*
 * callback when PIC0 irq status changed
 */
static void pic_irq_request(struct kvm *kvm, int level)
{
	struct kvm_pic *s = kvm->arch.vpic;

	if (!s->output)
		s->wakeup_needed = true;
	s->output = level;
}

static const struct kvm_io_device_ops picdev_master_ops = {
	.read     = picdev_master_read,
	.write    = picdev_master_write,
};

static const struct kvm_io_device_ops picdev_slave_ops = {
	.read     = picdev_slave_read,
	.write    = picdev_slave_write,
};

static const struct kvm_io_device_ops picdev_eclr_ops = {
	.read     = picdev_eclr_read,
	.write    = picdev_eclr_write,
};

int kvm_pic_init(struct kvm *kvm)
{
	struct kvm_pic *s;
	int ret;

	/*
	 * 创建kvm_pic结构体，一个kvm_pic结构体包含两片级联的i8259a
	 */
	s = kzalloc(sizeof(struct kvm_pic), GFP_KERNEL_ACCOUNT);
	if (!s)
		return -ENOMEM;
	spin_lock_init(&s->lock);
	s->kvm = kvm;
	s->pics[0].elcr_mask = 0xf8;
	s->pics[1].elcr_mask = 0xde;
	s->pics[0].pics_state = s;
	s->pics[1].pics_state = s;

	/*
	 * Initialize PIO device
	 *
	 * 在KVM_PIO_BUS上创建3个设备
	 */
	kvm_iodevice_init(&s->dev_master, &picdev_master_ops);
	kvm_iodevice_init(&s->dev_slave, &picdev_slave_ops);
	kvm_iodevice_init(&s->dev_eclr, &picdev_eclr_ops);
	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, 0x20, 2,
				      &s->dev_master);
	if (ret < 0)
		goto fail_unlock;

	ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, 0xa0, 2, &s->dev_slave);
	if (ret < 0)
		goto fail_unreg_2;

	ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, 0x4d0, 2, &s->dev_eclr);
	if (ret < 0)
		goto fail_unreg_1;

	mutex_unlock(&kvm->slots_lock);

	kvm->arch.vpic = s;

	return 0;

fail_unreg_1:
	kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS, &s->dev_slave);

fail_unreg_2:
	kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS, &s->dev_master);

fail_unlock:
	mutex_unlock(&kvm->slots_lock);

	kfree(s);

	return ret;
}

void kvm_pic_destroy(struct kvm *kvm)
{
	struct kvm_pic *vpic = kvm->arch.vpic;

	if (!vpic)
		return;

	mutex_lock(&kvm->slots_lock);
	kvm_io_bus_unregister_dev(vpic->kvm, KVM_PIO_BUS, &vpic->dev_master);
	kvm_io_bus_unregister_dev(vpic->kvm, KVM_PIO_BUS, &vpic->dev_slave);
	kvm_io_bus_unregister_dev(vpic->kvm, KVM_PIO_BUS, &vpic->dev_eclr);
	mutex_unlock(&kvm->slots_lock);

	kvm->arch.vpic = NULL;
	kfree(vpic);
}
