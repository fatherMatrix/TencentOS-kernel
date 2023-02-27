// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2002-3 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 */

#include <linux/device.h>
#include <linux/init.h>
#include <linux/memory.h>
#include <linux/of.h>

#include "base.h"

/**
 * driver_init - initialize driver model.
 *
 * Call the driver model init functions to initialize their
 * subsystems. Called early from init/main.c.
 */
void __init driver_init(void)
{
	/* These are the core pieces */
	/*
	 * 注册devtmpfs文件系统
	 */
	devtmpfs_init();
	/*
	 * 创建/sys/devices目录
	 */
	devices_init();
	/*
	 * 创建/sys/bus目录
	 */
	buses_init();
	/*
	 * 创建/sys/class目录
	 */
	classes_init();
	/*
	 * 创建/sys/firmware目录
	 */
	firmware_init();
	/*
	 * 创建/sys/hypervisor目录
	 */
	hypervisor_init();

	/* These are also core pieces, but must come after the
	 * core core pieces.
	 */
	of_core_init();
	platform_bus_init();
	cpu_dev_init();
	memory_dev_init();
	container_dev_init();
}
