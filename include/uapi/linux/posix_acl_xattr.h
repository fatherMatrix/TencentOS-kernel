/* SPDX-License-Identifier: LGPL-2.1+ WITH Linux-syscall-note */
/*
 * Copyright (C) 2002 Andreas Gruenbacher <a.gruenbacher@computer.org>
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 */

#ifndef __UAPI_POSIX_ACL_XATTR_H
#define __UAPI_POSIX_ACL_XATTR_H

#include <linux/types.h>

/* Supported ACL a_version fields */
#define POSIX_ACL_XATTR_VERSION	0x0002

/* An undefined entry e_id value */
#define ACL_UNDEFINED_ID	(-1)

struct posix_acl_xattr_entry {
	/*
	 * 包含六种tag类型：
	 * ACL_USER_OBJ: 相当于user的权限
	 * ACL_USER：ACL定义的其他用户的权限
	 * ACL_GROUP_OBJ：相当于group的权限
	 * ACL_GROUP：是ACL定义的其他用户组的权限
	 * ACL_MASK：定义了ACL_USER、ACL_GROUP_OBJ和ACL_GROUP的最大权限
	 * ACL_OTHER：相当于other的权限
	 */
	__le16			e_tag;
	/*
	 * 代表权限，即rwx
	 */
	__le16			e_perm;
	/*
	 * 标识唯一的用户或用户组id。
	 * 只有ACL_USER和ACL_GROUP有值，因为只有这两个tag定义了额外的用户权限
	 */
	__le32			e_id;
};

struct posix_acl_xattr_header {
	__le32			a_version;
};

#endif	/* __UAPI_POSIX_ACL_XATTR_H */
