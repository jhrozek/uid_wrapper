/*
 * Copyright (c) 2009      Andrew Tridgell
 * Copyright (c) 2011-2013 Andreas Schneider <asn@samba.org>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_SYSCALL_H
#include <syscall.h>
#endif
#include <dlfcn.h>

#define LIBC_NAME "libc.so"

struct uwrap_libc_fns {
#ifdef HAVE_SETEUID
	int (*_libc_seteuid)(uid_t euid);
#endif
#ifdef HAVE_SETREUID
	int (*_libc_setreuid)(uid_t ruid, uid_t euid);
#endif
#ifdef HAVE_SETREUID
	int (*_libc_setresuid)(uid_t ruid, uid_t euid, uid_t suid);
#endif
	uid_t (*_libc_geteuid)(void);
#ifdef HAVE_SETEGID
	int (*_libc_setegid)(uid_t egid);
#endif
#ifdef HAVE_SETREGID
	int (*_libc_setregid)(uid_t rgid, uid_t egid);
#endif
#ifdef HAVE_SETREGID
	int (*_libc_setresgid)(uid_t rgid, uid_t egid, uid_t sgid);
#endif
	gid_t (*_libc_getegid)(void);
	int (*_libc_getgroups)(int size, gid_t list[]);
	int (*_libc_setgroups)(size_t size, const gid_t *list);
	uid_t (*_libc_getuid)(void);
	gid_t (*_libc_getgid)(void);
#ifdef HAVE_SYSCALL
	long int (*_libc_syscall)(long int sysno, ...);
#endif
};

/*
 * We keep the virtualised euid/egid/groups information here
 */
struct uwrap {
	struct {
		void *handle;
		struct uwrap_libc_fns fns;
	} libc;
	bool initialised;
	bool enabled;
	uid_t myuid;
	uid_t euid;
	uid_t mygid;
	gid_t egid;
	gid_t *groups;
	int ngroups;
};

static struct uwrap uwrap;

static void *uwrap_libc_fn(struct uwrap *u, const char *fn_name)
{
	void *func;

	if (u->libc.handle == NULL) {
		return NULL;
	}

	func = dlsym(u->libc.handle, fn_name);
	if (func == NULL) {
		printf("Failed to find %s in %s: %s\n",
				fn_name, LIBC_NAME, dlerror());
		exit(-1);
	}

	return func;
}

static void uwrap_libc_init(struct uwrap *u)
{
	unsigned int i;

	for (u->libc.handle = NULL, i = 10; u->libc.handle == NULL; i--) {
		char soname[256] = {0};

		snprintf(soname, sizeof(soname), "%s.%u", LIBC_NAME, i);
		u->libc.handle = dlopen(soname, RTLD_LAZY);
	}

	if (u->libc.handle == NULL) {
		printf("Failed to dlopen %s.%u: %s\n", LIBC_NAME, i, dlerror());
		exit(-1);
	}

#ifdef HAVE_SETEUID
	*(void **) (&u->libc.fns._libc_seteuid) = uwrap_libc_fn(u, "seteuid");
#endif
#ifdef HAVE_SETREUID
	*(void **) (&u->libc.fns._libc_setreuid) = uwrap_libc_fn(u, "setreuid");
#endif
#ifdef HAVE_SETRESUID
	*(void **) (&u->libc.fns._libc_setresuid) = uwrap_libc_fn(u, "setresuid");
#endif
	*(void **) (&u->libc.fns._libc_geteuid) = uwrap_libc_fn(u, "geteuid");
#ifdef HAVE_SETEGID
	*(void **) (&u->libc.fns._libc_setegid) = uwrap_libc_fn(u, "setegid");
#endif
#ifdef HAVE_SETREGID
	*(void **) (&u->libc.fns._libc_setregid) = uwrap_libc_fn(u, "setregid");
#endif
#ifdef HAVE_SETRESGID
	*(void **) (&u->libc.fns._libc_setresgid) = uwrap_libc_fn(u, "setresgid");
#endif
	*(void **) (&u->libc.fns._libc_getegid) = uwrap_libc_fn(u, "getegid");
	*(void **) (&u->libc.fns._libc_getgroups) = uwrap_libc_fn(u, "getgroups");
	*(void **) (&u->libc.fns._libc_setgroups) = uwrap_libc_fn(u, "setgroups");
	*(void **) (&u->libc.fns._libc_getuid) = uwrap_libc_fn(u, "getuid");
	*(void **) (&u->libc.fns._libc_getgid) = uwrap_libc_fn(u, "getgid");
#ifdef HAVE_SYSCALL
	*(void **) (&u->libc.fns._libc_syscall) = uwrap_libc_fn(u, "syscall");
#endif
}

static void uwrap_init(void)
{
	if (uwrap.initialised) {
		return;
	}

	uwrap_libc_init(&uwrap);

	uwrap.initialised = true;
	uwrap.enabled = false;

	if (getenv("UID_WRAPPER")) {
		uwrap.enabled = true;
		/* put us in one group */
		uwrap.myuid = uwrap.euid = geteuid();
		uwrap.mygid = uwrap.egid = getegid();
		uwrap.ngroups = 1;
		uwrap.groups = malloc(sizeof(gid_t) * uwrap.ngroups);
		uwrap.groups[0] = 0;
	}
}

static int uwrap_enabled(void)
{
	uwrap_init();

	return uwrap.enabled ? 1 : 0;
}

#ifdef HAVE_SETEUID
int seteuid(uid_t euid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_seteuid(euid);
	}

	/* assume for now that the ruid stays as root */
	if (euid == 0) {
		uwrap.euid = uwrap.myuid;
	} else {
		uwrap.euid = euid;
	}

	return 0;
}
#endif

#ifdef HAVE_SETREUID
int setreuid(uid_t ruid, uid_t euid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setreuid(ruid, euid);
	}
	/* assume for now that the ruid stays as root */
	if (euid == 0) {
		uwrap.euid = uwrap.myuid;
	} else {
		uwrap.euid = euid;
	}

	return 0;
}
#endif

#ifdef HAVE_SETRESUID
int setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setresuid(ruid, euid, suid);
	}

	/* assume for now that the ruid stays as root */
	if (euid == 0) {
		uwrap.euid = uwrap.myuid;
	} else {
		uwrap.euid = euid;
	}

	return 0;
}
#endif

uid_t geteuid(void)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_geteuid();
	}

	return uwrap.euid;
}

#ifdef HAVE_SETEGID
int setegid(gid_t egid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setegid(egid);
	}

	/* assume for now that the ruid stays as root */
	if (egid == 0) {
		uwrap.egid = uwrap.mygid;
	} else {
		uwrap.egid = egid;
	}

	return 0;
}
#endif

#ifdef HAVE_SETREGID
int setregid(gid_t rgid, gid_t egid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setregid(rgid, egid);
	}

	/* assume for now that the ruid stays as root */
	if (egid == 0) {
		uwrap.egid = uwrap.mygid;
	} else {
		uwrap.egid = egid;
	}

	return 0;
}
#endif

#ifdef HAVE_SETRESGID
int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setregid(rgid, egid, sgid);
	}

	/* assume for now that the ruid stays as root */
	if (egid == 0) {
		uwrap.egid = uwrap.mygid;
	} else {
		uwrap.egid = egid;
	}
	return 0;
}
#endif

uid_t getegid(void)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_getegid();
	}

	return uwrap.egid;
}

int setgroups(size_t size, const gid_t *list)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setgroups(size, list);
	}

	free(uwrap.groups);
	uwrap.groups = NULL;
	uwrap.ngroups = 0;

	if (size != 0) {
		uwrap.groups = malloc(sizeof(gid_t) * size);
		if (uwrap.groups == NULL) {
			errno = ENOMEM;
			return -1;
		}
		uwrap.ngroups = size;
		memcpy(uwrap.groups, list, size*sizeof(gid_t));
	}

	return 0;
}

int getgroups(int size, gid_t *list)
{
	int ngroups;

	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_getgroups(size, list);
	}

	ngroups = uwrap.ngroups;

	if (size > ngroups) {
		size = ngroups;
	}
	if (size == 0) {
		return ngroups;
	}
	if (size < ngroups) {
		errno = EINVAL;
		return -1;
	}
	memcpy(list, uwrap.groups, size*sizeof(gid_t));

	return ngroups;
}

uid_t getuid(void)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_getuid();
	}

	/* we don't simulate ruid changing */
	return 0;
}

gid_t getgid(void)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_getgid();
	}

	/* we don't simulate rgid changing */
	return 0;
}

#ifdef HAVE_SYSCALL
long int syscall (long int sysno, ...)
{
	long int rc;
	va_list va;

	va_start(va, sysno);

	switch (sysno) {
		case SYS_setreuid:
			rc = setreuid(va_arg(va, uid_t),
				      va_arg(va, uid_t));
			break;
		case SYS_setresuid:
			rc = setresuid(va_arg(va, uid_t),
				       va_arg(va, uid_t),
				       va_arg(va, uid_t));
			break;
		default:
			rc = uwrap.libc.fns._libc_syscall(sysno, va);
			break;
	}
	va_end(va);

	return rc;
}
#endif
