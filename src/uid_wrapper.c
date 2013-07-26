/*
 * Copyright (c) 2009      Andrew Tridgell
 * Copyright (c) 2011-2013 Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

#ifdef HAVE_GCC_THREAD_LOCAL_STORAGE
# define UWRAP_THREAD __thread
#else
# define UWRAP_THREAD
#endif

#ifdef NDEBUG
#define UWRAP_DEBUG(...)
#else
#define UWRAP_DEBUG(...) fprintf(stderr, __VA_ARGS__)
#endif

#define LIBC_NAME "libc.so"

struct uwrap_libc_fns {
	int (*_libc_setuid)(uid_t uid);
	uid_t (*_libc_getuid)(void);

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

	int (*_libc_setgid)(gid_t gid);
	gid_t (*_libc_getgid)(void);
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
	uid_t ruid;
	uid_t euid;
	uid_t suid;
	uid_t mygid;
	gid_t rgid;
	gid_t egid;
	gid_t sgid;
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
	int flags = RTLD_LAZY;

#ifdef RTLD_DEEPBIND
	flags |= RTLD_DEEPBIND;
#endif

	for (u->libc.handle = NULL, i = 10; u->libc.handle == NULL; i--) {
		char soname[256] = {0};

		snprintf(soname, sizeof(soname), "%s.%u", LIBC_NAME, i);
		u->libc.handle = dlopen(soname, flags);
	}

	if (u->libc.handle == NULL) {
		printf("Failed to dlopen %s.%u: %s\n", LIBC_NAME, i, dlerror());
		exit(-1);
	}

	*(void **) (&u->libc.fns._libc_setuid) = uwrap_libc_fn(u, "setuid");
	*(void **) (&u->libc.fns._libc_getuid) = uwrap_libc_fn(u, "getuid");

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

	*(void **) (&u->libc.fns._libc_setgid) = uwrap_libc_fn(u, "setgid");
	*(void **) (&u->libc.fns._libc_getgid) = uwrap_libc_fn(u, "getgid");
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
		uwrap.myuid = uwrap.libc.fns._libc_geteuid();
		uwrap.mygid = uwrap.libc.fns._libc_getegid();

		uwrap.ruid = uwrap.euid = uwrap.suid = uwrap.myuid;
		uwrap.rgid = uwrap.egid = uwrap.sgid = uwrap.mygid;

		uwrap.ngroups = 1;
		uwrap.groups = malloc(sizeof(gid_t) * uwrap.ngroups);
		uwrap.groups[0] = uwrap.mygid;
	}
}

static int uwrap_enabled(void)
{
	uwrap_init();

	return uwrap.enabled ? 1 : 0;
}

static int uwrap_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	if (ruid == (uid_t)-1 && euid == (uid_t)-1 && suid == (uid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	if (ruid != (uid_t)-1) {
		uwrap.ruid = ruid;
	}

	if (euid != (uid_t)-1) {
		uwrap.euid = euid;
	}

	if (suid != (uid_t)-1) {
		uwrap.suid = suid;
	}

	return 0;
}

/*
 * SETUID
 */
int setuid(uid_t uid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setuid(uid);
	}

	return uwrap_setresuid(uid, -1, -1);
}

/*
 * GETUID
 */
static uid_t uwrap_getuid(void)
{
	return uwrap.ruid;
}

uid_t getuid(void)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_getuid();
	}

	return uwrap_getuid();
}

#ifdef HAVE_SETEUID
int seteuid(uid_t euid)
{
	if (euid == (uid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_seteuid(euid);
	}

	return uwrap_setresuid(-1, euid, -1);
}
#endif

#ifdef HAVE_SETREUID
int setreuid(uid_t ruid, uid_t euid)
{
	if (ruid == (uid_t)-1 && euid == (uid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setreuid(ruid, euid);
	}

	return uwrap_setresuid(ruid, euid, -1);
}
#endif

#ifdef HAVE_SETRESUID
int setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setresuid(ruid, euid, suid);
	}

	return uwrap_setresuid(ruid, euid, suid);
}
#endif

static uid_t uwrap_geteuid(void)
{
	return uwrap.euid;
}

uid_t geteuid(void)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_geteuid();
	}

	return uwrap_geteuid();
}

/*
 * SETGID
 */
static int uwrap_setgid(gid_t gid)
{
	if (gid == (gid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	uwrap.rgid = gid;

	return 0;
}

int setgid(gid_t gid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setgid(gid);
	}

	return uwrap_setgid(gid);
}

/*
 * GETGID
 */
static gid_t uwrap_getgid(void)
{
	return uwrap.ruid;
}

gid_t getgid(void)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_getgid();
	}

	return uwrap_getgid();
}

static int uwrap_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	if (rgid == (gid_t)-1 && egid == (gid_t)-1 && sgid == (gid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	if (rgid != (gid_t)-1) {
		uwrap.rgid = rgid;
	}

	if (egid != (gid_t)-1) {
		uwrap.egid = egid;
	}

	if (sgid != (gid_t)-1) {
		uwrap.sgid = sgid;
	}

	return 0;
}

#ifdef HAVE_SETEGID
int setegid(gid_t egid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setegid(egid);
	}

	return uwrap_setresgid(-1, egid, -1);
}
#endif

#ifdef HAVE_SETREGID
int setregid(gid_t rgid, gid_t egid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setregid(rgid, egid);
	}

	return uwrap_setresgid(rgid, egid, -1);
}
#endif

#ifdef HAVE_SETRESGID
int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setregid(rgid, egid, sgid);
	}

	return uwrap_setresgid(rgid, egid, sgid);
}
#endif

static uid_t uwrap_getegid(void)
{
	return uwrap.egid;
}

uid_t getegid(void)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_getegid();
	}

	return uwrap_getegid();
}

static int uwrap_setgroups(size_t size, const gid_t *list)
{
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

int setgroups(size_t size, const gid_t *list)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setgroups(size, list);
	}

	return uwrap_setgroups(size, list);
}

static int uwrap_getgroups(int size, gid_t *list)
{
	int ngroups;

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

int getgroups(int size, gid_t *list)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_getgroups(size, list);
	}

	return uwrap_getgroups(size, list);
}

static long int libc_vsyscall(long int sysno, va_list va)
{
	long int args[8];
	long int rc;
	int i;

	for (i = 0; i < 8; i++) {
		args[i] = va_arg(va, long int);
	}

	rc = uwrap.libc.fns._libc_syscall(sysno,
					  args[0],
					  args[1],
					  args[2],
					  args[3],
					  args[4],
					  args[5],
					  args[6],
					  args[7]);

	return rc;
}

#if (defined(HAVE_SYS_SYSCALL_H) || defined(HAVE_SYSCALL_H)) \
    && (defined(SYS_setreuid) || defined(SYS_setreuid32))
static long int uwrap_syscall (long int sysno, va_list vp)
{
	long int rc;

	switch (sysno) {
		/* gid */
		case SYS_setgid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setgid32:
#endif
			{
				gid_t gid = (gid_t) va_arg(vp, int);

				rc = uwrap_setresgid(gid, -1, -1);
			}
			break;
		case SYS_setregid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setregid32:
#endif
			{
				uid_t rgid = (uid_t) va_arg(vp, int);
				uid_t egid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresgid(rgid, egid, -1);
			}
			break;
		case SYS_setresgid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setresgid32:
#endif
			{
				uid_t rgid = (uid_t) va_arg(vp, int);
				uid_t egid = (uid_t) va_arg(vp, int);
				uid_t sgid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresgid(rgid, egid, sgid);
			}
			break;

		/* uid */
		case SYS_setuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setuid32:
#endif
			{
				uid_t uid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresuid(uid, -1, -1);
			}
			break;
		case SYS_setreuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setreuid32:
#endif
			{
				uid_t ruid = (uid_t) va_arg(vp, int);
				uid_t euid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresuid(ruid, euid, -1);
			}
			break;
		case SYS_setresuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setresuid32:
#endif
			{
				uid_t ruid = (uid_t) va_arg(vp, int);
				uid_t euid = (uid_t) va_arg(vp, int);
				uid_t suid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresuid(ruid, euid, suid);
			}
			break;

		/* groups */
		case SYS_setgroups:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setgroups32:
#endif
			{
				size_t size = (size_t) va_arg(vp, size_t);
				gid_t *list = (gid_t *) va_arg(vp, int *);

				rc = uwrap_setgroups(size, list);
			}
			break;
#ifdef SYS_initgroups
		case SYS_initgroups:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_initgroups32:
#endif
			{
				const char *user = (const char *) va_arg(vp, char*);
				gid_t group = (gid_t) va_arg(vp, int);

				rc = initgroups(user, group);
			}
			break;
#endif
		default:
			UWRAP_DEBUG("UID_WRAPPER calling non-wrapped syscall "
				    "%lu\n", sysno);

			rc = libc_vsyscall(sysno, vp);
			break;
	}

	return rc;
}

#ifdef HAVE_SYSCALL
long int syscall (long int sysno, ...)
{
	long int rc;
	va_list va;

	va_start(va, sysno);

	if (!uwrap_enabled()) {
		rc = libc_vsyscall(sysno, va);
		va_end(va);
		return rc;
	}

	rc = uwrap_syscall(sysno, va);
	va_end(va);

	return rc;
}
#endif /* HAVE_SYSCALL */
#endif /* HAVE_SYS_SYSCALL_H || HAVE_SYSCALL_H */
