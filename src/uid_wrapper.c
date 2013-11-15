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

#include <pthread.h>

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

#define UWRAP_DLIST_ADD(list,item) do { \
	if (!(list)) { \
		(item)->prev	= NULL; \
		(item)->next	= NULL; \
		(list)		= (item); \
	} else { \
		(item)->prev	= NULL; \
		(item)->next	= (list); \
		(list)->prev	= (item); \
		(list)		= (item); \
	} \
} while (0)

#define UWRAP_DLIST_REMOVE(list,item) do { \
	if ((list) == (item)) { \
		(list)		= (item)->next; \
		if (list) { \
			(list)->prev	= NULL; \
		} \
	} else { \
		if ((item)->prev) { \
			(item)->prev->next	= (item)->next; \
		} \
		if ((item)->next) { \
			(item)->next->prev	= (item)->prev; \
		} \
	} \
	(item)->prev	= NULL; \
	(item)->next	= NULL; \
} while (0)

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
struct uwrap_thread {
	pthread_t tid;
	bool dead;

	uid_t ruid;
	uid_t euid;
	uid_t suid;

	gid_t rgid;
	gid_t egid;
	gid_t sgid;

	gid_t *groups;
	int ngroups;

	struct uwrap_thread *next;
	struct uwrap_thread *prev;
};

struct uwrap {
	struct {
		void *handle;
		struct uwrap_libc_fns fns;
	} libc;

	bool initialised;
	bool enabled;

	uid_t myuid;
	uid_t mygid;

	struct uwrap_thread *ids;
};

static struct uwrap uwrap;

/* Shortcut to the list item */
static UWRAP_THREAD struct uwrap_thread *uwrap_tls_id;

/* The mutex or accessing the id */
static pthread_mutex_t uwrap_id_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *uwrap_libc_fn(struct uwrap *u, const char *fn_name)
{
	void *func;

#ifdef HAVE_APPLE
	func = dlsym(RTLD_NEXT, fn_name);
#else
	if (u->libc.handle == NULL) {
		return NULL;
	}

	func = dlsym(u->libc.handle, fn_name);
#endif
	if (func == NULL) {
		printf("Failed to find %s in %s: %s\n",
				fn_name, LIBC_NAME, dlerror());
		exit(-1);
	}

	return func;
}

static void uwrap_libc_init(struct uwrap *u)
{
	unsigned int i = 0;
#ifndef HAVE_APPLE
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
#endif

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

static struct uwrap_thread *find_uwrap_id(pthread_t tid)
{
	struct uwrap_thread *id;

	for (id = uwrap.ids; id; id = id->next) {
		if (pthread_equal(id->tid, tid)) {
			return id;
		}
	}

	return NULL;
}

static int uwrap_new_id(pthread_t tid, bool do_alloc)
{
	struct uwrap_thread *id = uwrap_tls_id;

	if (do_alloc) {
		id = malloc(sizeof(struct uwrap_thread));
		if (id == NULL) {
			errno = ENOMEM;
			return -1;
		}
	}

	id->tid = tid;
	id->dead = false;

	id->ruid = id->euid = id->suid = uwrap.myuid;
	id->rgid = id->egid = id->sgid = uwrap.mygid;

	id->ngroups = 1;
	id->groups = malloc(sizeof(gid_t) * id->ngroups);
	id->groups[0] = uwrap.mygid;

	if (do_alloc) {
		UWRAP_DLIST_ADD(uwrap.ids, id);
		uwrap_tls_id = id;
	}

	return 0;
}

static void uwrap_thread_prepare(void)
{
	pthread_mutex_lock(&uwrap_id_mutex);

	/*
	 * What happens if another atfork prepare functions calls a uwrap
	 * function? So disable it in case another atfork prepare function
	 * calls a (s)uid function.
	 */
	uwrap.enabled = false;
}

static void uwrap_thread_parent(void)
{
	uwrap.enabled = true;

	pthread_mutex_unlock(&uwrap_id_mutex);
}

static void uwrap_thread_child(void)
{
	uwrap.enabled = true;

	pthread_mutex_unlock(&uwrap_id_mutex);
}

static void uwrap_init(void)
{
	const char *env = getenv("UID_WRAPPER");
	pthread_t tid = pthread_self();



	if (uwrap.initialised) {
		struct uwrap_thread *id = uwrap_tls_id;
		int rc;

		/*
		 * If we hold a lock and the application forks, then the child
		 * is not able to unlock the mutex and we are in a deadlock.
		 * This should prevent such deadlocks.
		 */
		pthread_atfork(&uwrap_thread_prepare,
			       &uwrap_thread_parent,
			       &uwrap_thread_child);

		if (id != NULL) {
			return;
		}

		pthread_mutex_lock(&uwrap_id_mutex);
		id = find_uwrap_id(tid);
		if (id == NULL) {
			rc = uwrap_new_id(tid, 1);
			if (rc < 0) {
				exit(-1);
			}
		} else {
			/* We reuse an old thread id */
			uwrap_tls_id = id;

			uwrap_new_id(tid, 0);
		}
		pthread_mutex_unlock(&uwrap_id_mutex);

		return;
	}

	pthread_mutex_lock(&uwrap_id_mutex);

	uwrap_libc_init(&uwrap);

	uwrap.initialised = true;
	uwrap.enabled = false;

	if (env != NULL && env[0] == '1') {
		const char *root = getenv("UID_WRAPPER_ROOT");
		int rc;

		/* put us in one group */
		if (root != NULL && root[0] == '1') {
			uwrap.myuid = 0;
			uwrap.mygid = 0;
		} else {
			uwrap.myuid = uwrap.libc.fns._libc_geteuid();
			uwrap.mygid = uwrap.libc.fns._libc_getegid();
		}

		rc = uwrap_new_id(tid, 1);
		if (rc < 0) {
			exit(-1);
		}

		uwrap.enabled = true;
	}

	pthread_mutex_unlock(&uwrap_id_mutex);
}

static int uwrap_enabled(void)
{
	uwrap_init();

	return uwrap.enabled ? 1 : 0;
}

static int uwrap_setresuid_thread(uid_t ruid, uid_t euid, uid_t suid)
{
	struct uwrap_thread *id = uwrap_tls_id;

	if (ruid == (uid_t)-1 && euid == (uid_t)-1 && suid == (uid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&uwrap_id_mutex);
	if (ruid != (uid_t)-1) {
		id->ruid = ruid;
	}

	if (euid != (uid_t)-1) {
		id->euid = euid;
	}

	if (suid != (uid_t)-1) {
		id->suid = suid;
	}
	pthread_mutex_unlock(&uwrap_id_mutex);

	return 0;
}

static int uwrap_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	struct uwrap_thread *id;

	if (ruid == (uid_t)-1 && euid == (uid_t)-1 && suid == (uid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&uwrap_id_mutex);
	for (id = uwrap.ids; id; id = id->next) {
		if (id->dead) {
			continue;
		}

		if (ruid != (uid_t)-1) {
			id->ruid = ruid;
		}

		if (euid != (uid_t)-1) {
			id->euid = euid;
		}

		if (suid != (uid_t)-1) {
			id->suid = suid;
		}
	}
	pthread_mutex_unlock(&uwrap_id_mutex);

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

/*
 * GETUID
 */
static uid_t uwrap_getuid(void)
{
	struct uwrap_thread *id = uwrap_tls_id;
	uid_t uid;

	pthread_mutex_lock(&uwrap_id_mutex);
	uid = id->ruid;
	pthread_mutex_unlock(&uwrap_id_mutex);

	return uid;
}

uid_t getuid(void)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_getuid();
	}

	return uwrap_getuid();
}

/*
 * GETEUID
 */
static uid_t uwrap_geteuid(void)
{
	const char *env = getenv("UID_WRAPPER_ROOT");
	struct uwrap_thread *id = uwrap_tls_id;
	uid_t uid;

	pthread_mutex_lock(&uwrap_id_mutex);
	uid = id->euid;
	pthread_mutex_unlock(&uwrap_id_mutex);

	/* Disable root and return myuid */
	if (env != NULL && env[0] == '2') {
		uid = uwrap.myuid;
	}

	return uid;
}

uid_t geteuid(void)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_geteuid();
	}

	return uwrap_geteuid();
}

static int uwrap_setresgid_thread(gid_t rgid, gid_t egid, gid_t sgid)
{
	struct uwrap_thread *id = uwrap_tls_id;

	if (rgid == (gid_t)-1 && egid == (gid_t)-1 && sgid == (gid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&uwrap_id_mutex);
	if (rgid != (gid_t)-1) {
		id->rgid = rgid;
	}

	if (egid != (gid_t)-1) {
		id->egid = egid;
	}

	if (sgid != (gid_t)-1) {
		id->sgid = sgid;
	}
	pthread_mutex_unlock(&uwrap_id_mutex);

	return 0;
}

static int uwrap_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	struct uwrap_thread *id;

	if (rgid == (gid_t)-1 && egid == (gid_t)-1 && sgid == (gid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&uwrap_id_mutex);
	for (id = uwrap.ids; id; id = id->next) {
		if (id->dead) {
			continue;
		}

		if (rgid != (gid_t)-1) {
			id->rgid = rgid;
		}

		if (egid != (gid_t)-1) {
			id->egid = egid;
		}

		if (sgid != (gid_t)-1) {
			id->sgid = sgid;
		}
	}
	pthread_mutex_unlock(&uwrap_id_mutex);

	return 0;
}

/*
 * SETGID
 */
int setgid(gid_t gid)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setgid(gid);
	}

	return uwrap_setresgid(gid, -1, -1);
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

/*
 * GETGID
 */
static gid_t uwrap_getgid(void)
{
	struct uwrap_thread *id = uwrap_tls_id;
	gid_t gid;

	pthread_mutex_lock(&uwrap_id_mutex);
	gid = id->rgid;
	pthread_mutex_unlock(&uwrap_id_mutex);

	return gid;
}

gid_t getgid(void)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_getgid();
	}

	return uwrap_getgid();
}

/*
 * GETEGID
 */
static uid_t uwrap_getegid(void)
{
	struct uwrap_thread *id = uwrap_tls_id;
	gid_t gid;

	pthread_mutex_lock(&uwrap_id_mutex);
	gid = id->egid;
	pthread_mutex_unlock(&uwrap_id_mutex);

	return gid;
}

uid_t getegid(void)
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_getegid();
	}

	return uwrap_getegid();
}

static int uwrap_setgroups_thread(size_t size, const gid_t *list)
{
	struct uwrap_thread *id = uwrap_tls_id;
	int rc = -1;

	pthread_mutex_lock(&uwrap_id_mutex);
	free(id->groups);
	id->groups = NULL;
	id->ngroups = 0;

	if (size != 0) {
		id->groups = malloc(sizeof(gid_t) * size);
		if (id->groups == NULL) {
			errno = ENOMEM;
			goto out;
		}
		id->ngroups = size;
		memcpy(id->groups, list, size * sizeof(gid_t));
	}

	rc = 0;
out:
	pthread_mutex_unlock(&uwrap_id_mutex);

	return rc;
}

static int uwrap_setgroups(size_t size, const gid_t *list)
{
	struct uwrap_thread *id;
	int rc = -1;

	pthread_mutex_lock(&uwrap_id_mutex);
	for (id = uwrap.ids; id; id = id->next) {
		free(id->groups);
		id->groups = NULL;
		id->ngroups = 0;

		if (size != 0) {
			id->groups = malloc(sizeof(gid_t) * size);
			if (id->groups == NULL) {
				errno = ENOMEM;
				goto out;
			}
			id->ngroups = size;
			memcpy(id->groups, list, size * sizeof(gid_t));
		}
	}

	rc = 0;
out:
	pthread_mutex_unlock(&uwrap_id_mutex);

	return rc;
}

#ifdef HAVE_SETGROUPS_INT
int setgroups(int size, const gid_t *list)
#else
int setgroups(size_t size, const gid_t *list)
#endif
{
	if (!uwrap_enabled()) {
		return uwrap.libc.fns._libc_setgroups(size, list);
	}

	return uwrap_setgroups(size, list);
}

static int uwrap_getgroups(int size, gid_t *list)
{
	struct uwrap_thread *id = uwrap_tls_id;
	int ngroups;

	pthread_mutex_lock(&uwrap_id_mutex);
	ngroups = id->ngroups;

	if (size > ngroups) {
		size = ngroups;
	}
	if (size == 0) {
		goto out;
	}
	if (size < ngroups) {
		errno = EINVAL;
		ngroups = -1;
	}
	memcpy(list, id->groups, size * sizeof(gid_t));

out:
	pthread_mutex_unlock(&uwrap_id_mutex);

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
		case SYS_getgid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_getgid32:
#endif
			{
				rc = uwrap_getgid();
			}
			break;
		case SYS_getegid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_getegid32:
#endif
			{
				rc = uwrap_getegid();
			}
			break;
		case SYS_setgid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setgid32:
#endif
			{
				gid_t gid = (gid_t) va_arg(vp, int);

				rc = uwrap_setresgid_thread(gid, -1, -1);
			}
			break;
		case SYS_setregid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setregid32:
#endif
			{
				uid_t rgid = (uid_t) va_arg(vp, int);
				uid_t egid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresgid_thread(rgid, egid, -1);
			}
			break;
#ifdef SYS_setresgid
		case SYS_setresgid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setresgid32:
#endif
			{
				uid_t rgid = (uid_t) va_arg(vp, int);
				uid_t egid = (uid_t) va_arg(vp, int);
				uid_t sgid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresgid_thread(rgid, egid, sgid);
			}
			break;
#endif /* SYS_setresgid */

		/* uid */
		case SYS_getuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_getuid32:
#endif
			{
				rc = uwrap_getuid();
			}
			break;
		case SYS_geteuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_geteuid32:
#endif
			{
				rc = uwrap_geteuid();
			}
			break;
		case SYS_setuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setuid32:
#endif
			{
				uid_t uid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresuid_thread(uid, -1, -1);
			}
			break;
		case SYS_setreuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setreuid32:
#endif
			{
				uid_t ruid = (uid_t) va_arg(vp, int);
				uid_t euid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresuid_thread(ruid, euid, -1);
			}
			break;
#ifdef SYS_setresuid
		case SYS_setresuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setresuid32:
#endif
			{
				uid_t ruid = (uid_t) va_arg(vp, int);
				uid_t euid = (uid_t) va_arg(vp, int);
				uid_t suid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresuid_thread(ruid, euid, suid);
			}
			break;
#endif /* SYS_setresuid */

		/* groups */
		case SYS_setgroups:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setgroups32:
#endif
			{
				size_t size = (size_t) va_arg(vp, size_t);
				gid_t *list = (gid_t *) va_arg(vp, int *);

				rc = uwrap_setgroups_thread(size, list);
			}
			break;
		default:
			UWRAP_DEBUG("UID_WRAPPER calling non-wrapped syscall "
				    "%lu\n", sysno);

			rc = libc_vsyscall(sysno, vp);
			break;
	}

	return rc;
}

#ifdef HAVE_SYSCALL
#ifdef HAVE_SYSCALL_INT
int syscall (int sysno, ...)
#else
long int syscall (long int sysno, ...)
#endif
{
#ifdef HAVE_SYSCALL_INT
	int rc;
#else
	long int rc;
#endif
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
