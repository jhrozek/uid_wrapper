#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <grp.h>

#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_SYSCALL_H
#include <syscall.h>
#endif

#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static void test_uwrap_seteuid(void **state)
{
	int rc;
	uid_t u;

	(void) state; /* unused */

	rc = seteuid(-1);
	assert_int_equal(rc, -1);

	rc = seteuid(0);
	assert_int_equal(rc, 0);

	u = geteuid();
#ifdef SYS_geteuid /* not available on Solaris */
	assert_int_equal(u, syscall(SYS_geteuid));
#endif

	rc = setuid(42);
	assert_int_equal(rc, 0);

	u = getuid();
	assert_int_equal(u, 42);
}

static void test_uwrap_setuid(void **state)
{
	int rc;
	uid_t u;

	(void) state; /* unused */

	rc = setuid(-1);
	assert_int_equal(rc, -1);

	rc = setuid(42);
	assert_int_equal(rc, 0);

	u = getuid();
	assert_int_equal(u, 42);
}

static void test_uwrap_setegid(void **state)
{
	int rc;
	uid_t u;

	(void) state; /* unused */

	rc = setegid(0);
	assert_int_equal(rc, 0);

	u = getegid();
#ifdef SYS_getegid /* Not available on Solaris */
	assert_int_equal(u, syscall(SYS_getegid));
#endif

	rc = setegid(42);
	assert_int_equal(rc, 0);

	u = getegid();
	assert_int_equal(u, 42);
}

#ifdef HAVE_SETREGID
static void test_uwrap_setregid(void **state)
{
	int rc;
	uid_t u;

	(void) state; /* unused */

	rc = setregid(1, 2);
	assert_int_equal(rc, 0);

	u = getgid();
	assert_int_equal(u, 1);

	u = getegid();
	assert_int_equal(u, 2);
}
#endif

#ifdef HAVE_SETRESGID
static void test_uwrap_setresgid(void **state)
{
	int rc;
	uid_t u;

	(void) state; /* unused */

	rc = setresgid(1, 2, -1);
	assert_int_equal(rc, 0);

	u = getgid();
	assert_int_equal(u, 1);

	u = getegid();
	assert_int_equal(u, 2);
}
#endif

static void test_uwrap_setgid(void **state)
{
	int rc;
	gid_t u;

	(void) state; /* unused */

	rc = setgid(-1);
	assert_int_equal(rc, -1);

	rc = setgid(42);
	assert_int_equal(rc, 0);

	u = getgid();
	assert_int_equal(u, 42);
}

static void test_uwrap_syscall(void **state)
{
	long int rc;
	struct timeval tv1, tv2;
	struct timezone tz1, tz2;

	(void) state; /* unused */

	rc = syscall(SYS_getpid);
	assert_int_equal(rc, getpid());

	rc = access(".", R_OK);
	assert_int_equal(rc, 0);

	rc = syscall(SYS_access, ".", R_OK);
	assert_int_equal(rc, 0);

	ZERO_STRUCT(tv1);
	ZERO_STRUCT(tv2);
	ZERO_STRUCT(tz1);
	ZERO_STRUCT(tz2);

	rc = gettimeofday(&tv1, &tz1);
	assert_int_equal(rc, 0);

	rc = syscall(SYS_gettimeofday, &tv2, &tz2);
	assert_int_equal(rc, 0);

	assert_int_equal(tv1.tv_sec, tv2.tv_sec);
	assert_int_equal(tz2.tz_dsttime, tz2.tz_dsttime);
	assert_int_equal(tz2.tz_minuteswest, tz2.tz_minuteswest);
}

static void test_uwrap_syscall_setreuid(void **state)
{
	long int rc;
	uid_t u;

	(void) state; /* unused */

	rc = syscall(SYS_setreuid, -1, 0);
	assert_int_equal(rc, 0);

	u = geteuid();
#ifdef SYS_geteuid /* not available on Solaris */
	assert_int_equal(u, syscall(SYS_geteuid));
#endif

	rc = syscall(SYS_setreuid, -1, 42);
	assert_int_equal(rc, 0);

	u = geteuid();
	assert_int_equal(u, 42);
}

static void test_uwrap_syscall_setregid(void **state)
{
	long int rc;
	gid_t g;

	(void) state; /* unused */

	rc = syscall(SYS_setregid, -1, 0);
	assert_int_equal(rc, 0);

	g = getegid();
#ifdef SYS_getegid /* Not available on Solaris */
	assert_int_equal(g, syscall(SYS_getegid));
#endif

	rc = syscall(SYS_setregid, -1, 42);
	assert_int_equal(rc, 0);

	g = getegid();
	assert_int_equal(g, 42);
}

static void test_uwrap_getgroups(void **state)
{
	gid_t rlist[16] = {0};
	int rc;

	(void) state; /* unused */

	rc = getgroups(ARRAY_SIZE(rlist), rlist);
	assert_int_equal(rc, 1);
	assert_int_equal(rlist[0], getegid());
}

static void test_uwrap_setgroups(void **state)
{
	gid_t glist[] = { 100, 200, 300, 400, 500 };
	gid_t rlist[16];
	int rc;

	(void) state; /* unused */

	rc = setgroups(ARRAY_SIZE(glist), glist);
	assert_int_equal(rc, 0);

	rc = getgroups(ARRAY_SIZE(rlist), rlist);
	assert_int_equal(rc, 5);

	assert_memory_equal(glist, rlist, sizeof(glist));
}

int main(void) {
	int rc;

	const UnitTest tests[] = {
		unit_test(test_uwrap_syscall),
		unit_test(test_uwrap_getgroups),

		unit_test(test_uwrap_seteuid),
		unit_test(test_uwrap_setuid),
		unit_test(test_uwrap_setegid),
#ifdef HAVE_SETREGID
		unit_test(test_uwrap_setregid),
#endif
#ifdef HAVE_SETRESGID
		unit_test(test_uwrap_setresgid),
#endif
		unit_test(test_uwrap_setgid),
		unit_test(test_uwrap_syscall_setreuid),
		unit_test(test_uwrap_syscall_setregid),
		unit_test(test_uwrap_setgroups),
	};

	rc = run_tests(tests);

	return rc;
}
