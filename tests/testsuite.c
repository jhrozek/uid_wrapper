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
#include <unistd.h>

#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_SYSCALL_H
#include <syscall.h>
#endif

static void test_uwrap_seteuid(void **state)
{
	int rc;
	uid_t u;
	char *env;

	env = getenv("UID_WRAPPER");
	if (env == NULL) {
		printf("UID_WRAPPER env not set, uid_wrapper is disabled\n");
		return;
	}

	(void) state; /* unused */

	rc = seteuid(0);
	assert_int_equal(rc, 0);

	u = geteuid();
	assert_int_equal(u, syscall(SYS_getuid));

	rc = seteuid(42);
	assert_int_equal(rc, 0);

	u = geteuid();
	assert_int_equal(u, 42);
}

static void test_uwrap_setegid(void **state)
{
	int rc;
	uid_t u;
	char *env;

	env = getenv("UID_WRAPPER");
	if (env == NULL) {
		printf("UID_WRAPPER env not set, uid_wrapper is disabled\n");
		return;
	}

	(void) state; /* unused */

	rc = setegid(0);
	assert_int_equal(rc, 0);

	u = getegid();
	assert_int_equal(u, syscall(SYS_getgid));

	rc = setegid(42);
	assert_int_equal(rc, 0);

	u = getegid();
	assert_int_equal(u, 42);
}

static void test_uwrap_syscall(void **state)
{
	long int rc;
	char *env;
	struct stat sb;

	env = getenv("UID_WRAPPER");
	if (env == NULL) {
		printf("UID_WRAPPER env not set, uid_wrapper is disabled\n");
		return;
	}

	(void) state; /* unused */

	rc = access(".", R_OK);
	assert_int_equal(rc, 0);

	rc = syscall(SYS_access, ".", R_OK);
	assert_int_equal(rc, 0);

	rc = syscall(SYS_stat, ".", &sb);
	assert_int_equal(rc, 0);

	assert_true(S_ISDIR(sb.st_mode));
}

static void test_uwrap_syscall_setreuid(void **state)
{
	long int rc;
	uid_t u;
	char *env;

	env = getenv("UID_WRAPPER");
	if (env == NULL) {
		printf("UID_WRAPPER env not set, uid_wrapper is disabled\n");
		return;
	}

	(void) state; /* unused */

	rc = syscall(SYS_setreuid, -1, 0);
	assert_int_equal(rc, 0);

	u = geteuid();
	assert_int_equal(u, syscall(SYS_getuid));

	rc = syscall(SYS_setreuid, -1, 42);
	assert_int_equal(rc, 0);

	u = geteuid();
	assert_int_equal(u, 42);
}

static void test_uwrap_syscall_setregid(void **state)
{
	long int rc;
	gid_t g;
	char *env;

	env = getenv("UID_WRAPPER");
	if (env == NULL) {
		printf("UID_WRAPPER env not set, uid_wrapper is disabled\n");
		return;
	}

	(void) state; /* unused */

	rc = syscall(SYS_setregid, -1, 0);
	assert_int_equal(rc, 0);

	g = getegid();
	assert_int_equal(g, syscall(SYS_getgid));

	rc = syscall(SYS_setregid, -1, 42);
	assert_int_equal(rc, 0);

	g = getegid();
	assert_int_equal(g, 42);
}

int main(void) {
	int rc;

	const UnitTest tests[] = {
		unit_test(test_uwrap_seteuid),
		unit_test(test_uwrap_setegid),
		unit_test(test_uwrap_syscall),
		unit_test(test_uwrap_syscall_setreuid),
		unit_test(test_uwrap_syscall_setregid),
	};

	rc = run_tests(tests);

	return rc;
}
