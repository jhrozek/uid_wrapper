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
	char *env;

	env = getenv("UID_WRAPPER");
	if (env == NULL) {
		printf("UID_WRAPPER env not set, uid_wrapper is disabled\n");
		return;
	}

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
#ifdef SYS_getegid /* Not available on Solaris */
	assert_int_equal(u, syscall(SYS_getegid));
#endif

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
	assert_int_equal(u, syscall(SYS_geteuid));

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
	assert_int_equal(g, syscall(SYS_getegid));

	rc = syscall(SYS_setregid, -1, 42);
	assert_int_equal(rc, 0);

	g = getegid();
	assert_int_equal(g, 42);
}

int main(void) {
	int rc;

	const UnitTest tests[] = {
		unit_test(test_uwrap_syscall),
		unit_test(test_uwrap_seteuid),
		unit_test(test_uwrap_setuid),
		unit_test(test_uwrap_setegid),
		unit_test(test_uwrap_syscall_setreuid),
		unit_test(test_uwrap_syscall_setregid),
	};

	rc = run_tests(tests);

	return rc;
}
