#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
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
	assert_int_equal(u, 0);

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
	assert_int_equal(u, 0);

	rc = setegid(42);
	assert_int_equal(rc, 0);

	u = getegid();
	assert_int_equal(u, 42);
}

static void test_uwrap_syscall(void **state)
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
	assert_int_equal(u, 0);

	rc = syscall(SYS_setreuid, -1, 42);
	assert_int_equal(rc, 0);

	u = geteuid();
	assert_int_equal(u, 42);
}

int main(void) {
	int rc;

	const UnitTest tests[] = {
		unit_test(test_uwrap_seteuid),
		unit_test(test_uwrap_setegid),
		unit_test(test_uwrap_syscall),
	};

	rc = run_tests(tests);

	return rc;
}
